//! Operator-installed console extensions. Packages are trusted code, not a sandbox.
//! Credentials and backend origins are never included in browser discovery.
use crate::{
    admin_users::{MutationAuthority, Store, User},
    proxy::Body,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Transport-owned context. Only a local relay may supply generated forwarding headers.
#[derive(Clone)]
pub struct ClientContext {
    pub ip: std::net::IpAddr,
    pub user_agent: Option<String>,
}
pub fn client_context<B>(request: &Request<B>, peer: std::net::IpAddr) -> Result<ClientContext> {
    let mut ip = peer;
    if peer.is_loopback() {
        let mut values = request.headers().get_all("x-forwarded-for").iter();
        if let Some(value) = values.next() {
            ensure!(values.next().is_none(), "ambiguous forwarded client");
            ip = value.to_str()?.parse()?;
        }
    }
    let user_agent = request
        .headers()
        .get(hyper::header::USER_AGENT)
        .map(|v| v.to_str().map(str::to_owned))
        .transpose()?;
    ensure!(
        user_agent.as_ref().is_none_or(|v| v.len() <= 1024),
        "user agent too large"
    );
    Ok(ClientContext { ip, user_agent })
}

pub enum Authority {
    Local(Arc<Store>, MutationAuthority),
    Remote {
        client: reqwest::Client,
        endpoint: reqwest::Url,
        authorization: reqwest::header::HeaderValue,
        actor_id: i64,
    },
}
impl Authority {
    pub async fn check(&self) -> Result<()> {
        match self {
            Self::Local(users, authority) => users.authorize_admin(authority.clone()).await,
            Self::Remote {
                client,
                endpoint,
                authorization,
                actor_id,
            } => {
                let mut response = client
                    .get(endpoint.clone())
                    .header(reqwest::header::AUTHORIZATION, authorization.clone())
                    .timeout(Duration::from_secs(3))
                    .send()
                    .await?;
                ensure!(
                    response.status() == StatusCode::OK,
                    "administrator authority unavailable"
                );
                ensure!(
                    response.content_length().is_none_or(|n| n <= 16384),
                    "authority response too large"
                );
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        bytes.len() + chunk.len() <= 16384,
                        "authority response too large"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                #[derive(Deserialize)]
                struct Identity {
                    user: User,
                }
                let identity: Identity = serde_json::from_slice(&bytes)?;
                ensure!(
                    identity.user.enabled
                        && identity.user.role == crate::admin_users::Role::Admin
                        && identity.user.id == *actor_id,
                    "administrator authority was revoked"
                );
                Ok(())
            }
        }
    }
}

const BODY_LIMIT: usize = 1024 * 1024;
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    plugins: Vec<Binding>,
    #[serde(default)]
    audit_database: Option<PathBuf>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    id: String,
    directory: PathBuf,
    manifest_sha256: String,
    backend: String,
    #[serde(default)]
    tls: Option<BackendTls>,
    token_env: String,
    #[serde(default)]
    delegate_actor: bool,
    #[serde(default)]
    delegation_cookie: Option<String>,
    #[serde(default)]
    delegation_authority: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendTls {
    server_name: String,
    ca: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    id: String,
    name: String,
    version: String,
    api_version: u32,
    entry: String,
    assets: BTreeMap<String, String>,
    routes: Vec<Route>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    path: String,
    method: String,
    mutation: bool,
}
struct Asset {
    bytes: Bytes,
    mime: &'static str,
}
struct Plugin {
    client: reqwest::Client,
    manifest: Manifest,
    backend: reqwest::Url,
    token: reqwest::header::HeaderValue,
    delegation_key: Option<Vec<u8>>,
    delegation_cookie: Option<String>,
    delegation_authority: Option<String>,
    assets: BTreeMap<String, Asset>,
}
pub struct Registry {
    plugins: BTreeMap<String, Plugin>,
    slots: tokio::sync::Semaphore,
    audit: PathBuf,
}
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 32
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn asset_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}
fn route_name(s: &str) -> bool {
    s.len() <= 128 && s.split('/').all(valid_id)
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_file() && meta.len() <= limit as u64,
        "invalid plugin file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o022 == 0,
            "plugin file must not be group/world writable"
        );
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "plugin file too large");
    Ok(bytes)
}
fn reply(status: StatusCode, value: Value) -> Response<Body> {
    bytes_reply(
        status,
        "application/json",
        Bytes::from(serde_json::to_vec(&value).unwrap()),
    )
}
fn bytes_reply(status: StatusCode, mime: &str, bytes: Bytes) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", mime)
        .header("cache-control", "no-store")
        .header("x-content-type-options", "nosniff")
        .body(
            Full::new(bytes)
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap()
}
fn problem(status: StatusCode, detail: &str) -> Response<Body> {
    reply(status, json!({"error":detail}))
}
impl Registry {
    pub fn load(path: &Path) -> Result<Self> {
        let config: Configuration = serde_json::from_slice(&bounded_file(path, 64 * 1024)?)?;
        ensure!(config.plugins.len() <= 8, "too many console plugins");
        let mut plugins = BTreeMap::new();
        for binding in config.plugins {
            ensure!(valid_id(&binding.id), "invalid plugin id");
            ensure!(
                fs::symlink_metadata(&binding.directory)?
                    .file_type()
                    .is_dir(),
                "plugin package must be a real directory"
            );
            let manifest_bytes = bounded_file(&binding.directory.join("manifest.json"), 64 * 1024)?;
            ensure!(
                sha(&manifest_bytes) == binding.manifest_sha256,
                "plugin manifest pin mismatch"
            );
            let manifest: Manifest = serde_json::from_slice(&manifest_bytes)?;
            ensure!(
                manifest.id == binding.id
                    && manifest.api_version == 1
                    && !manifest.name.is_empty()
                    && manifest.name.len() <= 64,
                "invalid console plugin manifest"
            );
            semver::Version::parse(&manifest.version)?;
            ensure!(
                manifest.assets.len() <= 16
                    && manifest.routes.len() <= 32
                    && manifest.entry.ends_with(".js")
                    && manifest.assets.contains_key(&manifest.entry),
                "invalid plugin entry/limits"
            );
            let mut assets = BTreeMap::new();
            let mut total = 0;
            for (name, digest) in &manifest.assets {
                ensure!(asset_name(name), "invalid plugin asset name");
                let mime = match name.rsplit('.').next() {
                    Some("js") => "text/javascript; charset=utf-8",
                    Some("css") => "text/css; charset=utf-8",
                    Some("html") => "text/html; charset=utf-8",
                    _ => anyhow::bail!("unsupported plugin asset"),
                };
                let bytes = bounded_file(&binding.directory.join(name), BODY_LIMIT)?;
                total += bytes.len();
                ensure!(
                    total <= RESPONSE_LIMIT && sha(&bytes) == *digest,
                    "plugin asset pin mismatch or size exceeded"
                );
                assets.insert(
                    name.clone(),
                    Asset {
                        bytes: Bytes::from(bytes),
                        mime,
                    },
                );
            }
            let mut endpoints = std::collections::HashSet::new();
            for route in &manifest.routes {
                ensure!(
                    route_name(&route.path)
                        && matches!(route.method.as_str(), "GET" | "POST" | "PUT" | "DELETE")
                        && (route.method != "GET" || !route.mutation)
                        && (!matches!(route.method.as_str(), "PUT" | "DELETE") || route.mutation)
                        && endpoints.insert((route.path.clone(), route.method.clone())),
                    "invalid/duplicate plugin route"
                );
            }
            let mut backend = reqwest::Url::parse(&binding.backend)?;
            ensure!(
                backend.username().is_empty()
                    && backend.password().is_none()
                    && backend.path() == "/"
                    && backend.query().is_none()
                    && backend.fragment().is_none(),
                "plugin backend must be an origin"
            );
            let loopback = backend
                .host_str()
                .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
                .is_some_and(|ip| ip.is_loopback());
            ensure!(
                backend.scheme() == "https" || (backend.scheme() == "http" && loopback),
                "plugin backend requires HTTPS or literal loopback HTTP"
            );
            let mut client = reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(3));
            if let Some(tls) = &binding.tls {
                ensure!(backend.scheme() == "https", "plugin mTLS requires HTTPS");
                ensure!(
                    matches!(
                        rustls::pki_types::ServerName::try_from(tls.server_name.clone())?,
                        rustls::pki_types::ServerName::DnsName(_)
                    ),
                    "plugin TLS server name must be DNS"
                );
                ensure!(
                    [&tls.ca, &tls.certificate, &tls.key]
                        .iter()
                        .all(|p| p.is_absolute()),
                    "plugin TLS paths must be absolute"
                );
                let host = backend
                    .host_str()
                    .context("plugin host required")?
                    .to_owned();
                if let Ok(ip) = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
                    let port = backend
                        .port_or_known_default()
                        .context("plugin port required")?;
                    backend.set_host(Some(&tls.server_name))?;
                    client = client.resolve(&tls.server_name, std::net::SocketAddr::new(ip, port));
                } else {
                    ensure!(
                        host.eq_ignore_ascii_case(&tls.server_name),
                        "plugin Service DNS must match TLS server name"
                    );
                }
                let roots =
                    reqwest::Certificate::from_pem_bundle(&crate::tls::read_bounded(&tls.ca)?)?;
                ensure!(!roots.is_empty(), "plugin CA must not be empty");
                client = client.tls_built_in_root_certs(false);
                for root in roots {
                    client = client.add_root_certificate(root);
                }
                let mut identity = crate::tls::read_bounded(&tls.certificate)?;
                identity.push(b'\n');
                identity.extend(crate::tls::read_bounded(&tls.key)?);
                client = client.identity(reqwest::Identity::from_pem(&identity)?);
            }
            let client = client.build()?;
            ensure!(
                binding.token_env.len() <= 128
                    && binding
                        .token_env
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
                "invalid plugin credential variable"
            );
            let token = std::env::var(&binding.token_env)
                .context("plugin credential environment variable is missing")?;
            ensure!(
                !token.is_empty() && token.len() <= 4096,
                "invalid plugin credential"
            );
            ensure!(
                binding
                    .delegation_cookie
                    .as_ref()
                    .is_none_or(|name| binding.delegate_actor
                        && !name.is_empty()
                        && name.len() <= 128
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))),
                "delegation_cookie requires actor delegation and a safe cookie name"
            );
            ensure!(
                binding
                    .delegation_authority
                    .as_ref()
                    .is_none_or(|v| v == "hangang"
                        && binding.delegate_actor
                        && binding.delegation_cookie.is_none()),
                "Hangang authority requires actor delegation without a native cookie gate"
            );
            let delegation_key = binding.delegate_actor.then(|| token.as_bytes().to_vec());
            if binding.delegate_actor {
                ensure!(
                    token.len() >= 32,
                    "delegation key must be at least 32 bytes"
                );
            }
            let mut token = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
            token.set_sensitive(true);
            ensure!(
                plugins
                    .insert(
                        binding.id,
                        Plugin {
                            client,
                            manifest,
                            backend,
                            token,
                            delegation_key,
                            delegation_cookie: binding.delegation_cookie,
                            delegation_authority: binding.delegation_authority,
                            assets
                        }
                    )
                    .is_none(),
                "duplicate plugin binding"
            );
        }
        let audit = config
            .audit_database
            .unwrap_or_else(|| path.with_extension("audit.sqlite3"));
        Ok(Self {
            plugins,
            audit,
            slots: tokio::sync::Semaphore::new(8),
        })
    }
    pub fn discovery(&self) -> Value {
        json!({"api_version":1,"plugins":self.plugins.values().map(|p|json!({"id":p.manifest.id,"name":p.manifest.name,"version":p.manifest.version,"entry":format!("/ui/plugins/{}/{}",p.manifest.id,p.manifest.entry),"api_base":format!("/v1/plugins/{}",p.manifest.id),"authentication":p.delegation_authority.as_deref().unwrap_or("native")})).collect::<Vec<_>>()})
    }
    pub fn asset<B>(&self, request: &Request<B>) -> Option<Response<Body>> {
        let path = request.uri().path().strip_prefix("/ui/plugins/")?;
        let (id, name) = path.split_once('/')?;
        let asset = self.plugins.get(id)?.assets.get(name)?;
        if request.uri().query().is_some()
            || !matches!(*request.method(), Method::GET | Method::HEAD)
        {
            return Some(problem(
                StatusCode::METHOD_NOT_ALLOWED,
                "GET or HEAD required",
            ));
        }
        let mut response = bytes_reply(
            StatusCode::OK,
            asset.mime,
            if request.method() == Method::HEAD {
                Bytes::new()
            } else {
                asset.bytes.clone()
            },
        );
        response.headers_mut().insert(
            "content-length",
            asset.bytes.len().to_string().parse().unwrap(),
        );
        Some(response)
    }
    pub async fn handle(
        &self,
        req: Request<Incoming>,
        authority: Authority,
        actor: User,
    ) -> Response<Body> {
        let Ok(_slot) = self.slots.try_acquire() else {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "plugin request capacity reached",
            );
        };
        if authority.check().await.is_err() {
            return problem(StatusCode::FORBIDDEN, "administrator authority was revoked");
        }
        let path = req.uri().path().to_owned();
        if path == "/v1/plugins" {
            return if req.method() == Method::GET {
                reply(StatusCode::OK, self.discovery())
            } else {
                problem(StatusCode::METHOD_NOT_ALLOWED, "GET required")
            };
        }
        if path == "/v1/plugins/audit" && req.method() == Method::GET {
            let audit = self.audit.clone();
            let result = tokio::task::spawn_blocking(move || audit_read(&audit)).await;
            if authority.check().await.is_err() {
                return problem(StatusCode::FORBIDDEN, "administrator authority was revoked");
            }
            return match result {
                Ok(Ok(v)) => reply(StatusCode::OK, v),
                _ => problem(StatusCode::SERVICE_UNAVAILABLE, "plugin audit unavailable"),
            };
        }
        let Some((id, endpoint)) = path
            .strip_prefix("/v1/plugins/")
            .and_then(|p| p.split_once('/'))
        else {
            return problem(StatusCode::NOT_FOUND, "unknown plugin endpoint");
        };
        let Some(plugin) = self.plugins.get(id) else {
            return problem(StatusCode::NOT_FOUND, "unknown plugin");
        };
        let Some(route) = plugin
            .manifest
            .routes
            .iter()
            .find(|r| r.path == endpoint && r.method == req.method().as_str())
        else {
            return problem(StatusCode::NOT_FOUND, "plugin route is not registered");
        };
        if req.uri().query().is_some() {
            return problem(
                StatusCode::BAD_REQUEST,
                "plugin query parameters are not supported",
            );
        }
        let delegated_context = req.extensions().get::<ClientContext>().cloned();
        let mut delegated_handle = None;
        if let Some(cookie_name) = &plugin.delegation_cookie {
            if delegated_context.is_none() {
                return problem(StatusCode::BAD_REQUEST, "trusted client context required");
            }
            let mut matches = Vec::new();
            let mut size = 0;
            for cookie in req.headers().get_all(hyper::header::COOKIE) {
                size += cookie.as_bytes().len();
                if size > 8192 {
                    return problem(
                        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                        "Hopae cookies exceeded limit",
                    );
                }
                if let Ok(cookie) = cookie.to_str() {
                    for field in cookie.split(';') {
                        if let Some((name, value)) = field.trim().split_once('=')
                            && name == cookie_name
                        {
                            matches.push(value.to_owned());
                        }
                    }
                }
            }
            if matches.len() != 1 {
                return problem(
                    StatusCode::UNAUTHORIZED,
                    "Sign in to Hopae using its native login before management",
                );
            }
            delegated_handle = matches.pop();
        }
        let method = req.method().clone();
        let body = match tokio::time::timeout(
            Duration::from_secs(5),
            Limited::new(req.into_body(), BODY_LIMIT).collect(),
        )
        .await
        {
            Ok(Ok(b)) => b.to_bytes(),
            Ok(Err(_)) => {
                return problem(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "plugin request body exceeded limit",
                );
            }
            Err(_) => return problem(StatusCode::REQUEST_TIMEOUT, "plugin request body timeout"),
        };
        if (method == Method::GET && !body.is_empty())
            || (method != Method::GET && serde_json::from_slice::<Value>(&body).is_err())
        {
            return problem(
                StatusCode::BAD_REQUEST,
                "plugin request must be bounded JSON",
            );
        }
        // Recheck after reading a potentially slow body, immediately before dispatch.
        if authority.check().await.is_err() {
            return problem(StatusCode::FORBIDDEN, "administrator authority was revoked");
        }
        let record = if route.mutation {
            let audit = self.audit.clone();
            let actor = actor.clone();
            let route = endpoint.to_owned();
            let id = id.to_owned();
            let method = method.to_string();
            let digest = sha(&body);
            match tokio::task::spawn_blocking(move || {
                audit_begin(&audit, &actor, &id, &route, &method, &digest)
            })
            .await
            {
                Ok(Ok(n)) => Some(n),
                _ => {
                    return problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "plugin audit admission failed",
                    );
                }
            }
        } else {
            None
        };
        if authority.check().await.is_err() {
            if let Some(record) = record {
                let audit = self.audit.clone();
                let _ =
                    tokio::task::spawn_blocking(move || audit_complete(&audit, record, 403)).await;
            }
            return problem(StatusCode::FORBIDDEN, "administrator authority was revoked");
        }
        let result = async {
            let url = plugin.backend.join(&format!("v1/{endpoint}"))?;
            let mut request = plugin.client.request(method.clone(), url.clone());
            if let Some(key) = &plugin.delegation_key {
                use crate::console_delegation_wire::{Assertion, digest, sign};
                let assertion = Assertion {
                    authority: plugin.delegation_authority.clone(),
                    actor_id: actor.id,
                    actor_name: actor.username.clone(),
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)?
                        .as_secs(),
                    nonce: crate::admin_users::random_hex_id()?,
                    method: method.as_str().into(),
                    path: url.path().into(),
                    body_sha256: digest(&body),
                    handle_sha256: digest(delegated_handle.as_deref().unwrap_or("").as_bytes()),
                    client_ip: delegated_context
                        .as_ref()
                        .map_or("127.0.0.1".into(), |c| c.ip.to_string()),
                    user_agent: delegated_context
                        .as_ref()
                        .and_then(|c| c.user_agent.clone()),
                };
                let (encoded, signature) =
                    sign(&assertion, key).context("delegation signing failed")?;
                if let Some(handle) = &delegated_handle {
                    let mut value = reqwest::header::HeaderValue::from_str(handle)?;
                    value.set_sensitive(true);
                    request = request.header("x-hopae-delegated-handle", value);
                }
                request = request
                    .header("x-hopae-delegation", encoded)
                    .header("x-hopae-delegation-mac", signature);
            }
            let mut response = request
                .header(reqwest::header::AUTHORIZATION, plugin.token.clone())
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body)
                .send()
                .await?;
            let status = response.status();
            ensure!(!status.is_redirection(), "plugin redirects are forbidden");
            ensure!(
                response
                    .content_length()
                    .is_none_or(|n| n <= RESPONSE_LIMIT as u64),
                "plugin response too large"
            );
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await? {
                ensure!(
                    bytes.len() + chunk.len() <= RESPONSE_LIMIT,
                    "plugin response too large"
                );
                bytes.extend_from_slice(&chunk);
            }
            let _: Value = serde_json::from_slice(&bytes)?;
            let status = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                StatusCode::BAD_GATEWAY
            } else {
                status
            };
            Ok::<_, anyhow::Error>(bytes_reply(status, "application/json", Bytes::from(bytes)))
        }
        .await;
        let mut response = result.unwrap_or_else(|_| {
            problem(
                StatusCode::BAD_GATEWAY,
                if record.is_some() {
                    "plugin outcome uncertain; inspect current state before retrying"
                } else {
                    "plugin backend unavailable or invalid response"
                },
            )
        });
        if let Some(record) = record {
            let audit = self.audit.clone();
            let status = response.status().as_u16();
            if !matches!(
                tokio::task::spawn_blocking(move || audit_complete(&audit, record, status)).await,
                Ok(Ok(()))
            ) {
                response = problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "plugin outcome uncertain; inspect current state before retrying",
                );
            }
            response.headers_mut().insert(
                "x-hangang-plugin-operation",
                record.to_string().parse().unwrap(),
            );
        }
        if authority.check().await.is_err() {
            return problem(StatusCode::FORBIDDEN, "administrator authority was revoked");
        }
        response
    }
}
fn audit_connection(path: &Path) -> Result<rusqlite::Connection> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.permissions().mode() & 0o077 == 0,
        "plugin audit must be private"
    );
    drop(file);
    let db = rusqlite::Connection::open(path)?;
    db.busy_timeout(Duration::from_millis(250))?;
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS plugin_operations(id INTEGER PRIMARY KEY, started_at INTEGER NOT NULL, completed_at INTEGER, actor_id INTEGER NOT NULL, actor_name TEXT NOT NULL, plugin TEXT NOT NULL, path TEXT NOT NULL, method TEXT NOT NULL, body_sha256 TEXT NOT NULL, status INTEGER);")?;
    Ok(db)
}
fn audit_begin(
    path: &Path,
    actor: &User,
    plugin: &str,
    route: &str,
    method: &str,
    digest: &str,
) -> Result<i64> {
    let mut db = audit_connection(path)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let count: i64 = tx.query_row("SELECT count(*) FROM plugin_operations", [], |r| r.get(0))?;
    ensure!(count < 100_000, "plugin audit capacity exhausted");
    tx.execute("INSERT INTO plugin_operations(started_at,actor_id,actor_name,plugin,path,method,body_sha256) VALUES(unixepoch(),?1,?2,?3,?4,?5,?6)",rusqlite::params![actor.id,actor.username,plugin,route,method,digest])?;
    let id = tx.last_insert_rowid();
    tx.commit()?;
    Ok(id)
}
fn audit_complete(path: &Path, id: i64, status: u16) -> Result<()> {
    let db = audit_connection(path)?;
    ensure!(db.execute("UPDATE plugin_operations SET completed_at=unixepoch(),status=?1 WHERE id=?2 AND completed_at IS NULL",rusqlite::params![status,id])?==1,"plugin audit completion failed");
    Ok(())
}
fn audit_read(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(json!({"operations":[]}));
    }
    let db = audit_connection(path)?;
    let mut stmt=db.prepare("SELECT id,started_at,completed_at,actor_id,actor_name,plugin,path,method,body_sha256,status FROM plugin_operations ORDER BY id DESC LIMIT 100")?;
    let rows=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"started_at":r.get::<_,i64>(1)?,"completed_at":r.get::<_,Option<i64>>(2)?,"actor_id":r.get::<_,i64>(3)?,"actor_name":r.get::<_,String>(4)?,"plugin":r.get::<_,String>(5)?,"path":r.get::<_,String>(6)?,"method":r.get::<_,String>(7)?,"body_sha256":r.get::<_,String>(8)?,"status":r.get::<_,Option<i64>>(9)?})))?;
    Ok(json!({"operations":rows.collect::<rusqlite::Result<Vec<_>>>()?}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("index.js"), "export function mount(){}").unwrap();
        let manifest = json!({"id":"guard","name":"Guard","version":"0.1.0","api_version":1,"entry":"index.js","assets":{"index.js":sha(b"export function mount(){}")},"routes":[{"path":"status","method":"GET","mutation":false},{"path":"policy","method":"PUT","mutation":true}]});
        fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let config = root.join("plugins.json");
        let m = fs::read(root.join("manifest.json")).unwrap();
        fs::write(&config,serde_json::to_vec(&json!({"plugins":[{"id":"guard","directory":root,"manifest_sha256":sha(&m),"backend":"http://127.0.0.1:9080","token_env":"HOME"}]})).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for file in fs::read_dir(root).unwrap() {
                fs::set_permissions(file.unwrap().path(), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        (dir, config)
    }
    #[tokio::test]
    async fn discovery_has_no_credentials_and_assets_are_exact_immutable_snapshots() {
        let (dir, path) = package();
        let registry = Registry::load(&path).unwrap();
        let discovery = registry.discovery().to_string();
        assert!(!discovery.contains("9080") && !discovery.contains("token_env"));
        fs::write(dir.path().join("index.js"), "changed after startup").unwrap();
        let req = Request::builder()
            .uri("/ui/plugins/guard/index.js")
            .body(())
            .unwrap();
        let response = registry.asset(&req).unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "export function mount(){}"
        );
        assert!(
            registry
                .asset(
                    &Request::builder()
                        .uri("/ui/plugins/guard/../plugins.json")
                        .body(())
                        .unwrap()
                )
                .is_none()
        );
        assert!(
            registry
                .asset(
                    &Request::builder()
                        .uri("/ui/plugins/guard/manifest.json")
                        .body(())
                        .unwrap()
                )
                .is_none()
        );
    }
    #[test]
    fn mutual_tls_requires_https_matching_dns_and_absolute_paths() {
        let (_dir, path) = package();
        let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        config["plugins"][0]["tls"] = json!({"server_name":"sumunjang.example.test","ca":"/missing/ca.pem","certificate":"/missing/client.pem","key":"/missing/client.key"});
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(Registry::load(&path).is_err());
        config["plugins"][0]["backend"] = json!("https://other.example.test:9080");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(Registry::load(&path).is_err());
        config["plugins"][0]["backend"] = json!("https://sumunjang.example.test:9080");
        config["plugins"][0]["tls"]["ca"] = json!("relative.pem");
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        assert!(Registry::load(&path).is_err());
    }
    #[test]
    fn tampered_manifest_and_assets_fail_closed() {
        let (dir, path) = package();
        fs::write(dir.path().join("index.js"), "tampered").unwrap();
        assert!(Registry::load(&path).is_err());
        let (dir, path) = package();
        fs::write(dir.path().join("manifest.json"), "{}").unwrap();
        assert!(Registry::load(&path).is_err());
    }
    #[test]
    fn backend_requires_fixed_origin_and_safe_transport() {
        for origin in [
            "http://192.0.2.1/",
            "http://localhost/",
            "http://127.0.0.1/?target=evil",
            "https://user:password@example.org/",
            "https://example.org/v1/",
        ] {
            let (_dir, path) = package();
            let mut cfg: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            cfg["plugins"][0]["backend"] = origin.into();
            fs::write(&path, serde_json::to_vec(&cfg).unwrap()).unwrap();
            assert!(Registry::load(&path).is_err(), "{origin}");
        }
    }
    #[test]
    fn audit_persists_actor_and_outcome_without_request_body_or_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let actor = User {
            id: 7,
            username: "operator".into(),
            role: crate::admin_users::Role::Admin,
            enabled: true,
        };
        let id = audit_begin(
            &path,
            &actor,
            "guard",
            "rules",
            "PUT",
            &sha(b"sensitive request"),
        )
        .unwrap();
        assert!(audit_read(&path).unwrap()["operations"][0]["status"].is_null());
        audit_complete(&path, id, 200).unwrap();
        let audit = audit_read(&path).unwrap();
        assert_eq!(audit["operations"][0]["actor_id"], 7);
        assert_eq!(audit["operations"][0]["status"], 200);
        assert!(!audit.to_string().contains("sensitive request"));
        assert!(audit_complete(&path, id, 201).is_err());
    }
    #[test]
    fn audit_rejects_symlinks_and_nonprivate_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::write(&target, "").unwrap();
        let path = dir.path().join("audit.db");
        symlink(&target, &path).unwrap();
        assert!(audit_connection(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::write(&path, "").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(audit_connection(&path).is_err());
    }
}
