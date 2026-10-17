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
    /// Contract v2 (`api_version: 2`): bounded route patterns `prefix/*`.
    #[serde(default)]
    route_patterns: Vec<RoutePattern>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    path: String,
    method: String,
    mutation: bool,
}
/// `{"path": "zones/*", "method": "GET", "mutation": false, "max_depth": 1}`:
/// matches `zones/<s1>[/…/<sN>]` with 1 ≤ N ≤ `max_depth` segments, each a
/// valid identifier (lowercase letters, digits, `-`, ≤ 32 bytes), for exactly
/// this method. The prefix itself is a valid route name; the bare prefix is
/// not matched (declare it as a plain route).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutePattern {
    path: String,
    method: String,
    mutation: bool,
    #[serde(default = "default_depth")]
    max_depth: usize,
}
fn default_depth() -> usize {
    1
}
/// Plain routes per package (v1 allowed 32). Lookup is a linear scan of short
/// strings and the manifest stays operator-reviewed and ≤ 64 KiB, so 64 keeps
/// review practical while leaving room for complete owner APIs.
const MAX_ROUTES: usize = 64;
/// Route patterns per package (contract v2) and segments a pattern may span.
const MAX_PATTERNS: usize = 16;
const MAX_PATTERN_DEPTH: usize = 4;
/// Plain routes and patterns together.
const MAX_ROUTE_ENTRIES: usize = 64;
fn valid_method(method: &str, mutation: bool) -> bool {
    matches!(method, "GET" | "POST" | "PUT" | "DELETE")
        && (method != "GET" || !mutation)
        && (!matches!(method, "PUT" | "DELETE") || mutation)
}
impl Manifest {
    /// The mutation flag of the route or pattern registered for this exact
    /// endpoint and method; `None` when nothing is registered. Plain routes
    /// win; a pattern only matches its prefix followed by 1..=max_depth valid
    /// identifier segments, so `..`, empty segments, encoded slashes and
    /// other methods never match.
    fn resolve(&self, endpoint: &str, method: &str) -> Option<bool> {
        if let Some(route) = self
            .routes
            .iter()
            .find(|r| r.path == endpoint && r.method == method)
        {
            return Some(route.mutation);
        }
        if endpoint.len() > 256 {
            return None;
        }
        self.route_patterns.iter().find_map(|p| {
            let prefix = p.path.strip_suffix("/*")?;
            let rest = endpoint.strip_prefix(prefix)?.strip_prefix('/')?;
            let depth = rest.split('/').count();
            (p.method == method && depth <= p.max_depth && rest.split('/').all(valid_id))
                .then_some(p.mutation)
        })
    }
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
        let config: Configuration = serde_json::from_slice(&{
            let mut bytes = Vec::new();
            crate::private_file::open_private_config(path, 64 * 1024)
                .context("console plugin configuration must be a private bounded regular file")?
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() <= 64 * 1024,
                "console plugin configuration too large"
            );
            bytes
        })?;
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
                    && matches!(manifest.api_version, 1 | 2)
                    && (manifest.api_version == 2 || manifest.route_patterns.is_empty())
                    && !manifest.name.is_empty()
                    && manifest.name.len() <= 64,
                "invalid console plugin manifest"
            );
            semver::Version::parse(&manifest.version)?;
            ensure!(
                manifest.assets.len() <= 16
                    && manifest.routes.len() <= MAX_ROUTES
                    && manifest.route_patterns.len() <= MAX_PATTERNS
                    && manifest.routes.len() + manifest.route_patterns.len() <= MAX_ROUTE_ENTRIES
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
                        && valid_method(&route.method, route.mutation)
                        && endpoints.insert((route.path.clone(), route.method.clone())),
                    "invalid/duplicate plugin route"
                );
            }
            let mut patterns = std::collections::HashSet::new();
            for pattern in &manifest.route_patterns {
                let prefix = pattern.path.strip_suffix("/*").unwrap_or("");
                ensure!(
                    route_name(prefix)
                        && (1..=MAX_PATTERN_DEPTH).contains(&pattern.max_depth)
                        && valid_method(&pattern.method, pattern.mutation)
                        && patterns.insert((prefix.to_owned(), pattern.method.clone())),
                    "invalid/duplicate plugin route pattern"
                );
                // A plain route under the prefix with the same method would be
                // shadowed ambiguously; require one or the other.
                ensure!(
                    !manifest.routes.iter().any(|r| r.method == pattern.method
                        && r.path
                            .strip_prefix(prefix)
                            .is_some_and(|rest| rest.starts_with('/'))),
                    "plugin route overlaps a route pattern"
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
        json!({"api_version":1,"plugins":self.plugins.values().map(|p|json!({"id":p.manifest.id,"name":p.manifest.name,"version":p.manifest.version,"entry":format!("/ui/plugins/{}/{}",p.manifest.id,p.manifest.entry),"api_base":format!("/v1/plugins/{}",p.manifest.id),"authentication":p.delegation_authority.as_deref().unwrap_or("native"),"routes":p.manifest.routes.iter().map(|r|json!({"path":r.path,"method":r.method,"mutation":r.mutation})).collect::<Vec<_>>(),"route_patterns":p.manifest.route_patterns.iter().map(|r|json!({"path":r.path,"method":r.method,"mutation":r.mutation,"max_depth":r.max_depth})).collect::<Vec<_>>()})).collect::<Vec<_>>()})
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
        let Some(mutation) = plugin.manifest.resolve(endpoint, req.method().as_str()) else {
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
        // Optional operator reason for a mutation (percent-encoded UTF-8), kept
        // in the private operation journal; it is never forwarded to the backend.
        let reason = match change_reason(req.headers()) {
            Ok(reason) => reason,
            Err(()) => return problem(StatusCode::BAD_REQUEST, "invalid change reason"),
        };
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
        let record = if mutation {
            let audit = self.audit.clone();
            let actor = actor.clone();
            let route = endpoint.to_owned();
            let id = id.to_owned();
            let method = method.to_string();
            let digest = sha(&body);
            let reason = reason.clone();
            match tokio::task::spawn_blocking(move || {
                audit_begin_with_reason(
                    &audit,
                    &actor,
                    &id,
                    &route,
                    &method,
                    &digest,
                    reason.as_deref(),
                )
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
        }
        if authority.check().await.is_err() {
            // Never disclose the protected backend response after revocation.
            // A dispatched mutation may nevertheless have committed; preserve
            // its admitted, non-secret correlation without claiming rollback.
            response = problem(
                StatusCode::FORBIDDEN,
                if record.is_some() {
                    "administrator authority was revoked; plugin outcome uncertain; inspect current state before retrying"
                } else {
                    "administrator authority was revoked"
                },
            );
        }
        if let Some(record) = record {
            response.headers_mut().insert(
                "x-hangang-plugin-operation",
                record.to_string().parse().unwrap(),
            );
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
    // Additive column for journals created before change reasons existed.
    let has_reason: bool = db.query_row(
        "SELECT count(*) FROM pragma_table_info('plugin_operations') WHERE name='reason'",
        [],
        |r| r.get::<_, i64>(0),
    )? == 1;
    if !has_reason {
        db.execute_batch("ALTER TABLE plugin_operations ADD COLUMN reason TEXT;")?;
    }
    Ok(db)
}
/// Decodes the optional `x-hangang-change-reason` header: percent-encoded
/// UTF-8, 1 to 512 characters, no control characters.
fn change_reason(headers: &hyper::HeaderMap) -> std::result::Result<Option<String>, ()> {
    let mut values = headers.get_all("x-hangang-change-reason").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.len() > 4096 {
        return Err(());
    }
    let raw = value.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        if raw[index] == b'%' {
            let hex = raw.get(index + 1..index + 3).ok_or(())?;
            let text = std::str::from_utf8(hex).map_err(|_| ())?;
            bytes.push(u8::from_str_radix(text, 16).map_err(|_| ())?);
            index += 3;
        } else {
            bytes.push(raw[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| ())?;
    let text = text.trim();
    if text.is_empty() || text.chars().count() > 512 || text.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(text.to_owned()))
}
#[cfg(test)]
fn audit_begin(
    path: &Path,
    actor: &User,
    plugin: &str,
    route: &str,
    method: &str,
    digest: &str,
) -> Result<i64> {
    audit_begin_with_reason(path, actor, plugin, route, method, digest, None)
}
fn audit_begin_with_reason(
    path: &Path,
    actor: &User,
    plugin: &str,
    route: &str,
    method: &str,
    digest: &str,
    reason: Option<&str>,
) -> Result<i64> {
    let mut db = audit_connection(path)?;
    let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let count: i64 = tx.query_row("SELECT count(*) FROM plugin_operations", [], |r| r.get(0))?;
    ensure!(count < 100_000, "plugin audit capacity exhausted");
    tx.execute("INSERT INTO plugin_operations(started_at,actor_id,actor_name,plugin,path,method,body_sha256,reason) VALUES(unixepoch(),?1,?2,?3,?4,?5,?6,?7)",rusqlite::params![actor.id,actor.username,plugin,route,method,digest,reason])?;
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
    let mut stmt=db.prepare("SELECT id,started_at,completed_at,actor_id,actor_name,plugin,path,method,body_sha256,status,reason FROM plugin_operations ORDER BY id DESC LIMIT 100")?;
    let rows=stmt.query_map([],|r|Ok(json!({"id":r.get::<_,i64>(0)?,"started_at":r.get::<_,i64>(1)?,"completed_at":r.get::<_,Option<i64>>(2)?,"actor_id":r.get::<_,i64>(3)?,"actor_name":r.get::<_,String>(4)?,"plugin":r.get::<_,String>(5)?,"path":r.get::<_,String>(6)?,"method":r.get::<_,String>(7)?,"body_sha256":r.get::<_,String>(8)?,"status":r.get::<_,Option<i64>>(9)?,"reason":r.get::<_,Option<String>>(10)?})))?;
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
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        }
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
        assert!(discovery.contains(r#"{"method":"PUT","mutation":true,"path":"policy"}"#));
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
    /// Exercise Incoming request bodies through real loopback HTTP on both sides of
    /// the mediator. CAS must live in JSON: proxy header allowlists are not a lock.
    #[tokio::test]
    async fn guard_policy_document_body_cas_survives_proxy_and_conflict_is_audited_once() {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        };
        async fn serve<F, Fut>(handler: F) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>)
        where
            F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
            Fut: std::future::Future<Output = Response<Body>> + Send + 'static,
        {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let handler = Arc::new(handler);
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request| {
                            let handler = handler.clone();
                            async move { Ok::<_, std::convert::Infallible>(handler(request).await) }
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            (address, task)
        }
        let calls = Arc::new(Mutex::new(Vec::<(String, String, Value)>::new()));
        let admin = Arc::new(AtomicBool::new(true));
        let (backend,backend_task)=serve({
            let calls=calls.clone();let admin=admin.clone();
            move |request| {
                let calls=calls.clone();let admin=admin.clone();
                async move {
                    if request.uri().path()=="/authority" {
                        return reply(StatusCode::OK,json!({"user":{"id":7,"username":"fixture-operator","role":if admin.load(Ordering::SeqCst){"admin"}else{"viewer"},"enabled":true}}));
                    }
                    let method=request.method().to_string();let path=request.uri().path().to_owned();
                    let bytes=request.into_body().collect().await.unwrap().to_bytes();
                    let body=if bytes.is_empty(){Value::Null}else{serde_json::from_slice(&bytes).unwrap()};
                    calls.lock().unwrap().push((method.clone(),path.clone(),body.clone()));
                    assert_eq!(path,"/v1/policy/document","no legacy route or caller-selected backend");
                    if method=="GET" {return reply(StatusCode::OK,json!({"revision":4,"policy":{"mode":"observe"}}));}
                    if body["expected_revision"]!=4 {
                        return reply(StatusCode::CONFLICT,json!({"title":"Revision Conflict","revision":4,"detail":"policy changed; draft retained"}));
                    }
                    if body["policy"]["revoke_after_apply"]==true {
                        admin.store(false,Ordering::SeqCst);
                    }
                    reply(StatusCode::OK,json!({"revision":5,"policy":body["policy"]}))
                }
            }
        }).await;
        let (dir, path) = package();
        let manifest_path = dir.path().join("manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["routes"] = json!([{"path":"policy/document","method":"GET","mutation":false},{"path":"policy/document","method":"PUT","mutation":true}]);
        let manifest = serde_json::to_vec(&manifest).unwrap();
        fs::write(&manifest_path, &manifest).unwrap();
        let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        config["plugins"][0]["backend"] = json!(format!("http://{backend}"));
        config["plugins"][0]["manifest_sha256"] = json!(sha(&manifest));
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let registry = Arc::new(Registry::load(&path).unwrap());
        let (proxy, proxy_task) = serve({
            let registry = registry.clone();
            move |request| {
                let registry = registry.clone();
                async move {
                    registry
                        .handle(
                            request,
                            Authority::Remote {
                                client: reqwest::Client::new(),
                                endpoint: format!("http://{backend}/authority").parse().unwrap(),
                                authorization: reqwest::header::HeaderValue::from_static(
                                    "Bearer fixture-only",
                                ),
                                actor_id: 7,
                            },
                            User {
                                id: 7,
                                username: "fixture-operator".into(),
                                role: crate::admin_users::Role::Admin,
                                enabled: true,
                            },
                        )
                        .await
                }
            }
        })
        .await;
        let client = reqwest::Client::new();
        let endpoint = format!("http://{proxy}/v1/plugins/guard/policy/document");
        let read = client.get(&endpoint).send().await.unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        assert_eq!(read.json::<Value>().await.unwrap()["revision"], 4);
        let stale = json!({"expected_revision":3,"policy":{"mode":"enforce"}});
        let conflict = client
            .put(&endpoint)
            .header("if-match", "4")
            .json(&stale)
            .send()
            .await
            .unwrap();
        assert_eq!(conflict.status(), StatusCode::CONFLICT);
        assert!(
            conflict
                .headers()
                .contains_key("x-hangang-plugin-operation")
        );
        assert_eq!(
            conflict.json::<Value>().await.unwrap(),
            json!({"title":"Revision Conflict","revision":4,"detail":"policy changed; draft retained"})
        );
        let current = json!({"expected_revision":4,"policy":{"mode":"enforce"}});
        let applied = client.put(&endpoint).json(&current).send().await.unwrap();
        assert_eq!(applied.status(), StatusCode::OK);
        assert_eq!(applied.json::<Value>().await.unwrap()["revision"], 5);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![
                ("GET".into(), "/v1/policy/document".into(), Value::Null),
                ("PUT".into(), "/v1/policy/document".into(), stale.clone()),
                ("PUT".into(), "/v1/policy/document".into(), current.clone())
            ]
        );
        let audit = audit_read(&registry.audit).unwrap();
        let operations = audit["operations"].as_array().unwrap();
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0]["status"], 200);
        assert_eq!(operations[1]["status"], 409);
        for (operation, body) in operations.iter().zip([&current, &stale]) {
            assert_eq!(operation["actor_id"], 7);
            assert_eq!(operation["actor_name"], "fixture-operator");
            assert_eq!(operation["path"], "policy/document");
            assert_eq!(operation["method"], "PUT");
            assert_eq!(
                operation["body_sha256"],
                sha(&serde_json::to_vec(body).unwrap())
            );
        }
        let legacy = client
            .put(format!("http://{proxy}/v1/plugins/guard/policy"))
            .json(&current)
            .send()
            .await
            .unwrap();
        assert_eq!(legacy.status(), StatusCode::NOT_FOUND);
        assert_eq!(calls.lock().unwrap().len(), 3);
        let late = json!({"expected_revision":4,"policy":{"revoke_after_apply":true,"protected_value":"backend-secret-sentinel"}});
        let revoked = client.put(&endpoint).json(&late).send().await.unwrap();
        assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
        let operation: i64 = revoked.headers()["x-hangang-plugin-operation"]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        let redacted = revoked.text().await.unwrap();
        assert!(!redacted.contains("backend-secret-sentinel"));
        assert!(redacted.contains("outcome uncertain"));
        let audit = audit_read(&registry.audit).unwrap();
        assert_eq!(audit["operations"][0]["id"], operation);
        assert_eq!(audit["operations"][0]["status"], 200);
        assert_eq!(calls.lock().unwrap().len(), 4);
        let forbidden = client.put(&endpoint).json(&current).send().await.unwrap();
        assert_eq!(forbidden.status(), StatusCode::FORBIDDEN);
        assert!(
            !forbidden
                .headers()
                .contains_key("x-hangang-plugin-operation")
        );
        assert_eq!(calls.lock().unwrap().len(), 4);
        assert_eq!(
            audit_read(&registry.audit).unwrap()["operations"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        proxy_task.abort();
        backend_task.abort();
    }
    #[test]
    fn the_registry_configuration_is_a_private_file_or_a_kubernetes_volume_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plugins.json");
        fs::write(&plain, br#"{"plugins":[]}"#).unwrap();
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Registry::load(&plain).is_err(), "world-readable");
        fs::set_permissions(&plain, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Registry::load(&plain).is_ok());
        let vol = dir.path().join("vol");
        let version = vol.join("..2026_10_17_10_00_00.1");
        fs::create_dir_all(&version).unwrap();
        fs::write(version.join("plugins.json"), br#"{"plugins":[]}"#).unwrap();
        fs::set_permissions(
            version.join("plugins.json"),
            fs::Permissions::from_mode(0o400),
        )
        .unwrap();
        symlink("..2026_10_17_10_00_00.1", vol.join("..data")).unwrap();
        symlink("..data/plugins.json", vol.join("plugins.json")).unwrap();
        assert!(Registry::load(&vol.join("plugins.json")).is_ok());
        symlink(&plain, vol.join("escape.json")).unwrap();
        assert!(
            Registry::load(&vol.join("escape.json")).is_err(),
            "a link out of the volume"
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
    fn change_reason_is_decoded_bounded_and_journaled() {
        let mut headers = hyper::HeaderMap::new();
        assert_eq!(change_reason(&headers), Ok(None));
        headers.insert(
            "x-hangang-change-reason",
            "%EC%9D%B4%EC%9E%A5%20left".parse().unwrap(),
        );
        assert_eq!(change_reason(&headers), Ok(Some("이장 left".into())));
        for bad in ["%ZZ", "%0A", "%20", "%E0%80"] {
            headers.insert("x-hangang-change-reason", bad.parse().unwrap());
            assert_eq!(change_reason(&headers), Err(()), "{bad}");
        }
        headers.insert("x-hangang-change-reason", "a".repeat(513).parse().unwrap());
        assert_eq!(change_reason(&headers), Err(()));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let actor = User {
            id: 7,
            username: "operator".into(),
            role: crate::admin_users::Role::Admin,
            enabled: true,
        };
        audit_begin_with_reason(
            &path,
            &actor,
            "hopae",
            "users/disable",
            "POST",
            &sha(b"{}"),
            Some("left the company"),
        )
        .unwrap();
        audit_begin(&path, &actor, "hopae", "users/enable", "POST", &sha(b"{}")).unwrap();
        let audit = audit_read(&path).unwrap();
        assert!(audit["operations"][0]["reason"].is_null());
        assert_eq!(audit["operations"][1]["reason"], "left the company");
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

    type Calls = Arc<std::sync::Mutex<Vec<(String, String, Value, Option<String>)>>>;
    /// A signed-delegation backend and the broker in front of it for `manifest`
    /// (plugin id = manifest id). The backend records each call with the
    /// actor of an assertion verified over the exact method, path and body.
    async fn delegated_fixture(
        manifest: Value,
    ) -> (
        String,
        Calls,
        PathBuf,
        tempfile::TempDir,
        Vec<tokio::task::AbortHandle>,
    ) {
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::sync::Mutex;
        let id = manifest["id"].as_str().unwrap().to_owned();
        let key = std::env::var("PATH").unwrap_or_default();
        assert!(
            key.len() >= 32,
            "the delegation key fixture reads PATH (at least 32 bytes)"
        );
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = listener.local_addr().unwrap();
        let backend_calls = calls.clone();
        let backend_key = key.clone();
        let backend_task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let calls = backend_calls.clone();
                let key = backend_key.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let calls = calls.clone();
                        let key = key.clone();
                        async move {
                            if request.uri().path() == "/authority" {
                                return Ok::<_, std::convert::Infallible>(reply(
                                    StatusCode::OK,
                                    json!({"user":{"id":7,"username":"fixture-operator","role":"admin","enabled":true}}),
                                ));
                            }
                            let header = |name: &str| {
                                request
                                    .headers()
                                    .get(name)
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned)
                            };
                            let assertion = match (
                                header("x-hopae-delegation"),
                                header("x-hopae-delegation-mac"),
                            ) {
                                (Some(encoded), Some(mac)) => {
                                    crate::console_delegation_wire::verify(
                                        &encoded,
                                        &mac,
                                        key.as_bytes(),
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap()
                                            .as_secs(),
                                    )
                                }
                                _ => None,
                            };
                            let method = request.method().to_string();
                            let path = request.uri().path().to_owned();
                            let bytes = request.into_body().collect().await.unwrap().to_bytes();
                            let verified = assertion.filter(|a| {
                                a.path == path
                                    && a.method == method
                                    && a.body_sha256
                                        == crate::console_delegation_wire::digest(&bytes)
                            });
                            calls.lock().unwrap().push((
                                method,
                                path,
                                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
                                verified.map(|a| a.actor_name),
                            ));
                            Ok(reply(
                                StatusCode::OK,
                                json!({"items":[{"id":"u_kim","status":"active","reason":null,"kind":"human","display_name":"Kim"}],"resolved":1,"unknown":0,"complete":true,"privacy_profile":"standard"}),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("index.js"), "export function mount(){}").unwrap();
        let manifest = serde_json::to_vec(&manifest).unwrap();
        fs::write(root.join("manifest.json"), &manifest).unwrap();
        let config = root.join("plugins.json");
        fs::write(&config, serde_json::to_vec(&json!({"plugins":[{"id":id,"directory":root,"manifest_sha256":sha(&manifest),"backend":format!("http://{backend}"),"token_env":"PATH","delegate_actor":true,"delegation_authority":"hangang"}]})).unwrap()).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        }
        {
            use std::os::unix::fs::PermissionsExt;
            for file in fs::read_dir(root).unwrap() {
                fs::set_permissions(file.unwrap().path(), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
        }
        let registry = Arc::new(Registry::load(&config).unwrap());
        let audit_path = registry.audit.clone();
        let authority = move || Authority::Remote {
            client: reqwest::Client::new(),
            endpoint: format!("http://{backend}/authority").parse().unwrap(),
            authorization: reqwest::header::HeaderValue::from_static("Bearer fixture-only"),
            actor_id: 7,
        };
        let actor = || User {
            id: 7,
            username: "fixture-operator".into(),
            role: crate::admin_users::Role::Admin,
            enabled: true,
        };
        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            loop {
                let (stream, _) = proxy_listener.accept().await.unwrap();
                let registry = registry.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let registry = registry.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                registry.handle(request, authority(), actor()).await,
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let base = format!("http://{proxy}/v1/plugins/{id}");
        (
            base,
            calls,
            audit_path,
            dir,
            vec![proxy_task.abort_handle(), backend_task.abort_handle()],
        )
    }

    /// Hopae subject directory and authentication explain (Hopae
    /// docs/SUBJECT_DIRECTORY.md, AUTHENTICATION_EXPLAIN.md) are POST reads:
    /// listed as non-mutating routes they are forwarded to the exact
    /// /v1/<path> with a signed actor assertion over the body, are not
    /// recorded as mutations, and every other method or path is refused.
    #[tokio::test]
    async fn hopae_subject_directory_reads_are_signed_non_mutating_posts() {
        let (base, calls, audit_path, _dir, tasks) = delegated_fixture(json!({"id":"hopae","name":"Hopae","version":"0.1.8","api_version":1,"entry":"index.js","assets":{"index.js":sha(b"export function mount(){}")},"routes":[
            {"path":"subjects/resolve","method":"POST","mutation":false},
            {"path":"subjects/search","method":"POST","mutation":false},
            {"path":"subjects/lifecycle","method":"POST","mutation":false},
            {"path":"subjects/lifecycle/snapshot","method":"POST","mutation":false},
            {"path":"explain/authentication","method":"POST","mutation":false}]})).await;
        let client = reqwest::Client::new();
        for (path, body) in [
            (
                "subjects/resolve",
                json!({"ids":["u_kim","u_gone"],"privacy_profile":"strict"}),
            ),
            (
                "subjects/search",
                json!({"q":"kim","kind":"human","limit":20}),
            ),
            ("subjects/lifecycle", json!({"cursor":null,"limit":100})),
            (
                "subjects/lifecycle/snapshot",
                json!({"cursor":null,"limit":200}),
            ),
            (
                "explain/authentication",
                json!({"url":"https://app.example.test/","subject":"u_kim"}),
            ),
        ] {
            let response = client
                .post(format!("{base}/{path}"))
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            let last = calls.lock().unwrap().last().cloned().unwrap();
            assert_eq!(
                (last.0.as_str(), last.1.as_str()),
                ("POST", format!("/v1/{path}").as_str())
            );
            assert_eq!(last.2, body);
            assert_eq!(
                last.3.as_deref(),
                Some("fixture-operator"),
                "{path} must carry a verified assertion over the exact body"
            );
        }
        let count = calls.lock().unwrap().len();
        assert_eq!(
            client
                .get(format!("{base}/subjects/resolve"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .post(format!("{base}/subjects/purge"))
                .json(&json!({}))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            client
                .post(format!("{base}/subjects/resolve"))
                .body("ids=u_kim")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(calls.lock().unwrap().len(), count);
        assert!(
            audit_read(&audit_path).unwrap()["operations"]
                .as_array()
                .unwrap()
                .is_empty(),
            "reads are not mutations"
        );
        tasks.iter().for_each(tokio::task::AbortHandle::abort);
    }

    fn manifest_v2(routes: Value, patterns: Value) -> Manifest {
        serde_json::from_value(json!({"id":"guard","name":"Guard","version":"0.2.0","api_version":2,"entry":"index.js","assets":{},"routes":routes,"route_patterns":patterns})).unwrap()
    }

    /// Contract v2 patterns match only their prefix plus 1..=max_depth
    /// identifier segments for the declared method; plain routes win.
    #[test]
    fn route_patterns_match_bounded_identifier_segments_only() {
        let m = manifest_v2(
            json!([{"path":"zones","method":"GET","mutation":false}]),
            json!([{"path":"zones/*","method":"GET","mutation":false},{"path":"zones/*","method":"DELETE","mutation":true},{"path":"rules/sets/*","method":"PUT","mutation":true,"max_depth":2}]),
        );
        assert_eq!(m.resolve("zones", "GET"), Some(false));
        assert_eq!(m.resolve("zones/corp", "GET"), Some(false));
        assert_eq!(m.resolve("zones/corp", "DELETE"), Some(true));
        assert_eq!(m.resolve("rules/sets/a/b", "PUT"), Some(true));
        for (path, method) in [
            ("zones/corp", "POST"), // method not declared for the pattern
            ("zones/corp", "HEAD"),
            ("zones/a/b", "GET"), // deeper than max_depth
            ("rules/sets/a/b/c", "PUT"),
            ("zones/", "GET"), // empty segment
            ("zones//x", "GET"),
            ("zones/..", "GET"),     // traversal
            ("zones/%2e%2e", "GET"), // encoded traversal
            ("zones/a%2Fb", "GET"),  // encoded slash
            ("zones/Corp", "GET"),   // not a valid identifier
            ("zonesx/corp", "GET"),  // prefix must end at a segment
            ("other/zones/corp", "GET"),
        ] {
            assert_eq!(m.resolve(path, method), None, "{method} {path}");
        }
        assert_eq!(m.resolve(&format!("zones/{}", "a".repeat(33)), "GET"), None);
    }

    #[test]
    fn route_pattern_manifests_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("index.js"), "export function mount(){}").unwrap();
        let load = |manifest: Value| {
            let bytes = serde_json::to_vec(&manifest).unwrap();
            fs::write(root.join("manifest.json"), &bytes).unwrap();
            let config = root.join("plugins.json");
            fs::write(&config, serde_json::to_vec(&json!({"plugins":[{"id":"guard","directory":root,"manifest_sha256":sha(&bytes),"backend":"http://127.0.0.1:9080","token_env":"HOME"}]})).unwrap()).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
            }
            use std::os::unix::fs::PermissionsExt;
            for file in fs::read_dir(root).unwrap() {
                fs::set_permissions(file.unwrap().path(), fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            Registry::load(&config)
        };
        let base = |version: u32, routes: Value, patterns: Value| json!({"id":"guard","name":"Guard","version":"0.2.0","api_version":version,"entry":"index.js","assets":{"index.js":sha(b"export function mount(){}")},"routes":routes,"route_patterns":patterns});
        let ok = json!([{"path":"zones/*","method":"POST","mutation":true}]);
        assert!(load(base(2, json!([]), ok.clone())).is_ok());
        // v1 manifests keep their exact semantics: no patterns.
        assert!(load(base(1, json!([]), ok.clone())).is_err());
        assert!(load(base(3, json!([]), json!([]))).is_err());
        for bad in [
            json!([{"path":"zones","method":"GET","mutation":false}]), // no /*
            json!([{"path":"zones/*/x","method":"GET","mutation":false}]),
            json!([{"path":"../*","method":"GET","mutation":false}]),
            json!([{"path":"zones/*","method":"GET","mutation":true}]), // GET cannot mutate
            json!([{"path":"zones/*","method":"DELETE","mutation":false}]), // DELETE must mutate
            json!([{"path":"zones/*","method":"PATCH","mutation":true}]),
            json!([{"path":"zones/*","method":"GET","mutation":false,"max_depth":0}]),
            json!([{"path":"zones/*","method":"GET","mutation":false,"max_depth":5}]),
            json!([{"path":"zones/*","method":"GET","mutation":false},{"path":"zones/*","method":"GET","mutation":false}]),
        ] {
            assert!(load(base(2, json!([]), bad.clone())).is_err(), "{bad}");
        }
        // A plain route under a pattern prefix with the same method is ambiguous.
        assert!(
            load(base(
                2,
                json!([{"path":"zones/corp","method":"GET","mutation":false}]),
                json!([{"path":"zones/*","method":"GET","mutation":false}])
            ))
            .is_err()
        );
        // Plain routes: up to 64; patterns: up to 16; together at most 64.
        let routes = |n: usize| {
            Value::Array(
                (0..n)
                    .map(|i| json!({"path":format!("r{i}"),"method":"GET","mutation":false}))
                    .collect(),
            )
        };
        let patterns = |n: usize| {
            Value::Array(
                (0..n)
                    .map(|i| json!({"path":format!("p{i}/*"),"method":"GET","mutation":false}))
                    .collect(),
            )
        };
        assert!(load(base(1, routes(64), json!([]))).is_ok());
        assert!(load(base(1, routes(65), json!([]))).is_err());
        assert!(load(base(2, json!([]), patterns(16))).is_ok());
        assert!(load(base(2, json!([]), patterns(17))).is_err());
        assert!(load(base(2, routes(49), patterns(16))).is_err());
        assert!(load(base(2, routes(48), patterns(16))).is_ok());
    }

    /// A pattern route is forwarded to exactly `/v1/<prefix>/<segment>` with
    /// the method requested; the delegation assertion covers that exact path,
    /// method and body; the pattern's mutation flag decides journaling.
    #[tokio::test]
    async fn route_patterns_forward_the_exact_signed_path_and_journal_mutations() {
        let (base, calls, audit_path, _dir, tasks) = delegated_fixture(json!({"id":"guard","name":"Guard","version":"0.2.0","api_version":2,"entry":"index.js","assets":{"index.js":sha(b"export function mount(){}")},
            "routes":[{"path":"zones","method":"GET","mutation":false}],
            "route_patterns":[{"path":"zones/*","method":"POST","mutation":true},{"path":"zones/*","method":"GET","mutation":false}]})).await;
        let client = reqwest::Client::new();
        let response = client
            .post(format!("{base}/zones/corp"))
            .json(&json!({"reason":"x"}))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let last = calls.lock().unwrap().last().cloned().unwrap();
        assert_eq!(
            (last.0.as_str(), last.1.as_str()),
            ("POST", "/v1/zones/corp")
        );
        assert_eq!(
            last.3.as_deref(),
            Some("fixture-operator"),
            "assertion must cover the exact forwarded path"
        );
        assert!(
            response
                .headers()
                .contains_key("x-hangang-plugin-operation")
        );
        let operations = audit_read(&audit_path).unwrap()["operations"].clone();
        assert_eq!(operations[0]["path"], "zones/corp");
        assert_eq!(operations.as_array().unwrap().len(), 1);
        let response = client
            .get(format!("{base}/zones/corp"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            audit_read(&audit_path).unwrap()["operations"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "pattern reads are not mutations"
        );
        let before = calls.lock().unwrap().len();
        for (method, path) in [
            ("DELETE", "zones/corp"),
            ("POST", "zones/a/b"),
            ("POST", "zones/..%2fstatus"),
            ("PUT", "zones/corp"),
        ] {
            let response = client
                .request(method.parse().unwrap(), format!("{base}/{path}"))
                .json(&json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        }
        assert_eq!(
            calls.lock().unwrap().len(),
            before,
            "refused requests never reach the backend"
        );
        tasks.iter().for_each(tokio::task::AbortHandle::abort);
    }
}
