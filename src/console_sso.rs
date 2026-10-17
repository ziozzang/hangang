//! Optional console SSO broker. Provider credentials stay in Hopae. Opaque
//! browser sessions require their native Hopae cookie on every request; the
//! upstream receives only private five-second leases for existing accounts.
//!
//! With `operator_policy` (Hopae ADR-0021) every verify answer must carry
//! Hopae's HMAC-signed operator assertion (`x-hopae-operator-assertion`):
//! the level the operator reached, the second factor and when it was used.
//! Sign-in needs the configured minimum (or Hopae's enrollment grace when
//! accepted), every mutation needs the minimum without grace, and a sensitive
//! action (publish, activate, factor reset, ...) needs the factor used within
//! `sensitive_max_age_seconds`; otherwise the operator is sent to the step-up
//! path, which Hopae protects.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use hangang::{admin_plugins::ClientContext, admin_users::User, hopae_native::Client};
use hyper::{HeaderMap, header::HeaderValue};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::Read,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    public_url: String,
    native_address: pumgye_client::Endpoint,
    #[serde(default)]
    native_tls: Option<hangang::config::HopaeNativeTls>,
    gateway_key_env: String,
    upstream_token_env: String,
    #[serde(default = "cookie_name")]
    cookie: String,
    /// Stable opaque Hopae IDs -> existing Hangang usernames. Never email matching.
    accounts: HashMap<String, String>,
    /// Phishing-resistant operator assurance (Hopae ADR-0021).
    #[serde(default)]
    operator_policy: Option<OperatorPolicyConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorPolicyConfig {
    /// Hopae's operator assertion public keys (base64 Ed25519) by key id:
    /// the current one, and the next one during a rotation (1 or 2 entries).
    assertion_public_keys: std::collections::BTreeMap<String, String>,
    /// `1` to `3`; default `2`.
    #[serde(default)]
    minimum_aal: Option<u8>,
    /// `webauthn` (default) or `any`.
    #[serde(default)]
    require_factor: Option<String>,
    /// Admit operators Hopae admits during its enrollment grace (read-only:
    /// mutations still need the factor). Default false.
    #[serde(default)]
    accept_enrollment_grace: bool,
    /// Freshness of the factor for sensitive actions (default 300, 30 to 3600).
    #[serde(default)]
    sensitive_max_age_seconds: Option<u64>,
    /// The console path Hopae steps up on (default `/ui/step-up`).
    #[serde(default)]
    step_up_path: Option<String>,
    /// Path fragments marking a sensitive action (defaults below).
    #[serde(default)]
    sensitive_paths: Option<Vec<String>>,
}

/// Mutation paths that need a fresh factor unless configured otherwise:
/// publications, activations, factor resets, account and grant changes.
pub const DEFAULT_SENSITIVE: [&str; 9] = [
    "/publish",
    "/activate",
    "/factors/reset",
    "/bulk-disable",
    "/v1/admin-users",
    "/v1/users",
    "/v1/config",
    "/v1/plugins",
    "/v1/audit/policy",
];

/// The operator policy as enforced.
pub struct OperatorPolicy {
    keys: Vec<(String, ed25519_dalek::VerifyingKey)>,
    pub minimum_aal: u8,
    pub require_webauthn: bool,
    pub accept_grace: bool,
    pub max_age: u64,
    pub step_up_path: String,
    pub sensitive: Vec<String>,
}

/// The claims of Hopae's operator assertion (ADR-0021). Unknown claims are
/// ignored so Hopae can add some.
#[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct Assurance {
    pub v: u8,
    pub kid: String,
    pub aud: String,
    pub app: String,
    pub host: String,
    pub sub: String,
    pub sid: String,
    pub aal: u8,
    pub factor: Option<String>,
    pub factor_at: Option<i64>,
    pub high_assurance: bool,
    pub auth_time: i64,
    pub require_aal: u8,
    pub require_factor: String,
    pub satisfied: bool,
    pub grace: bool,
    pub iat: i64,
    pub exp: i64,
}

/// Why the operator must step up (or is refused), with where to go.
#[derive(Debug)]
pub struct StepUp {
    pub code: &'static str,
    pub step_up_url: String,
}
impl std::fmt::Display for StepUp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for StepUp {}

const ASSERTION_DOMAIN: &str = "hopae-operator-assertion.v2.";

/// Verify an operator assertion: format, the Ed25519 signature under the
/// pinned key its `kid` names, audience, lifetime (`now` within
/// `[iat - 5, exp]`).
pub fn verify_assertion(
    keys: &[(String, ed25519_dalek::VerifyingKey)],
    token: &str,
    now: i64,
) -> Result<Assurance> {
    use ed25519_dalek::Verifier;
    ensure!(token.len() <= 4096, "operator assertion too large");
    let mut parts = token.split('.');
    let (Some("v2"), Some(payload), Some(sig), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        anyhow::bail!("malformed operator assertion");
    };
    let sig = ed25519_dalek::Signature::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig)?,
    )?;
    let claims: Assurance =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?)?;
    let (_, key) = keys
        .iter()
        .find(|(kid, _)| *kid == claims.kid)
        .ok_or_else(|| anyhow::anyhow!("operator assertion key not pinned"))?;
    key.verify(
        &[ASSERTION_DOMAIN.as_bytes(), payload.as_bytes()].concat(),
        &sig,
    )
    .map_err(|_| anyhow::anyhow!("operator assertion signature rejected"))?;
    ensure!(
        claims.v == 2 && claims.aud == "hangang-console",
        "operator assertion audience rejected"
    );
    ensure!(
        now <= claims.exp && claims.iat <= now + 5,
        "operator assertion expired"
    );
    Ok(claims)
}

/// The pinned public keys: 1 or 2 (current and next), key ids of
/// `A-Za-z0-9._-` (1 to 64), base64 Ed25519 public keys.
fn pinned_keys(
    keys: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<(String, ed25519_dalek::VerifyingKey)>> {
    ensure!(
        (1..=2).contains(&keys.len()),
        "assertion_public_keys must pin 1 or 2 keys (current and next)"
    );
    keys.iter()
        .map(|(kid, key)| {
            ensure!(
                !kid.is_empty()
                    && kid.len() <= 64
                    && kid
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
                "assertion_public_keys key id must be 1 to 64 of A-Za-z0-9._-"
            );
            let bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
                .decode(key.trim())
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "assertion_public_keys.{kid} is not a base64 Ed25519 public key"
                    )
                })?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).map_err(|_| {
                anyhow::anyhow!("assertion_public_keys.{kid} is not an Ed25519 public key")
            })?;
            Ok((kid.clone(), key))
        })
        .collect()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl OperatorPolicy {
    fn from_config(c: &OperatorPolicyConfig) -> Result<Self> {
        let keys = pinned_keys(&c.assertion_public_keys)?;
        let minimum_aal = c.minimum_aal.unwrap_or(2);
        ensure!((1..=3).contains(&minimum_aal), "minimum_aal must be 1 to 3");
        let require_webauthn = match c.require_factor.as_deref() {
            None | Some("webauthn") => true,
            Some("any") => false,
            Some(_) => anyhow::bail!("require_factor must be webauthn or any"),
        };
        let max_age = c.sensitive_max_age_seconds.unwrap_or(300);
        ensure!(
            (30..=3600).contains(&max_age),
            "sensitive_max_age_seconds must be 30 to 3600"
        );
        let step_up_path = c
            .step_up_path
            .clone()
            .unwrap_or_else(|| "/ui/step-up".into());
        ensure!(
            step_up_path.starts_with("/ui/")
                && !step_up_path.contains("//")
                && step_up_path.len() <= 128,
            "step_up_path must be a /ui/ path"
        );
        let sensitive = c
            .sensitive_paths
            .clone()
            .unwrap_or_else(|| DEFAULT_SENSITIVE.iter().map(|s| s.to_string()).collect());
        ensure!(
            sensitive.len() <= 64 && sensitive.iter().all(|p| !p.is_empty() && p.len() <= 128),
            "invalid sensitive_paths"
        );
        Ok(Self {
            keys,
            minimum_aal,
            require_webauthn,
            accept_grace: c.accept_enrollment_grace,
            max_age,
            step_up_path,
            sensitive,
        })
    }

    #[cfg(test)]
    pub fn for_tests(
        key: ed25519_dalek::VerifyingKey,
        minimum_aal: u8,
        accept_grace: bool,
    ) -> Self {
        Self {
            keys: vec![("op-1".into(), key)],
            minimum_aal,
            require_webauthn: true,
            accept_grace,
            max_age: 300,
            step_up_path: "/ui/step-up".into(),
            sensitive: DEFAULT_SENSITIVE.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// The step-up location, returning to `back` (a `/ui/` path).
    pub fn step_up_url(&self, back: &str) -> String {
        let back = if back.starts_with("/ui/") && !back.contains("//") {
            back
        } else {
            "/ui/"
        };
        format!(
            "{}?return={}",
            self.step_up_path,
            back.bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                        (b as char).to_string()
                    }
                    _ => format!("%{b:02X}"),
                })
                .collect::<String>()
        )
    }

    fn meets(&self, a: &Assurance) -> bool {
        a.satisfied
            && a.aal >= self.minimum_aal
            && (!self.require_webauthn || a.factor.as_deref() == Some("webauthn"))
    }

    /// May the operator hold a console session (sign-in, reads)?
    pub fn admit(&self, a: &Assurance) -> Result<(), StepUp> {
        if self.meets(a) || (self.accept_grace && a.grace) {
            Ok(())
        } else {
            Err(StepUp {
                code: "operator_step_up_required",
                step_up_url: self.step_up_url("/ui/"),
            })
        }
    }

    /// Whether `method` on `path` changes state.
    pub fn is_mutation(method: &hyper::Method, path: &str) -> bool {
        !matches!(
            *method,
            hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS
        ) && path != "/v1/auth/logout"
    }

    pub fn is_sensitive(&self, path: &str) -> bool {
        self.sensitive.iter().any(|p| path.contains(p.as_str()))
    }

    /// May the operator perform `method` on `path` now? Mutations need the
    /// policy without grace; sensitive ones a factor used within `max_age`.
    pub fn allow(
        &self,
        a: &Assurance,
        method: &hyper::Method,
        path: &str,
        now: i64,
    ) -> Result<(), StepUp> {
        if !Self::is_mutation(method, path) {
            return self.admit(a);
        }
        let fresh = a
            .factor_at
            .is_some_and(|t| now - t <= self.max_age as i64 && t <= now + 5);
        if !self.meets(a) {
            return Err(StepUp {
                code: "operator_step_up_required",
                step_up_url: self.step_up_url("/ui/"),
            });
        }
        if self.is_sensitive(path) && !fresh {
            return Err(StepUp {
                code: "operator_reauthentication_required",
                step_up_url: self.step_up_url("/ui/"),
            });
        }
        Ok(())
    }
}
fn cookie_name() -> String {
    "__Host-hopae".into()
}
#[derive(Clone)]
struct Session {
    identity: String,
    assurance: Arc<Mutex<Option<Assurance>>>,
    handle: String,
    ip: std::net::IpAddr,
    ua: Option<String>,
    expires: Instant,
    lease: Arc<tokio::sync::Mutex<Option<Lease>>>,
}
struct Lease {
    token: HeaderValue,
    user: User,
    expires: Instant,
}
pub struct Sso {
    config: Config,
    policy: Option<OperatorPolicy>,
    native: Client,
    system: HeaderValue,
    origin: String,
    sessions: Mutex<HashMap<String, Session>>,
}
fn secret(value: String) -> Result<HeaderValue> {
    ensure!(
        (32..=4096).contains(&value.len()),
        "invalid SSO credential size"
    );
    let mut v = HeaderValue::from_str(&value)?;
    v.set_sensitive(true);
    Ok(v)
}
/// Whether a configuration file's owner and mode keep it private to this
/// process: (a) owned by the effective user with no group or other bits, or
/// (b) root-owned, in one of the process's groups (a Kubernetes ConfigMap or
/// Secret volume with `fsGroup`), with no write bits and no other bits (0440,
/// 0400). World-readable or writable files never qualify.
fn private_owner_mode(uid: u32, gid: u32, mode: u32, euid: u32, gids: &[u32]) -> bool {
    let mode = mode & 0o7777;
    (uid == euid && mode & 0o077 == 0)
        || (uid == 0 && gids.contains(&gid) && mode & 0o222 == 0 && mode & 0o007 == 0)
}

fn process_groups() -> Vec<u32> {
    // SAFETY: getegid/getgroups only write into the buffer of the stated size.
    let mut groups = vec![unsafe { libc::getegid() }];
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count > 0 {
        let mut more = vec![0 as libc::gid_t; count as usize];
        let n = unsafe { libc::getgroups(count, more.as_mut_ptr()) };
        if n > 0 {
            more.truncate(n as usize);
            groups.extend(more);
        }
    }
    groups
}

/// The real file behind `path`: `path` itself when it is not a symlink, or
/// the Kubernetes atomic-writer layout (`<dir>/<name>` -> `..data/<name>`,
/// `<dir>/..data` -> `..<version>`, a real directory in `<dir>`). Any other
/// symlink is refused, so a file cannot be pulled from outside its volume.
fn kubernetes_volume_file(path: &Path) -> Result<std::path::PathBuf> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.file_type().is_symlink() {
        return Ok(path.to_path_buf());
    }
    let name = path
        .file_name()
        .context("configuration path has no file name")?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    ensure!(
        std::fs::read_link(path)? == Path::new("..data").join(name),
        "configuration symlink is not the Kubernetes volume layout"
    );
    let version = std::fs::read_link(dir.join("..data"))?;
    let mut parts = version.components();
    let single = matches!(
        (parts.next(), parts.next()),
        (Some(std::path::Component::Normal(v)), None)
            if v.to_str().is_some_and(|v| v.starts_with("..") && v.len() > 2 && !v.contains('/'))
    );
    ensure!(
        single,
        "configuration volume ..data must name a version directory beside it"
    );
    let version_dir = dir.join(&version);
    ensure!(
        std::fs::symlink_metadata(&version_dir)?
            .file_type()
            .is_dir(),
        "configuration volume version is not a directory"
    );
    Ok(version_dir.join(name))
}

/// Open a private, bounded regular configuration file (see
/// `private_owner_mode` and `kubernetes_volume_file`).
pub fn open_private_config(path: &Path, limit: u64) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let real = kubernetes_volume_file(path)?;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&real)?;
    let meta = f.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= limit,
        "not a bounded regular file"
    );
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    ensure!(
        private_owner_mode(meta.uid(), meta.gid(), meta.mode(), euid, &process_groups()),
        "file is readable or writable beyond its owner (or a root-owned volume group)"
    );
    Ok(f)
}

impl Sso {
    pub fn load(path: &Path) -> Result<Self> {
        let mut f = open_private_config(path, 65536)
            .context("SSO configuration must be a private bounded regular file")?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut f).take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "SSO configuration too large");
        let config: Config = serde_json::from_slice(&bytes)?;
        let url = reqwest::Url::parse(&config.public_url)?;
        let local = url
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && local),
            "SSO origin requires HTTPS or literal loopback"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "SSO public_url must be an origin"
        );
        ensure!(
            (config.native_address.is_loopback() || config.native_tls.is_some())
                && config.native_address.port() != 0,
            "remote SSO native peer requires mTLS"
        );
        ensure!(
            config.cookie.len() <= 64
                && !config.cookie.is_empty()
                && config
                    .cookie
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid SSO cookie name"
        );
        ensure!(
            !config.accounts.is_empty() && config.accounts.len() <= 256,
            "SSO requires explicit bounded account mappings"
        );
        for (id, name) in &config.accounts {
            ensure!(
                id.starts_with("u_") && id.len() <= 64,
                "invalid Hopae identity"
            );
            hangang::admin_users::validate_username(name)?;
        }
        let key =
            secret(std::env::var(&config.gateway_key_env).context("SSO gateway key unavailable")?)?;
        let token = std::env::var(&config.upstream_token_env)
            .context("SSO upstream credential unavailable")?;
        let system = secret(format!("Bearer {token}"))?;
        config.native_address.validate()?;
        let native = Client::from_config(
            &hangang::config::HopaeNative {
                transport: hangang::config::HopaeTransport::Native,
                address: config.native_address.clone(),
                pool_size: 8,
                tls: config.native_tls.clone(),
            },
            key,
        )?;
        let origin = url.origin().ascii_serialization();
        let policy = config
            .operator_policy
            .as_ref()
            .map(OperatorPolicy::from_config)
            .transpose()?;
        Ok(Self {
            policy,
            config,
            native,
            system,
            origin,
            sessions: Mutex::new(HashMap::new()),
        })
    }
    pub fn discovery(&self) -> serde_json::Value {
        serde_json::json!({"provider":"hopae","login_url":"/_hopae/login?return=%2Fui%2F%3Fsso%3Dhopae"})
    }
    pub fn exchange_allowed(&self, h: &HeaderMap) -> bool {
        let one = |name: &str| {
            let mut i = h.get_all(name).iter();
            let v = i.next().and_then(|v| v.to_str().ok());
            if i.next().is_some() { None } else { v }
        };
        one("origin") == Some(self.origin.as_str())
            && one("x-hangang-sso") == Some("1")
            && h.get("sec-fetch-site").is_none_or(|v| v == "same-origin")
    }
    fn handle(&self, h: &HeaderMap) -> Result<String> {
        let mut found = Vec::new();
        let mut size = 0;
        for v in h.get_all("cookie") {
            size += v.as_bytes().len();
            ensure!(size <= 8192, "SSO cookies too large");
            for part in v.to_str()?.split(';') {
                if let Some((name, value)) = part.trim().split_once('=')
                    && name == self.config.cookie
                {
                    found.push(value.to_owned());
                }
            }
        }
        ensure!(found.len() == 1, "native Hopae login required");
        let handle = found.pop().unwrap();
        ensure!(
            handle.len() <= 256 && !handle.is_empty(),
            "invalid Hopae handle"
        );
        Ok(handle)
    }
    pub fn policy(&self) -> Option<&OperatorPolicy> {
        self.policy.as_ref()
    }

    async fn identity(
        &self,
        handle: &str,
        context: &ClientContext,
    ) -> Result<(String, Option<Assurance>)> {
        let mut h = HeaderMap::new();
        for (n, v) in [
            ("x-hopae-contract", "1".to_owned()),
            ("x-original-url", format!("{}/ui/", self.origin)),
            ("x-original-method", "GET".into()),
            ("x-hangang-canonical-path", "/ui/".into()),
            ("x-hangang-route-id", "hangang-console-sso".into()),
            (
                "x-forwarded-host",
                self.origin.split_once("://").unwrap().1.to_owned(),
            ),
            (
                "x-forwarded-proto",
                reqwest::Url::parse(&self.origin)?.scheme().into(),
            ),
            ("x-forwarded-for", context.ip.to_string()),
            ("cookie", format!("{}={handle}", self.config.cookie)),
            ("accept", "application/json".into()),
        ] {
            let mut v = HeaderValue::from_str(&v)?;
            if n == "cookie" {
                v.set_sensitive(true);
            }
            h.insert(hyper::header::HeaderName::from_bytes(n.as_bytes())?, v);
        }
        if let Some(ua) = &context.user_agent {
            h.insert("user-agent", HeaderValue::from_str(ua)?);
        }
        let response =
            tokio::time::timeout(Duration::from_secs(2), self.native.verify(&h)).await??;
        if response.status() != 200 {
            // Hopae's policy (ADR-0021) wants a step-up first.
            if let Some(policy) = &self.policy
                && response.status() == 401
                && response
                    .headers()
                    .get("x-hopae-reason")
                    .is_some_and(|v| v == "step_up_required")
            {
                return Err(StepUp {
                    code: "operator_step_up_required",
                    step_up_url: policy.step_up_url("/ui/"),
                }
                .into());
            }
            anyhow::bail!("Hopae session rejected");
        }
        let id = response
            .headers()
            .get("x-forwarded-user")
            .context("Hopae identity missing")?
            .to_str()?;
        ensure!(
            self.config.accounts.contains_key(id),
            "Hopae identity is not mapped to a Hangang account"
        );
        let assurance = match &self.policy {
            None => None,
            Some(policy) => {
                let token = response
                    .headers()
                    .get("x-hopae-operator-assertion")
                    .context("Hopae operator assertion missing")?
                    .to_str()?;
                let a = verify_assertion(&policy.keys, token, unix_now())?;
                let host = self.origin.split_once("://").map_or("", |(_, h)| h);
                ensure!(
                    a.sub == id
                        && a.host
                            .eq_ignore_ascii_case(host.split(':').next().unwrap_or(host)),
                    "operator assertion is for another identity or host"
                );
                Some(a)
            }
        };
        Ok((id.into(), assurance))
    }
    async fn lease(
        &self,
        session: &Session,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
    ) -> Result<(HeaderValue, User)> {
        let mut cached = session.lease.lock().await;
        if let Some(lease) = cached.as_ref().filter(|v| v.expires > Instant::now()) {
            return Ok((lease.token.clone(), lease.user.clone()));
        }
        let mut response = client
            .post(upstream.join("v1/auth/sso-lease")?)
            .header("authorization", self.system.clone())
            .json(&serde_json::json!({"username":self.config.accounts[&session.identity]}))
            .timeout(Duration::from_secs(2))
            .send()
            .await?;
        ensure!(
            response.status() == 200,
            "mapped Hangang account unavailable"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 16384,
                "SSO lease response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Reply {
            token: String,
            user: User,
        }
        let r: Reply = serde_json::from_slice(&bytes)?;
        ensure!(
            r.user.enabled
                && r.user
                    .username
                    .eq_ignore_ascii_case(&self.config.accounts[&session.identity]),
            "invalid Hangang identity"
        );
        let token = secret(format!("Bearer {}", r.token))?;
        let user = r.user;
        *cached = Some(Lease {
            token: token.clone(),
            user: user.clone(),
            expires: Instant::now() + Duration::from_secs(1),
        });
        Ok((token, user))
    }
    pub async fn exchange(
        &self,
        h: &HeaderMap,
        context: &ClientContext,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
    ) -> Result<serde_json::Value> {
        ensure!(
            self.exchange_allowed(h),
            "same-origin SSO exchange required"
        );
        let handle = self.handle(h)?;
        let (identity, assurance) = self.identity(&handle, context).await?;
        if let (Some(policy), Some(a)) = (&self.policy, &assurance) {
            policy.admit(a)?;
        }
        let session = Session {
            identity,
            assurance: Arc::new(Mutex::new(assurance.clone())),
            handle,
            ip: context.ip,
            ua: context.user_agent.clone(),
            expires: Instant::now() + Duration::from_secs(28800),
            lease: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (_, user) = self.lease(&session, client, upstream).await?;
        let mut random = [0; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = format!(
            "hsso_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, v| v.expires > Instant::now());
        ensure!(sessions.len() < 512, "SSO session capacity reached");
        sessions.insert(token.clone(), session);
        Ok(
            serde_json::json!({"token":token,"user":user,"expires_in_seconds":28800,"assurance":assurance}),
        )
    }
    /// The mapped account and the latest operator assurance of a session.
    pub fn session_info(&self, token: &str) -> Option<(String, Option<Assurance>)> {
        let s = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()?;
        let a = s
            .assurance
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Some((self.config.accounts[&s.identity].clone(), a))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn authorization(
        &self,
        token: &str,
        h: &HeaderMap,
        context: &ClientContext,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
        method: &hyper::Method,
        path: &str,
    ) -> Result<HeaderValue> {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
            .context("SSO session expired")?;
        ensure!(
            session.expires > Instant::now()
                && session.ip == context.ip
                && session.ua == context.user_agent
                && self.handle(h)? == session.handle,
            "SSO session binding rejected"
        );
        let (identity, assurance) = self.identity(&session.handle, context).await?;
        ensure!(identity == session.identity, "SSO identity changed");
        if let (Some(policy), Some(a)) = (&self.policy, &assurance) {
            *session.assurance.lock().unwrap_or_else(|e| e.into_inner()) = Some(a.clone());
            policy.allow(a, method, path, unix_now())?;
        }
        Ok(self.lease(&session, client, upstream).await?.0)
    }
    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangang::hopae_wire;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    #[tokio::test]
    async fn native_identity_is_live_and_explicitly_mapped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let allow = Arc::new(AtomicBool::new(true));
        let flag = allow.clone();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0; 16];
            socket.read_exact(&mut head).await.unwrap();
            let (id, len) = hopae_wire::parse_header(head).unwrap();
            assert_eq!(id, 0);
            let mut key = vec![0; len];
            socket.read_exact(&mut key).await.unwrap();
            assert_eq!(key, b"fixture-key-at-least-thirty-two-bytes");
            socket
                .write_all(&hopae_wire::frame_header(0, 1).unwrap())
                .await
                .unwrap();
            socket.write_all(&[1]).await.unwrap();
            loop {
                if socket.read_exact(&mut head).await.is_err() {
                    break;
                }
                let (id, len) = hopae_wire::parse_header(head).unwrap();
                let mut bytes = vec![0; len];
                socket.read_exact(&mut bytes).await.unwrap();
                let h = hopae_wire::decode_request(&bytes).unwrap();
                assert!(
                    h.iter()
                        .any(|(n, v)| n == "cookie" && v == b"__Host-hopae=fixture-handle")
                );
                let reply = hopae_wire::Reply {
                    status: if flag.load(Ordering::SeqCst) {
                        200
                    } else {
                        403
                    },
                    headers: vec![("x-forwarded-user".into(), b"u_fixture".to_vec())],
                    body: vec![],
                };
                let bytes = hopae_wire::encode_reply(&reply).unwrap();
                socket
                    .write_all(&hopae_wire::frame_header(id, bytes.len()).unwrap())
                    .await
                    .unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
        });
        let config = Config {
            public_url: "https://console.example.test/".into(),
            native_address: address.into(),
            native_tls: None,
            gateway_key_env: "FIXTURE".into(),
            upstream_token_env: "FIXTURE".into(),
            cookie: cookie_name(),
            accounts: HashMap::from([("u_fixture".into(), "operator".into())]),
            operator_policy: None,
        };
        let sso = Sso {
            policy: None,
            config,
            native: Client::new(
                address,
                2,
                secret("fixture-key-at-least-thirty-two-bytes".into()).unwrap(),
            ),
            system: secret("fixture-system-at-least-thirty-two-bytes".into()).unwrap(),
            origin: "https://console.example.test".into(),
            sessions: Mutex::new(HashMap::new()),
        };
        let context = ClientContext {
            ip: "192.0.2.1".parse().unwrap(),
            user_agent: None,
        };
        assert_eq!(
            sso.identity("fixture-handle", &context).await.unwrap().0,
            "u_fixture"
        );
        allow.store(false, Ordering::SeqCst);
        assert!(sso.identity("fixture-handle", &context).await.is_err());
        let mut h = HeaderMap::new();
        h.insert("origin", "https://console.example.test".parse().unwrap());
        h.insert("x-hangang-sso", "1".parse().unwrap());
        assert!(sso.exchange_allowed(&h));
        h.append("origin", "https://console.example.test".parse().unwrap());
        assert!(!sso.exchange_allowed(&h));
        let mut h = HeaderMap::new();
        h.insert("cookie", "__Host-hopae=a; __Host-hopae=b".parse().unwrap());
        assert!(sso.handle(&h).is_err());
        task.abort();
    }
}

#[cfg(test)]
mod private_file_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn owner_and_mode_rules() {
        let me = 1000;
        // (a) the process's own file, private.
        assert!(private_owner_mode(me, 50, 0o100600, me, &[50]));
        assert!(private_owner_mode(me, 50, 0o400, me, &[]));
        assert!(!private_owner_mode(me, 50, 0o640, me, &[]));
        assert!(!private_owner_mode(me, 50, 0o604, me, &[50]));
        // (b) root-owned volume file in one of our groups, no write, no other.
        assert!(private_owner_mode(0, 2000, 0o440, me, &[1000, 2000]));
        assert!(private_owner_mode(0, 2000, 0o400, me, &[2000]));
        assert!(
            !private_owner_mode(0, 2000, 0o444, me, &[2000]),
            "world-readable"
        );
        assert!(
            !private_owner_mode(0, 2000, 0o460, me, &[2000]),
            "group-writable"
        );
        assert!(
            !private_owner_mode(0, 2000, 0o640, me, &[2000]),
            "owner-writable"
        );
        assert!(
            !private_owner_mode(0, 3000, 0o440, me, &[2000]),
            "another group"
        );
        assert!(
            !private_owner_mode(1234, 2000, 0o440, me, &[2000]),
            "another non-root owner"
        );
    }

    fn write(path: &Path, mode: u32) {
        std::fs::write(path, b"{}").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn plain_files_and_the_kubernetes_volume_layout() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("sso.json");
        write(&plain, 0o600);
        assert!(open_private_config(&plain, 1024).is_ok());
        write(&plain, 0o644);
        assert!(open_private_config(&plain, 1024).is_err(), "world-readable");
        write(&plain, 0o600);
        assert!(open_private_config(&plain, 1).is_err(), "over the bound");

        // <vol>/..2026_10_17/sso.json, ..data -> ..2026_10_17, sso.json -> ..data/sso.json
        let vol = dir.path().join("vol");
        let version = vol.join("..2026_10_17_09_00_00.1");
        std::fs::create_dir_all(&version).unwrap();
        write(&version.join("sso.json"), 0o600);
        symlink("..2026_10_17_09_00_00.1", vol.join("..data")).unwrap();
        symlink("..data/sso.json", vol.join("sso.json")).unwrap();
        assert!(open_private_config(&vol.join("sso.json"), 1024).is_ok());
        write(&version.join("sso.json"), 0o644);
        assert!(open_private_config(&vol.join("sso.json"), 1024).is_err());
        write(&version.join("sso.json"), 0o600);

        // A symlink out of the volume, or ..data pointing elsewhere: refused.
        symlink(&plain, vol.join("escape.json")).unwrap();
        assert!(open_private_config(&vol.join("escape.json"), 1024).is_err());
        let other = dir.path().join("other");
        std::fs::create_dir_all(other.join("..x")).unwrap();
        write(&other.join("..x").join("sso.json"), 0o600);
        symlink(&version, other.join("..data")).unwrap();
        symlink("..data/sso.json", other.join("sso.json")).unwrap();
        assert!(
            open_private_config(&other.join("sso.json"), 1024).is_err(),
            "absolute ..data target"
        );
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        symlink("../vol/..2026_10_17_09_00_00.1", nested.join("..data")).unwrap();
        symlink("..data/sso.json", nested.join("sso.json")).unwrap();
        assert!(
            open_private_config(&nested.join("sso.json"), 1024).is_err(),
            "..data escaping the volume"
        );
    }
}

#[cfg(test)]
mod operator_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42; 32])
    }
    fn other() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn public(k: &SigningKey) -> VerifyingKey {
        k.verifying_key()
    }

    fn pinned(k: &SigningKey) -> Vec<(String, VerifyingKey)> {
        vec![("op-1".into(), public(k))]
    }

    fn sign(claims: &serde_json::Value, key: &SigningKey) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(claims).unwrap());
        let sig = key.sign(&[ASSERTION_DOMAIN.as_bytes(), payload.as_bytes()].concat());
        format!(
            "v2.{payload}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes())
        )
    }

    fn claims(now: i64) -> serde_json::Value {
        serde_json::json!({
            "v": 2, "kid": "op-1", "aud": "hangang-console", "app": "console", "host": "console.example.test",
            "sub": "u_op", "sid": "s_op", "aal": 2, "factor": "webauthn", "factor_at": now - 10,
            "high_assurance": false, "auth_time": now - 100, "require_aal": 2,
            "require_factor": "webauthn", "satisfied": true, "grace": false,
            "iat": now, "exp": now + 60
        })
    }

    #[test]
    fn assertions_are_verified_strictly() {
        let now = 1_000_000;
        let c = claims(now);
        let a = verify_assertion(&pinned(&key()), &sign(&c, &key()), now).unwrap();
        assert_eq!((a.aal, a.factor.as_deref()), (2, Some("webauthn")));
        // Another key, a changed claim, expiry, the wrong audience.
        assert!(verify_assertion(&pinned(&other()), &sign(&c, &key()), now).is_err());
        assert!(verify_assertion(&pinned(&key()), &sign(&c, &other()), now).is_err());
        let t = sign(&c, &key());
        let forged = t.replacen("v2.", "v2.e", 1);
        assert!(verify_assertion(&pinned(&key()), &forged, now).is_err());
        assert!(verify_assertion(&pinned(&key()), &t, now + 61).is_err());
        let mut elsewhere = c.clone();
        elsewhere["aud"] = "elsewhere".into();
        assert!(verify_assertion(&pinned(&key()), &sign(&elsewhere, &key()), now).is_err());
        // Unknown future claims are ignored.
        let mut more = c.clone();
        more["new_claim"] = 1.into();
        assert!(verify_assertion(&pinned(&key()), &sign(&more, &key()), now).is_ok());
        // Rotation: the next key pinned beside the current one; an unpinned kid.
        let both = vec![
            ("op-0".into(), public(&other())),
            ("op-1".into(), public(&key())),
        ];
        assert!(verify_assertion(&both, &t, now).is_ok());
        let mut next = c.clone();
        next["kid"] = "op-0".into();
        assert!(verify_assertion(&both, &sign(&next, &other()), now).is_ok());
        assert!(verify_assertion(&both, &sign(&next, &key()), now).is_err());
        let mut unknown = c.clone();
        unknown["kid"] = "op-9".into();
        assert!(verify_assertion(&both, &sign(&unknown, &key()), now).is_err());
        // The old HMAC form (v1) is not accepted.
        assert!(verify_assertion(&both, &t.replacen("v2.", "v1.", 1), now).is_err());
    }

    #[test]
    fn pinned_keys_are_checked() {
        use base64::Engine;
        let b =
            |k: &SigningKey| base64::engine::general_purpose::STANDARD.encode(public(k).to_bytes());
        let map = |e: &[(&str, String)]| {
            e.iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        assert_eq!(pinned_keys(&map(&[("op-1", b(&key()))])).unwrap().len(), 1);
        assert_eq!(
            pinned_keys(&map(&[("op-1", b(&key())), ("op-2", b(&other()))]))
                .unwrap()
                .len(),
            2
        );
        assert!(pinned_keys(&map(&[])).is_err());
        assert!(
            pinned_keys(&map(&[
                ("a", b(&key())),
                ("b", b(&key())),
                ("c", b(&key()))
            ]))
            .is_err()
        );
        assert!(pinned_keys(&map(&[("a b", b(&key()))])).is_err());
        assert!(pinned_keys(&map(&[("op-1", "c2hvcnQ=".into())])).is_err());
    }

    #[test]
    fn sign_in_mutations_and_sensitive_actions_need_the_policy_and_freshness() {
        let now = 1_000_000;
        let p = OperatorPolicy::for_tests(public(&key()), 2, false);
        let a: Assurance = serde_json::from_value(claims(now)).unwrap();
        let get = hyper::Method::GET;
        let post = hyper::Method::POST;
        assert!(p.admit(&a).is_ok());
        assert!(p.allow(&a, &post, "/v1/routes", now).is_ok());
        assert!(
            p.allow(
                &a,
                &post,
                "/v1/plugins/hopae/routes/authentication/profiles/publish",
                now
            )
            .is_ok()
        );
        // A stale factor: reads and ordinary changes pass, sensitive ones step up.
        let stale = now + 301;
        assert!(p.allow(&a, &get, "/v1/routes", stale).is_ok());
        assert!(p.allow(&a, &post, "/v1/routes", stale).is_ok());
        let e = p
            .allow(
                &a,
                &post,
                "/v1/plugins/hopae/routes/users/factors/reset",
                stale,
            )
            .unwrap_err();
        assert_eq!(e.code, "operator_reauthentication_required");
        assert_eq!(e.step_up_url, "/ui/step-up?return=%2Fui%2F");
        // A TOTP session does not meet a webauthn policy.
        let mut totp = a.clone();
        totp.factor = Some("totp".into());
        totp.satisfied = false;
        assert_eq!(
            p.admit(&totp).unwrap_err().code,
            "operator_step_up_required"
        );
        // AAL 3 required.
        let p3 = OperatorPolicy::for_tests(public(&key()), 3, false);
        assert!(p3.admit(&a).is_err());
        // The grace admits reads only when accepted, never mutations.
        let mut grace = a.clone();
        grace.satisfied = false;
        grace.grace = true;
        grace.factor = None;
        grace.factor_at = None;
        assert!(p.admit(&grace).is_err());
        let pg = OperatorPolicy::for_tests(public(&key()), 2, true);
        assert!(pg.admit(&grace).is_ok());
        assert!(pg.allow(&grace, &get, "/v1/routes", now).is_ok());
        assert!(pg.allow(&grace, &post, "/v1/routes", now).is_err());
        // Logout is never blocked; step-up returns stay inside /ui/.
        assert!(pg.allow(&grace, &post, "/v1/auth/logout", now).is_ok());
        assert_eq!(
            p.step_up_url("https://evil.example/"),
            "/ui/step-up?return=%2Fui%2F"
        );
        assert_eq!(p.step_up_url("//evil"), "/ui/step-up?return=%2Fui%2F");
    }
}
