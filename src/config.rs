use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pumgye: Option<pumgye_core::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pumgye_authority: Option<crate::pumgye::AuthorityConfig>,
    #[serde(default)]
    pub revision: u64,
    /// Process-wide runtime settings carried in the shared document so a
    /// fleet converges on them through the API. A set field overrides the
    /// command-line value of the same name; an unset field keeps it.
    #[serde(default, skip_serializing_if = "Settings::is_empty")]
    pub settings: Settings,
    /// Highest cache invalidation generation ever committed to this
    /// document's history, kept even while `cache` is null. The authority
    /// raises `cache.generation` to it on every write, so re-enabling the
    /// cache or rolling the document back can never reopen a namespace that
    /// a purge retired, on any instance (it travels with the document and
    /// through restarts and handoffs).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cache_generation_floor: u64,
    #[serde(default)]
    pub certificates: Vec<crate::certificates::CertificateFiles>,
    #[serde(default)]
    pub cache: Option<crate::cache_store::CacheConfig>,
    /// Node-local database path and limits; database bytes never enter the
    /// configuration authority. A new source starts pending after publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geoip_database: Option<crate::geoip_runtime::Source>,
    #[serde(default)]
    pub http: Vec<HttpRoute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_http: Vec<crate::public_listener_config::Listener>,
    #[serde(default)]
    pub tcp: Vec<TcpRoute>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub udp: Vec<crate::udp::Route>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workload_http: Vec<crate::workload_http::Listener>,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Runtime settings that are otherwise command-line only. Every field is
/// optional: `null`/absent means "use the process default".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_blocks: Option<Vec<crate::request_blocks::Rule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_security: Option<Vec<crate::response_security::Rule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_csrf: Option<Vec<crate::path_csrf::Rule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_allowlists: Option<Vec<crate::path_allowlists::Rule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_redis: Option<crate::security_redis::Settings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_failure_bans: Option<Vec<crate::path_failure_bans::Rule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_ban_scope: Option<crate::path_failure_bans::Scope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_rate_limits: Option<Vec<crate::path_rate_limits::Rule>>,
    /// Explicit pre-routing path deny namespaces. No implicit blocked paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_blocks: Option<Vec<crate::path_blocks::Rule>>,
    /// Permit the deployment fingerprint header only for explicit debugging.
    /// This does not generate a header; it allows configured/origin values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debug_gateway_header: Option<bool>,
    /// Response-head metadata selection shared by the ring and access trace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_recording: Option<crate::http_recording::Policy>,
    /// Completion-history selection for accepted raw TCP connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_recent_recording: Option<crate::tcp_recording::Policy>,
    /// Peers whose `X-Forwarded-For`/`X-Forwarded-Proto` are trusted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_proxy_cidrs: Option<Vec<ipnet::IpNet>>,
    /// Response header names removed from every upstream response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remove_response_headers: Option<Vec<String>>,
    /// Status for `require_tls` redirects: 301, 302, 307, 308 or 426.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_redirect_code: Option<u16>,
    /// Default upstream response-header timeout for routes without their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_timeout_ms: Option<u64>,
    /// Accept request paths containing `.`/`..` segments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_dot_segments: Option<bool>,
    /// Unauthenticated readiness probe path on the public listener.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
}
impl Settings {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        if let Some(rules) = &self.request_blocks {
            crate::request_blocks::validate(rules)?;
        }
        if let Some(rules) = &self.response_security {
            crate::response_security::validate(rules)?;
        }
        if let Some(rules) = &self.path_csrf {
            crate::path_csrf::validate(rules)?;
        }
        if let Some(rules) = &self.path_allowlists {
            crate::path_allowlists::validate(rules)?;
        }
        if let Some(settings) = &self.security_redis {
            settings.validate()?;
        }
        if let Some(rules) = &self.path_failure_bans {
            crate::path_failure_bans::validate(rules)?;
        }
        if let Some(rules) = &self.path_rate_limits {
            crate::path_rate_limits::validate(rules)?;
        }
        if let Some(rules) = &self.path_blocks {
            crate::path_blocks::validate(rules)?;
        }
        if let Some(policy) = &self.http_recording {
            policy.validate()?;
        }
        if let Some(policy) = &self.tcp_recent_recording {
            policy.validate()?;
        }
        if let Some(cidrs) = &self.trusted_proxy_cidrs {
            anyhow::ensure!(
                cidrs.len() <= 1024,
                "settings.trusted_proxy_cidrs has too many entries"
            );
        }
        if let Some(names) = &self.remove_response_headers {
            anyhow::ensure!(
                names.len() <= 64,
                "settings.remove_response_headers has too many entries"
            );
            for name in names {
                anyhow::ensure!(
                    valid_response_header_name(name),
                    "settings.remove_response_headers contains an invalid name: {name}"
                );
                anyhow::ensure!(
                    !is_protected_response_header(name),
                    "settings.remove_response_headers cannot remove protected header: {name}"
                );
            }
        }
        if let Some(code) = self.https_redirect_code {
            anyhow::ensure!(
                matches!(code, 301 | 302 | 307 | 308 | 426),
                "settings.https_redirect_code must be 301, 302, 307, 308 or 426"
            );
        }
        if let Some(timeout) = self.upstream_timeout_ms {
            anyhow::ensure!(
                (1..=86_400_000).contains(&timeout),
                "settings.upstream_timeout_ms must be 1..86400000"
            );
        }
        if let Some(path) = &self.health_path {
            anyhow::ensure!(
                path.starts_with('/')
                    && path.len() <= 256
                    && path
                        .bytes()
                        .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#'),
                "settings.health_path must be an absolute path without query or fragment"
            );
        }
        Ok(())
    }
}

/// `Settings` with names and durations parsed once per snapshot.
#[derive(Debug, Default)]
pub struct PreparedSettings {
    pub request_blocks: Vec<crate::request_blocks::Compiled>,
    pub response_security: Vec<crate::response_security::Compiled>,
    pub path_csrf: Vec<std::sync::Arc<crate::path_csrf::Compiled>>,
    pub path_allowlists: Vec<std::sync::Arc<crate::path_allowlists::Compiled>>,
    pub(crate) security_redis: Option<std::sync::Arc<crate::security_redis::Backend>>,
    pub path_failure_bans: Vec<std::sync::Arc<crate::path_failure_bans::Bucket>>,
    pub path_rate_limits: Vec<std::sync::Arc<crate::path_rate_limits::Bucket>>,
    pub debug_gateway_header: Option<bool>,
    pub http_recording: Option<std::sync::Arc<crate::http_recording::CompiledPolicy>>,
    pub tcp_recent_recording: Option<std::sync::Arc<crate::tcp_recording::CompiledPolicy>>,
    pub trusted_proxy_cidrs: Option<std::sync::Arc<Vec<ipnet::IpNet>>>,
    pub remove_response_headers: Option<std::sync::Arc<Vec<hyper::header::HeaderName>>>,
    pub https_redirect_code: Option<u16>,
    pub upstream_timeout: Option<std::time::Duration>,
    pub allow_dot_segments: Option<bool>,
    pub health_path: Option<std::sync::Arc<str>>,
}
impl PreparedSettings {
    fn prepare(settings: &Settings) -> anyhow::Result<Self> {
        use anyhow::Context;
        settings.validate()?;
        Ok(Self {
            request_blocks: crate::request_blocks::prepare(
                settings.request_blocks.as_deref().unwrap_or(&[]),
            )?,
            response_security: crate::response_security::prepare(
                settings.response_security.as_deref().unwrap_or(&[]),
            )?,
            path_csrf: crate::path_csrf::prepare(settings.path_csrf.as_deref().unwrap_or(&[]))?,
            path_allowlists: crate::path_allowlists::prepare(
                settings.path_allowlists.as_deref().unwrap_or(&[]),
            )?,
            security_redis: None,
            path_failure_bans: Vec::new(),
            path_rate_limits: Vec::new(),
            debug_gateway_header: settings.debug_gateway_header,
            http_recording: settings
                .http_recording
                .as_ref()
                .map(|policy| policy.compile().map(std::sync::Arc::new))
                .transpose()?,
            tcp_recent_recording: settings
                .tcp_recent_recording
                .as_ref()
                .map(|policy| policy.compile().map(std::sync::Arc::new))
                .transpose()?,
            trusted_proxy_cidrs: settings
                .trusted_proxy_cidrs
                .as_ref()
                .map(|cidrs| std::sync::Arc::new(cidrs.clone())),
            remove_response_headers: settings
                .remove_response_headers
                .as_ref()
                .map(|names| {
                    names
                        .iter()
                        .map(|name| hyper::header::HeaderName::from_bytes(name.as_bytes()))
                        .collect::<Result<Vec<_>, _>>()
                        .map(std::sync::Arc::new)
                })
                .transpose()
                .context("settings.remove_response_headers")?,
            https_redirect_code: settings.https_redirect_code,
            upstream_timeout: settings
                .upstream_timeout_ms
                .map(std::time::Duration::from_millis),
            allow_dot_segments: settings.allow_dot_segments,
            health_path: settings.health_path.as_deref().map(std::sync::Arc::from),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathMatch {
    #[default]
    Prefix,
    Exact,
    SegmentPrefix,
}
/// ASCII case handling for `path_prefix` comparison. Folding never changes the
/// request path forwarded upstream and never applies Unicode case folding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathCase {
    Sensitive,
    Insensitive,
}
/// Declared gateway authentication boundary for an HTTP route. This is a
/// classification and validation constraint, not a complete Zero Trust policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    /// Preserve behavior of configurations written before this field existed.
    #[default]
    Legacy,
    /// Deliberately accessible without gateway authentication.
    Public,
    /// The application, rather than this gateway, owns subject authentication.
    Application,
    /// Require native Basic and/or external authorization before proxying.
    Protected,
}
fn is_legacy_access_mode(mode: &AccessMode) -> bool {
    *mode == AccessMode::Legacy
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRoute {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acme_http01: Option<crate::acme_http01::Config>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listener_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "is_legacy_access_mode")]
    pub access_mode: AccessMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_policy: Option<crate::resource_policy::ResourcePolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language_policy: Option<crate::language_policy::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_policy: Option<crate::country_policy::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwt_auth: Option<crate::jwt_runtime::JwtAuth>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_auth: Option<crate::workload_auth::Policy>,
    /// Persist policy while excluding this route from new traffic.
    #[serde(default = "enabled_default", skip_serializing_if = "is_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub host_regex: Option<String>,
    #[serde(default)]
    pub upstream: crate::upstream::OutboundOptions,
    #[serde(default)]
    pub upstream_host: Option<String>,
    #[serde(default)]
    pub preserve_host: bool,
    #[serde(default)]
    pub max_requests: Option<usize>,
    /// Time budget, in milliseconds, for the upstream to return response
    /// headers (this covers sending the request body plus the upstream's
    /// time-to-first-byte). Overrides the global default for this route; raise
    /// it for large uploads or slow-first-byte upstreams such as LLM
    /// completions. Response body streaming afterwards is bounded by the
    /// transport idle timeout, not this value.
    #[serde(default)]
    pub upstream_timeout_ms: Option<u64>,
    /// Additional attempts to a freshly selected backend when a connection-level
    /// error occurs BEFORE any response byte, for safely replayable requests
    /// only (bodyless GET/HEAD/OPTIONS/DELETE without a body transform or
    /// upgrade). 0 (default) disables retries. Never replays a request that may
    /// have had a side effect.
    #[serde(default)]
    pub retries: u8,
    /// Require TLS for this route. A plaintext request (by terminated transport
    /// or, behind a trusted proxy, by X-Forwarded-Proto) is answered with an
    /// HTTPS redirect (or 426) instead of being proxied.
    #[serde(default)]
    pub require_tls: bool,
    /// Override the global plaintext-to-HTTPS policy for this route.
    #[serde(default)]
    pub https_redirect_code: Option<u16>,
    #[serde(default)]
    pub cache: Option<crate::cache_policy::RouteCache>,
    #[serde(default)]
    pub host: Option<String>,
    /// Alternative Host patterns for one route with shared backends and rules.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_http_hosts"
    )]
    pub hosts: Vec<String>,
    /// Redirect alias hosts to one operator-selected canonical domain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_domain: Option<CanonicalDomain>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_match: PathMatch,
    /// ASCII case handling of `path_prefix`. Absent: insensitive for a route
    /// that has authentication or `access_mode: protected` and a prefix,
    /// otherwise sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_case: Option<PathCase>,
    /// Cookie names removed (exact, case-sensitive) from the request sent
    /// upstream, with or without `auth`. The effective set is the union with
    /// `auth.strip_request_cookies`. The authorization call still receives the
    /// full listed `cookie` header.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_request_cookies: Vec<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// RFC 6901 JSON pointers mapped to expected values.
    #[serde(default)]
    pub json: BTreeMap<String, serde_json::Value>,
    pub backends: Vec<crate::pool_member::Backend>,
    #[serde(default)]
    pub deny_cidrs: Vec<ipnet::IpNet>,
    #[serde(default)]
    pub lua: Option<String>,
    #[serde(default)]
    pub request_transform: Option<crate::transform::BodyTransform>,
    #[serde(default)]
    pub response_transform: Option<crate::transform::BodyTransform>,
    #[serde(default)]
    pub auth: Option<ExternalAuth>,
    /// Native HTTP Basic authentication. Challenges missing/invalid credentials
    /// with 401 + WWW-Authenticate, verifies against a salted-SHA-256 store,
    /// optionally hides the Authorization header and sets an identity header.
    #[serde(default)]
    pub basic_auth: Option<BasicAuth>,
    #[serde(default)]
    pub balance: crate::balance::BalanceConfig,
    /// Streaming-safe response header additions/replacements applied to the
    /// upstream response head (no body buffering). Framing/hop-by-hop names are
    /// rejected.
    #[serde(default)]
    pub response_set_headers: BTreeMap<String, String>,
    /// Streaming-safe response header removals (e.g. removing `server`).
    #[serde(default)]
    pub response_remove_headers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CanonicalScheme {
    Http,
    #[default]
    Https,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDomain {
    #[serde(default = "enabled_default", skip_serializing_if = "is_enabled")]
    pub enabled: bool,
    pub host: String,
    #[serde(default)]
    pub scheme: CanonicalScheme,
    #[serde(default = "canonical_status")]
    pub status: u16,
    #[serde(default = "canonical_paths")]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub exclude_path_prefixes: Vec<String>,
    #[serde(default = "canonical_methods")]
    pub methods: Vec<String>,
}

fn canonical_status() -> u16 {
    302
}
fn canonical_paths() -> Vec<String> {
    vec!["/".into()]
}
fn canonical_methods() -> Vec<String> {
    vec!["GET".into(), "HEAD".into()]
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuth {
    pub url: String,
    /// Renew bounded native machine evidence for long-lived requests.
    #[serde(default, skip_serializing_if = "is_false")]
    pub renew_native_evidence: bool,
    /// Request-bound native service authentication and resource decision before dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_resource: Option<crate::native_resource::Configuration>,
    /// Optional authenticated HOP1 transport; remote connections require mTLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native: Option<HopaeNative>,
    #[serde(default)]
    pub request_headers: Vec<String>,
    #[serde(default)]
    pub response_headers: Vec<String>,
    #[serde(default = "auth_timeout")]
    pub timeout_ms: u64,
    /// When true, a 3xx/401/403 authorization response is forwarded to the
    /// client (status, Location, Set-Cookie, WWW-Authenticate, Content-Type,
    /// Cache-Control and a bounded body) instead of a generic denial. This
    /// supports SSO login/ban redirects and cookie setup. Other non-2xx
    /// statuses still fail closed with 503.
    #[serde(default)]
    pub forward_response: bool,
    /// Only when the configured authorization service returns one exact
    /// `X-Hangang-Auth-Terminal: 1` field on a successful response, send its
    /// bounded response directly to the client instead of contacting upstream.
    #[serde(default)]
    pub terminal_response: bool,
    /// Fixed headers added to every authorization call, as literals or
    /// `{"env": "NAME"}` references resolved when a configuration is
    /// activated. Environment values are never serialized, logged or shown.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub static_request_headers: BTreeMap<String, StaticHeaderValue>,
    /// Cookie names removed from the request sent upstream after an allowed
    /// authorization. The authorization call still receives the full listed
    /// `cookie` header. Names are exact and case-sensitive.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strip_request_cookies: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HopaeTransport {
    #[default]
    Native,
    Grpc,
}

/// Native Hopae transport. No decision caching or HTTP fallback.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopaeNative {
    #[serde(default)]
    pub transport: HopaeTransport,
    pub address: pumgye_client::Endpoint,
    #[serde(default = "hopae_pool_size")]
    pub pool_size: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<HopaeNativeTls>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HopaeNativeTls {
    pub server_name: String,
    pub ca: std::path::PathBuf,
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
}
fn hopae_pool_size() -> usize {
    32
}

/// A static authorization request header value: a literal or a reference to a
/// process environment variable. Only the reference is ever part of the
/// configuration; the resolved value lives in the prepared runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StaticHeaderValue {
    Literal(String),
    Env(StaticHeaderEnv),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticHeaderEnv {
    pub env: String,
}

const MAX_STATIC_REQUEST_HEADERS: usize = 16;
const MAX_STATIC_HEADER_VALUE: usize = 1024;
const MAX_STRIP_REQUEST_COOKIES: usize = 16;
const MAX_COOKIE_NAME: usize = 128;

fn validate_strip_request_cookies(names: &[String]) -> anyhow::Result<()> {
    ensure!(
        names.len() <= MAX_STRIP_REQUEST_COOKIES,
        "too many strip_request_cookies entries"
    );
    let mut seen = std::collections::HashSet::new();
    for name in names {
        ensure!(
            !name.is_empty()
                && name.len() <= MAX_COOKIE_NAME
                && name.bytes().all(|b| matches!(b,
                    b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
                    | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')),
            "invalid strip_request_cookies name {name:?}"
        );
        ensure!(
            seen.insert(name.as_str()),
            "duplicate strip_request_cookies name {name:?}"
        );
    }
    Ok(())
}

fn valid_static_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=128).contains(&bytes.len())
        && (bytes[0] == b'_' || bytes[0].is_ascii_uppercase())
        && bytes[1..]
            .iter()
            .all(|b| *b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// Names the proxy owns on the authorization call: connection-management,
/// framing and generated-context headers.
fn unsafe_auth_header(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "content-length"
            | "transfer-encoding"
            | "upgrade"
            | "te"
            | "trailer"
            | "keep-alive"
            | "proxy-authorization"
            | "proxy-connection"
            | "x-real-ip"
            | "proxy-authenticate"
            | "x-original-method"
            | "x-original-uri"
            | "x-original-url"
            | "x-original-client-ip"
    ) || name.starts_with("x-forwarded-")
        || name == "forwarded"
}

fn is_false(value: &bool) -> bool {
    !*value
}
fn validate_static_request_headers(auth: &ExternalAuth) -> anyhow::Result<()> {
    anyhow::ensure!(
        !auth.renew_native_evidence || auth.native.is_some(),
        "evidence renewal requires native Hopae transport"
    );
    ensure!(
        auth.static_request_headers.len() <= MAX_STATIC_REQUEST_HEADERS,
        "too many static authorization request headers"
    );
    for (name, value) in &auth.static_request_headers {
        let parsed: hyper::header::HeaderName = name
            .parse()
            .with_context(|| format!("invalid static authorization header name {name:?}"))?;
        ensure!(
            parsed.as_str() == name,
            "static authorization header name {name:?} must be lowercase"
        );
        ensure!(
            name != "x-hangang-auth-terminal"
                && !unsafe_auth_header(name)
                && !name.starts_with("x-original-"),
            "static authorization header {name:?} is reserved"
        );
        ensure!(
            !auth
                .request_headers
                .iter()
                .chain(&auth.response_headers)
                .any(|other| other.eq_ignore_ascii_case(name)),
            "static authorization header {name:?} collides with a listed request or response header"
        );
        match value {
            StaticHeaderValue::Literal(text) => {
                ensure!(
                    text.len() <= MAX_STATIC_HEADER_VALUE
                        && hyper::header::HeaderValue::from_str(text).is_ok(),
                    "static authorization header {name:?} has an invalid literal value"
                );
            }
            StaticHeaderValue::Env(reference) => ensure!(
                valid_static_env_name(&reference.env),
                "static authorization header {name:?} has an invalid environment variable name"
            ),
        }
    }
    Ok(())
}

/// A static authorization header whose environment variable could not be
/// resolved on this node. Names the variable, never a value.
#[derive(Debug)]
pub struct StaticHeaderEnvError {
    pub variable: String,
    message: String,
}
impl std::fmt::Display for StaticHeaderEnvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for StaticHeaderEnvError {}

/// A route whose external authorization cannot run on this node because a
/// static header variable is unusable. Requests to it fail closed with 503.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthUnavailable {
    pub variable: String,
}

/// How a snapshot treats unusable static-header environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnvPolicy {
    /// Reject the snapshot: authoring paths and process startup.
    Strict,
    /// Activate the snapshot but fail the affected routes closed: passive
    /// follower paths that must not keep serving an older, weaker revision.
    FailClosed,
}

/// Resolve static authorization headers for activation. Errors name the
/// variable, never its value. Values are marked sensitive so `Debug` output
/// of the resulting `HeaderValue` is redacted.
pub fn resolve_static_request_headers(
    auth: &ExternalAuth,
) -> anyhow::Result<Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>> {
    resolve_static_request_headers_with(auth, |name| std::env::var_os(name))
}

fn resolve_static_request_headers_with(
    auth: &ExternalAuth,
    lookup: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> anyhow::Result<Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>> {
    let mut resolved = Vec::with_capacity(auth.static_request_headers.len());
    for (name, value) in &auth.static_request_headers {
        let header_name: hyper::header::HeaderName = name
            .parse()
            .with_context(|| format!("invalid static authorization header name {name:?}"))?;
        let mut header_value = match value {
            StaticHeaderValue::Literal(text) => hyper::header::HeaderValue::from_str(text)
                .with_context(|| format!("invalid static authorization header {name:?}"))?,
            StaticHeaderValue::Env(reference) => {
                ensure!(
                    valid_static_env_name(&reference.env),
                    "invalid environment variable name for static authorization header {name:?}"
                );
                let fail = |reason: &str| {
                    anyhow::Error::new(StaticHeaderEnvError {
                        variable: reference.env.clone(),
                        message: format!(
                            "environment variable {} for static authorization header {name:?} {reason}",
                            reference.env
                        ),
                    })
                };
                let raw = lookup(&reference.env)
                    .ok_or_else(|| fail("is not set"))?
                    .into_string()
                    .map_err(|_| fail("is not valid UTF-8"))?;
                if raw.is_empty() {
                    return Err(fail("is empty"));
                }
                if raw.len() > MAX_STATIC_HEADER_VALUE {
                    return Err(fail("is too long"));
                }
                hyper::header::HeaderValue::from_str(&raw)
                    .map_err(|_| fail("is not a valid header value"))?
            }
        };
        header_value.set_sensitive(true);
        resolved.push((header_name, header_value));
    }
    Ok(resolved)
}
fn auth_timeout() -> u64 {
    1000
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    #[serde(default = "default_basic_realm")]
    pub realm: String,
    /// Credentials as `username:salt_hex:sha256_hex` or an explicitly
    /// versioned `v1:sha1-suffix:username_b64:suffix_b64:sha1_hex:identity_b64`
    /// compatibility entry. SHA-1 entries exist only to migrate existing
    /// salted credential stores without access to their plaintext passwords;
    /// newly provisioned credentials should use `--hash-password`.
    pub credentials: Vec<String>,
    /// Remove the incoming Authorization header before forwarding upstream.
    #[serde(default)]
    pub hide_credentials: bool,
    /// Kong-compatible priority of Proxy-Authorization over Authorization.
    /// This header is consumed only for authentication and remains removed
    /// from upstream requests as a hop-by-hop proxy credential.
    #[serde(default)]
    pub accept_proxy_authorization: bool,
    /// Optional header set to the authenticated username for the upstream.
    #[serde(default)]
    pub identity_header: Option<String>,
}

fn default_basic_realm() -> String {
    "restricted".to_owned()
}

/// Parse and validate a `username:salt_hex:sha256_hex` credential entry.
pub fn parse_basic_credential(entry: &str) -> anyhow::Result<(&str, Vec<u8>, Vec<u8>)> {
    crate::basic_auth::parse_credential(entry)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpRoute {
    pub id: String,
    #[serde(default = "enabled_default", skip_serializing_if = "is_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub upstream: crate::upstream::OutboundOptions,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<crate::tcp_health::TcpHealthPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country_policy: Option<crate::country_policy::Policy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_tls: Option<crate::workload_tls::Policy>,
    #[serde(default)]
    pub sni: Option<crate::client_hello::SniMatch>,
    #[serde(default)]
    pub max_connections: Option<usize>,
    pub listen: std::net::SocketAddr,
    pub backends: Vec<crate::pool_member::Backend>,
    #[serde(default)]
    pub deny_cidrs: Vec<ipnet::IpNet>,
}

fn enabled_default() -> bool {
    true
}
fn is_enabled(value: &bool) -> bool {
    *value
}

#[derive(Default)]
struct PreparedUpstreamTls {
    configs: std::collections::HashMap<String, std::sync::Arc<rustls::ClientConfig>>,
    trust: std::collections::HashMap<String, [u8; 32]>,
}

impl Config {
    /// Resolve every enabled route's static authorization header values and
    /// discard them: preflight for `--check` and configuration validation.
    /// Errors name the route and variable, never a value.
    pub fn check_static_request_headers(&self) -> anyhow::Result<()> {
        for route in self.http.iter().filter(|route| route.enabled) {
            if let Some(auth) = &route.auth {
                resolve_static_request_headers(auth).map_err(|error| {
                    anyhow::anyhow!("route {} external authorization: {error:#}", route.id)
                })?;
            }
        }
        Ok(())
    }
    /// Whether this document uses identified pool members. Shared-store
    /// writers must gate this wire format until all readers support it.
    pub fn has_named_members(&self) -> bool {
        self.http
            .iter()
            .flat_map(|route| &route.backends)
            .chain(self.tcp.iter().flat_map(|route| &route.backends))
            .any(|backend| backend.id().is_some())
    }

    pub fn prepare_upstream_tls(
        &self,
    ) -> anyhow::Result<std::collections::HashMap<String, std::sync::Arc<rustls::ClientConfig>>>
    {
        Ok(self.prepare_upstream_tls_with_trust()?.configs)
    }

    fn prepare_upstream_tls_with_trust(&self) -> anyhow::Result<PreparedUpstreamTls> {
        let mut prepared = PreparedUpstreamTls::default();
        for (id, options) in self
            .http
            .iter()
            .filter(|r| r.enabled)
            .map(|r| (&r.id, &r.upstream))
            .chain(
                self.tcp
                    .iter()
                    .filter(|r| r.enabled)
                    .map(|r| (&r.id, &r.upstream)),
            )
        {
            if let Some(tls) = &options.tls {
                let (config, trust) = crate::upstream::build_client_config_with_trust(
                    &crate::tls::client_config(None)?,
                    tls,
                )?;
                prepared
                    .configs
                    .insert(id.clone(), std::sync::Arc::new(config));
                if let Some(trust) = trust {
                    prepared.trust.insert(id.clone(), trust);
                }
            }
        }
        Ok(prepared)
    }
    pub fn prepare_host_regexes(&self) -> anyhow::Result<PreparedHostRegexes> {
        let mut prepared = PreparedHostRegexes::default();
        for route in &self.http {
            if let Some(pattern) = &route.host_regex {
                prepared
                    .http
                    .insert(route.id.clone(), crate::host_match::compile_regex(pattern)?);
            }
        }
        for route in &self.tcp {
            if let Some(sni) = &route.sni {
                let patterns = sni
                    .host_regexes
                    .iter()
                    .map(|pattern| crate::host_match::compile_regex(pattern))
                    .collect::<anyhow::Result<Vec<_>>>()?;
                if !patterns.is_empty() {
                    prepared.sni.insert(route.id.clone(), patterns);
                }
            }
        }
        Ok(prepared)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::{Context, bail, ensure};
        use std::collections::HashSet;
        self.settings.validate()?;
        crate::acme_http01::validate(self)?;
        ensure!(
            self.pumgye.is_none() || self.pumgye_authority.is_none(),
            "Pumgye policy belongs to either embedded or independent authority"
        );
        if let Some(authority) = &self.pumgye_authority {
            authority.validate()?;
        }
        if let Some(policy) = &self.pumgye {
            policy.compile()?;
        }
        for route in &self.http {
            if let Some(gate) = route
                .resource_policy
                .as_ref()
                .and_then(|policy| policy.pumgye.as_ref())
            {
                if self.pumgye_authority.is_some() {
                    gate.validate_remote()?;
                } else {
                    gate.validate(self.pumgye.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("Pumgye gate requires policy or authority")
                    })?)?;
                }
            }
        }
        for route in &self.http {
            if let Some(gate) = route
                .resource_policy
                .as_ref()
                .and_then(|p| p.pumgye_resource.as_ref())
            {
                if let Some(authority) = &self.pumgye_authority {
                    ensure!(
                        authority.transport == crate::pumgye::DecisionTransport::Grpc,
                        "resource authority requires gRPC transport"
                    );
                    gate.validate_remote()?;
                } else {
                    gate.validate(self.pumgye.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("resource gate requires policy or authority")
                    })?)?;
                }
            }
        }
        for route in &self.http {
            if let Some(native) = route
                .auth
                .as_ref()
                .and_then(|auth| auth.native_resource.as_ref())
            {
                ensure!(
                    route.access_mode == AccessMode::Protected,
                    "native resource requires protected access"
                );
                ensure!(
                    route
                        .auth
                        .as_ref()
                        .and_then(|auth| auth.native.as_ref())
                        .is_some_and(|transport| transport.transport == HopaeTransport::Grpc
                            && transport.tls.is_some()),
                    "native resource requires Hopae gRPC mTLS"
                );
                ensure!(
                    self.pumgye_authority
                        .as_ref()
                        .is_some_and(|authority| authority.transport
                            == crate::pumgye::DecisionTransport::Grpc
                            && authority.tls.is_some()),
                    "native resource requires independent Pumgye gRPC mTLS"
                );
                let policy = route
                    .resource_policy
                    .as_ref()
                    .filter(|policy| policy.enforce)
                    .ok_or_else(|| {
                        anyhow::anyhow!("native resource requires enforced resource policy")
                    })?;
                let gate = policy.pumgye_resource.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("native resource requires owner resource/action gate")
                })?;
                native.compile_for_route(gate.clone(), route, self.revision)?;
            }
        }
        ensure!(
            self.settings
                .path_allowlists
                .as_deref()
                .unwrap_or(&[])
                .iter()
                .all(|rule| rule.allow_countries.is_empty())
                || self.geoip_database.is_some(),
            "URL country whitelist requires geoip_database"
        );
        crate::udp::validate_routes(&self.udp)?;
        if let Some(source) = &self.geoip_database {
            source.validate().context("geoip_database")?;
        }
        for policy in self
            .http
            .iter()
            .filter_map(|route| route.country_policy.as_ref())
            .chain(
                self.tcp
                    .iter()
                    .filter_map(|route| route.country_policy.as_ref()),
            )
        {
            policy.validate()?;
            ensure!(
                !policy.enforce || self.geoip_database.is_some(),
                "enforced country policy requires geoip_database"
            );
        }
        ensure!(
            self.cache_generation_floor <= crate::cache_store::MAX_GENERATION,
            "cache_generation_floor must be 0..4294967295"
        );
        ensure!(
            self.http.len() + self.tcp.len() + self.udp.len() <= 1024,
            "at most 1024 routes are allowed"
        );
        ensure!(
            self.http
                .iter()
                .filter(|route| route.balance.active_health.is_some())
                .map(|route| route.backends.len())
                .sum::<usize>()
                + self
                    .tcp
                    .iter()
                    .filter(|route| route.health.is_some())
                    .map(|route| route.backends.len())
                    .sum::<usize>()
                <= 1024,
            "at most 1024 actively probed HTTP/TCP backends are allowed"
        );
        for limit in self
            .http
            .iter()
            .filter_map(|r| r.max_requests)
            .chain(self.tcp.iter().filter_map(|r| r.max_connections))
        {
            ensure!(
                (1..=1_000_000).contains(&limit),
                "route admission limit must be 1..1000000"
            );
        }
        for timeout in self.http.iter().filter_map(|r| r.upstream_timeout_ms) {
            ensure!(
                (1..=86_400_000).contains(&timeout),
                "upstream_timeout_ms must be 1..86400000 (24h)"
            );
        }
        for retries in self.http.iter().map(|r| r.retries) {
            ensure!(retries <= 16, "retries must be 0..16");
        }
        for code in self
            .http
            .iter()
            .filter_map(|route| route.https_redirect_code)
        {
            ensure!(
                matches!(code, 301 | 302 | 307 | 308 | 426),
                "route https_redirect_code must be 301, 302, 307, 308 or 426"
            );
        }
        for basic in self.http.iter().filter_map(|r| r.basic_auth.as_ref()) {
            ensure!(
                !basic.credentials.is_empty() && basic.credentials.len() <= 4096,
                "basic_auth requires 1..4096 credentials"
            );
            ensure!(
                basic
                    .realm
                    .bytes()
                    .all(|b| b >= 0x20 && b != 0x7f && b != b'"'),
                "basic_auth realm contains invalid characters"
            );
            let mut usernames = std::collections::HashSet::with_capacity(basic.credentials.len());
            for credential in &basic.credentials {
                let (username, identity_headers) =
                    crate::basic_auth::credential_metadata(credential)?;
                ensure!(
                    usernames.insert(username.clone()),
                    "basic_auth contains duplicate username: {username}"
                );
                if basic.identity_header.is_some() {
                    ensure!(
                        hyper::header::HeaderValue::from_str(&username).is_ok(),
                        "basic-auth username cannot be represented as an identity header value"
                    );
                }
                for (name, _) in identity_headers {
                    ensure!(
                        valid_response_header_name(name.as_str())
                            && !name.as_str().starts_with("x-forwarded-")
                            && !name.as_str().starts_with("x-original-")
                            && !matches!(
                                name.as_str(),
                                "forwarded" | "x-real-ip" | "x-hangang-auth-terminal"
                            ),
                        "unsafe basic-auth credential identity header"
                    );
                    if let Some(identity) = &basic.identity_header {
                        ensure!(
                            !name.as_str().eq_ignore_ascii_case(identity),
                            "basic-auth credential identity conflicts with identity_header"
                        );
                    }
                }
            }
            if let Some(name) = &basic.identity_header {
                ensure!(
                    valid_response_header_name(name),
                    "basic_auth identity_header is invalid or protected: {name}"
                );
            }
        }
        for route in &self.http {
            for name in route
                .response_remove_headers
                .iter()
                .chain(route.response_set_headers.keys())
            {
                ensure!(
                    valid_response_header_name(name),
                    "response header rule targets an invalid or protected header: {name}"
                );
            }
            for value in route.response_set_headers.values() {
                ensure!(
                    value.bytes().all(|b| b >= 0x20 && b != 0x7f),
                    "response header value contains control characters"
                );
            }
        }
        if let Some(cache) = &self.cache {
            cache.validate()?;
        }
        crate::certificates::validate_set(&self.certificates)?;
        ensure!(
            self.http
                .iter()
                .map(|r| &r.upstream)
                .chain(self.tcp.iter().map(|r| &r.upstream))
                .filter(|o| o.tls.as_ref().is_some_and(|t| t.ca_file.is_some()))
                .count()
                <= 16,
            "at most 16 routes may load private upstream CA files"
        );
        ensure!(
            self.http.iter().filter(|r| r.host_regex.is_some()).count()
                + self
                    .tcp
                    .iter()
                    .filter_map(|r| r.sni.as_ref())
                    .map(|s| s.host_regexes.len())
                    .sum::<usize>()
                <= 256,
            "at most 256 host regular expressions per configuration"
        );
        self.validate_path_case_overlap()?;
        let mut ids = HashSet::new();
        for id in self
            .http
            .iter()
            .map(|r| &r.id)
            .chain(self.tcp.iter().map(|r| &r.id))
            .chain(self.udp.iter().map(|r| &r.id))
        {
            ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
                "invalid route id"
            );
            ensure!(ids.insert(id), "duplicate route id: {id}");
        }
        ensure!(
            self.workload_http.len() <= 64,
            "at most 64 workload HTTP listeners"
        );
        let mut workload_ids = HashSet::new();
        let mut workload_addresses = HashSet::new();
        for listener in &self.workload_http {
            listener.validate()?;
            ensure!(
                workload_ids.insert(&listener.id),
                "duplicate workload HTTP listener id"
            );
            if listener.enabled {
                ensure!(
                    workload_addresses.insert(listener.listen),
                    "duplicate workload HTTP listener address"
                );
                ensure!(
                    !self
                        .tcp
                        .iter()
                        .any(|route| route.enabled && route.listen == listener.listen),
                    "workload HTTP listener conflicts with TCP listener"
                );
            }
        }
        ensure!(
            self.public_http.len() <= 64,
            "at most 64 public HTTP listeners"
        );
        ensure!(
            self.public_http
                .iter()
                .map(|listener| listener.certificates.len())
                .sum::<usize>()
                <= 1024,
            "at most 1024 named public TLS certificates across all listeners"
        );
        let mut public_ids = HashSet::new();
        let mut public_addresses = HashSet::new();
        for listener in &self.public_http {
            listener.validate()?;
            ensure!(
                public_ids.insert(listener.id.as_str()),
                "duplicate public HTTP listener id"
            );
            if listener.enabled {
                ensure!(
                    public_addresses.insert(listener.listen),
                    "duplicate public HTTP listener address"
                );
                ensure!(
                    !workload_addresses.contains(&listener.listen),
                    "public HTTP listener conflicts with workload HTTP listener"
                );
                ensure!(
                    !self
                        .tcp
                        .iter()
                        .any(|r| r.enabled && r.listen == listener.listen),
                    "public HTTP listener conflicts with TCP listener"
                );
            }
        }
        let workload_identity_headers: HashSet<String> = self
            .http
            .iter()
            .filter_map(|route| route.workload_auth.as_ref()?.identity_header.as_ref())
            .map(|name| name.to_ascii_lowercase())
            .collect();
        let authentication_identity_headers = authentication_identity_headers(&self.http)?;
        for route in &self.http {
            let mut other_identity = Vec::new();
            if let Some(jwt) = &route.jwt_auth {
                other_identity.extend(
                    jwt.identity_header
                        .iter()
                        .map(|name| name.to_ascii_lowercase()),
                );
            }
            if let Some(auth) = &route.auth {
                other_identity.extend(
                    auth.response_headers
                        .iter()
                        .map(|name| name.to_ascii_lowercase()),
                );
            }
            if let Some(basic) = &route.basic_auth {
                other_identity.extend(
                    crate::basic_auth::prepare(basic)?
                        .reserved_headers()
                        .iter()
                        .map(|name| name.as_str().to_owned()),
                );
            }
            ensure!(
                !other_identity
                    .iter()
                    .any(|name| workload_identity_headers.contains(name)),
                "workload identity header conflicts with another authenticator"
            );
            ensure!(
                !route.headers.keys().any(
                    |name| authentication_identity_headers.contains(&name.to_ascii_lowercase())
                ),
                "verified authentication identity cannot be a request-header predicate"
            );
        }
        let mut resources: std::collections::HashMap<&str, &HttpRoute> = Default::default();
        let mut jwt_policies = std::collections::HashSet::new();
        for r in &self.http {
            ensure!(
                r.listener_ids.len() <= 64,
                "route {} has too many listener IDs",
                r.id
            );
            let mut route_listener_ids = HashSet::new();
            for id in &r.listener_ids {
                ensure!(
                    route_listener_ids.insert(id),
                    "route {} has duplicate listener ID",
                    r.id
                );
                ensure!(
                    id == "default" || public_ids.contains(id.as_str()),
                    "route {} references unknown public HTTP listener {id}",
                    r.id
                );
            }
            ensure!(
                r.workload_auth.is_none() || r.listener_ids.is_empty(),
                "workload_auth route cannot select public HTTP listeners"
            );
            if let Some(workload) = &r.workload_auth {
                workload.validate()?;
                ensure!(
                    r.access_mode == AccessMode::Protected && r.resource_policy.is_some(),
                    "workload_auth requires protected access and resource_policy"
                );
                if let Some(name) = &workload.identity_header {
                    ensure!(
                        !r.auth.as_ref().is_some_and(|auth| auth
                            .response_headers
                            .iter()
                            .any(|other| other.eq_ignore_ascii_case(name))),
                        "workload identity header conflicts with external authorization"
                    );
                    ensure!(
                        !r.jwt_auth
                            .as_ref()
                            .and_then(|jwt| jwt.identity_header.as_ref())
                            .is_some_and(|other| other.eq_ignore_ascii_case(name)),
                        "workload identity header conflicts with JWT"
                    );
                    if let Some(basic) = &r.basic_auth {
                        let prepared = crate::basic_auth::prepare(basic)?;
                        ensure!(
                            !prepared
                                .reserved_headers()
                                .iter()
                                .any(|other| other.as_str().eq_ignore_ascii_case(name)),
                            "workload identity header conflicts with Basic authentication"
                        );
                    }
                }
            }
            if let Some(jwt) = &r.jwt_auth {
                if jwt_policies.insert(serde_json::to_vec(jwt)?) {
                    ensure!(
                        jwt_policies.len() <= 64,
                        "at most 64 distinct JWT policies per configuration"
                    );
                    jwt.validate()?;
                }
                ensure!(
                    r.basic_auth.is_none(),
                    "JWT and Basic authentication cannot share Authorization"
                );
                if let Some(name) = &jwt.identity_header {
                    ensure!(
                        valid_response_header_name(name),
                        "JWT identity header is invalid or protected"
                    );
                    ensure!(
                        !r.auth.as_ref().is_some_and(|auth| auth
                            .response_headers
                            .iter()
                            .any(|other| other.eq_ignore_ascii_case(name))),
                        "JWT identity header conflicts with external authorization identity"
                    );
                }
            }
            if let Some(policy) = &r.language_policy {
                policy.compile()?;
            }
            if (r.basic_auth.is_some()
                || r.auth.is_some()
                || r.jwt_auth.is_some()
                || r.workload_auth.is_some()
                || r.response_transform.is_some())
                && let Some(path) = &r.path_prefix
            {
                ensure!(
                    crate::resource_policy::canonical_path(path)? == *path,
                    "security-sensitive route path_prefix must be canonical"
                );
            }
            if let Some(policy) = &r.resource_policy {
                ensure!(
                    r.access_mode == AccessMode::Protected,
                    "resource policy requires access_mode protected"
                );
                policy.validate_binding_with_workload(
                    r.basic_auth.as_ref(),
                    r.auth.as_ref(),
                    r.jwt_auth.as_ref(),
                    r.workload_auth.as_ref(),
                )?;
                if let Some(path) = &r.path_prefix {
                    ensure!(
                        crate::resource_policy::canonical_path(path)? == *path,
                        "resource path_prefix must be canonical"
                    );
                }
                if let Some(prior) = resources.insert(&policy.resource_id, r) {
                    ensure!(
                        prior.resource_policy == r.resource_policy
                            && prior.language_policy == r.language_policy
                            && prior.country_policy == r.country_policy
                            && prior.basic_auth == r.basic_auth
                            && prior.auth == r.auth
                            && prior.jwt_auth == r.jwt_auth
                            && prior.workload_auth == r.workload_auth
                            && effective_public_listeners(prior) == effective_public_listeners(r),
                        "routes sharing a resource_id must share policy and authenticators"
                    );
                }
            }
            match r.access_mode {
                AccessMode::Legacy => {}
                AccessMode::Protected => ensure!(
                    r.basic_auth.is_some()
                        || r.auth.is_some()
                        || r.jwt_auth.is_some()
                        || r.workload_auth.is_some(),
                    "route {} access_mode protected requires basic_auth or auth or jwt_auth",
                    r.id
                ),
                AccessMode::Public | AccessMode::Application => ensure!(
                    r.basic_auth.is_none()
                        && r.auth.is_none()
                        && r.jwt_auth.is_none()
                        && r.workload_auth.is_none(),
                    "route {} access_mode public/application conflicts with basic_auth or auth or jwt_auth",
                    r.id
                ),
            }
            ensure!(
                usize::from(r.host.is_some())
                    + usize::from(r.host_regex.is_some())
                    + usize::from(!r.hosts.is_empty())
                    <= 1,
                "host, hosts and host_regex are mutually exclusive"
            );
            ensure!(r.hosts.len() <= 32, "hosts may contain at most 32 patterns");
            let mut seen_hosts = std::collections::HashSet::new();
            for host in &r.hosts {
                validate_http_match_host(host)?;
                ensure!(
                    seen_hosts.insert(host.to_ascii_lowercase()),
                    "duplicate hosts pattern"
                );
            }
            if let Some(canonical) = &r.canonical_domain {
                ensure!(
                    canonical.host.len() <= 253
                        && !canonical.host.is_empty()
                        && canonical.host.is_ascii()
                        && canonical.host.parse::<std::net::IpAddr>().is_err()
                        && canonical.host == canonical.host.to_ascii_lowercase()
                        && !canonical.host.ends_with('.')
                        && !canonical.host.contains([':', '@'])
                        && !crate::host_match::is_glob(&canonical.host)
                        && crate::host_match::validate_pattern(&canonical.host).is_ok(),
                    "canonical_domain host must be an exact DNS host"
                );
                ensure!(
                    r.host.iter().chain(r.hosts.iter()).any(|host| {
                        !crate::host_match::is_glob(host)
                            && host.eq_ignore_ascii_case(&canonical.host)
                    }),
                    "canonical_domain host must belong to route exact host or hosts"
                );
                ensure!(
                    !(r.require_tls && canonical.scheme == CanonicalScheme::Http),
                    "canonical_domain http scheme conflicts with require_tls"
                );
                ensure!(
                    matches!(canonical.status, 301 | 302 | 307 | 308),
                    "canonical_domain status must be 301, 302, 307 or 308"
                );
                ensure!(
                    !canonical.path_prefixes.is_empty()
                        && canonical.path_prefixes.len() <= 32
                        && canonical.exclude_path_prefixes.len() <= 32,
                    "canonical_domain path prefixes must contain 1..32 includes and at most 32 excludes"
                );
                ensure!(
                    canonical
                        .path_prefixes
                        .iter()
                        .chain(&canonical.exclude_path_prefixes)
                        .map(String::len)
                        .sum::<usize>()
                        <= 64 * 1024,
                    "canonical_domain path prefix bytes exceed 65536"
                );
                let mut includes = std::collections::HashSet::new();
                let mut excludes = std::collections::HashSet::new();
                for prefix in &canonical.path_prefixes {
                    ensure!(
                        valid_canonical_prefix(prefix),
                        "canonical_domain path prefix is invalid"
                    );
                    ensure!(
                        includes.insert(prefix),
                        "canonical_domain include prefix duplicated"
                    );
                }
                for prefix in &canonical.exclude_path_prefixes {
                    ensure!(
                        valid_canonical_prefix(prefix),
                        "canonical_domain path prefix is invalid"
                    );
                    ensure!(
                        excludes.insert(prefix) && !includes.contains(prefix),
                        "canonical_domain exclude prefix duplicated or conflicts with include"
                    );
                }
                ensure!(
                    !canonical.methods.is_empty() && canonical.methods.len() <= 2,
                    "canonical_domain methods must contain 1..2 safe values"
                );
                let mut methods = std::collections::HashSet::new();
                for method in &canonical.methods {
                    ensure!(
                        matches!(method.as_str(), "GET" | "HEAD") && methods.insert(method),
                        "canonical_domain method is invalid or duplicated"
                    );
                }
            }
            if let Some(pattern) = &r.host_regex {
                ensure!(
                    !pattern.is_empty() && pattern.len() <= 1024,
                    "host_regex must contain 1..1024 bytes"
                );
            }
            r.upstream.validate()?;
            ensure!(
                !(r.preserve_host && r.upstream_host.is_some()),
                "preserve_host conflicts with upstream_host"
            );
            if let Some(host) = &r.upstream_host {
                ensure!(
                    host.len() <= 255 && !host.contains('@'),
                    "invalid upstream_host"
                );
                let authority: hyper::http::uri::Authority =
                    host.parse().context("invalid upstream_host")?;
                ensure!(!authority.host().is_empty(), "invalid upstream_host");
                let _: hyper::header::HeaderValue =
                    host.parse().context("invalid upstream_host")?;
            }
            if r.upstream.tls.is_some() {
                ensure!(
                    r.backends
                        .iter()
                        .all(|b| b.address().starts_with("https://")),
                    "HTTP upstream TLS options require HTTPS backends"
                );
            }
            r.balance.validate(r.backends.len())?;
            if let Some(cache) = &r.cache {
                cache.validate()?;
                ensure!(
                    self.cache.is_some(),
                    "route cache requires global cache configuration"
                );
            }
            for transform in [&r.request_transform, &r.response_transform]
                .into_iter()
                .flatten()
            {
                transform.validate()?;
            }
            // A request transform runs after authentication established the
            // upstream-facing identity headers; it must not be able to set or
            // remove them, or the upstream would trust a configured value in
            // place of the authenticated one.
            if let Some(transform) = &r.request_transform {
                ensure!(
                    transform.when_prefix.is_none(),
                    "request transforms cannot use when_prefix"
                );
                let identity_headers = r
                    .basic_auth
                    .as_ref()
                    .and_then(|basic| basic.identity_header.as_deref())
                    .into_iter()
                    .chain(
                        r.auth
                            .iter()
                            .flat_map(|auth| auth.response_headers.iter().map(String::as_str)),
                    )
                    .chain(
                        r.jwt_auth
                            .iter()
                            .filter_map(|jwt| jwt.identity_header.as_deref()),
                    )
                    .chain(authentication_identity_headers.iter().map(String::as_str))
                    .chain(
                        r.workload_auth
                            .iter()
                            .filter_map(|auth| auth.identity_header.as_deref()),
                    )
                    .map(str::to_owned)
                    .chain(r.basic_auth.iter().flat_map(|basic| {
                        basic.credentials.iter().flat_map(|credential| {
                            crate::basic_auth::credential_metadata(credential)
                                .expect("validated compatibility credential")
                                .1
                                .into_iter()
                                .map(|(name, _)| name.as_str().to_owned())
                                .collect::<Vec<_>>()
                        })
                    }));
                for name in identity_headers {
                    ensure!(
                        !transform.mutates_header(&name),
                        "route {} request_transform must not set or remove the authentication identity header {name}",
                        r.id
                    );
                }
            }
            // The Basic identity header is removed (as a client-supplied
            // reserved name) before the external authorization call, so both
            // authenticators claiming the same header cannot compose.
            if let (Some(identity), Some(auth)) = (
                r.basic_auth
                    .as_ref()
                    .and_then(|basic| basic.identity_header.as_deref()),
                &r.auth,
            ) {
                ensure!(
                    !auth
                        .response_headers
                        .iter()
                        .any(|name| name.eq_ignore_ascii_case(identity)),
                    "route {} basic_auth identity_header {identity} conflicts with auth response_headers",
                    r.id
                );
            }
            if let (Some(basic), Some(auth)) = (&r.basic_auth, &r.auth) {
                for credential in &basic.credentials {
                    for (name, _) in crate::basic_auth::credential_metadata(credential)?.1 {
                        ensure!(
                            !auth
                                .response_headers
                                .iter()
                                .any(|response_name| response_name
                                    .eq_ignore_ascii_case(name.as_str())),
                            "route {} basic-auth credential identity {} conflicts with auth response_headers",
                            r.id,
                            name
                        );
                    }
                }
            }
            if let Some(auth) = &r.auth {
                let url: reqwest::Url = auth.url.parse().context("invalid authorization URL")?;
                ensure!(
                    matches!(url.scheme(), "http" | "https")
                        && url.host_str().is_some()
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url.fragment().is_none(),
                    "invalid authorization URL"
                );
                ensure!(
                    (1..=5000).contains(&auth.timeout_ms),
                    "authorization timeout must be 1..5000 ms"
                );
                ensure!(
                    auth.request_headers.len() <= 32 && auth.response_headers.len() <= 32,
                    "too many authorization headers"
                );
                for (name, identity) in auth
                    .request_headers
                    .iter()
                    .map(|name| (name, false))
                    .chain(auth.response_headers.iter().map(|name| (name, true)))
                {
                    let name: hyper::header::HeaderName =
                        name.parse().context("invalid authorization header")?;
                    ensure!(
                        name.as_str() != "x-hangang-auth-terminal",
                        "authorization terminal marker is reserved"
                    );
                    // Identity names conventionally carried under the
                    // `x-forwarded-` prefix by single sign-on services may be
                    // copied from the authorization RESPONSE; the proxy owns
                    // them (client copies are removed before authorization and
                    // the authenticated values are re-asserted after forwarding
                    // headers are generated). They are never request inputs.
                    if identity && is_identity_forwarded_header(name.as_str()) {
                        continue;
                    }
                    ensure!(
                        !unsafe_auth_header(name.as_str()),
                        "unsafe authorization header"
                    );
                }
                if let Some(native) = &auth.native {
                    native.address.validate()?;
                    ensure!(
                        (native.address.is_loopback() || native.tls.is_some()),
                        "native Hopae requires a nonzero unicast address; remote connections require mTLS"
                    );
                    ensure!(
                        native.transport != HopaeTransport::Grpc || native.tls.is_some(),
                        "Hopae gRPC requires mTLS"
                    );
                    if let Some(tls) = &native.tls {
                        ensure!(
                            rustls::pki_types::ServerName::try_from(tls.server_name.clone())
                                .is_ok(),
                            "invalid native Hopae TLS server name"
                        );
                        ensure!(
                            [&tls.ca, &tls.certificate, &tls.key]
                                .iter()
                                .all(|p| p.is_absolute()),
                            "native Hopae TLS paths must be absolute"
                        );
                    }
                    ensure!(
                        (1..=256).contains(&native.pool_size),
                        "native Hopae pool_size must be 1..256"
                    );
                    ensure!(
                        url.path() == "/_hopae/verify" && url.query().is_none(),
                        "native Hopae requires the verify URL"
                    );
                    ensure!(
                        auth.static_request_headers
                            .keys()
                            .any(|n| n.eq_ignore_ascii_case("x-hopae-gateway-key")),
                        "native Hopae requires a static caller key"
                    );
                }
                validate_static_request_headers(auth)?;
                validate_strip_request_cookies(&auth.strip_request_cookies)?;
            }
            validate_strip_request_cookies(&r.strip_request_cookies)?;
            ensure!(
                !r.backends.is_empty() && r.backends.len() <= 128,
                "route {} needs 1..128 backends",
                r.id
            );
            crate::pool_member::validate_backends(&r.backends, &r.balance.weights)?;
            ensure!(
                r.deny_cidrs.len() <= 1024 && r.headers.len() <= 64 && r.json.len() <= 64,
                "too many route conditions"
            );
            for b in &r.backends {
                let b = b.address();
                if crate::discovery::parse_reference(b)?.is_some() {
                    continue;
                }
                let uri: hyper::Uri = b.parse().context("invalid backend URI")?;
                ensure!(
                    matches!(uri.scheme_str(), Some("http" | "https")),
                    "backend scheme must be http or https"
                );
                let authority = uri.authority().context("backend requires authority")?;
                ensure!(
                    !authority.as_str().contains('@') && !authority.host().is_empty(),
                    "backend credentials are forbidden"
                );
                let suffix = &authority.as_str()[authority.host().len()..];
                ensure!(
                    suffix.is_empty()
                        || suffix
                            .strip_prefix(':')
                            .is_some_and(|p| p.parse::<u16>().is_ok_and(|p| p > 0)),
                    "invalid backend port"
                );
                ensure!(
                    uri.query().is_none(),
                    "backend URL must not contain a query"
                );
            }
            if let Some(h) = &r.host {
                validate_http_match_host(h)?;
            }
            if let Some(p) = &r.path_prefix {
                ensure!(
                    p.starts_with('/') && p.len() <= 2048,
                    "path_prefix must start with /"
                );
            }
            for (key, value) in &r.headers {
                key.parse::<hyper::header::HeaderName>()
                    .context("invalid match header")?;
                value
                    .parse::<hyper::header::HeaderValue>()
                    .context("invalid match header value")?;
            }
            for key in r.json.keys() {
                ensure!(
                    key.is_empty() || key.starts_with('/'),
                    "JSON condition keys must be RFC 6901 pointers"
                );
                let mut chars = key.chars();
                while let Some(c) = chars.next() {
                    if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                        bail!("invalid JSON pointer escape");
                    }
                }
            }
            if let Some(code) = &r.lua {
                ensure!(code.len() <= 16384, "Lua script exceeds 16 KiB");
            }
        }
        let mut inbound_policies = std::collections::HashSet::new();
        let mut listens = std::collections::HashMap::<_, &TcpRoute>::new();
        let mut sni_hosts = HashSet::new();
        let mut sni_globs = std::collections::HashMap::<std::net::SocketAddr, usize>::new();
        for r in &self.tcp {
            r.upstream.validate()?;
            if let Some(policy) = &r.inbound_tls {
                if inbound_policies.insert(serde_json::to_vec(policy)?) {
                    ensure!(
                        inbound_policies.len() <= 64,
                        "at most 64 distinct inbound mTLS policies"
                    );
                    policy.validate()?;
                }
                ensure!(
                    r.sni.is_none(),
                    "inbound TLS termination cannot use SNI passthrough"
                );
            }
            if let Some(health) = &r.health {
                health.validate()?;
            }
            ensure!(r.listen.port() != 0, "TCP listener port must be nonzero");
            if let Some(sni) = &r.sni {
                sni.validate()?;
                for pattern in &sni.host_regexes {
                    ensure!(
                        !r.enabled
                            || sni_hosts.insert((r.listen, r.priority, format!("regex:{pattern}"))),
                        "duplicate SNI host regex at the same priority"
                    );
                }
                for host in &sni.hosts {
                    let simple = host
                        .strip_prefix("*.")
                        .is_some_and(|suffix| !crate::host_match::is_glob(suffix));
                    if r.enabled && crate::host_match::is_glob(host) && !simple {
                        let count = sni_globs.entry(r.listen).or_default();
                        *count += 1;
                        ensure!(
                            *count <= 256,
                            "at most 256 general SNI glob patterns per listener"
                        );
                    }
                    ensure!(
                        !r.enabled
                            || sni_hosts.insert((r.listen, r.priority, host.to_ascii_lowercase())),
                        "duplicate SNI host on TCP listener"
                    );
                }
            }
            if let Some(previous) = r.enabled.then(|| listens.insert(r.listen, r)).flatten() {
                ensure!(
                    previous.sni.is_some() && r.sni.is_some(),
                    "shared TCP listener requires SNI on every route"
                );
                let a = previous.sni.as_ref().unwrap();
                let b = r.sni.as_ref().unwrap();
                ensure!(
                    a.max_client_hello_bytes == b.max_client_hello_bytes
                        && a.hello_timeout_ms == b.hello_timeout_ms,
                    "SNI routes sharing a listener require identical ClientHello limits"
                );
            }
            ensure!(
                !r.backends.is_empty() && r.backends.len() <= 128,
                "TCP route needs 1..128 backends"
            );
            crate::pool_member::validate_backends(&r.backends, &[])?;
            ensure!(r.deny_cidrs.len() <= 1024, "too many CIDRs");
            for b in &r.backends {
                let b = b.address();
                if crate::discovery::parse_reference(b)?.is_some() {
                    continue;
                }
                let uri: hyper::http::uri::Authority = b.parse().context("invalid TCP backend")?;
                ensure!(
                    !uri.as_str().contains('@')
                        && !uri.host().is_empty()
                        && uri.port_u16().is_some_and(|p| p > 0),
                    "TCP backend must be host:port"
                );
            }
        }
        Ok(())
    }
    /// Enforced resource namespaces survive deletion, renaming, and disabled
    /// routes until a prior revision explicitly releases their exact scope.
    /// A document replacing an active snapshot must also declare an intentional
    /// downgrade when an existing protected route keeps its ID. Older editors
    /// omit access_mode and authentication fields; serde would otherwise turn
    /// that replacement into an anonymous Legacy route.
    /// Two routes whose prefixes differ only in ASCII case, may serve the same
    /// host, and disagree on case sensitivity would select by an ambiguous
    /// rule: the sensitive route would be reachable only through exact-case
    /// requests while the insensitive one claims every variant. Reject them;
    /// an operator resolves it by setting `path_case` on both routes.
    fn validate_path_case_overlap(&self) -> anyhow::Result<()> {
        for (index, left) in self.http.iter().enumerate() {
            if left.path_prefix.is_none() {
                continue;
            }
            for right in &self.http[index + 1..] {
                if right.path_prefix.is_none() {
                    continue;
                }
                let (left_scope, right_scope) = (route_scope(left), route_scope(right));
                // Reject only when the scopes meet solely through case folding:
                // nested layouts such as /admin and /admin/open stay valid.
                if left.path_case_insensitive() != right.path_case_insensitive()
                    && crate::resource_guard::scopes_intersect(left_scope, right_scope)
                    && !crate::resource_guard::scopes_intersect(
                        (left_scope.0, left_scope.1, false),
                        (right_scope.0, right_scope.1, false),
                    )
                    && hosts_may_overlap(left, right)
                    && !effective_public_listeners(left)
                        .is_disjoint(&effective_public_listeners(right))
                {
                    anyhow::bail!(
                        "routes {} and {} have path_prefix values that differ only in case but different path_case; set path_case explicitly on both routes",
                        left.id,
                        right.id
                    );
                }
            }
        }
        Ok(())
    }
    /// Non-fatal findings. They are logged when a configuration is activated
    /// and printed by `--check`; they never reject a configuration.
    pub fn warnings(&self) -> Vec<String> {
        let mut shadow = Vec::new();
        for (pi, protected) in self.http.iter().enumerate() {
            let prefix = protected.path_prefix.as_deref().unwrap_or("/");
            if !protected.is_path_scoped_protection() || !protected.enabled {
                continue;
            }
            for (qi, other) in self.http.iter().enumerate() {
                if qi == pi
                    || !other.enabled
                    || other.is_path_scoped_protection()
                    || other.auth.is_some()
                    || other.basic_auth.is_some()
                    || other.jwt_auth.is_some()
                    || other.access_mode == AccessMode::Protected
                    || !selected_before((qi, other), (pi, protected))
                    || !hosts_may_overlap(other, protected)
                    || effective_public_listeners(other)
                        .is_disjoint(&effective_public_listeners(protected))
                {
                    continue;
                }
                let covers = crate::resource_guard::scopes_intersect(
                    route_scope(other),
                    route_scope(protected),
                );
                if covers {
                    shadow.push(format!(
                        "route {} (unauthenticated) is selected before protected route {} and its path scope intersects {}: it can shadow the protection on overlapping hosts",
                        other.id, protected.id, prefix
                    ));
                }
            }
        }
        shadow
            .into_iter()
            .chain(self.http
            .iter()
            .filter(|route| {
                route.path_case == Some(PathCase::Sensitive) && route.is_path_scoped_protection()
            })
            .map(|route| {
                format!(
                    "route {} protects path_prefix {} with path_case sensitive: a case variant of the prefix selects a sibling route and bypasses this protection when the upstream is case-insensitive",
                    route.id,
                    route.path_prefix.as_deref().unwrap_or_default()
                )
            }))
            .collect()
    }
    /// Emit [`Config::warnings`] at warn level.
    pub fn log_warnings(&self) {
        for warning in self.warnings() {
            tracing::warn!("{warning}");
        }
    }
    pub fn validate_transition_from(&self, previous: &Self) -> anyhow::Result<()> {
        use anyhow::ensure;
        for old in &previous.http {
            let Some(policy) = old.resource_policy.as_ref().filter(|policy| policy.enforce) else {
                continue;
            };
            ensure!(
                self.http.iter().any(|new| {
                    new.resource_policy.as_ref().is_some_and(|next| {
                        next.resource_id == policy.resource_id
                            && (!policy.has_pumgye() || next.has_pumgye())
                    }) && resource_hosts_preserved(old, new)
                        && new.path_prefix == old.path_prefix
                        && new.path_match == old.path_match
                        && new.path_case_insensitive() == old.path_case_insensitive()
                        && effective_public_listeners(new) == effective_public_listeners(old)
                }),
                "resource {} scope cannot be removed or moved; first publish enforce=false at its existing scope",
                policy.resource_id
            );
        }
        // A direct active-listener replacement must not silently remove
        // workload authentication (including a rename or SNI route split).
        // Disable or remove the protected listener in an earlier revision
        // before explicitly repurposing that socket for unauthenticated use.
        for old in previous
            .tcp
            .iter()
            .filter(|route| route.enabled && route.inbound_tls.is_some())
        {
            ensure!(
                self.tcp
                    .iter()
                    .filter(|route| route.enabled && route.listen == old.listen)
                    .all(|route| route.inbound_tls.is_some()),
                "active TCP mTLS listener must be disabled or removed in a prior revision before removing authentication"
            );
        }
        for old in previous
            .workload_http
            .iter()
            .filter(|listener| listener.enabled)
        {
            ensure!(
                !self
                    .tcp
                    .iter()
                    .any(|route| route.enabled && route.listen == old.listen),
                "workload HTTP listener must be removed in a prior revision before changing socket role"
            );
        }
        for old in previous.tcp.iter().filter(|route| route.enabled) {
            ensure!(
                !self
                    .workload_http
                    .iter()
                    .any(|listener| listener.enabled && listener.listen == old.listen),
                "TCP listener must be removed in a prior revision before changing socket role"
            );
        }
        let protected: std::collections::HashSet<&str> = previous
            .http
            .iter()
            .filter(|route| route.access_mode == AccessMode::Protected)
            .map(|route| route.id.as_str())
            .collect();
        for route in &self.http {
            ensure!(
                !protected.contains(route.id.as_str()) || route.access_mode != AccessMode::Legacy,
                "protected route {} requires explicit access_mode when replacing it",
                route.id
            );
        }
        Ok(())
    }
}

// Host aliases may be added or reordered without releasing an existing scope.
// Prove containment structurally; never guess containment between regex/globs.
pub fn effective_public_listeners(route: &HttpRoute) -> std::collections::BTreeSet<&str> {
    if route.listener_ids.is_empty() {
        ["default"].into_iter().collect()
    } else {
        route.listener_ids.iter().map(String::as_str).collect()
    }
}

fn resource_hosts_preserved(old: &HttpRoute, new: &HttpRoute) -> bool {
    let unrestricted = |route: &HttpRoute| {
        route.host.is_none() && route.hosts.is_empty() && route.host_regex.is_none()
    };
    if unrestricted(new) {
        return true;
    }
    if unrestricted(old) {
        return false;
    }
    if old.host_regex.is_some() || new.host_regex.is_some() {
        return old.host_regex == new.host_regex;
    }
    old.host.iter().chain(old.hosts.iter()).all(|pattern| {
        new.host
            .iter()
            .chain(new.hosts.iter())
            .any(|next| pattern.eq_ignore_ascii_case(next))
    })
}

fn deserialize_http_hosts<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let hosts = Vec::<String>::deserialize(deserializer)?;
    if hosts.is_empty() {
        return Err(serde::de::Error::custom(
            "hosts must contain at least one pattern",
        ));
    }
    Ok(hosts)
}

/// Conservative: an unconstrained host, a regex or a glob may match anything.
fn hosts_may_overlap(left: &HttpRoute, right: &HttpRoute) -> bool {
    #[derive(PartialEq)]
    enum Key {
        Ip(std::net::IpAddr),
        Name(String),
    }
    fn patterns(route: &HttpRoute) -> Option<Vec<Key>> {
        if route.host_regex.is_some() {
            return None;
        }
        let mut all: Vec<&String> = route.hosts.iter().collect();
        all.extend(route.host.iter());
        if all.is_empty() || all.iter().any(|h| h.contains(['*', '?'])) {
            return None;
        }
        // Same equivalence as host_match::matches: IP literals compare as
        // addresses, names ASCII case-insensitively (also without a root dot,
        // which guarded hosts trim).
        Some(
            all.iter()
                .map(|h| match crate::host_match::parse_ip(h) {
                    Some(ip) => Key::Ip(ip),
                    None => Key::Name(h.trim_end_matches('.').to_ascii_lowercase()),
                })
                .collect(),
        )
    }
    match (patterns(left), patterns(right)) {
        (Some(a), Some(b)) => a.iter().any(|h| b.contains(h)),
        _ => true,
    }
}

/// The (mode, operand, case-insensitive) scope a route selects by. A route
/// without a prefix selects every path.
fn route_scope(route: &HttpRoute) -> (PathMatch, &str, bool) {
    match &route.path_prefix {
        Some(prefix) => (route.path_match, prefix, route.path_case_insensitive()),
        None => (PathMatch::Prefix, "", false),
    }
}

/// Selection order: higher priority first, ties by configuration order.
fn selected_before(first: (usize, &HttpRoute), second: (usize, &HttpRoute)) -> bool {
    first.1.priority > second.1.priority
        || (first.1.priority == second.1.priority && first.0 < second.0)
}

fn validate_http_match_host(host: &str) -> anyhow::Result<()> {
    use anyhow::ensure;
    if crate::host_match::is_glob(host) {
        crate::host_match::validate_pattern(host)?;
    }
    ensure!(
        !host.is_empty()
            && host.len() <= 255
            && !host
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'/'),
        "invalid match host"
    );
    Ok(())
}

fn valid_canonical_prefix(prefix: &str) -> bool {
    prefix.starts_with('/')
        && prefix.len() <= 2048
        && !prefix.contains(['?', '#', '\\'])
        && !prefix
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
        && !prefix
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
}

#[derive(Default)]
pub struct PreparedHostRegexes {
    pub http: std::collections::HashMap<String, regex::Regex>,
    pub sni: std::collections::HashMap<String, Vec<regex::Regex>>,
}
pub struct HttpRuntime {
    pub host_regex: Option<regex::Regex>,
    pub admission: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    pub route: HttpRoute,
    /// Shared with the previous snapshot when the route's backends and
    /// balancing policy are unchanged, so passive-health quarantine and
    /// least-connections accounting survive unrelated configuration updates.
    pub balancer: std::sync::Arc<crate::balance::Balancer>,
    pub cache_fingerprint: String,
    pub request_transform: Option<std::sync::Arc<crate::transform::BodyTransform>>,
    pub response_transform: Option<std::sync::Arc<crate::transform::BodyTransform>>,
    pub basic_auth: Option<crate::basic_auth::Prepared>,
    pub language_policy: Option<crate::language_policy::CompiledLanguagePolicy>,
    pub country_policy: Option<crate::country_policy::CompiledCountryPolicy>,
    pub jwt_auth: Option<std::sync::Arc<crate::jwt_runtime::Runtime>>,
    pub workload_auth: Option<std::sync::Arc<crate::workload_auth::Runtime>>,
    pub auth_reserved: Vec<hyper::header::HeaderName>,
    /// Resolved `auth.static_request_headers` (values marked sensitive). Held
    /// only in the prepared runtime; never serialized.
    pub auth_static_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)>,
    /// Set when a passive path activated this route without its static
    /// header variable; every request to the route is answered with 503.
    pub auth_unavailable: Option<AuthUnavailable>,
    pub auth_native: Option<std::sync::Arc<crate::hopae_native::Client>>,
    pub native_resource: Option<std::sync::Arc<crate::native_resource::Binding>>,
}
struct PublicationRetirements {
    reservation: crate::retired_members::Reservation,
    records: Vec<crate::retired_members::Record>,
}

pub struct Snapshot {
    pub pumgye: Option<std::sync::Arc<pumgye_core::CompiledPolicy>>,
    pub pumgye_remote: Option<std::sync::Arc<crate::pumgye::AuthorityRuntime>>,
    retirements: std::sync::Mutex<Option<PublicationRetirements>>,
    native_predecessors: Vec<std::sync::Arc<crate::native_resource::Binding>>,
    pub retired_members: std::sync::Arc<crate::retired_members::Registry>,
    pub settings: std::sync::Arc<PreparedSettings>,
    /// Header names used by any declarative HTTP route predicate. Incoming
    /// duplicates for these names are rejected before routing so the selected
    /// route and an upstream cannot interpret different values.
    pub http_match_headers: std::collections::HashSet<hyper::header::HeaderName>,
    pub workload_identity_headers: Vec<hyper::header::HeaderName>,
    /// Identity outputs reserved across every route, including public fallbacks.
    pub authentication_identity_headers: Vec<hyper::header::HeaderName>,
    pub workload_routes:
        std::collections::HashMap<String, std::sync::Arc<crate::workload_auth::Runtime>>,
    /// Whole-route generations for admitted JWT streams; unchanged unrelated
    /// publications preserve their leases without scanning all routes per frame.
    pub jwt_routes: std::collections::HashMap<String, std::sync::Arc<HttpRoute>>,
    pub http_workload_tls:
        std::collections::HashMap<String, std::sync::Arc<crate::workload_material::Slot>>,
    pub public_http_tls:
        std::collections::HashMap<String, std::sync::Arc<arc_swap::ArcSwap<rustls::ServerConfig>>>,
    pub public_http_generations: std::collections::HashMap<String, std::sync::Arc<()>>,
    pub sni_regex: std::collections::HashMap<String, Vec<regex::Regex>>,
    pub upstream_tls: std::collections::HashMap<String, std::sync::Arc<rustls::ClientConfig>>,
    // Fingerprints of the exact custom CA certificates used by prepared TLS.
    // Never re-read files to decide whether health observations may be reused.
    #[doc(hidden)]
    pub upstream_trust: std::collections::HashMap<String, [u8; 32]>,
    pub tcp_inbound_tls:
        std::collections::HashMap<String, std::sync::Arc<crate::workload_material::Slot>>,
    pub certificates: Option<std::sync::Arc<arc_swap::ArcSwap<rustls::ServerConfig>>>,
    pub cache: Option<std::sync::Arc<crate::cache::CacheRuntime>>,
    pub geoip: Option<std::sync::Arc<crate::geoip_runtime::Slot>>,
    pub config: Config,
    pub admissions:
        std::collections::HashMap<String, std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub http: Vec<std::sync::Arc<HttpRuntime>>,
    pub(crate) http_route_indices: std::collections::HashMap<String, usize>,
    pub resource_guards: Vec<std::sync::Arc<HttpRuntime>>,
    /// Authentication-bearing routes impose an unambiguous path/authority
    /// profile on their host, including requests selecting a public fallback.
    pub authentication_path_guards: Vec<std::sync::Arc<HttpRuntime>>,
    pub tcp_health: std::collections::HashMap<String, std::sync::Arc<crate::tcp_health::TcpHealth>>,
    pub tcp_member_admissions: std::collections::HashMap<
        String,
        Vec<std::sync::Arc<crate::member_admission::MemberAdmission>>,
    >,
    pub tcp_member_activity:
        std::collections::HashMap<String, std::sync::Arc<crate::tcp_member::TcpMemberActivity>>,
}
fn named_backends(backends: &[crate::pool_member::Backend]) -> bool {
    backends
        .first()
        .is_some_and(|backend| backend.id().is_some())
}

fn stable_backend_mapping(
    current: &[crate::pool_member::Backend],
    previous: &[crate::pool_member::Backend],
) -> Vec<Option<usize>> {
    let old: std::collections::HashMap<_, _> = previous
        .iter()
        .enumerate()
        .filter_map(|(index, backend)| {
            backend
                .id()
                .map(|id| (id, (index, backend.address(), backend.desired_state())))
        })
        .collect();
    current
        .iter()
        .map(|backend| {
            backend
                .id()
                .and_then(|id| old.get(id))
                .filter(|(_, address, state)| {
                    *address == backend.address() && *state == backend.desired_state()
                })
                .map(|(index, _, _)| *index)
        })
        .collect()
}

fn prepare_http_balancer(
    route: &HttpRoute,
    previous: Option<&Snapshot>,
    trust: &std::collections::HashMap<String, [u8; 32]>,
) -> std::sync::Arc<crate::balance::Balancer> {
    let named = named_backends(&route.backends);
    let mut balance = route.balance.clone();
    if named && route.backends.iter().any(|backend| backend.weight() != 1) {
        balance.weights = route
            .backends
            .iter()
            .map(|backend| backend.weight())
            .collect();
    }
    if let Some(snapshot) = previous
        && let Some(old) = snapshot
            .http
            .iter()
            .find(|runtime| runtime.route.id == route.id)
    {
        let transport_matches = old.route.enabled == route.enabled
            && old.route.upstream == route.upstream
            && snapshot.upstream_trust.get(&route.id) == trust.get(&route.id);
        if old.route.backends == route.backends
            && old.route.balance == route.balance
            && transport_matches
        {
            return old.balancer.clone();
        }
        if named && named_backends(&old.route.backends) && transport_matches {
            return std::sync::Arc::new(crate::balance::Balancer::with_member_states(
                balance,
                Some(&old.balancer),
                &stable_backend_mapping(&route.backends, &old.route.backends),
                &route
                    .backends
                    .iter()
                    .map(|backend| backend.desired_state())
                    .collect::<Vec<_>>(),
            ));
        }
    }
    if !named {
        return std::sync::Arc::new(crate::balance::Balancer::new(balance, route.backends.len()));
    }
    std::sync::Arc::new(crate::balance::Balancer::with_member_states(
        balance,
        None,
        &[],
        &route
            .backends
            .iter()
            .map(|backend| backend.desired_state())
            .collect::<Vec<_>>(),
    ))
}

impl Snapshot {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        Self::build(config, None, EnvPolicy::Strict)
    }
    pub fn replace(config: Config, previous: &Self) -> anyhow::Result<Self> {
        Self::build(config, Some(previous), EnvPolicy::Strict)
    }
    /// Like [`Self::replace`] for passive paths (shared-store polls, file
    /// reloads): a route whose static-header variable is unusable on this
    /// node activates fail-closed instead of rejecting the whole snapshot.
    pub fn replace_follower(config: Config, previous: &Self) -> anyhow::Result<Self> {
        Self::build(config, Some(previous), EnvPolicy::FailClosed)
    }
    /// Reset runtime/cache history while still retiring the replaced generation
    /// at publication. Used when attaching to a fresh authority epoch.
    pub fn replace_fresh(config: Config, previous: &Self) -> anyhow::Result<Self> {
        Self::replace_fresh_with(config, previous, EnvPolicy::Strict)
    }
    /// [`Self::replace_fresh`] for a passive attachment (fail-closed routes).
    pub fn replace_fresh_follower(config: Config, previous: &Self) -> anyhow::Result<Self> {
        Self::replace_fresh_with(config, previous, EnvPolicy::FailClosed)
    }
    fn replace_fresh_with(
        config: Config,
        previous: &Self,
        policy: EnvPolicy,
    ) -> anyhow::Result<Self> {
        config.validate_transition_from(&previous.config)?;
        let mut next = Self::build(config, None, policy)?;
        if next.config.geoip_database == previous.config.geoip_database {
            next.geoip = previous.geoip.clone();
        }
        next.native_predecessors = previous
            .http
            .iter()
            .filter_map(|route| route.native_resource.clone())
            .collect();
        next.retired_members = previous.retired_members.clone();
        next.retirements = std::sync::Mutex::new(Some(next.retirements_from(previous)?));
        Ok(next)
    }

    fn retirements_from(&self, previous: &Self) -> anyhow::Result<PublicationRetirements> {
        use crate::retired_members::{Counter, Record};
        let mut records = Vec::new();
        let successors: std::collections::HashMap<_, _> = self
            .http
            .iter()
            .map(|next| (next.route.id.as_str(), next.balancer.as_ref()))
            .collect();
        for old in &previous.http {
            for counter in old
                .balancer
                .retirements(successors.get(old.route.id.as_str()).copied())
            {
                let backend = &old.route.backends[counter.index()];
                records.push(Record {
                    protocol: "http",
                    route_id: old.route.id.clone(),
                    member_id: backend.id().map(str::to_owned),
                    address: backend.address().to_owned(),
                    counter: Counter::Http(counter),
                });
            }
        }
        let old_routes: std::collections::HashMap<_, _> = previous
            .config
            .tcp
            .iter()
            .map(|route| (route.id.as_str(), route))
            .collect();
        for (route, gates) in &previous.tcp_member_admissions {
            let successor = self.tcp_member_admissions.get(route);
            for (index, old) in gates.iter().enumerate() {
                if successor
                    .is_some_and(|gates| gates.iter().any(|next| std::sync::Arc::ptr_eq(old, next)))
                {
                    continue;
                }
                let backend = &old_routes[route.as_str()].backends[index];
                records.push(Record {
                    protocol: "tcp",
                    route_id: route.clone(),
                    member_id: backend.id().map(str::to_owned),
                    address: backend.address().to_owned(),
                    counter: Counter::Tcp(old.clone()),
                });
            }
        }
        let reservation = self.retired_members.reserve(records.len())?;
        Ok(PublicationRetirements {
            reservation,
            records,
        })
    }

    /// Side effects that belong to publication, not preparation: call once
    /// immediately before this snapshot becomes visible. Idempotent.
    /// Enabled routes that fail closed because this node lacks a static
    /// authorization header variable, as `(route id, variable name)`.
    pub fn unavailable_authorization(&self) -> Vec<(&str, &str)> {
        self.http
            .iter()
            .filter_map(|runtime| {
                runtime
                    .auth_unavailable
                    .as_ref()
                    .map(|unavailable| (runtime.route.id.as_str(), unavailable.variable.as_str()))
            })
            .collect()
    }
    pub fn activated(&self) {
        // Keep the lock through retirement: concurrent idempotent callers must
        // not return while another caller is still closing predecessor gates.
        let mut retirements = self
            .retirements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for binding in &self.native_predecessors {
            binding.retire();
        }
        if let Some(plan) = retirements.take() {
            plan.reservation.commit(plan.records);
        }
        if let (Some(runtime), Some(settings)) = (&self.cache, &self.config.cache) {
            runtime.adopt_generation(settings.generation);
        }
    }
    fn build(config: Config, previous: Option<&Self>, policy: EnvPolicy) -> anyhow::Result<Self> {
        config.validate()?;
        if let Some(previous) = previous {
            config.validate_transition_from(&previous.config)?;
        }
        let mut settings = PreparedSettings::prepare(&config.settings)?;
        settings.path_rate_limits = crate::path_rate_limits::prepare(
            config.settings.path_rate_limits.as_deref().unwrap_or(&[]),
            previous
                .map(|old| old.settings.path_rate_limits.as_slice())
                .unwrap_or(&[]),
        );
        settings.path_failure_bans = crate::path_failure_bans::prepare(
            config.settings.path_failure_bans.as_deref().unwrap_or(&[]),
            previous
                .map(|old| old.settings.path_failure_bans.as_slice())
                .unwrap_or(&[]),
        );
        settings.security_redis = match &config.settings.security_redis {
            Some(redis) => previous
                .filter(|old| old.config.settings.security_redis.as_ref() == Some(redis))
                .and_then(|old| old.settings.security_redis.clone())
                .map(Ok)
                .unwrap_or_else(|| crate::security_redis::Backend::new(redis.clone()))
                .map(Some)?,
            None => None,
        };
        let settings = std::sync::Arc::new(settings);
        let geoip = config
            .geoip_database
            .as_ref()
            .map(|source| {
                previous
                    .filter(|old| old.config.geoip_database.as_ref() == Some(source))
                    .and_then(|old| old.geoip.clone())
                    .map(Ok)
                    .unwrap_or_else(|| crate::geoip_runtime::Slot::new(source.clone()))
            })
            .transpose()?;
        let http_match_headers = config
            .http
            .iter()
            .filter(|route| route.enabled)
            .flat_map(|route| route.headers.keys())
            .map(|name| {
                name.parse::<hyper::header::HeaderName>()
                    .expect("validated HTTP match header")
            })
            .collect();
        let PreparedUpstreamTls {
            configs: upstream_tls,
            trust: upstream_trust,
        } = config.prepare_upstream_tls_with_trust()?;
        let mut regexes = config.prepare_host_regexes()?;
        let admissions: std::collections::HashMap<_, _> = config
            .http
            .iter()
            .map(|r| &r.id)
            .chain(config.tcp.iter().map(|r| &r.id))
            .map(|id| {
                let counter = previous
                    .and_then(|old| old.admissions.get(id))
                    .cloned()
                    .unwrap_or_default();
                (id.clone(), counter)
            })
            .collect();
        let mut jwt_runtimes = std::collections::HashMap::new();
        for jwt in config
            .http
            .iter()
            .filter_map(|route| route.jwt_auth.as_ref())
        {
            let key = serde_json::to_vec(jwt)?;
            if let std::collections::hash_map::Entry::Vacant(entry) = jwt_runtimes.entry(key) {
                let previous_runtime = previous
                    .into_iter()
                    .flat_map(|old| old.http.iter())
                    .find(|old| old.route.jwt_auth.as_ref() == Some(jwt))
                    .and_then(|old| old.jwt_auth.clone());
                entry.insert(match previous_runtime {
                    Some(runtime) => runtime,
                    None => std::sync::Arc::new(crate::jwt_runtime::Runtime::new(jwt.clone())?),
                });
            }
        }
        let jwt_routes = config
            .http
            .iter()
            .filter(|route| route.enabled && route.jwt_auth.is_some())
            .map(|route| {
                let old = previous
                    .and_then(|snapshot| snapshot.jwt_routes.get(&route.id))
                    .filter(|old| old.as_ref() == route);
                (
                    route.id.clone(),
                    old.cloned()
                        .unwrap_or_else(|| std::sync::Arc::new(route.clone())),
                )
            })
            .collect();
        let mut workload_routes = std::collections::HashMap::new();
        for route in config
            .http
            .iter()
            .filter(|route| route.enabled && route.workload_auth.is_some())
        {
            let old = previous
                .and_then(|snapshot| snapshot.workload_routes.get(&route.id))
                .filter(|runtime| runtime.matches_route(route));
            let runtime = match old {
                Some(runtime) => runtime.clone(),
                None => std::sync::Arc::new(crate::workload_auth::Runtime::new(route)?),
            };
            workload_routes.insert(route.id.clone(), runtime);
        }
        let workload_identity_headers: Vec<hyper::header::HeaderName> = config
            .http
            .iter()
            .filter_map(|route| route.workload_auth.as_ref()?.identity_header.as_ref())
            .map(|name| {
                name.parse::<hyper::header::HeaderName>()
                    .expect("validated workload identity header")
            })
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        let authentication_identity_headers: Vec<hyper::header::HeaderName> =
            authentication_identity_headers(&config.http)?
                .into_iter()
                .map(|name| {
                    name.parse()
                        .expect("validated authentication identity header")
                })
                .collect();
        let mut auth_static_headers = std::collections::HashMap::new();
        let mut auth_unavailable = std::collections::HashMap::new();
        let mut native_clients = std::collections::HashMap::new();
        for route in config.http.iter().filter(|route| route.enabled) {
            if let Some(auth) = &route.auth {
                match resolve_static_request_headers(auth) {
                    Ok(resolved) => {
                        if let Some(native) = &auth.native {
                            let key = resolved
                                .iter()
                                .find(|(n, _)| n.as_str() == "x-hopae-gateway-key")
                                .expect("validated native caller key")
                                .1
                                .clone();
                            let reused = previous
                                .and_then(|old| {
                                    old.http.iter().find(|r| {
                                        r.route.id == route.id
                                            && r.route.auth.as_ref() == Some(auth)
                                            && r.auth_static_headers == resolved
                                    })
                                })
                                .and_then(|r| r.auth_native.clone());
                            let client = match reused {
                                Some(client) => client,
                                None => std::sync::Arc::new(
                                    crate::hopae_native::Client::from_config(native, key)?,
                                ),
                            };
                            native_clients.insert(route.id.clone(), client);
                        }
                        auth_static_headers.insert(route.id.clone(), resolved);
                    }
                    Err(error) => {
                        let unavailable = error.downcast_ref::<StaticHeaderEnvError>();
                        match (policy, unavailable) {
                            (EnvPolicy::FailClosed, Some(failure)) => {
                                tracing::warn!(
                                    route = %route.id,
                                    variable = %failure.variable,
                                    "route authorization unavailable on this node; the route fails closed with 503"
                                );
                                auth_unavailable.insert(
                                    route.id.clone(),
                                    AuthUnavailable {
                                        variable: failure.variable.clone(),
                                    },
                                );
                            }
                            _ => {
                                return Err(anyhow::anyhow!(
                                    "route {} external authorization: {error:#}",
                                    route.id
                                ));
                            }
                        }
                    }
                }
            }
        }
        let mut native_bindings = std::collections::HashMap::new();
        for route in &config.http {
            if let Some(native) = route
                .auth
                .as_ref()
                .and_then(|auth| auth.native_resource.as_ref())
            {
                let binding = native.compile_for_route(
                    route
                        .resource_policy
                        .as_ref()
                        .unwrap()
                        .pumgye_resource
                        .as_ref()
                        .unwrap()
                        .clone(),
                    route,
                    config.revision,
                )?;
                if let Some(transport) = native_clients.get(&route.id) {
                    binding.prepare_transport(transport)?;
                }
                native_bindings.insert(route.id.clone(), std::sync::Arc::new(binding));
            }
        }
        let mut http: Vec<std::sync::Arc<HttpRuntime>> = config
            .http
            .iter()
            .cloned()
            .map(|route| {
                let basic_auth = route
                    .basic_auth
                    .as_ref()
                    .map(crate::basic_auth::prepare)
                    .transpose()
                    .expect("validated basic-auth credentials");
                let jwt_auth = route.jwt_auth.as_ref().map(|jwt| {
                    jwt_runtimes[&serde_json::to_vec(jwt).expect("serializable JWT policy")].clone()
                });
                let workload_auth = workload_routes.get(&route.id).cloned();
                let auth_reserved = basic_auth
                    .iter()
                    .flat_map(|auth| auth.reserved_headers().iter())
                    .chain(
                        jwt_auth
                            .iter()
                            .flat_map(|auth| auth.reserved_headers().iter()),
                    )
                    .chain(authentication_identity_headers.iter())
                    .chain(
                        workload_auth
                            .iter()
                            .flat_map(|auth| auth.reserved_headers().iter()),
                    )
                    .cloned()
                    .collect();
                std::sync::Arc::new(HttpRuntime {
                    host_regex: regexes.http.remove(&route.id),
                    jwt_auth,
                    workload_auth,
                    auth_reserved,
                    auth_static_headers: auth_static_headers.remove(&route.id).unwrap_or_default(),
                    auth_unavailable: auth_unavailable.remove(&route.id),
                    auth_native: native_clients.remove(&route.id),
                    native_resource: native_bindings.remove(&route.id),
                    admission: admissions[&route.id].clone(),
                    balancer: prepare_http_balancer(&route, previous, &upstream_trust),
                    request_transform: route.request_transform.clone().map(std::sync::Arc::new),
                    response_transform: route.response_transform.clone().map(std::sync::Arc::new),
                    basic_auth,
                    language_policy: route
                        .language_policy
                        .as_ref()
                        .map(|policy| policy.compile().expect("validated language policy")),
                    country_policy: route
                        .country_policy
                        .as_ref()
                        .map(|policy| policy.compile().expect("validated country policy")),
                    cache_fingerprint: {
                        use sha2::Digest;
                        format!(
                            "{:x}",
                            sha2::Sha256::digest(
                                serde_json::to_vec(&route).expect("serializable route")
                            )
                        )
                    },
                    route,
                })
            })
            .collect();
        http.sort_by_key(|runtime| std::cmp::Reverse(runtime.route.priority));
        let http_route_indices = http
            .iter()
            .enumerate()
            .map(|(index, runtime)| (runtime.route.id.clone(), index))
            .collect();
        let previous_tcp_routes: std::collections::HashMap<_, _> = previous
            .into_iter()
            .flat_map(|old| old.config.tcp.iter())
            .map(|route| (route.id.as_str(), route))
            .collect();
        let tcp_member_activity = config
            .tcp
            .iter()
            .map(|route| {
                let old = previous.and_then(|snapshot| {
                    Some((
                        previous_tcp_routes
                            .get(route.id.as_str())?
                            .backends
                            .as_slice(),
                        snapshot.tcp_member_activity.get(&route.id)?.as_ref(),
                    ))
                });
                (
                    route.id.clone(),
                    std::sync::Arc::new(crate::tcp_member::TcpMemberActivity::new(
                        &route.backends,
                        old,
                    )),
                )
            })
            .collect();
        let tcp_member_admissions = config
            .tcp
            .iter()
            .map(|route| {
                let compatible = previous_tcp_routes.get(route.id.as_str()).filter(|old| {
                    old.enabled == route.enabled
                        && old.upstream == route.upstream
                        && old.health == route.health
                        && previous.is_some_and(|snapshot| {
                            snapshot.upstream_trust.get(&route.id) == upstream_trust.get(&route.id)
                        })
                });
                let mapping = match compatible {
                    Some(old)
                        if named_backends(&route.backends) && named_backends(&old.backends) =>
                    {
                        stable_backend_mapping(&route.backends, &old.backends)
                    }
                    Some(old) if old.backends == route.backends => {
                        (0..route.backends.len()).map(Some).collect()
                    }
                    _ => vec![None; route.backends.len()],
                };
                let old =
                    previous.and_then(|snapshot| snapshot.tcp_member_admissions.get(&route.id));
                let gates = mapping
                    .into_iter()
                    .enumerate()
                    .map(|(current_index, index)| {
                        index
                            .and_then(|index| old.and_then(|gates| gates.get(index)))
                            .cloned()
                            .unwrap_or_else(|| {
                                let gate = crate::member_admission::MemberAdmission::serving();
                                if route.backends[current_index].desired_state()
                                    != crate::pool_member::DesiredState::Serving
                                {
                                    gate.retire();
                                }
                                std::sync::Arc::new(gate)
                            })
                    })
                    .collect();
                (route.id.clone(), gates)
            })
            .collect();
        let mut tcp_health = std::collections::HashMap::new();
        for route in &config.tcp {
            let Some(health) = &route.health else {
                continue;
            };
            let old_route = previous_tcp_routes.get(route.id.as_str()).copied();
            let compatible = old_route.is_some_and(|old| {
                old.upstream == route.upstream
                    && old.enabled == route.enabled
                    && previous.is_some_and(|old| {
                        old.upstream_trust.get(&route.id) == upstream_trust.get(&route.id)
                    })
            });
            let old_health = previous.and_then(|old| old.tcp_health.get(&route.id));
            let state = match (old_route, old_health) {
                (Some(old), Some(state))
                    if compatible
                        && old.backends == route.backends
                        && old.health == route.health =>
                {
                    state.clone()
                }
                (Some(old), Some(state))
                    if compatible
                        && named_backends(&old.backends)
                        && named_backends(&route.backends) =>
                {
                    std::sync::Arc::new(crate::tcp_health::TcpHealth::with_reused_nodes(
                        health.clone(),
                        state,
                        &stable_backend_mapping(&route.backends, &old.backends),
                    ))
                }
                _ => std::sync::Arc::new(crate::tcp_health::TcpHealth::new(
                    health.clone(),
                    route.backends.len(),
                )),
            };
            tcp_health.insert(route.id.clone(), state);
        }
        let cache = config
            .cache
            .as_ref()
            .filter(|settings| settings.enabled)
            .map(|settings| {
                // The runtime (and its disk store) survives a change of the
                // invalidation generation alone: the generation is adopted in
                // place by `activated` once this snapshot is published — never
                // during preparation, which may still fail — discarding both
                // tiers on this instance exactly as a local purge would while the
                // shared document carries it to every other instance. Any other
                // cache change builds a fresh runtime.
                previous
                    .filter(|old| {
                        old.config
                            .cache
                            .as_ref()
                            .is_some_and(|old| old.runtime_compatible(settings))
                    })
                    .and_then(|old| old.cache.clone())
                    .unwrap_or_else(|| crate::cache::CacheRuntime::new(settings.clone()))
            });
        let mut tcp_inbound_tls = std::collections::HashMap::new();
        let mut inbound_material: std::collections::HashMap<
            Vec<u8>,
            std::sync::Arc<crate::workload_material::Slot>,
        > = std::collections::HashMap::new();
        for route in config.tcp.iter().filter(|route| route.enabled) {
            let Some(policy) = &route.inbound_tls else {
                continue;
            };
            // Reuse the live slot for an unchanged binding. File generations
            // are owned by the watcher, never rolled back by a prepared config.
            if let Some(old) = previous
                .filter(|old| {
                    old.config.tcp.iter().any(|prior| {
                        prior.id == route.id
                            && prior.enabled
                            && prior.listen == route.listen
                            && prior.inbound_tls == route.inbound_tls
                    })
                })
                .and_then(|old| old.tcp_inbound_tls.get(&route.id))
            {
                tcp_inbound_tls.insert(route.id.clone(), old.clone());
                continue;
            }
            // Validate candidates now, but new slots stay closed until the
            // watcher verifies material after their active publication.
            let policy_key = serde_json::to_vec(policy)?;
            let prepared = match inbound_material.entry(policy_key) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.get().clone(),
                std::collections::hash_map::Entry::Vacant(entry) => entry
                    .insert(std::sync::Arc::new(crate::workload_material::Slot::new(
                        policy.clone(),
                        std::sync::Arc::new(crate::workload_tls::Prepared::load(policy)?),
                        false,
                    )))
                    .clone(),
            };
            // Identical new TCP policies share one live verification slot,
            // bounding periodic PEM reads by material sets rather than routes.
            tcp_inbound_tls.insert(route.id.clone(), prepared);
        }
        let mut http_workload_tls = std::collections::HashMap::new();
        for listener in config
            .workload_http
            .iter()
            .filter(|listener| listener.enabled)
        {
            if let Some(old) = previous
                .filter(|old| {
                    old.config.workload_http.iter().any(|prior| {
                        prior.enabled
                            && prior.id == listener.id
                            && prior.listen == listener.listen
                            && prior.tls == listener.tls
                    })
                })
                .and_then(|old| old.http_workload_tls.get(&listener.id))
            {
                http_workload_tls.insert(listener.id.clone(), old.clone());
                continue;
            }
            let mut prepared = crate::workload_tls::Prepared::load(&listener.tls)?;
            std::sync::Arc::make_mut(&mut prepared.server_config).alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            http_workload_tls.insert(
                listener.id.clone(),
                std::sync::Arc::new(crate::workload_material::Slot::new(
                    listener.tls.clone(),
                    std::sync::Arc::new(prepared),
                    true,
                )),
            );
        }
        let certificates = if config.certificates.is_empty() {
            None
        } else {
            Some(
                if let Some(existing) = previous
                    .filter(|old| old.config.certificates == config.certificates)
                    .and_then(|old| old.certificates.clone())
                {
                    existing
                } else {
                    std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(crate::certificates::load(
                        &config.certificates,
                    )?))
                },
            )
        };
        let mut public_http_tls = std::collections::HashMap::new();
        let mut public_http_generations = std::collections::HashMap::new();
        for listener in config
            .public_http
            .iter()
            .filter(|listener| listener.enabled)
        {
            let old = previous
                .filter(|snapshot| {
                    snapshot
                        .config
                        .public_http
                        .iter()
                        .any(|prior| prior.enabled && prior == listener)
                })
                .and_then(|snapshot| snapshot.public_http_generations.get(&listener.id));
            public_http_generations.insert(
                listener.id.clone(),
                old.cloned().unwrap_or_else(|| std::sync::Arc::new(())),
            );
        }
        for listener in config
            .public_http
            .iter()
            .filter(|listener| listener.enabled && !listener.certificates.is_empty())
        {
            let existing = previous
                .filter(|old| {
                    old.config.public_http.iter().any(|prior| {
                        prior.enabled
                            && prior.id == listener.id
                            && prior.listen == listener.listen
                            && prior.certificates == listener.certificates
                    })
                })
                .and_then(|old| old.public_http_tls.get(&listener.id));
            let slot = if let Some(existing) = existing {
                existing.clone()
            } else {
                std::sync::Arc::new(arc_swap::ArcSwap::from_pointee(
                    crate::certificates::load_public(&listener.certificates)?,
                ))
            };
            public_http_tls.insert(listener.id.clone(), slot);
        }
        let pumgye = config
            .pumgye
            .as_ref()
            .map(|policy| policy.compile().map(std::sync::Arc::new))
            .transpose()?;
        let pumgye_remote = if let Some(authority) = &config.pumgye_authority {
            if let Some(old) = previous
                .and_then(|snapshot| snapshot.pumgye_remote.as_ref())
                .filter(|old| &old.config == authority)
            {
                Some(old.clone())
            } else {
                match crate::pumgye::AuthorityRuntime::prepare(authority) {
                    Ok(runtime) => {
                        if let Some(old) =
                            previous.and_then(|snapshot| snapshot.pumgye_remote.as_ref())
                        {
                            runtime.require_revision(old.revision());
                        }
                        Some(runtime)
                    }
                    Err(error) if policy == EnvPolicy::Strict => return Err(error),
                    Err(_) => None,
                }
            }
        } else {
            None
        };
        let mut next = Self {
            pumgye,
            pumgye_remote,
            retirements: Default::default(),
            native_predecessors: previous
                .into_iter()
                .flat_map(|old| old.http.iter())
                .filter_map(|route| route.native_resource.clone())
                .collect(),
            retired_members: previous
                .map(|old| old.retired_members.clone())
                .unwrap_or_default(),
            settings,
            http_match_headers,
            workload_identity_headers,
            authentication_identity_headers,
            workload_routes,
            jwt_routes,
            http_workload_tls,
            public_http_tls,
            public_http_generations,
            sni_regex: regexes.sni,
            upstream_tls,
            upstream_trust,
            tcp_inbound_tls,
            certificates,
            cache,
            geoip,
            config,
            authentication_path_guards: http
                .iter()
                .filter(|runtime| {
                    runtime.route.basic_auth.is_some()
                        || runtime.route.auth.is_some()
                        || runtime.route.jwt_auth.is_some()
                        || runtime.route.workload_auth.is_some()
                        || (runtime.route.path_prefix.is_some()
                            && runtime.route.response_transform.is_some())
                })
                .cloned()
                .collect(),
            resource_guards: http
                .iter()
                .filter(|runtime| {
                    runtime
                        .route
                        .resource_policy
                        .as_ref()
                        .is_some_and(|policy| policy.enforce)
                })
                .cloned()
                .collect(),
            http,
            http_route_indices,
            tcp_health,
            tcp_member_activity,
            tcp_member_admissions,
            admissions,
        };
        if let Some(previous) = previous {
            next.retired_members = previous.retired_members.clone();
            next.retirements = std::sync::Mutex::new(Some(next.retirements_from(previous)?));
        }
        Ok(next)
    }
}

fn authentication_identity_headers(
    routes: &[HttpRoute],
) -> anyhow::Result<std::collections::HashSet<String>> {
    let mut names = std::collections::HashSet::new();
    for route in routes {
        if route
            .auth
            .as_ref()
            .and_then(|auth| auth.native_resource.as_ref())
            .is_some_and(|native| native.observed.is_some())
        {
            // Fixed native outputs remain reserved even when the origin allowlist
            // omits them. Client lookalikes must not become forwarded metadata.
            names.extend(
                [
                    "x-forwarded-user",
                    "x-hopae-aal",
                    "x-hopae-principal-kind",
                    "x-hopae-service-id",
                    "x-hopae-evidence-ttl-ms",
                    "x-hopae-subject",
                    "x-hopae-human-policy-subject",
                    "x-hopae-human-policy-issuer",
                ]
                .into_iter()
                .map(str::to_owned),
            );
        }
        for name in route
            .workload_auth
            .iter()
            .filter_map(|auth| auth.identity_header.as_ref())
            .chain(
                route
                    .jwt_auth
                    .iter()
                    .filter_map(|auth| auth.identity_header.as_ref()),
            )
            .chain(
                route
                    .basic_auth
                    .iter()
                    .filter_map(|auth| auth.identity_header.as_ref()),
            )
            .chain(
                route
                    .auth
                    .iter()
                    .flat_map(|auth| auth.response_headers.iter()),
            )
        {
            names.insert(name.to_ascii_lowercase());
        }
        if let Some(basic) = &route.basic_auth {
            names.extend(
                crate::basic_auth::prepare(basic)?
                    .reserved_headers()
                    .iter()
                    .map(|name| name.as_str().to_owned()),
            );
        }
    }
    ensure!(
        !names.contains("cookie"),
        "cookie cannot be an authentication identity output header"
    );
    Ok(names)
}

impl HttpRoute {
    /// Cookie names removed from the upstream request: the union of the route
    /// field and `auth.strip_request_cookies`.
    pub fn effective_strip_cookies(&self) -> Vec<String> {
        let mut names = self.strip_request_cookies.clone();
        if let Some(auth) = &self.auth {
            for name in &auth.strip_request_cookies {
                if !names.contains(name) {
                    names.push(name.clone());
                }
            }
        }
        names
    }

    /// A route that authenticates or is declared protected and has a path
    /// prefix is scoped case-insensitively unless it says otherwise.
    fn is_path_scoped_protection(&self) -> bool {
        self.path_prefix.is_some()
            && (self.auth.is_some()
                || self.basic_auth.is_some()
                || self.jwt_auth.is_some()
                || self.access_mode == AccessMode::Protected)
    }
    /// Effective ASCII case handling of `path_prefix` for route selection.
    pub fn path_case_insensitive(&self) -> bool {
        match self.path_case {
            Some(PathCase::Insensitive) => true,
            Some(PathCase::Sensitive) => false,
            None => self.is_path_scoped_protection(),
        }
    }
    /// All scripts must compile before a configuration can become active.
    pub fn scripts(&self) -> impl Iterator<Item = &str> {
        self.lua.as_deref().into_iter().chain(
            [&self.request_transform, &self.response_transform]
                .into_iter()
                .flatten()
                .filter_map(|transform| transform.lua.as_deref()),
        )
    }
}

/// Response header names no rule may set or remove, per route or globally
/// (`--remove-response-headers`): framing, hop-by-hop and representation
/// headers whose streaming removal would corrupt the client-visible message
/// (for example dropping `content-encoding` from still-compressed bytes).
/// Case-insensitive.
/// Identity headers a single sign-on authorization service may return under
/// the otherwise reserved `x-forwarded-` prefix.
pub fn is_identity_forwarded_header(name: &str) -> bool {
    matches!(
        name,
        "x-forwarded-user"
            | "x-forwarded-email"
            | "x-forwarded-groups"
            | "x-forwarded-preferred-username"
            | "x-forwarded-access-token"
    )
}

pub fn is_protected_response_header(name: &str) -> bool {
    const PROTECTED: [&str; 9] = [
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "trailer",
        "upgrade",
        "te",
        "content-range",
    ];
    PROTECTED
        .iter()
        .any(|protected| protected.eq_ignore_ascii_case(name))
}

/// A response header a route rule may set/remove: a valid lowercase-insensitive
/// header token that is not a framing or hop-by-hop header (those would corrupt
/// message framing or connection semantics if rewritten streaming).
pub(crate) fn valid_response_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_'
                        | b'.'
                        | b'!'
                        | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'^'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
        && !is_protected_response_header(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn geoip_source(file: &str) -> crate::geoip_runtime::Source {
        crate::geoip_runtime::Source {
            file: file.into(),
            max_file_bytes: 32 * 1024 * 1024,
            max_age_days: 14,
            reload_interval_seconds: 30,
        }
    }

    #[test]
    fn native_resource_requires_protected_enforced_remote_grpc_and_public_pin() {
        use base64::Engine;
        let public = base64::engine::general_purpose::STANDARD.encode(
            ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes(),
        );
        let tls = serde_json::json!({"server_name":"owned.example.test", "ca":"/owned/ca.pem", "certificate":"/owned/client.pem", "key":"/owned/client.key"});
        let document = serde_json::json!({"http":[{
            "id":"orders", "host":"orders.example.test", "path_prefix":"/private",
            "access_mode":"protected", "backends":["http://127.0.0.1:9090"],
            "auth":{"url":"https://owned.example.test/_hopae/verify",
                "native":{"transport":"grpc", "address":"127.0.0.1:9001", "tls":tls},
                "native_resource":{"audience":"orders-api", "issuer_ref":"owned", "key_epoch":1, "public_key":public},
                "request_headers":["authorization"], "response_headers":["x-forwarded-user","x-hopae-aal","x-hopae-principal-kind"],
                "static_request_headers":{"x-hopae-gateway-key":"owned-caller-key-not-a-secret","x-hopae-contract":"1"}},
            "resource_policy":{"resource_id":"orders", "principal":{"source":"external","subject_header":"x-forwarded-user"}, "allow":[],
                "pumgye_resource":{"service_id":"orders", "resource":"db:orders", "actions":{"GET":"select"}}}
        }], "pumgye_authority":{"transport":"grpc", "decision_address":"127.0.0.1:9002", "management_address":"127.0.0.1:9003",
            "tls":tls, "decision_token_env":"PUMGYE_DECISION_TOKEN", "admin_token_env":"PUMGYE_ADMIN_TOKEN"}});
        let valid: Config = serde_json::from_value(document.clone()).unwrap();
        valid.validate().unwrap();
        for (path, replacement) in [
            ("/http/0/access_mode", serde_json::json!("public")),
            ("/http/0/resource_policy/enforce", serde_json::json!(false)),
            ("/http/0/auth/native/transport", serde_json::json!("native")),
            ("/http/0/auth/native/tls", serde_json::Value::Null),
            ("/pumgye_authority/transport", serde_json::json!("native")),
            ("/pumgye_authority/tls", serde_json::Value::Null),
            ("/pumgye_authority", serde_json::Value::Null),
            (
                "/http/0/resource_policy/pumgye_resource",
                serde_json::Value::Null,
            ),
            (
                "/http/0/auth/native_resource/public_key",
                serde_json::json!("invalid"),
            ),
        ] {
            let mut bad = document.clone();
            if path.ends_with("/enforce") {
                bad["http"][0]["resource_policy"]["enforce"] = replacement;
            } else {
                *bad.pointer_mut(path).unwrap() = replacement;
            }
            let bad: Config = serde_json::from_value(bad).unwrap();
            assert!(
                bad.validate().is_err(),
                "accepted unsafe native configuration: {path}"
            );
        }
    }

    #[test]
    fn geoip_source_is_optional_validated_without_file_io_and_reuses_only_exact_policy() {
        let mut config = Config::default();
        assert!(
            serde_json::to_value(&config)
                .unwrap()
                .get("geoip_database")
                .is_none()
        );
        assert!(Snapshot::new(config.clone()).unwrap().geoip.is_none());

        config.geoip_database = Some(geoip_source("/not-a-real-geoip.mmdb"));
        let first = Snapshot::new(config.clone()).unwrap();
        let original = first.geoip.as_ref().unwrap();
        assert!(!original.status().ready);
        assert!(original.load().is_none());
        assert_eq!(
            serde_json::from_value::<Config>(serde_json::to_value(&config).unwrap())
                .unwrap()
                .geoip_database,
            config.geoip_database
        );

        let same = Snapshot::replace(config.clone(), &first).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            original,
            same.geoip.as_ref().unwrap()
        ));
        let fresh_authority = Snapshot::replace_fresh(config.clone(), &same).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            original,
            fresh_authority.geoip.as_ref().unwrap()
        ));

        config
            .geoip_database
            .as_mut()
            .unwrap()
            .reload_interval_seconds = 31;
        let changed = Snapshot::replace(config.clone(), &fresh_authority).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            original,
            changed.geoip.as_ref().unwrap()
        ));
        assert!(changed.geoip.as_ref().unwrap().load().is_none());
        let changed_slot = changed.geoip.as_ref().unwrap();

        config.geoip_database = Some(geoip_source("/another-geoip.mmdb"));
        let changed_file = Snapshot::replace(config.clone(), &changed).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            changed_slot,
            changed_file.geoip.as_ref().unwrap()
        ));
        config.geoip_database = None;
        assert!(
            Snapshot::replace(config, &changed_file)
                .unwrap()
                .geoip
                .is_none()
        );
    }

    #[test]
    fn geoip_source_invalid_structure_rejected_even_without_file_read() {
        let mut config = Config {
            geoip_database: Some(geoip_source("relative.mmdb")),
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.geoip_database = Some(geoip_source("/valid-shape.mmdb"));
        config.geoip_database.as_mut().unwrap().max_file_bytes = 0;
        assert!(Snapshot::new(config).is_err());
    }

    #[test]
    fn country_policy_validates_both_protocols_and_compiles_without_database_io() {
        let policy = crate::country_policy::Policy {
            allow: vec!["KR".into()],
            deny: vec![],
            on_unknown: crate::country_policy::UnknownAction::Deny,
            enforce: true,
        };
        let mut config = route();
        config.http[0].country_policy = Some(policy.clone());
        assert!(config.validate().is_err(), "enforced HTTP needs a source");
        config.http[0].enabled = false;
        assert!(config.validate().is_err(), "disabled routes still validate");
        config.geoip_database = Some(geoip_source("/not-a-real-geoip.mmdb"));
        let prepared = Snapshot::new(config.clone()).unwrap();
        assert!(prepared.http[0].country_policy.as_ref().unwrap().enforced());
        assert!(prepared.geoip.as_ref().unwrap().load().is_none());

        let mut tcp: TcpRoute = serde_json::from_str(
            r#"{"id":"tcp","enabled":false,"listen":"127.0.0.1:9009","backends":["127.0.0.1:9010"]}"#,
        )
        .unwrap();
        tcp.country_policy = Some(policy);
        config.tcp.push(tcp);
        assert!(Snapshot::new(config.clone()).is_ok());
        config.geoip_database = None;
        assert!(Snapshot::new(config.clone()).is_err());
        config.http[0].country_policy.as_mut().unwrap().enforce = false;
        config.tcp[0].country_policy.as_mut().unwrap().enforce = false;
        assert!(Snapshot::new(config.clone()).is_ok());
        config.tcp[0].country_policy.as_mut().unwrap().allow = vec!["bad".into()];
        assert!(
            config.validate().is_err(),
            "inactive rules remain validated"
        );
    }

    fn route() -> Config {
        serde_json::from_str(r#"{"http":[{"id":"main","backends":["http://127.0.0.1:8080"]}]}"#)
            .unwrap()
    }
    #[test]
    fn canonical_domain_defaults_and_group_validation_are_strict() {
        let mut config = route();
        config.http[0].hosts = vec!["www.example.test".into(), "example.test".into()];
        config.http[0].canonical_domain = Some(
            serde_json::from_value(serde_json::json!({
                "host":"example.test"
            }))
            .unwrap(),
        );
        config.validate().unwrap();
        let policy = config.http[0].canonical_domain.as_ref().unwrap();
        assert!(policy.enabled);
        assert_eq!(policy.scheme, CanonicalScheme::Https);
        assert_eq!(policy.status, 302);
        assert_eq!(policy.path_prefixes, ["/"]);
        assert_eq!(policy.methods, ["GET", "HEAD"]);

        for invalid in [
            "",
            "*.example.test",
            "foo?.example.test",
            "Example.test",
            "example.test.",
            "example.test:443",
            "other.test",
            "éxample.test",
        ] {
            let mut bad = config.clone();
            bad.http[0].canonical_domain.as_mut().unwrap().host = invalid.into();
            assert!(bad.validate().is_err(), "{invalid:?}");
        }
        let mut ip_group = config.clone();
        ip_group.http[0].hosts.push("192.0.2.1".into());
        ip_group.http[0].canonical_domain.as_mut().unwrap().host = "192.0.2.1".into();
        assert!(
            ip_group.validate().is_err(),
            "canonical target must be a DNS host"
        );
        for status in [200, 303, 426] {
            let mut bad = config.clone();
            bad.http[0].canonical_domain.as_mut().unwrap().status = status;
            assert!(bad.validate().is_err(), "{status}");
        }
        let mut bad = config.clone();
        bad.http[0].canonical_domain.as_mut().unwrap().methods = vec!["POST".into()];
        assert!(bad.validate().is_err());
        bad = config.clone();
        bad.http[0].canonical_domain.as_mut().unwrap().path_prefixes = vec!["wp-login.php".into()];
        assert!(bad.validate().is_err());
        for path in ["/a?b", "/a#b", "/a\\b", "/a b", "/a/../b", "/./a"] {
            let mut bad = config.clone();
            bad.http[0].canonical_domain.as_mut().unwrap().path_prefixes = vec![path.into()];
            assert!(bad.validate().is_err(), "{path:?}");
        }
        bad = config.clone();
        bad.http[0]
            .canonical_domain
            .as_mut()
            .unwrap()
            .exclude_path_prefixes = vec!["/".into()];
        assert!(bad.validate().is_err(), "include/exclude exact conflict");
        bad = config;
        bad.http[0].require_tls = true;
        bad.http[0].canonical_domain.as_mut().unwrap().scheme = CanonicalScheme::Http;
        assert!(
            bad.validate().is_err(),
            "canonical policy cannot downgrade require_tls"
        );
    }
    #[test]
    fn named_public_listener_validation_and_legacy_wire() {
        let mut config = route();
        let wire = serde_json::to_value(&config).unwrap();
        assert!(wire.get("public_http").is_none());
        assert!(wire["http"][0].get("listener_ids").is_none());
        let listener: crate::public_listener_config::Listener =
            serde_json::from_str(r#"{"id":"edge","listen":"127.0.0.1:8443"}"#).unwrap();
        assert!(listener.enabled);
        config.public_http.push(listener.clone());
        config.http[0].listener_ids = vec!["edge".into()];
        config.validate().unwrap();
        config.http[0].listener_ids.push("edge".into());
        assert!(config.validate().is_err());
        config.http[0].listener_ids = vec!["missing".into()];
        assert!(config.validate().is_err());
        config.http[0].listener_ids.clear();
        config.public_http.push(listener.clone());
        assert!(config.validate().is_err());
        config.public_http[1].id = "other".into();
        assert!(config.validate().is_err());
        config.public_http[1].enabled = false;
        config.validate().unwrap();
        config.public_http[1].id = "default".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn protected_scope_cannot_move_between_public_listeners() {
        let mut old = route();
        old.http[0].resource_policy = Some(
            serde_json::from_str(
                r#"{"resource_id":"private","principal":{"source":"basic"},"allow":[]}"#,
            )
            .unwrap(),
        );
        let mut next = old.clone();
        next.http[0].listener_ids = vec!["default".into()];
        next.validate_transition_from(&old).unwrap();
        next.http[0].listener_ids = vec!["edge".into()];
        assert!(next.validate_transition_from(&old).is_err());
        next.http[0].resource_policy.as_mut().unwrap().enforce = false;
        next.validate_transition_from(&old).unwrap_err();
        old.http[0].resource_policy.as_mut().unwrap().enforce = false;
        next.validate_transition_from(&old).unwrap();
    }
    #[test]
    fn public_listener_generation_does_not_revive_after_disable() {
        let mut config = route();
        config
            .public_http
            .push(serde_json::from_str(r#"{"id":"edge","listen":"127.0.0.1:8443"}"#).unwrap());
        let first = Snapshot::new(config.clone()).unwrap();
        let same = Snapshot::replace(config.clone(), &first).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &first.public_http_generations["edge"],
            &same.public_http_generations["edge"]
        ));
        config.public_http[0].enabled = false;
        let disabled = Snapshot::replace(config.clone(), &same).unwrap();
        assert!(!disabled.public_http_generations.contains_key("edge"));
        config.public_http[0].enabled = true;
        let restored = Snapshot::replace(config, &disabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &first.public_http_generations["edge"],
            &restored.public_http_generations["edge"]
        ));
    }
    #[test]
    fn activation_defaults_preserve_legacy_json_and_disabled_policy_round_trips() {
        let mut config = route();
        assert!(config.http[0].enabled);
        assert!(
            serde_json::to_value(&config).unwrap()["http"][0]
                .get("enabled")
                .is_none()
        );
        config.http[0].enabled = false;
        config.http[0]
            .headers
            .insert("x-unused".into(), "match".into());
        config.cache = Some(crate::cache_store::CacheConfig {
            enabled: false,
            ..Default::default()
        });
        let serialized = serde_json::to_vec(&config).unwrap();
        let restored: Config = serde_json::from_slice(&serialized).unwrap();
        assert!(!restored.http[0].enabled);
        assert_eq!(restored.http[0].backends, config.http[0].backends);
        let snapshot = Snapshot::new(restored).unwrap();
        assert!(snapshot.cache.is_none());
        assert!(snapshot.config.cache.is_some());
        assert!(!snapshot.http_match_headers.contains("x-unused"));
        config.cache.as_mut().unwrap().enabled = true;
        assert!(Snapshot::new(config).unwrap().cache.is_some());
    }

    #[test]
    fn access_mode_round_trip_and_authentication_requirement_are_explicit() {
        let mut config = route();
        assert_eq!(config.http[0].access_mode, AccessMode::Legacy);
        assert!(
            serde_json::to_value(&config).unwrap()["http"][0]
                .get("access_mode")
                .is_none()
        );
        assert!(config.validate().is_ok());

        // A disabled protected route must be valid before it can be enabled.
        config.http[0].enabled = false;
        config.http[0].access_mode = AccessMode::Protected;
        config.http[0].lua = Some("hangang.reject(403)".into());
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requires basic_auth or auth")
        );
        let credential = format!("alice:{}:{}", "00".repeat(16), "00".repeat(32));
        config.http[0].basic_auth = Some(BasicAuth {
            realm: "restricted".into(),
            credentials: vec![credential],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: None,
        });
        assert!(config.validate().is_ok());
        let serialized = serde_json::to_value(&config).unwrap();
        assert_eq!(serialized["http"][0]["access_mode"], "protected");
        let restored: Config = serde_json::from_value(serialized).unwrap();
        assert_eq!(restored.http[0].access_mode, AccessMode::Protected);
        assert!(restored.validate().is_ok());

        config.http[0].basic_auth = None;
        assert!(
            config.validate().is_err(),
            "removing the last authenticator must fail"
        );
        for mode in [AccessMode::Public, AccessMode::Application] {
            config.http[0].access_mode = mode;
            assert!(config.validate().is_ok());
            config.http[0].auth = Some(ExternalAuth {
                renew_native_evidence: false,
                native_resource: None,
                native: None,
                url: "http://127.0.0.1:9/check".into(),
                request_headers: vec![],
                response_headers: vec![],
                timeout_ms: 1000,
                forward_response: false,
                terminal_response: false,
                static_request_headers: Default::default(),
                strip_request_cookies: Default::default(),
            });
            assert!(
                config.validate().is_err(),
                "{mode:?} cannot imply gateway auth"
            );
            config.http[0].auth = None;
        }
        assert!(serde_json::from_str::<AccessMode>("\"other\"").is_err());
    }

    #[test]
    fn replacing_protected_route_requires_explicit_downgrade() {
        let mut protected = route();
        protected.http[0].access_mode = AccessMode::Protected;
        protected.http[0].basic_auth = Some(BasicAuth {
            realm: "restricted".into(),
            credentials: vec![format!("alice:{}:{}", "00".repeat(16), "00".repeat(32))],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: None,
        });
        let active = Snapshot::new(protected.clone()).unwrap();

        let mut older_editor = protected.clone();
        older_editor.http[0].access_mode = AccessMode::Legacy;
        older_editor.http[0].basic_auth = None;
        assert!(older_editor.validate().is_ok());
        assert!(
            Snapshot::replace(older_editor.clone(), &active)
                .err()
                .unwrap()
                .to_string()
                .contains("requires explicit access_mode")
        );
        let mut disabled_previous = protected.clone();
        disabled_previous.http[0].enabled = false;
        let disabled_active = Snapshot::new(disabled_previous).unwrap();
        assert!(
            Snapshot::replace(older_editor.clone(), &disabled_active).is_err(),
            "a disabled protected route retains its declared boundary"
        );

        older_editor.http[0].access_mode = AccessMode::Public;
        assert!(Snapshot::replace(older_editor, &active).is_ok());

        let mut removed = protected;
        removed.http.clear();
        assert!(Snapshot::replace(removed, &active).is_ok());
    }

    #[test]
    fn accepts_minimal() {
        assert!(route().validate().is_ok());
    }
    #[test]
    fn unrelated_updates_keep_backend_health_and_load_state() {
        let mut config: Config = serde_json::from_str(
            r#"{"http":[{"id":"main","backends":["http://127.0.0.1:8080","http://127.0.0.1:8081"],
                "balance":{"mode":"least_connections","health":{"failure_threshold":1,"cooldown_ms":60000}}}]}"#,
        )
        .unwrap();
        let first = Snapshot::new(config.clone()).unwrap();
        let balancer = first.http[0].balancer.clone();
        let lease = balancer.acquire(0).unwrap();
        lease.record(false);
        assert!(!balancer.available(0), "backend 0 is quarantined");
        // An unrelated change (a second route) must not reset quarantine or
        // the in-flight lease on the surviving route.
        config.http.push(
            serde_json::from_str(r#"{"id":"other","backends":["http://127.0.0.1:9090"]}"#).unwrap(),
        );
        let second = Snapshot::replace(config.clone(), &first).unwrap();
        let main = second.http.iter().find(|r| r.route.id == "main").unwrap();
        assert!(std::sync::Arc::ptr_eq(&main.balancer, &balancer));
        assert!(!main.balancer.available(0));
        assert_eq!(main.balancer.select(), Some(1));
        drop(lease);
        // Changing the backend set starts fresh state for that route only.
        config.http[0].backends.push("http://127.0.0.1:8082".into());
        let third = Snapshot::replace(config, &second).unwrap();
        let main = third.http.iter().find(|r| r.route.id == "main").unwrap();
        assert!(!std::sync::Arc::ptr_eq(&main.balancer, &balancer));
        assert!(main.balancer.available(0));
    }
    #[test]
    fn checking_requalifies_after_reactivation_or_upstream_transport_change() {
        let mut config = route();
        config.http[0].balance.active_health = Some(crate::balance::ActiveHealthPolicy {
            path: "/ready".into(),
            host: None,
            interval_ms: 3000,
            timeout_ms: 2000,
            healthy_statuses: vec![200],
            unhealthy_statuses: vec![503],
            healthy_successes: 2,
            unhealthy_http_failures: 1,
            unhealthy_tcp_failures: 1,
            unhealthy_timeouts: 1,
            initial_state: crate::balance::InitialHealthState::Checking,
        });
        let first = Snapshot::new(config.clone()).unwrap();
        let original = first.http[0].balancer.clone();
        assert!(!original.available(0));
        original.record_active_status(0, 200);
        assert!(!original.available(0));
        original.record_active_status(0, 200);
        assert!(original.available(0));

        config.http.push(
            serde_json::from_str(r#"{"id":"other","backends":["http://127.0.0.1:9090"]}"#).unwrap(),
        );
        let unrelated = Snapshot::replace(config.clone(), &first).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &unrelated.http[0].balancer,
            &original
        ));
        assert!(unrelated.http[0].balancer.available(0));

        config.http[0].enabled = false;
        let disabled = Snapshot::replace(config.clone(), &unrelated).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &disabled.http[0].balancer,
            &original
        ));
        assert!(!disabled.http[0].balancer.available(0));
        config.http[0].enabled = true;
        let reenabled = Snapshot::replace(config.clone(), &disabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &reenabled.http[0].balancer,
            &disabled.http[0].balancer
        ));
        assert!(!reenabled.http[0].balancer.available(0));

        reenabled.http[0].balancer.record_active_status(0, 200);
        reenabled.http[0].balancer.record_active_status(0, 200);
        assert!(reenabled.http[0].balancer.available(0));
        config.http[0].upstream.connect_address = Some("127.0.0.1:18080".into());
        let new_transport = Snapshot::replace(config, &reenabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &new_transport.http[0].balancer,
            &reenabled.http[0].balancer
        ));
        assert!(!new_transport.http[0].balancer.available(0));
        assert_eq!(
            new_transport.http[0]
                .balancer
                .backend_state(0)
                .unwrap()
                .initial_check_pending,
            Some(true)
        );
    }
    #[test]
    fn healthy_default_never_reuses_observations_from_retired_transport() {
        let config: Config = serde_json::from_value(serde_json::json!({"http":[{
            "id":"pool", "backends":["http://127.0.0.1:8080"],
            "balance":{"active_health":{
                "path":"/ready", "interval_ms":100, "timeout_ms":100,
                "healthy_statuses":[200], "unhealthy_statuses":[503],
                "healthy_successes":1, "unhealthy_http_failures":1,
                "unhealthy_tcp_failures":1, "unhealthy_timeouts":1
            }}
        }]}))
        .unwrap();
        let first = Snapshot::new(config.clone()).unwrap();
        let retired = first.http[0].balancer.clone();
        retired.record_active_status(0, 503);
        assert!(!retired.available(0));

        // A preview must neither mutate live state nor transfer observations
        // from the old transport into the candidate's new transport.
        let mut candidate = config.clone();
        candidate.http[0].upstream.connect_address = Some("127.0.0.1:8081".into());
        let prepared = Snapshot::replace(candidate, &first).unwrap();
        let fresh = &prepared.http[0].balancer;
        assert!(!std::sync::Arc::ptr_eq(&retired, fresh));
        assert!(!retired.available(0));
        assert!(
            fresh.available(0),
            "healthy default remains initially eligible"
        );
        assert_eq!(fresh.backend_state(0).unwrap().probe_observed, Some(false));
        fresh.record_active_status(0, 503);
        retired.record_active_status(0, 200);
        assert!(
            !fresh.available(0),
            "late old success cannot recover new endpoint"
        );
        fresh.record_active_status(0, 200);
        retired.record_active_timeout(0);
        assert!(
            fresh.available(0),
            "late old timeout cannot quarantine new endpoint"
        );

        let mut disabled_config = config.clone();
        disabled_config.http[0].enabled = false;
        let disabled = Snapshot::replace(disabled_config, &first).unwrap();
        let reenabled = Snapshot::replace(config, &disabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &retired,
            &disabled.http[0].balancer
        ));
        assert!(!std::sync::Arc::ptr_eq(
            &disabled.http[0].balancer,
            &reenabled.http[0].balancer
        ));
        assert_eq!(
            reenabled.http[0]
                .balancer
                .backend_state(0)
                .unwrap()
                .probe_observed,
            Some(false)
        );
    }

    #[test]
    fn custom_ca_rotation_requalifies_http_and_tcp_using_prepared_trust() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ca.pem");
        let original_ca =
            rcgen::generate_simple_self_signed(vec!["original.local".into()]).unwrap();
        let rotated_ca = rcgen::generate_simple_self_signed(vec!["rotated.local".into()]).unwrap();
        for (initial_state, named) in [
            ("healthy", false),
            ("checking", false),
            ("healthy", true),
            ("checking", true),
        ] {
            std::fs::write(&path, original_ca.cert.pem()).unwrap();
            let mut config: Config = serde_json::from_value(serde_json::json!({
                "http":[{"id":"web", "backends":["https://127.0.0.1:8080"],
                    "upstream":{"tls":{"ca_file":path}},
                    "balance":{"active_health":{
                        "path":"/ready", "interval_ms":100, "timeout_ms":100,
                        "healthy_statuses":[200], "unhealthy_statuses":[503],
                        "healthy_successes":1, "unhealthy_http_failures":1,
                        "unhealthy_tcp_failures":1, "unhealthy_timeouts":1,
                        "initial_state":initial_state
                    }}
                }],
                "tcp":[{"id":"stream", "listen":"127.0.0.1:19091",
                    "backends":["127.0.0.1:8081"],
                    "upstream":{"tls":{"ca_file":path,"server_name":"origin.local"}},
                    "health":{"interval_ms":100,"timeout_ms":100,
                        "healthy_successes":1,"unhealthy_failures":1,"initial_state":initial_state}
                }]
            }))
            .unwrap();
            if named {
                use crate::pool_member::{Backend, DesiredState, PoolMember};
                for backends in [&mut config.http[0].backends, &mut config.tcp[0].backends] {
                    let address = backends[0].address().to_owned();
                    backends[0] = Backend::Member(PoolMember {
                        id: "first".into(),
                        address: address.clone(),
                        weight: 1,
                        desired_state: DesiredState::Serving,
                    });
                    backends.push(Backend::Member(PoolMember {
                        id: "second".into(),
                        address: address.replace("8080", "9080").replace("8081", "9081"),
                        weight: 1,
                        desired_state: DesiredState::Serving,
                    }));
                }
            }
            let first = Snapshot::new(config.clone()).unwrap();
            let web = &first.http[0].balancer;
            let stream = &first.tcp_health["stream"];
            web.record_active_status(0, 200);
            stream.record_success(0);
            assert!(web.available(0) && stream.available(0));

            // PEM formatting does not change the trust used by rustls.
            std::fs::write(&path, format!("\n{}\n", original_ca.cert.pem())).unwrap();
            let identical = Snapshot::replace(config.clone(), &first).unwrap();
            assert!(std::sync::Arc::ptr_eq(web, &identical.http[0].balancer));
            assert!(std::sync::Arc::ptr_eq(
                stream,
                &identical.tcp_health["stream"]
            ));

            // Same path and unchanged JSON, but new trust: both protocols get
            // fresh observations, without touching live state during preview.
            std::fs::write(&path, rotated_ca.cert.pem()).unwrap();
            if named {
                config.http[0].backends.reverse();
                config.tcp[0].backends.reverse();
            }
            let rotated = Snapshot::replace(config.clone(), &identical).unwrap();
            if named {
                assert_eq!(
                    rotated.http[0]
                        .balancer
                        .backend_state(1)
                        .unwrap()
                        .probe_observed,
                    Some(false)
                );
                assert!(
                    !rotated.tcp_health["stream"]
                        .backend_state(1)
                        .unwrap()
                        .probe_observed
                );
            }

            assert!(!std::sync::Arc::ptr_eq(web, &rotated.http[0].balancer));
            assert!(!std::sync::Arc::ptr_eq(
                stream,
                &rotated.tcp_health["stream"]
            ));
            assert_eq!(
                rotated.http[0]
                    .balancer
                    .backend_state(0)
                    .unwrap()
                    .probe_observed,
                Some(false)
            );
            assert_eq!(
                rotated.http[0].balancer.available(0),
                initial_state == "healthy"
            );
            assert_eq!(
                rotated.tcp_health["stream"].available(0),
                initial_state == "healthy"
            );
            assert!(web.available(0) && stream.available(0));

            std::fs::write(&path, b"invalid CA").unwrap();
            assert!(Snapshot::replace(config, &first).is_err());
            assert!(
                web.available(0) && stream.available(0),
                "failed preparation preserves live health"
            );
        }
    }

    #[test]
    fn checking_accepts_docker_backend_with_epoch_fenced_probes() {
        let mut config = route();
        config.http[0].backends = vec!["docker://api/edge/8080".into()];
        config.http[0].balance.active_health = Some(crate::balance::ActiveHealthPolicy {
            path: "/ready".into(),
            host: None,
            interval_ms: 3000,
            timeout_ms: 2000,
            healthy_statuses: vec![200],
            unhealthy_statuses: vec![503],
            healthy_successes: 1,
            unhealthy_http_failures: 1,
            unhealthy_tcp_failures: 1,
            unhealthy_timeouts: 1,
            initial_state: crate::balance::InitialHealthState::Checking,
        });
        config.validate().unwrap();
        config.http[0]
            .balance
            .active_health
            .as_mut()
            .unwrap()
            .initial_state = crate::balance::InitialHealthState::Healthy;
        assert!(
            config.validate().is_ok(),
            "legacy Docker active-health configuration must remain accepted"
        );
    }
    #[test]
    fn tcp_health_state_reuses_only_identical_routing_and_transport() {
        let mut config = Config::default();
        config.tcp.push(
            serde_json::from_str(
                r#"{"id":"stream","listen":"127.0.0.1:9001","backends":["127.0.0.1:8080"],"health":{"interval_ms":1000,"timeout_ms":500,"healthy_successes":2,"unhealthy_failures":2,"initial_state":"checking"}}"#,
            )
            .unwrap(),
        );
        let first = Snapshot::new(config.clone()).unwrap();
        let health = first.tcp_health["stream"].clone();
        assert!(!health.available(0));
        health.record_success(0);
        health.record_success(0);
        assert!(health.available(0));

        config.settings.allow_dot_segments = Some(false);
        let unrelated = Snapshot::replace(config.clone(), &first).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            &health,
            &unrelated.tcp_health["stream"]
        ));
        assert!(unrelated.tcp_health["stream"].available(0));

        config.tcp[0].upstream.connect_address = Some("127.0.0.1:18080".into());
        let changed_transport = Snapshot::replace(config.clone(), &unrelated).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &health,
            &changed_transport.tcp_health["stream"]
        ));
        assert!(!changed_transport.tcp_health["stream"].available(0));

        config.tcp[0].enabled = false;
        let disabled = Snapshot::replace(config.clone(), &changed_transport).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &changed_transport.tcp_health["stream"],
            &disabled.tcp_health["stream"]
        ));
        config.tcp[0].enabled = true;
        let reenabled = Snapshot::replace(config.clone(), &disabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &disabled.tcp_health["stream"],
            &reenabled.tcp_health["stream"]
        ));
        assert!(!reenabled.tcp_health["stream"].available(0));

        config.tcp[0].backends = vec!["127.0.0.1:8081".into()];
        let new_backend = Snapshot::replace(config.clone(), &reenabled).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &reenabled.tcp_health["stream"],
            &new_backend.tcp_health["stream"]
        ));
        config.tcp[0].health.as_mut().unwrap().healthy_successes = 1;
        let new_policy = Snapshot::replace(config, &new_backend).unwrap();
        assert!(!std::sync::Arc::ptr_eq(
            &new_backend.tcp_health["stream"],
            &new_policy.tcp_health["stream"]
        ));
    }

    #[test]
    fn http_and_tcp_health_targets_share_one_bounded_probe_budget() {
        let mut config = Config::default();
        for index in 0..8 {
            let mut route: TcpRoute = serde_json::from_str(
                r#"{"id":"temporary","enabled":false,"listen":"127.0.0.1:9001","backends":["127.0.0.1:8080"],"health":{"interval_ms":1000,"timeout_ms":500,"healthy_successes":1,"unhealthy_failures":1}}"#,
            )
            .unwrap();
            route.id = format!("tcp-{index}");
            route.backends = vec!["127.0.0.1:8080".into(); 128];
            config.tcp.push(route);
        }
        assert!(config.validate().is_ok(), "1024 TCP probe targets fit");
        let mut http = route().http.remove(0);
        http.balance.active_health = Some(crate::balance::ActiveHealthPolicy {
            path: "/ready".into(),
            host: None,
            interval_ms: 1000,
            timeout_ms: 500,
            healthy_statuses: vec![200],
            unhealthy_statuses: vec![503],
            healthy_successes: 1,
            unhealthy_http_failures: 1,
            unhealthy_tcp_failures: 1,
            unhealthy_timeouts: 1,
            initial_state: crate::balance::InitialHealthState::Healthy,
        });
        config.http.push(http);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("at most 1024 actively probed HTTP/TCP backends")
        );
    }
    #[test]
    fn rejects_invalid_upstream() {
        let mut c = route();
        for uri in [
            "file:///etc/passwd",
            "http://a:bad",
            "http://user@a",
            "http://",
            "ftp://example.com",
        ] {
            c.http[0].backends = vec![uri.into()];
            assert!(c.validate().is_err(), "{uri}");
        }
    }
    #[test]
    fn rejects_duplicate_ids() {
        let mut c = route();
        c.http.push(c.http[0].clone());
        assert!(c.validate().is_err());
    }
    #[test]
    fn rejects_unknown_fields() {
        assert!(serde_json::from_str::<Config>(r#"{"htpt":[]}"#).is_err());
    }
    #[test]
    fn validates_match_fields() {
        let mut c = route();
        c.http[0].json.insert("not-a-pointer".into(), true.into());
        assert!(c.validate().is_err());
        c.http[0].json.clear();
        c.http[0].headers.insert("bad header".into(), "x".into());
        assert!(c.validate().is_err());
    }
    #[test]
    fn rejects_unbounded_configuration() {
        let mut c = route();
        c.http[0].lua = Some("x".repeat(16385));
        assert!(c.validate().is_err());
    }

    #[test]
    fn caps_total_active_probes_across_routes() {
        let mut config = route();
        config.http[0].balance.active_health = Some(crate::balance::ActiveHealthPolicy {
            path: "/ready".into(),
            host: None,
            interval_ms: 3000,
            timeout_ms: 2000,
            healthy_statuses: vec![200],
            unhealthy_statuses: vec![503],
            healthy_successes: 1,
            unhealthy_http_failures: 2,
            unhealthy_tcp_failures: 2,
            unhealthy_timeouts: 2,
            initial_state: crate::balance::InitialHealthState::Healthy,
        });
        let template = config.http[0].clone();
        config.http = (0..8)
            .map(|index| {
                let mut route = template.clone();
                route.id = format!("active-{index}");
                route.backends = vec!["http://127.0.0.1:8080".into(); 128];
                route
            })
            .collect();
        assert!(config.validate().is_ok());
        let mut ninth = template;
        ninth.id = "active-8".into();
        ninth.backends = vec!["http://127.0.0.1:8080".into(); 128];
        config.http.push(ninth);
        assert!(config.validate().is_err());
    }

    #[test]
    fn protected_response_headers_are_recognized_case_insensitively() {
        for name in [
            "content-encoding",
            "Content-Encoding",
            "CONTENT-LENGTH",
            "content-range",
            "transfer-encoding",
            "connection",
        ] {
            assert!(is_protected_response_header(name), "{name}");
        }
        for name in ["server", "Server", "x-powered-by", "etag"] {
            assert!(!is_protected_response_header(name), "{name}");
        }
    }

    #[test]
    fn authentication_outputs_are_reserved_on_other_routes() {
        let mut config = route();
        config.http[0].basic_auth = Some(BasicAuth {
            realm: "restricted".into(),
            credentials: vec![format!("alice:{}:{}", "00".repeat(16), "00".repeat(32))],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: Some("X-Verified-User".into()),
        });
        let mut public = config.http[0].clone();
        public.id = "public".into();
        public.basic_auth = None;
        public.access_mode = AccessMode::Public;
        config.http.push(public);
        assert!(config.validate().is_ok());
        config.http[1]
            .headers
            .insert("x-verified-user".into(), "admin".into());
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("request-header predicate")
        );
        config.http[1].headers.clear();
        let mut transform = crate::transform::BodyTransform::default();
        transform
            .set_headers
            .insert("x-VERIFIED-user".into(), "admin".into());
        config.http[1].request_transform = Some(transform);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("authentication identity header")
        );
    }

    #[test]
    fn rejects_request_transform_touching_authentication_identity_headers() {
        let credential = format!("alice:{}:{}", "00".repeat(16), "00".repeat(32));
        let basic = BasicAuth {
            realm: "restricted".into(),
            credentials: vec![credential],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: Some("x-user".into()),
        };
        let mut set = crate::transform::BodyTransform::default();
        set.set_headers.insert("X-User".into(), "admin".into());
        let mut remove = crate::transform::BodyTransform::default();
        remove.remove_headers.push("x-USER".into());
        let mut unrelated = crate::transform::BodyTransform::default();
        unrelated
            .set_headers
            .insert("x-native".into(), "yes".into());

        // Basic identity: neither setting nor removing it is allowed, in any case.
        for transform in [&set, &remove] {
            let mut c = route();
            c.http[0].basic_auth = Some(basic.clone());
            c.http[0].request_transform = Some(transform.clone());
            assert!(c.validate().is_err());
        }
        // External-auth identity headers are protected the same way.
        let mut c = route();
        c.http[0].auth = Some(ExternalAuth {
            renew_native_evidence: false,
            native_resource: None,
            native: None,
            url: "http://127.0.0.1:9/auth".into(),
            request_headers: vec![],
            response_headers: vec!["x-user".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
            static_request_headers: Default::default(),
            strip_request_cookies: Default::default(),
        });
        c.http[0].request_transform = Some(set.clone());
        assert!(c.validate().is_err());
        // Basic identity and external-auth response_headers naming the same
        // header cannot compose: the identity is stripped before the call.
        let mut c = route();
        c.http[0].basic_auth = Some(basic.clone());
        c.http[0].auth = Some(ExternalAuth {
            renew_native_evidence: false,
            native_resource: None,
            native: None,
            url: "http://127.0.0.1:9/auth".into(),
            request_headers: vec![],
            response_headers: vec!["X-USER".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
            static_request_headers: Default::default(),
            strip_request_cookies: Default::default(),
        });
        assert!(c.validate().is_err());
        // An unrelated header, or the same name on the response transform
        // (a different message), stays valid.
        let mut c = route();
        c.http[0].basic_auth = Some(basic.clone());
        c.http[0].request_transform = Some(unrelated);
        c.http[0].response_transform = Some(set);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn rejects_duplicate_basic_auth_usernames() {
        let mut c = route();
        let credential = format!("alice:{}:{}", "00".repeat(16), "00".repeat(32));
        c.http[0].basic_auth = Some(BasicAuth {
            realm: "restricted".into(),
            credentials: vec![credential.clone(), credential],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: None,
        });
        assert!(c.validate().is_err());
    }

    #[test]
    fn rejects_compatibility_identity_overlapping_external_auth_even_when_null() {
        use base64::Engine;
        let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let credential = format!(
            "v1:sha1-suffix:{}:{}:{}:{}",
            encode(b"alice"),
            encode(b"consumer-id"),
            "00".repeat(20),
            encode(br#"{"X-Consumer-ID":null}"#)
        );
        let mut document = route();
        document.http[0].basic_auth = Some(BasicAuth {
            realm: "restricted".into(),
            credentials: vec![credential],
            hide_credentials: false,
            accept_proxy_authorization: true,
            identity_header: None,
        });
        document.http[0].auth = Some(ExternalAuth {
            renew_native_evidence: false,
            native_resource: None,
            native: None,
            url: "http://127.0.0.1:9/check".into(),
            request_headers: vec![],
            response_headers: vec!["x-consumer-id".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
            static_request_headers: Default::default(),
            strip_request_cookies: Default::default(),
        });
        assert!(document.validate().is_err());
    }

    fn static_auth(headers: serde_json::Value) -> Config {
        let mut config = route();
        config.http[0].auth = Some(
            serde_json::from_value(serde_json::json!({
                "url": "http://127.0.0.1:9/check",
                "request_headers": ["authorization"],
                "response_headers": ["x-user"],
                "static_request_headers": headers,
            }))
            .unwrap(),
        );
        config
    }

    #[test]
    fn static_request_headers_accept_literals_and_env_references() {
        let config = static_auth(serde_json::json!({
            "x-hopae-contract": "1",
            "x-hopae-gateway-key": {"env": "HANGANG_HOPAE_KEY"},
        }));
        config.validate().unwrap();
        // Round trip emits the reference, never a resolved value.
        let text = serde_json::to_string(&config).unwrap();
        assert!(text.contains(r#""x-hopae-gateway-key":{"env":"HANGANG_HOPAE_KEY"}"#));
        assert_eq!(
            serde_json::from_str::<Config>(&text).unwrap().http[0].auth,
            config.http[0].auth
        );
    }

    #[test]
    fn static_request_headers_reject_collisions_and_reserved_names() {
        for name in [
            "authorization", // also listed in request_headers
            "x-user",        // also listed in response_headers
            "x-hangang-auth-terminal",
            "host",
            "content-length",
            "transfer-encoding",
            "proxy-authorization",
            "connection",
            "keep-alive",
            "upgrade",
            "te",
            "trailer",
            "forwarded",
            "x-real-ip",
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-original-uri",
            "x-original-anything",
            "X-Upper",
            "bad name",
            "",
        ] {
            let config = static_auth(serde_json::json!({ name: "v" }));
            assert!(
                config.validate().is_err(),
                "static header name {name:?} must be rejected"
            );
        }
        static_auth(serde_json::json!({"x-ok": "v"}))
            .validate()
            .unwrap();
    }

    #[test]
    fn static_request_headers_enforce_value_and_count_limits() {
        let invalid = [
            serde_json::json!({"x-a": "line\nbreak"}),
            serde_json::json!({"x-a": "a".repeat(1025)}),
            serde_json::json!({"x-a": {"env": "lowercase"}}),
            serde_json::json!({"x-a": {"env": "1STARTS_DIGIT"}}),
            serde_json::json!({"x-a": {"env": ""}}),
            serde_json::json!({"x-a": {"env": "A".repeat(129)}}),
        ];
        for headers in invalid {
            assert!(
                static_auth(headers.clone()).validate().is_err(),
                "{headers}"
            );
        }
        static_auth(serde_json::json!({"x-a": "a".repeat(1024)}))
            .validate()
            .unwrap();
        static_auth(serde_json::json!({"x-a": {"env": "A".repeat(128)}}))
            .validate()
            .unwrap();
        let many = |count: usize| {
            serde_json::Value::Object(
                (0..count)
                    .map(|i| (format!("x-extra-{i}"), serde_json::json!("v")))
                    .collect(),
            )
        };
        static_auth(many(16)).validate().unwrap();
        assert!(static_auth(many(17)).validate().is_err());
        // The object form rejects unknown fields.
        assert!(
            serde_json::from_value::<StaticHeaderValue>(
                serde_json::json!({"env": "A", "extra": 1})
            )
            .is_err()
        );
    }

    #[test]
    fn static_request_headers_resolve_sensitive_values_and_name_only_the_variable() {
        let config = static_auth(serde_json::json!({
            "x-literal": "plain",
            "x-secret": {"env": "HANGANG_TEST_SECRET"},
        }));
        let auth = config.http[0].auth.as_ref().unwrap();
        let resolved = resolve_static_request_headers_with(auth, |name| {
            (name == "HANGANG_TEST_SECRET").then(|| "s3cr3t-value".into())
        })
        .unwrap();
        assert_eq!(resolved.len(), 2);
        let secret = resolved.iter().find(|(n, _)| n == "x-secret").unwrap();
        assert_eq!(secret.1.as_bytes(), b"s3cr3t-value");
        assert!(secret.1.is_sensitive());
        assert!(!format!("{resolved:?}").contains("s3cr3t-value"));
        // Missing, empty and malformed values reject with the variable name.
        for value in [
            None,
            Some(""),
            Some("bad\nvalue-xyz"),
            Some("é\u{1}secret-xyz"),
        ] {
            let error = resolve_static_request_headers_with(auth, |name| {
                (name == "HANGANG_TEST_SECRET")
                    .then(|| value.map(std::ffi::OsString::from))
                    .flatten()
            })
            .unwrap_err();
            let text = format!("{error:#}");
            assert!(text.contains("HANGANG_TEST_SECRET"), "{text}");
            assert!(!text.contains("xyz"), "{text}");
        }
    }

    #[test]
    fn activation_rejects_unset_static_header_variable_and_never_serializes_value() {
        let config = static_auth(serde_json::json!({
            "x-key": {"env": "HANGANG_HC3_DEFINITELY_UNSET"},
        }));
        let error = Snapshot::new(config).err().expect("unset variable rejects");
        assert!(format!("{error:#}").contains("HANGANG_HC3_DEFINITELY_UNSET"));
        // PATH is always present in a test process: use it as the "secret".
        let secret = std::env::var("PATH").unwrap();
        let config = static_auth(serde_json::json!({"x-key": {"env": "PATH"}}));
        let snapshot = Snapshot::new(config).unwrap();
        assert_eq!(snapshot.http[0].auth_static_headers.len(), 1);
        assert!(snapshot.http[0].auth_static_headers[0].1.is_sensitive());
        let dumped = serde_json::to_string(&snapshot.config).unwrap()
            + &serde_json::to_string(&snapshot.http[0].route).unwrap();
        assert!(dumped.contains(r#"{"env":"PATH"}"#));
        assert!(!dumped.contains(&secret));
    }
}

#[cfg(test)]
mod strip_cookie_tests {
    use super::*;

    fn auth_with(names: &[&str]) -> ExternalAuth {
        serde_json::from_value(serde_json::json!({
            "url": "http://127.0.0.1:9/check",
            "strip_request_cookies": names,
        }))
        .unwrap()
    }

    #[test]
    fn accepts_valid_names_and_round_trips() {
        let auth = auth_with(&["__Host-hopae", "__Host-hopae_bind", "Hopae", "hopae"]);
        validate_strip_request_cookies(&auth.strip_request_cookies).unwrap();
        let again: ExternalAuth =
            serde_json::from_str(&serde_json::to_string(&auth).unwrap()).unwrap();
        assert_eq!(again, auth);
        let empty = auth_with(&[]);
        assert!(
            !serde_json::to_string(&empty)
                .unwrap()
                .contains("strip_request_cookies")
        );
    }

    #[test]
    fn rejects_duplicates_bad_names_and_excess() {
        assert!(
            validate_strip_request_cookies(&auth_with(&["a", "a"]).strip_request_cookies).is_err()
        );
        for bad in ["", "a b", "a=b", "a;b", "a,b", "a\"b", "é", "a\tb", "(x)"] {
            assert!(
                validate_strip_request_cookies(&auth_with(&[bad]).strip_request_cookies).is_err(),
                "{bad:?}"
            );
        }
        let long = "a".repeat(129);
        assert!(
            validate_strip_request_cookies(&auth_with(&[long.as_str()]).strip_request_cookies)
                .is_err()
        );
        let ok = "a".repeat(128);
        assert!(
            validate_strip_request_cookies(&auth_with(&[ok.as_str()]).strip_request_cookies)
                .is_ok()
        );
        let names: Vec<String> = (0..17).map(|i| format!("c{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        assert!(validate_strip_request_cookies(&auth_with(&refs).strip_request_cookies).is_err());
        assert!(
            validate_strip_request_cookies(&auth_with(&refs[..16]).strip_request_cookies).is_ok()
        );
    }
}
