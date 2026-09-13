use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
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
    #[serde(default)]
    pub http: Vec<HttpRoute>,
    #[serde(default)]
    pub tcp: Vec<TcpRoute>,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Runtime settings that are otherwise command-line only. Every field is
/// optional: `null`/absent means "use the process default".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
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
    #[serde(default, skip_serializing_if = "is_legacy_access_mode")]
    pub access_mode: AccessMode,
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
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub path_match: PathMatch,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAuth {
    pub url: String,
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
        ensure!(
            self.cache_generation_floor <= crate::cache_store::MAX_GENERATION,
            "cache_generation_floor must be 0..4294967295"
        );
        ensure!(
            self.http.len() + self.tcp.len() <= 1024,
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
        let mut ids = HashSet::new();
        for id in self
            .http
            .iter()
            .map(|r| &r.id)
            .chain(self.tcp.iter().map(|r| &r.id))
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
        for r in &self.http {
            match r.access_mode {
                AccessMode::Legacy => {}
                AccessMode::Protected => ensure!(
                    r.basic_auth.is_some() || r.auth.is_some(),
                    "route {} access_mode protected requires basic_auth or auth",
                    r.id
                ),
                AccessMode::Public | AccessMode::Application => ensure!(
                    r.basic_auth.is_none() && r.auth.is_none(),
                    "route {} access_mode public/application conflicts with basic_auth or auth",
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
            if r.balance.active_health.as_ref().is_some_and(|health| {
                health.initial_state == crate::balance::InitialHealthState::Checking
            }) {
                ensure!(
                    !r.backends
                        .iter()
                        .any(|backend| backend.address().starts_with("docker://")),
                    "checking initial health does not support Docker backends"
                );
            }
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
                        !matches!(
                            name.as_str(),
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
                        ) && !name.as_str().starts_with("x-forwarded-")
                            && name != "forwarded",
                        "unsafe authorization header"
                    );
                }
            }
            ensure!(
                !r.backends.is_empty() && r.backends.len() <= 128,
                "route {} needs 1..128 backends",
                r.id
            );
            crate::pool_member::validate_backends(&r.backends, &r.balance.weights)?;
            validate_serving_members(&r.backends)?;
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
        let mut listens = std::collections::HashMap::<_, &TcpRoute>::new();
        let mut sni_hosts = HashSet::new();
        let mut sni_globs = std::collections::HashMap::<std::net::SocketAddr, usize>::new();
        for r in &self.tcp {
            r.upstream.validate()?;
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
            validate_serving_members(&r.backends)?;
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
    /// A document replacing an active snapshot must declare an intentional
    /// downgrade when an existing protected route keeps its ID. Older editors
    /// omit access_mode and authentication fields; serde would otherwise turn
    /// that replacement into an anonymous Legacy route.
    pub fn validate_transition_from(&self, previous: &Self) -> anyhow::Result<()> {
        use anyhow::ensure;
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
}
pub struct Snapshot {
    pub settings: std::sync::Arc<PreparedSettings>,
    /// Header names used by any declarative HTTP route predicate. Incoming
    /// duplicates for these names are rejected before routing so the selected
    /// route and an upstream cannot interpret different values.
    pub http_match_headers: std::collections::HashSet<hyper::header::HeaderName>,
    pub sni_regex: std::collections::HashMap<String, Vec<regex::Regex>>,
    pub upstream_tls: std::collections::HashMap<String, std::sync::Arc<rustls::ClientConfig>>,
    // Fingerprints of the exact custom CA certificates used by prepared TLS.
    // Never re-read files to decide whether health observations may be reused.
    #[doc(hidden)]
    pub upstream_trust: std::collections::HashMap<String, [u8; 32]>,
    pub certificates: Option<std::sync::Arc<arc_swap::ArcSwap<rustls::ServerConfig>>>,
    pub cache: Option<std::sync::Arc<crate::cache::CacheRuntime>>,
    pub config: Config,
    pub admissions:
        std::collections::HashMap<String, std::sync::Arc<std::sync::atomic::AtomicUsize>>,
    pub http: Vec<std::sync::Arc<HttpRuntime>>,
    pub tcp_health: std::collections::HashMap<String, std::sync::Arc<crate::tcp_health::TcpHealth>>,
}
fn named_backends(backends: &[crate::pool_member::Backend]) -> bool {
    backends
        .first()
        .is_some_and(|backend| backend.id().is_some())
}

fn validate_serving_members(backends: &[crate::pool_member::Backend]) -> anyhow::Result<()> {
    anyhow::ensure!(
        backends.iter().all(|backend| match backend {
            crate::pool_member::Backend::Legacy(_) => true,
            crate::pool_member::Backend::Member(member) =>
                member.desired_state == crate::pool_member::DesiredState::Serving,
        }),
        "draining and maintenance members require lifecycle publication support"
    );
    Ok(())
}

fn stable_backend_mapping(
    current: &[crate::pool_member::Backend],
    previous: &[crate::pool_member::Backend],
) -> Vec<Option<usize>> {
    let old: std::collections::HashMap<_, _> = previous
        .iter()
        .enumerate()
        .filter_map(|(index, backend)| backend.id().map(|id| (id, (index, backend.address()))))
        .collect();
    current
        .iter()
        .map(|backend| {
            backend
                .id()
                .and_then(|id| old.get(id))
                .filter(|(_, address)| *address == backend.address())
                .map(|(index, _)| *index)
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
            && (!(named || route.balance.active_health.is_some()) || transport_matches)
        {
            return old.balancer.clone();
        }
        if named && named_backends(&old.route.backends) && transport_matches {
            return std::sync::Arc::new(crate::balance::Balancer::with_reused_nodes(
                balance,
                &old.balancer,
                &stable_backend_mapping(&route.backends, &old.route.backends),
            ));
        }
    }
    std::sync::Arc::new(crate::balance::Balancer::new(balance, route.backends.len()))
}

impl Snapshot {
    pub fn new(config: Config) -> anyhow::Result<Self> {
        Self::build(config, None)
    }
    pub fn replace(config: Config, previous: &Self) -> anyhow::Result<Self> {
        Self::build(config, Some(previous))
    }
    /// Side effects that belong to publication, not preparation: call once
    /// right after this snapshot became the active one. Idempotent.
    pub fn activated(&self) {
        if let (Some(runtime), Some(settings)) = (&self.cache, &self.config.cache) {
            runtime.adopt_generation(settings.generation);
        }
    }
    fn build(config: Config, previous: Option<&Self>) -> anyhow::Result<Self> {
        config.validate()?;
        if let Some(previous) = previous {
            config.validate_transition_from(&previous.config)?;
        }
        let settings = std::sync::Arc::new(PreparedSettings::prepare(&config.settings)?);
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
        let mut http: Vec<std::sync::Arc<HttpRuntime>> = config
            .http
            .iter()
            .cloned()
            .map(|route| {
                std::sync::Arc::new(HttpRuntime {
                    host_regex: regexes.http.remove(&route.id),
                    admission: admissions[&route.id].clone(),
                    balancer: prepare_http_balancer(&route, previous, &upstream_trust),
                    request_transform: route.request_transform.clone().map(std::sync::Arc::new),
                    response_transform: route.response_transform.clone().map(std::sync::Arc::new),
                    basic_auth: route
                        .basic_auth
                        .as_ref()
                        .map(crate::basic_auth::prepare)
                        .transpose()
                        .expect("validated basic-auth credentials"),
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
        let previous_tcp_routes: std::collections::HashMap<_, _> = previous
            .into_iter()
            .flat_map(|old| old.config.tcp.iter())
            .map(|route| (route.id.as_str(), route))
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
        Ok(Self {
            settings,
            http_match_headers,
            sni_regex: regexes.sni,
            upstream_tls,
            upstream_trust,
            certificates,
            cache,
            config,
            http,
            tcp_health,
            admissions,
        })
    }
}

impl HttpRoute {
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
fn valid_response_header_name(name: &str) -> bool {
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
    fn route() -> Config {
        serde_json::from_str(r#"{"http":[{"id":"main","backends":["http://127.0.0.1:8080"]}]}"#)
            .unwrap()
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
                url: "http://127.0.0.1:9/check".into(),
                request_headers: vec![],
                response_headers: vec![],
                timeout_ms: 1000,
                forward_response: false,
                terminal_response: false,
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
    fn checking_rejects_docker_backend_until_probe_resolution_is_supported() {
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
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("checking initial health does not support Docker backends")
        );
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
            url: "http://127.0.0.1:9/auth".into(),
            request_headers: vec![],
            response_headers: vec!["x-user".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
        });
        c.http[0].request_transform = Some(set.clone());
        assert!(c.validate().is_err());
        // Basic identity and external-auth response_headers naming the same
        // header cannot compose: the identity is stripped before the call.
        let mut c = route();
        c.http[0].basic_auth = Some(basic.clone());
        c.http[0].auth = Some(ExternalAuth {
            url: "http://127.0.0.1:9/auth".into(),
            request_headers: vec![],
            response_headers: vec!["X-USER".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
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
            url: "http://127.0.0.1:9/check".into(),
            request_headers: vec![],
            response_headers: vec!["x-consumer-id".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
        });
        assert!(document.validate().is_err());
    }
}
