//! Bounded remote public-key retrieval for operator-configured JWT issuers.
//!
//! A token's `kid` is only an in-memory lookup key. It never affects a URL.
//! A provider belongs to one prepared configuration generation, so a fetch
//! from an older generation cannot publish keys into a replacement.
use crate::jwt_auth::{JwtAlgorithm, KeyRequest, PreparedKey, PreparedKeys};
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url, redirect};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

const MAX_BODY: usize = 128 * 1024;
const MAX_KEYS: usize = 32;
const MAX_CA_PEM: usize = 128 * 1024;

fn default_ttl() -> u64 {
    300
}
fn default_cooldown() -> u64 {
    10
}
fn default_timeout() -> u64 {
    3_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemoteJwksEndpoint {
    /// Read OIDC metadata from `<issuer>/.well-known/openid-configuration`.
    Oidc,
    /// Explicitly trust a JWKS URL, including a different origin if needed.
    Jwks { url: String },
}

impl<'de> Deserialize<'de> for RemoteJwksEndpoint {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OidcWire {
            kind: String,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct JwksWire {
            kind: String,
            url: String,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Oidc(OidcWire),
            Jwks(JwksWire),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Oidc(OidcWire { kind }) if kind == "oidc" => Ok(Self::Oidc),
            Wire::Jwks(JwksWire { kind, url }) if kind == "jwks" => Ok(Self::Jwks { url }),
            _ => Err(serde::de::Error::custom("invalid remote JWKS endpoint")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteJwksConfig {
    pub endpoint: RemoteJwksEndpoint,
    #[serde(default = "default_ttl")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_cooldown")]
    pub refresh_cooldown_seconds: u64,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// Optional operator-provided PEM trust anchor for a private IdP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

impl RemoteJwksConfig {
    pub fn validate(&self, issuer: &str) -> Result<()> {
        let issuer = trusted_https_url(issuer, "issuer")?;
        ensure!(issuer.query().is_none(), "issuer cannot contain a query");
        if let RemoteJwksEndpoint::Jwks { url } = &self.endpoint {
            trusted_https_url(url, "JWKS URL")?;
        }
        ensure!(
            (1..=3_600).contains(&self.cache_ttl_seconds),
            "JWKS cache TTL must be 1..3600 seconds"
        );
        ensure!(
            (1..=60).contains(&self.refresh_cooldown_seconds)
                && self.refresh_cooldown_seconds <= self.cache_ttl_seconds,
            "JWKS refresh cooldown must be 1..60 seconds and at most the cache TTL"
        );
        ensure!(
            (1..=5_000).contains(&self.timeout_ms),
            "JWKS request timeout must be 1..5000 ms"
        );
        if let Some(pem) = &self.ca_pem {
            ensure!(
                !pem.is_empty() && pem.len() <= MAX_CA_PEM,
                "JWKS CA PEM is empty or too large"
            );
            ensure!(
                !pem.contains("PRIVATE KEY"),
                "JWKS CA PEM cannot contain private material"
            );
            reqwest::Certificate::from_pem(pem.as_bytes()).context("invalid JWKS CA PEM")?;
        }
        Ok(())
    }
}

/// The caller maps `UnknownKey` to invalid token (401) and `Unavailable` to
/// dependency unavailable (503). Error messages contain no URL or key data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteKeyError {
    UnknownKey,
    Unavailable,
}
impl fmt::Display for RemoteKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey => f.write_str("JWT key identifier is not trusted"),
            Self::Unavailable => f.write_str("remote JWT keys are unavailable"),
        }
    }
}
impl std::error::Error for RemoteKeyError {}

struct Cache {
    keys: Option<Arc<PreparedKeys>>,
    expires_at: Instant,
    next_refresh_at: Instant,
    last_refresh_failed: bool,
}

/// Lazy, singleflight remote key source. There is no background task and no
/// unbounded queue of waiters: while one request fetches, others receive 503
/// unless their requested key remains within its hard TTL.
pub struct RemoteJwksProvider {
    config: RemoteJwksConfig,
    issuer: String,
    allowed_algorithms: Vec<JwtAlgorithm>,
    client: Client,
    cache: Mutex<Cache>,
    fetching: AtomicBool,
}

struct FetchGuard<'a>(&'a AtomicBool);
impl Drop for FetchGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl RemoteJwksProvider {
    /// Validates local policy and TLS roots without doing network I/O.
    /// The first key request fetches discovery (if selected) and JWKS.
    pub fn new(
        config: RemoteJwksConfig,
        issuer: &str,
        allowed_algorithms: &[JwtAlgorithm],
    ) -> Result<Self> {
        config.validate(issuer)?;
        ensure!(
            !allowed_algorithms.is_empty() && allowed_algorithms.len() <= 4,
            "remote JWT algorithm list must contain 1..4 values"
        );
        let mut builder = Client::builder()
            .no_proxy()
            .redirect(redirect::Policy::none())
            .https_only(true)
            .timeout(Duration::from_millis(config.timeout_ms))
            .connect_timeout(Duration::from_millis(config.timeout_ms));
        if let Some(pem) = &config.ca_pem {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(pem.as_bytes())?);
        }
        let client = builder.build().context("build remote JWKS HTTPS client")?;
        let now = Instant::now();
        Ok(Self {
            config,
            issuer: issuer.to_owned(),
            allowed_algorithms: allowed_algorithms.to_vec(),
            client,
            cache: Mutex::new(Cache {
                keys: None,
                expires_at: now,
                next_refresh_at: now,
                last_refresh_failed: false,
            }),
            fetching: AtomicBool::new(false),
        })
    }

    pub async fn key(
        &self,
        request: &KeyRequest,
    ) -> std::result::Result<Arc<PreparedKey>, RemoteKeyError> {
        // Restrict attacker-controlled lookup work. No URL is ever formed from
        // this value, including when it is unknown.
        if request.kid.is_empty() || request.kid.len() > 128 {
            return Err(RemoteKeyError::UnknownKey);
        }
        let now = Instant::now();
        {
            let cache = self.cache.lock().map_err(|_| RemoteKeyError::Unavailable)?;
            if now < cache.expires_at
                && let Some(key) = cache
                    .keys
                    .as_ref()
                    .and_then(|keys| keys.get_for(&request.kid, request.algorithm))
            {
                return Ok(key);
            }
            if now < cache.next_refresh_at {
                return Err(if now < cache.expires_at && !cache.last_refresh_failed {
                    RemoteKeyError::UnknownKey
                } else {
                    RemoteKeyError::Unavailable
                });
            }
        }
        if self
            .fetching
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // Recheck in case the winning fetch just completed.
            let cache = self.cache.lock().map_err(|_| RemoteKeyError::Unavailable)?;
            if Instant::now() < cache.expires_at
                && let Some(key) = cache
                    .keys
                    .as_ref()
                    .and_then(|keys| keys.get_for(&request.kid, request.algorithm))
            {
                return Ok(key);
            }
            return Err(RemoteKeyError::Unavailable);
        }
        let _guard = FetchGuard(&self.fetching);
        // Another fetch may have finished between the first check and our CAS.
        {
            let cache = self.cache.lock().map_err(|_| RemoteKeyError::Unavailable)?;
            let now = Instant::now();
            if now < cache.expires_at
                && let Some(key) = cache
                    .keys
                    .as_ref()
                    .and_then(|keys| keys.get_for(&request.kid, request.algorithm))
            {
                return Ok(key);
            }
            if now < cache.next_refresh_at {
                return Err(if now < cache.expires_at && !cache.last_refresh_failed {
                    RemoteKeyError::UnknownKey
                } else {
                    RemoteKeyError::Unavailable
                });
            }
        }
        // Reserve the cooldown before the first await. If the caller cancels
        // this future, the fetch guard drops but the next request cannot
        // immediately start another network operation.
        let fetch_started = Instant::now();
        {
            let mut cache = self.cache.lock().map_err(|_| RemoteKeyError::Unavailable)?;
            cache.next_refresh_at =
                fetch_started + Duration::from_secs(self.config.refresh_cooldown_seconds);
            cache.last_refresh_failed = true;
        }
        let fetch_deadline = fetch_started + Duration::from_secs(self.config.cache_ttl_seconds);
        let fetched = tokio::time::timeout(
            Duration::from_millis(self.config.timeout_ms),
            self.fetch_keys(),
        )
        .await;
        let now = Instant::now();
        let mut cache = self.cache.lock().map_err(|_| RemoteKeyError::Unavailable)?;
        cache.next_refresh_at = now + Duration::from_secs(self.config.refresh_cooldown_seconds);
        match fetched {
            Ok(Ok(keys)) if now < fetch_deadline => {
                cache.expires_at = fetch_deadline;
                cache.keys = Some(keys);
                cache.last_refresh_failed = false;
                cache
                    .keys
                    .as_ref()
                    .and_then(|keys| keys.get_for(&request.kid, request.algorithm))
                    .ok_or(RemoteKeyError::UnknownKey)
            }
            _ => {
                cache.last_refresh_failed = true;
                Err(RemoteKeyError::Unavailable)
            }
        }
    }

    /// Final admission fence after signature and claim verification. A key
    /// selected before expiry or a successful rotation cannot authorize new
    /// work after its cached generation is no longer current.
    pub fn is_current(&self, request: &KeyRequest, key: &Arc<PreparedKey>) -> bool {
        let Ok(cache) = self.cache.lock() else {
            return false;
        };
        Instant::now() < cache.expires_at
            && cache
                .keys
                .as_ref()
                .and_then(|keys| keys.get_for(&request.kid, request.algorithm))
                .is_some_and(|current| Arc::ptr_eq(&current, key))
    }

    async fn fetch_keys(&self) -> Result<Arc<PreparedKeys>> {
        let issuer = trusted_https_url(&self.issuer, "issuer")?;
        let uri = match &self.config.endpoint {
            RemoteJwksEndpoint::Jwks { url } => trusted_https_url(url, "JWKS URL")?,
            RemoteJwksEndpoint::Oidc => {
                let body = fetch_bounded(&self.client, &discovery_url(&issuer)?).await?;
                jwks_from_discovery(&body, &self.issuer, &issuer)?
            }
        };
        let body = fetch_bounded(&self.client, &uri).await?;
        let keys: serde_json::Value = serde_json::from_slice(&body).context("invalid JWKS JSON")?;
        let count = keys
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        ensure!(
            (1..=MAX_KEYS).contains(&count),
            "JWKS key count is outside 1..32"
        );
        let prepared = PreparedKeys::from_jwks_json(&body, &self.allowed_algorithms)?;
        ensure!(!prepared.is_empty(), "JWKS has no usable signing keys");
        Ok(Arc::new(prepared))
    }
}

fn trusted_https_url(raw: &str, what: &str) -> Result<Url> {
    ensure!(raw.len() <= 2048, "{what} is too long");
    let url = Url::parse(raw).with_context(|| format!("invalid {what}"))?;
    ensure!(url.scheme() == "https", "{what} must use HTTPS");
    ensure!(url.host_str().is_some(), "{what} must have a host");
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{what} cannot contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "{what} cannot contain a query or fragment"
    );
    Ok(url)
}

fn discovery_url(issuer: &Url) -> Result<Url> {
    // Url::join would replace the issuer's last path segment.
    trusted_https_url(
        &format!(
            "{}/.well-known/openid-configuration",
            issuer.as_str().trim_end_matches('/')
        ),
        "OIDC discovery URL",
    )
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

fn jwks_from_discovery(body: &[u8], issuer_raw: &str, issuer: &Url) -> Result<Url> {
    let document: DiscoveryDocument =
        serde_json::from_slice(body).context("invalid OIDC discovery JSON")?;
    ensure!(
        document.issuer == issuer_raw,
        "OIDC discovery issuer differs from configured issuer"
    );
    let uri = trusted_https_url(&document.jwks_uri, "discovered JWKS URL")?;
    // OIDC permits a different origin; that requires an explicit operator-
    // pinned JWKS URL here so metadata cannot expand network access.
    ensure!(
        same_origin(issuer, &uri),
        "discovered JWKS URL changes origin"
    );
    Ok(uri)
}

async fn fetch_bounded(client: &Client, url: &Url) -> Result<Vec<u8>> {
    let mut response = client
        .get(url.clone())
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .context("fetch remote key document")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "remote key document returned HTTP {}",
        response.status()
    );
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_BODY as u64,
            "remote key document exceeds size limit"
        );
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read remote key document")? {
        ensure!(
            chunk.len() <= MAX_BODY.saturating_sub(body.len()),
            "remote key document exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn config(endpoint: RemoteJwksEndpoint) -> RemoteJwksConfig {
        RemoteJwksConfig {
            endpoint,
            cache_ttl_seconds: 300,
            refresh_cooldown_seconds: 10,
            timeout_ms: 3000,
            ca_pem: None,
        }
    }

    #[test]
    fn validates_urls_and_preserves_path_issuer() {
        let issuer = "https://issuer.example/tenant/a";
        config(RemoteJwksEndpoint::Oidc).validate(issuer).unwrap();
        assert_eq!(
            discovery_url(&Url::parse(issuer).unwrap())
                .unwrap()
                .as_str(),
            "https://issuer.example/tenant/a/.well-known/openid-configuration"
        );
        for bad in [
            "http://issuer.example",
            "https://user:pass@issuer.example",
            "https://issuer.example/?secret=1",
            "https://issuer.example/#fragment",
        ] {
            assert!(config(RemoteJwksEndpoint::Oidc).validate(bad).is_err());
        }
        assert!(
            config(RemoteJwksEndpoint::Jwks {
                url: "http://jwks.example/keys".into()
            })
            .validate(issuer)
            .is_err()
        );
    }

    #[test]
    fn discovery_pins_exact_issuer_and_origin() {
        let issuer = Url::parse("https://issuer.example/tenant").unwrap();
        let good = br#"{"issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys"}"#;
        assert_eq!(
            jwks_from_discovery(good, issuer.as_str(), &issuer)
                .unwrap()
                .as_str(),
            "https://issuer.example/keys"
        );
        for bad in [
            br#"{"issuer":"https://issuer.example/other","jwks_uri":"https://issuer.example/keys"}"#.as_slice(),
            br#"{"issuer":"https://issuer.example/tenant","jwks_uri":"https://other.example/keys"}"#,
            br#"{"issuer":"https://issuer.example/tenant","jwks_uri":"https://issuer.example/keys?token=x"}"#,
        ] { assert!(jwks_from_discovery(bad, issuer.as_str(), &issuer).is_err()); }
    }

    #[test]
    fn bounds_cache_policy() {
        let mut candidate = config(RemoteJwksEndpoint::Oidc);
        candidate.cache_ttl_seconds = 0;
        assert!(candidate.validate("https://issuer.example").is_err());
        candidate.cache_ttl_seconds = 1;
        assert!(candidate.validate("https://issuer.example").is_err());
        candidate.refresh_cooldown_seconds = 1;
        candidate.validate("https://issuer.example").unwrap();
        candidate.timeout_ms = 5001;
        assert!(candidate.validate("https://issuer.example").is_err());
    }

    #[test]
    fn endpoint_wire_shape_is_explicit_and_closed() {
        let oidc: RemoteJwksConfig =
            serde_json::from_str(r#"{"endpoint":{"kind":"oidc"}}"#).unwrap();
        assert_eq!(oidc.cache_ttl_seconds, 300);
        assert_eq!(oidc.refresh_cooldown_seconds, 10);
        assert_eq!(oidc.timeout_ms, 3000);
        let pinned: RemoteJwksConfig = serde_json::from_str(
            r#"{"endpoint":{"kind":"jwks","url":"https://issuer.example/keys"}}"#,
        )
        .unwrap();
        pinned.validate("https://issuer.example").unwrap();
        for invalid in [
            r#"{"endpoint":{"kind":"oidc","url":"https://issuer.example/keys"}}"#,
            r#"{"endpoint":{"kind":"jwks"}}"#,
            r#"{"endpoint":{"kind":"jwks","url":"https://issuer.example/keys","insecure":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<RemoteJwksConfig>(invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[tokio::test]
    async fn lazy_fetch_rotates_keys_and_expires_closed() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut server = crate::tls::server_config(
            cert.cert.pem().as_bytes(),
            cert.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        server.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!(
            "https://localhost:{}",
            listener.local_addr().unwrap().port()
        );
        let requests = Arc::new(AtomicUsize::new(0));
        let error = Arc::new(AtomicBool::new(false));
        let hold_keys = Arc::new(AtomicBool::new(false));
        let key_delay_ms = Arc::new(AtomicU64::new(0));
        let key_id = Arc::new(Mutex::new("old".to_owned()));
        let task = {
            let issuer = issuer.clone();
            let requests = requests.clone();
            let error = error.clone();
            let hold_keys = hold_keys.clone();
            let key_delay_ms = key_delay_ms.clone();
            let key_id = key_id.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        continue;
                    };
                    let mut request = Vec::new();
                    loop {
                        let mut chunk = [0u8; 1024];
                        let Ok(count) = stream.read(&mut chunk).await else {
                            break;
                        };
                        if count == 0 {
                            break;
                        }
                        request.extend_from_slice(&chunk[..count]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n")
                            || request.len() > 4096
                        {
                            break;
                        }
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let discovery = request.starts_with(b"GET /.well-known/openid-configuration");
                    let id = key_id.lock().unwrap().clone();
                    let public = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
                    let x =
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes());
                    let body = if discovery {
                        format!(r#"{{"issuer":"{issuer}","jwks_uri":"{issuer}/keys"}}"#)
                    } else {
                        format!(
                            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{id}","alg":"EdDSA","use":"sig","x":"{x}"}}]}}"#
                        )
                    };
                    let status = if error.load(Ordering::SeqCst) {
                        "503 Service Unavailable"
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    if !discovery {
                        while hold_keys.load(Ordering::SeqCst) {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        tokio::time::sleep(Duration::from_millis(
                            key_delay_ms.load(Ordering::SeqCst),
                        ))
                        .await;
                    }
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
            })
        };
        let mut spec = config(RemoteJwksEndpoint::Oidc);
        spec.ca_pem = Some(cert.cert.pem());
        spec.cache_ttl_seconds = 1;
        spec.refresh_cooldown_seconds = 1;
        let provider =
            RemoteJwksProvider::new(spec.clone(), &issuer, &[JwtAlgorithm::EdDSA]).unwrap();
        assert_eq!(
            requests.load(Ordering::SeqCst),
            0,
            "construction must not fetch"
        );
        let old = KeyRequest {
            kid: "old".into(),
            algorithm: JwtAlgorithm::EdDSA,
        };
        let (first, competing) = tokio::join!(provider.key(&old), provider.key(&old));
        let old_key = first.ok().or_else(|| competing.ok()).unwrap();
        assert!(provider.is_current(&old, &old_key));
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "competing lookup must share one fetch"
        );
        assert!(provider.key(&old).await.is_ok());
        assert_eq!(
            provider
                .key(&KeyRequest {
                    kid: "unknown".into(),
                    algorithm: JwtAlgorithm::EdDSA
                })
                .await
                .err()
                .unwrap(),
            RemoteKeyError::UnknownKey
        );
        assert_eq!(
            requests.load(Ordering::SeqCst),
            2,
            "unknown kid is cooled down"
        );
        *key_id.lock().unwrap() = "new".into();
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        let new = KeyRequest {
            kid: "new".into(),
            algorithm: JwtAlgorithm::EdDSA,
        };
        let new_key = provider.key(&new).await.unwrap();
        assert!(provider.is_current(&new, &new_key));
        assert!(
            !provider.is_current(&old, &old_key),
            "rotated key loses its admission fence"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 4);

        // Cancel a cold lookup while the JWKS response is held. The cancelled
        // future must leave a cooldown, so a second attacker request cannot
        // immediately start a fresh discovery/JWKS fetch.
        hold_keys.store(true, Ordering::SeqCst);
        let cancelled = Arc::new(
            RemoteJwksProvider::new(spec.clone(), &issuer, &[JwtAlgorithm::EdDSA]).unwrap(),
        );
        let waiting = {
            let cancelled = cancelled.clone();
            let new = new.clone();
            tokio::spawn(async move { cancelled.key(&new).await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while requests.load(Ordering::SeqCst) < 6 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        waiting.abort();
        let _ = waiting.await;
        assert_eq!(
            cancelled.key(&new).await.err().unwrap(),
            RemoteKeyError::Unavailable
        );
        assert_eq!(requests.load(Ordering::SeqCst), 6);
        hold_keys.store(false, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        assert!(cancelled.key(&new).await.is_ok());
        assert_eq!(requests.load(Ordering::SeqCst), 8);

        // The two-request discovery/JWKS budget can finish before the 3-second
        // network timeout but still exceed the one-second cache lifetime.
        // Such a late key is never admitted.
        key_delay_ms.store(1_100, Ordering::SeqCst);
        let late = RemoteJwksProvider::new(spec, &issuer, &[JwtAlgorithm::EdDSA]).unwrap();
        assert_eq!(
            late.key(&new).await.err().unwrap(),
            RemoteKeyError::Unavailable
        );
        key_delay_ms.store(0, Ordering::SeqCst);

        error.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1_050)).await;
        assert_eq!(
            provider.key(&new).await.err().unwrap(),
            RemoteKeyError::Unavailable
        );
        assert!(
            !provider.is_current(&new, &new_key),
            "outage cannot extend hard expiry"
        );
        task.abort();
    }
}
