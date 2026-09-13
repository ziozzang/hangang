//! Native ACME certificate issuance and renewal.
//!
//! The module keeps the ACME control plane separate from listeners. The public
//! listener only needs an HttpChallengeStore, while a CertificateSink receives
//! a certificate after the certificate and key have been parsed as one matching
//! TLS configuration.

use crate::config_store::{
    ConfigStore, MAX_CHALLENGE_TTL, MIN_CHALLENGE_TTL, StoreError, StoreResult,
};
use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use hyper::http::{Request, Response, StatusCode, header};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, ExternalAccountKey,
    Identifier, Key, LetsEncrypt, NewAccount, NewOrder, OrderStatus, RetryPolicy, ZeroSsl,
};
use reqwest::Client;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs,
    io::AsyncReadExt,
    sync::{RwLock, watch},
    time::Instant,
};
use tokio_util::sync::CancellationToken;

const MAX_ACCOUNT_FILE: u64 = 1024 * 1024;
const MAX_PEM: usize = 1024 * 1024;
const MAX_JSON_RESPONSE: usize = 1024 * 1024;

fn http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("static ACME HTTP client options are valid")
}

async fn json_bounded<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    use futures_util::StreamExt;
    if let Some(length) = response.content_length() {
        ensure!(
            length <= MAX_JSON_RESPONSE as u64,
            "ACME provider response exceeds 1 MiB"
        );
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        ensure!(
            body.len().saturating_add(chunk.len()) <= MAX_JSON_RESPONSE,
            "ACME provider response exceeds 1 MiB"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice(&body)?)
}

type AcmeHyperClient =
    HyperClient<hyper_rustls::HttpsConnector<HttpConnector>, instant_acme::BodyWrapper<Bytes>>;
struct BoundedAcmeHttpClient(AcmeHyperClient);
impl instant_acme::HttpClient for BoundedAcmeHttpClient {
    fn request(
        &self,
        request: hyper::Request<instant_acme::BodyWrapper<Bytes>>,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<instant_acme::BytesResponse, instant_acme::Error>,
                > + Send,
        >,
    > {
        let client = self.0.clone();
        Box::pin(async move {
            tokio::time::timeout(Duration::from_secs(20), async move {
                let response = client
                    .request(request)
                    .await
                    .map_err(|error| instant_acme::Error::Other(Box::new(error)))?;
                let (parts, body) = response.into_parts();
                let body = http_body_util::Limited::new(body, MAX_JSON_RESPONSE);
                let bytes = body
                    .collect()
                    .await
                    .map_err(instant_acme::Error::Other)?
                    .to_bytes();
                Ok(instant_acme::BytesResponse {
                    parts,
                    body: Box::new(bytes),
                })
            })
            .await
            .map_err(|error| instant_acme::Error::Other(Box::new(error)))?
        })
    }
}

fn acme_http_client(ca_path: Option<&Path>) -> Result<Box<dyn instant_acme::HttpClient>> {
    let mut roots =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_path {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .context("read ACME CA bundle")?
            .take(MAX_PEM as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= MAX_PEM, "ACME CA bundle exceeds 1 MiB");
        let certs = rustls_pemfile::certs(&mut std::io::Cursor::new(bytes))
            .collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "ACME CA bundle is empty");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = HttpsConnectorBuilder::new()
        .with_tls_config(config)
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(Box::new(BoundedAcmeHttpClient(
        HyperClient::builder(TokioExecutor::new()).build(connector),
    )))
}

/// ACME directory selection. Custom directories must use HTTPS.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AcmeDirectory {
    LetsEncryptProduction,
    LetsEncryptStaging,
    ZeroSslProduction,
    Custom(String),
}
impl AcmeDirectory {
    pub fn url(&self) -> Result<String> {
        let url = match self {
            Self::LetsEncryptProduction => LetsEncrypt::Production.url().to_owned(),
            Self::LetsEncryptStaging => LetsEncrypt::Staging.url().to_owned(),
            Self::ZeroSslProduction => ZeroSsl::Production.url().to_owned(),
            Self::Custom(url) => url.clone(),
        };
        ensure!(url.starts_with("https://"), "ACME directory must use HTTPS");
        Ok(url)
    }
}

/// Which ACME authorization challenge to use.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChallengeMode {
    #[default]
    Auto,
    Http01,
    Dns01,
}

/// A ZeroSSL external account binding. The HMAC key may be base64url/base64.
#[derive(Clone)]
pub struct EabConfig {
    pub kid: String,
    pub hmac_key_base64: String,
}
impl fmt::Debug for EabConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EabConfig")
            .field("kid", &self.kid)
            .field("hmac_key_base64", &"[redacted]")
            .finish()
    }
}
impl EabConfig {
    fn key(&self) -> Result<Vec<u8>> {
        URL_SAFE_NO_PAD
            .decode(&self.hmac_key_base64)
            .or_else(|_| STANDARD.decode(&self.hmac_key_base64))
            .context("invalid EAB HMAC key encoding")
    }
}

/// Renewal and polling limits. All waits are cancellation aware.
#[derive(Clone, Debug)]
pub struct RenewalPolicy {
    pub renew_before: Duration,
    pub check_interval: Duration,
    pub retry_initial: Duration,
    pub retry_max: Duration,
    pub acme_timeout: Duration,
}
impl Default for RenewalPolicy {
    fn default() -> Self {
        Self {
            renew_before: Duration::from_secs(30 * 24 * 3600),
            check_interval: Duration::from_secs(24 * 3600),
            retry_initial: Duration::from_secs(5),
            retry_max: Duration::from_secs(5 * 60),
            acme_timeout: Duration::from_secs(10 * 60),
        }
    }
}

/// Engine configuration. This intentionally does not implement Debug because
/// it contains the optional EAB secret and paths to private key material.
#[derive(Clone)]
pub struct AcmeConfig {
    pub directory: AcmeDirectory,
    pub contacts: Vec<String>,
    pub domains: Vec<String>,
    pub challenge: ChallengeMode,
    pub account_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
    pub dns_propagation_timeout: Duration,
    pub dns_poll_interval: Duration,
    pub renewal: RenewalPolicy,
    pub eab: Option<EabConfig>,
    /// Optional CA bundle for a test/private ACME directory. Production
    /// configuration should leave this unset and use the system roots.
    pub ca_path: Option<PathBuf>,
}
impl AcmeConfig {
    pub fn new(domains: Vec<String>, account_path: impl Into<PathBuf>) -> Self {
        Self {
            directory: AcmeDirectory::LetsEncryptProduction,
            contacts: Vec::new(),
            domains,
            challenge: ChallengeMode::Auto,
            account_path: account_path.into(),
            certificate_path: None,
            private_key_path: None,
            dns_propagation_timeout: Duration::from_secs(10 * 60),
            dns_poll_interval: Duration::from_secs(5),
            renewal: RenewalPolicy::default(),
            eab: None,
            ca_path: None,
        }
    }
    fn checked_domains(&self) -> Result<Vec<String>> {
        ensure!(
            !self.domains.is_empty() && self.domains.len() <= 100,
            "ACME requires 1..=100 domains"
        );
        let mut result = Vec::with_capacity(self.domains.len());
        let mut seen = HashSet::new();
        for original in &self.domains {
            let domain = original.trim_end_matches('.').to_ascii_lowercase();
            ensure!(
                !domain.is_empty() && domain.len() <= 253 && domain.is_ascii(),
                "invalid ACME domain"
            );
            let base = domain.strip_prefix("*.").unwrap_or(&domain);
            ensure!(
                !base.is_empty() && base.len() <= 251 && base.parse::<IpAddr>().is_err(),
                "invalid ACME domain"
            );
            ensure!(
                base.split('.').all(|label| !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    && !label.starts_with('-')
                    && !label.ends_with('-')),
                "invalid ACME domain label"
            );
            ensure!(
                !domain.contains('*') || domain.starts_with("*."),
                "wildcard must be first label"
            );
            ensure!(seen.insert(domain.clone()), "duplicate ACME domain");
            result.push(domain);
        }
        let wildcard = result.iter().any(|d| d.starts_with("*."));
        ensure!(
            !(wildcard && self.challenge == ChallengeMode::Http01),
            "wildcard domains require DNS-01"
        );
        Ok(result)
    }
    fn mode(&self, domains: &[String]) -> ChallengeMode {
        if self.challenge == ChallengeMode::Auto && domains.iter().any(|d| d.starts_with("*.")) {
            ChallengeMode::Dns01
        } else if self.challenge == ChallengeMode::Auto {
            ChallengeMode::Http01
        } else {
            self.challenge
        }
    }
    /// Validate the configuration without contacting an ACME or DNS service.
    pub fn validate(&self) -> Result<()> {
        let domains = self.checked_domains()?;
        self.directory.url()?;
        ensure!(
            !self.account_path.as_os_str().is_empty(),
            "ACME account path is empty"
        );
        ensure!(
            !(self.certificate_path.as_ref() == Some(&self.account_path)
                || self.private_key_path.as_ref() == Some(&self.account_path)
                || self.certificate_path.is_some()
                    && self.certificate_path == self.private_key_path),
            "ACME account, certificate, and key paths must be distinct"
        );
        ensure!(
            self.dns_poll_interval > Duration::ZERO
                && self.dns_poll_interval <= Duration::from_secs(5 * 60)
                && self.dns_propagation_timeout > Duration::ZERO
                && self.dns_propagation_timeout <= Duration::from_secs(60 * 60),
            "DNS propagation durations are invalid"
        );
        ensure!(
            self.renewal.check_interval > Duration::ZERO
                && self.renewal.retry_initial > Duration::ZERO
                && self.renewal.retry_max >= self.renewal.retry_initial
                && self.renewal.acme_timeout > Duration::ZERO
                && self.renewal.acme_timeout <= Duration::from_secs(24 * 60 * 60),
            "renewal durations are invalid"
        );
        if matches!(self.directory, AcmeDirectory::ZeroSslProduction) {
            ensure!(self.eab.is_some(), "ZeroSSL requires EAB KID and HMAC key");
        }
        if let Some(eab) = &self.eab {
            ensure!(!eab.kid.trim().is_empty(), "EAB KID is empty");
            ensure!(!eab.key()?.is_empty(), "EAB HMAC key is empty");
        }
        let _ = domains;
        Ok(())
    }
}

/// JSON representation suitable for a mounted runtime configuration file.
/// Durations are expressed in seconds and EAB secrets are never logged by the
/// loader or engine.
#[derive(Clone, Deserialize)]
pub struct AcmeFileConfig {
    pub directory: Option<String>,
    pub contacts: Option<Vec<String>>,
    pub domains: Vec<String>,
    pub challenge: Option<String>,
    pub account_path: PathBuf,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
    pub dns_propagation_timeout_secs: Option<u64>,
    pub dns_poll_interval_secs: Option<u64>,
    pub eab_kid: Option<String>,
    pub eab_hmac_key_base64: Option<String>,
    pub ca_path: Option<PathBuf>,
    pub renew_before_secs: Option<u64>,
    pub check_interval_secs: Option<u64>,
    pub retry_initial_secs: Option<u64>,
    pub retry_max_secs: Option<u64>,
    pub acme_timeout_secs: Option<u64>,
}
impl fmt::Debug for AcmeFileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeFileConfig")
            .field("directory", &self.directory)
            .field("contacts", &self.contacts)
            .field("domains", &self.domains)
            .field("challenge", &self.challenge)
            .field("account_path", &self.account_path)
            .field("certificate_path", &self.certificate_path)
            .field("private_key_path", &self.private_key_path)
            .field("eab_kid", &self.eab_kid)
            .field("eab_hmac_key_base64", &"[redacted]")
            .finish()
    }
}
impl AcmeFileConfig {
    pub fn into_config(self) -> Result<AcmeConfig> {
        let mut config = AcmeConfig::new(self.domains, self.account_path);
        config.directory = match self
            .directory
            .as_deref()
            .unwrap_or("letsencrypt-production")
        {
            "letsencrypt-production" => AcmeDirectory::LetsEncryptProduction,
            "letsencrypt-staging" => AcmeDirectory::LetsEncryptStaging,
            "zerossl-production" => AcmeDirectory::ZeroSslProduction,
            custom if custom.starts_with("https://") => AcmeDirectory::Custom(custom.to_owned()),
            _ => bail!("unknown or insecure ACME directory"),
        };
        config.contacts = self.contacts.unwrap_or_default();
        config.challenge = match self.challenge.as_deref().unwrap_or("auto") {
            "auto" => ChallengeMode::Auto,
            "http-01" => ChallengeMode::Http01,
            "dns-01" => ChallengeMode::Dns01,
            _ => bail!("unknown ACME challenge mode"),
        };
        if let Some(value) = self.dns_propagation_timeout_secs {
            config.dns_propagation_timeout = Duration::from_secs(value);
        }
        if let Some(value) = self.dns_poll_interval_secs {
            config.dns_poll_interval = Duration::from_secs(value);
        }
        if let Some(value) = self.renew_before_secs {
            config.renewal.renew_before = Duration::from_secs(value);
        }
        if let Some(value) = self.check_interval_secs {
            config.renewal.check_interval = Duration::from_secs(value);
        }
        if let Some(value) = self.retry_initial_secs {
            config.renewal.retry_initial = Duration::from_secs(value);
        }
        if let Some(value) = self.retry_max_secs {
            config.renewal.retry_max = Duration::from_secs(value);
        }
        if let Some(value) = self.acme_timeout_secs {
            config.renewal.acme_timeout = Duration::from_secs(value);
        }
        config.certificate_path = self.certificate_path;
        config.private_key_path = self.private_key_path;
        config.ca_path = self.ca_path;
        match (self.eab_kid, self.eab_hmac_key_base64) {
            (None, None) => {}
            (Some(kid), Some(hmac_key_base64)) => {
                config.eab = Some(EabConfig {
                    kid,
                    hmac_key_base64,
                })
            }
            _ => bail!("EAB kid and HMAC key must be configured together"),
        }
        config.domains = config.checked_domains()?;
        config.validate()?;
        Ok(config)
    }
}

/// Read one bounded JSON runtime configuration.
pub async fn load_config_file(path: impl AsRef<Path>) -> Result<AcmeConfig> {
    let bytes = bounded_read(path.as_ref(), 256 * 1024).await?;
    serde_json::from_slice::<AcmeFileConfig>(&bytes)?.into_config()
}

/// Poll a mounted config file and send validated replacements. The receiver
/// starts with the initial config, and the task exits with cancellation.
pub async fn watch_config_file(
    path: impl Into<PathBuf>,
    interval: Duration,
    cancel: CancellationToken,
) -> Result<watch::Receiver<Result<AcmeConfig, String>>> {
    ensure!(
        interval > Duration::ZERO,
        "config poll interval must be positive"
    );
    let path = path.into();
    let initial = load_config_file(&path).await.map_err(|e| e.to_string());
    let (sender, receiver) = watch::channel(initial);
    tokio::spawn(async move {
        let mut previous = bounded_read(&path, 256 * 1024).await.ok();
        loop {
            tokio::select! { _ = cancel.cancelled() => return, _ = tokio::time::sleep(interval) => {} }
            let bytes = match bounded_read(&path, 256 * 1024).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    let _ = sender.send(Err(error.to_string()));
                    continue;
                }
            };
            if previous.as_ref() == Some(&bytes) {
                continue;
            }
            previous = Some(bytes.clone());
            let result = if bytes.len() > 256 * 1024 {
                Err("ACME config exceeds 256 KiB".to_owned())
            } else {
                match serde_json::from_slice::<AcmeFileConfig>(&bytes) {
                    Ok(value) => value.into_config().map_err(|e| e.to_string()),
                    Err(error) => Err(error.to_string()),
                }
            };
            let _ = sender.send(result);
        }
    });
    Ok(receiver)
}

#[derive(Clone, Hash, Eq, PartialEq)]
struct ChallengeKey {
    host: String,
    token: String,
}
/// One installed HTTP-01 response.
struct ChallengeEntry {
    value: String,
    /// Identifies this installation of the key. A keepalive and a failed
    /// insert's rollback act on the entry only while it still carries the
    /// id they were started with, so a replacement installed meanwhile is
    /// never withdrawn or rolled back by its predecessor.
    owner: u64,
    /// Stops the shared-record refresh for this entry (shared mode only).
    keepalive: Option<CancellationToken>,
}
/// Serializes the shared-store mutations of one key (see
/// `HttpChallengeStore::mutation_lock`).
type MutationLock = Arc<tokio::sync::Mutex<()>>;
/// Bounds on one shared-store mutation (see `SHARED_MUTATION_TIMEOUT` and
/// `SHARED_MUTATION_LIMIT`): the time the store gets to acknowledge it, and
/// the hard limit after which it is abandoned, which also bounds waiting
/// for the key's turn.
#[derive(Clone, Copy)]
struct MutationBounds {
    acknowledge: Duration,
    limit: Duration,
}
impl Default for MutationBounds {
    fn default() -> Self {
        Self {
            acknowledge: SHARED_MUTATION_TIMEOUT,
            limit: SHARED_MUTATION_LIMIT,
        }
    }
}
/// The key's mutation lock while an insert, refresh or removal mutates the
/// store. `mutate` moves the lock to the background together with a
/// mutation it abandons, so the lock outlives the caller until the store has
/// actually finished that mutation.
struct MutationGuard {
    lock: Option<tokio::sync::OwnedMutexGuard<()>>,
    bounds: MutationBounds,
}
impl MutationGuard {
    /// Wait for the key's turn, at most `bounds.limit`.
    async fn acquire(lock: &MutationLock, bounds: MutationBounds) -> Option<Self> {
        tokio::time::timeout(bounds.limit, lock.clone().lock_owned())
            .await
            .ok()
            .map(|lock| Self {
                lock: Some(lock),
                bounds,
            })
    }
    /// `false` once an abandoned mutation took the lock away.
    fn held(&self) -> bool {
        self.lock.is_some()
    }
}
/// Outcome of one store mutation run by `mutate`.
enum Mutated<T> {
    /// The store finished; `overdue` when it missed the acknowledgement time.
    Done {
        result: StoreResult<T>,
        overdue: bool,
    },
    /// Still running at the limit (or not started because an earlier
    /// abandoned mutation already holds the key's lock); it keeps the lock
    /// until it completes.
    Abandoned,
}

/// How long a shared HTTP-01 record lives without a refresh. The issuing
/// instance re-publishes every active record at half this interval until it
/// removes the record (`spawn_keepalive`), so an order that runs up to the
/// enforced `acme_timeout` keeps its tokens answerable on every instance,
/// while records left behind by a crashed instance expire on their own.
const SHARED_CHALLENGE_TTL: Duration = Duration::from_secs(10 * 60);
/// Publication attempts before an insert in shared mode is reported as
/// failed. Only a transport failure the store reports within
/// `SHARED_MUTATION_TIMEOUT` is retried; a rejection of the content, the
/// outcome of an overdue attempt and an abandoned attempt are final.
const SHARED_PUBLISH_ATTEMPTS: u32 = 3;
/// Pause between two publication attempts.
const SHARED_PUBLISH_RETRY_DELAY: Duration = Duration::from_millis(250);
/// A refresh keeps running this long at most after the insert when the
/// entry is never removed (twice the largest permitted `acme_timeout`), so a
/// leaked entry cannot be refreshed forever.
const SHARED_KEEPALIVE_LIMIT: Duration = Duration::from_secs(2 * 24 * 60 * 60);
/// Bound on a shared lookup made from the public listener: a slow store must
/// not hold a challenge connection longer than this (the request is answered
/// 404 instead).
const SHARED_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
/// Time the store has to acknowledge one publication or withdrawal. A
/// mutation still running after it is overdue: its future is not dropped
/// (the write may still land) and it is not retried in parallel; it is
/// awaited up to `SHARED_MUTATION_LIMIT` and its late outcome counts.
const SHARED_MUTATION_TIMEOUT: Duration = Duration::from_secs(5);
/// Hard limit on one mutation, measured from its start, and on waiting for
/// the key's turn. A mutation that has not finished by then is abandoned to
/// the background together with the key's mutation lock, which it releases
/// only once the store has actually completed it, so it can never land on
/// top of a later publication or withdrawal of the same token. An insert,
/// refresh or removal that cannot take the lock within this time fails
/// (insert) or skips its store mutation (refresh, removal) instead of
/// waiting longer.
const SHARED_MUTATION_LIMIT: Duration = Duration::from_secs(30);
/// Separator inside a shared record (`<host><SEP><key authorization>`). It is
/// printable ASCII (the store's value charset) and cannot occur in a hostname
/// or a key authorization.
const SHARED_RECORD_SEPARATOR: char = ' ';
/// Minimum interval between two identical store-failure warnings from the
/// listener path, so anonymous probes against a broken store cannot flood
/// the log.
const SHARED_WARNING_INTERVAL: u64 = 30;
/// Concurrent shared-store lookups the unauthenticated challenge path may
/// have in flight. Anonymous probes with unknown tokens beyond this bound get
/// a plain 404 instead of another store round trip, so the public listener
/// cannot amplify traffic into the configuration store.
const SHARED_LOOKUP_CONCURRENCY: usize = 8;

/// A bounded in-memory HTTP-01 response store for the public listener. With a
/// shared backend every instance behind a load balancer can answer the CA's
/// validation request for a token that another instance published.
#[derive(Clone)]
pub struct HttpChallengeStore {
    entries: Arc<RwLock<HashMap<ChallengeKey, ChallengeEntry>>>,
    /// Source of `ChallengeEntry::owner` ids, unique within this store.
    owners: Arc<std::sync::atomic::AtomicU64>,
    /// One lock per key for its shared-store mutations (publication,
    /// refresh, withdrawal), alive while an insert, keepalive or removal
    /// holds it. A replacement publishes and a removal withdraws only after
    /// the previous installation's in-flight refresh, never interleaved
    /// with it.
    mutations: Arc<std::sync::Mutex<HashMap<ChallengeKey, Weak<tokio::sync::Mutex<()>>>>>,
    shared: Option<Arc<dyn ConfigStore>>,
    /// Lifetime of one shared record between refreshes.
    shared_ttl: Duration,
    /// Acknowledgement time and hard limit of one shared-store mutation.
    mutation_bounds: MutationBounds,
    /// Unix second of the last store-failure warning from the lookup path.
    warned: Arc<std::sync::atomic::AtomicU64>,
    /// In-flight shared lookups from the listener path (see
    /// `SHARED_LOOKUP_CONCURRENCY`).
    lookups: Arc<tokio::sync::Semaphore>,
}
impl Default for HttpChallengeStore {
    fn default() -> Self {
        Self {
            entries: Arc::default(),
            owners: Arc::default(),
            mutations: Arc::default(),
            shared: None,
            shared_ttl: SHARED_CHALLENGE_TTL,
            mutation_bounds: MutationBounds::default(),
            warned: Arc::default(),
            lookups: Arc::new(tokio::sync::Semaphore::new(SHARED_LOOKUP_CONCURRENCY)),
        }
    }
}
impl HttpChallengeStore {
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }
    /// Publish every inserted token to `store` as well and fall back to it on
    /// a local miss. In this mode an insert succeeds only once the store has
    /// acknowledged the publication, and the record is refreshed until the
    /// token is removed, so validation may land on any instance.
    pub fn with_shared(self, store: Arc<dyn ConfigStore>) -> Self {
        Self {
            shared: Some(store),
            ..self
        }
    }
    /// Lifetime of one shared record between refreshes (default 10 minutes,
    /// clamped to the store's permitted range). Refreshes happen at half of
    /// it; mainly for tests that must observe a refresh quickly.
    pub fn with_shared_ttl(self, ttl: Duration) -> Self {
        Self {
            shared_ttl: ttl.clamp(MIN_CHALLENGE_TTL, MAX_CHALLENGE_TTL),
            ..self
        }
    }
    /// Time the store gets to acknowledge one publication or withdrawal
    /// (default 5 seconds) and the hard limit after which a mutation still
    /// running is abandoned to the background, which also bounds waiting
    /// for a token's previous mutation (default 30 seconds, never below the
    /// acknowledgement time); mainly for tests that must observe the
    /// bounds quickly.
    pub fn with_shared_mutation_bounds(self, acknowledge: Duration, limit: Duration) -> Self {
        let acknowledge = acknowledge.max(Duration::from_millis(10));
        Self {
            mutation_bounds: MutationBounds {
                acknowledge,
                limit: limit.max(acknowledge),
            },
            ..self
        }
    }
    pub fn has_shared(&self) -> bool {
        self.shared.is_some()
    }
    /// The lock serializing the shared-store mutations of `key`; created on
    /// first use and dropped with its last holder.
    fn mutation_lock(&self, key: &ChallengeKey) -> MutationLock {
        let mut locks = self
            .mutations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        locks.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }
    /// Install a response. With a shared store the token is also published
    /// there with bounded retries; a publication the store did not
    /// acknowledge fails the insert (and leaves no local entry) so the caller
    /// never tells the CA that a token only this instance can answer is
    /// ready. Without a store the entry is local only. Installing a key that
    /// is already installed replaces it: the previous installation stops
    /// refreshing and the new record is published once its in-flight
    /// publication, refresh or withdrawal has finished. `Ok` means this
    /// installation is published and still the key's current one; an
    /// installation that was replaced or removed before or while it was
    /// published is reported as superseded, since the record the fleet will
    /// serve is not its own.
    pub async fn insert(
        &self,
        host: impl AsRef<str>,
        token: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<()> {
        let host = normalize_host(host.as_ref())?;
        let token = token.into();
        let value = value.into();
        ensure!(valid_token(&token), "invalid ACME HTTP-01 token");
        ensure!(
            !value.is_empty() && value.len() <= 1024,
            "invalid ACME HTTP-01 response"
        );
        let key = ChallengeKey {
            host: host.clone(),
            token: token.clone(),
        };
        let owner = self
            .owners
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let keepalive = self.shared.as_ref().map(|_| CancellationToken::new());
        {
            let mut entries = self.entries.write().await;
            ensure!(
                entries.len() < 4096 || entries.contains_key(&key),
                "too many active HTTP-01 challenges"
            );
            if let Some(previous) = entries.insert(
                key.clone(),
                ChallengeEntry {
                    value: value.clone(),
                    owner,
                    keepalive: keepalive.clone(),
                },
            ) && let Some(previous) = previous.keepalive
            {
                // The replaced installation stops refreshing; its record is
                // superseded by the publication below.
                previous.cancel();
            }
        }
        let (Some(store), Some(keepalive)) = (&self.shared, keepalive) else {
            return Ok(());
        };
        let record = format!("{host}{SHARED_RECORD_SEPARATOR}{value}");
        // Publish only after the previous installation's in-flight
        // publication, refresh or withdrawal has completed in the store, so
        // none of them can overwrite or delete this record.
        let lock = self.mutation_lock(&key);
        let Some(mut guard) = MutationGuard::acquire(&lock, self.mutation_bounds).await else {
            self.roll_back(&key, owner, &keepalive).await;
            bail!(
                "ACME HTTP-01 challenge for {host} was not published to the shared store (a \
                 previous publication or withdrawal of this token has not completed after {}s); \
                 other instances would answer 404, so this authorization is aborted",
                self.mutation_bounds.limit.as_secs()
            );
        };
        if !self.owns(&key, owner).await {
            // Replaced or removed while waiting: the newer installation of the
            // key publishes its own record right after this lock is released;
            // this one was never published and must not report success.
            bail!(
                "ACME HTTP-01 challenge for {host} was superseded before it was published (the \
                 token was reinstalled or removed meanwhile), so this installation is not \
                 answerable"
            );
        }
        if let Err(error) =
            publish_acknowledged(store, &key, &record, self.shared_ttl, &mut guard).await
        {
            self.roll_back(&key, owner, &keepalive).await;
            bail!(
                "ACME HTTP-01 challenge for {host} was not published to the shared store \
                 ({error}); other instances would answer 404, so this authorization is aborted"
            );
        }
        if !self.owns(&key, owner).await {
            // Published, but replaced or removed meanwhile: the successor's
            // publication or withdrawal is queued behind this lock, so the
            // record just written is not the one the fleet will serve.
            bail!(
                "ACME HTTP-01 challenge for {host} was superseded while it was being published \
                 (the token was reinstalled or removed meanwhile), so this installation is not \
                 answerable"
            );
        }
        self.spawn_keepalive(store.clone(), key, record, keepalive, owner, lock.clone());
        Ok(())
    }
    /// Whether installation `owner` is still the key's current entry.
    async fn owns(&self, key: &ChallengeKey, owner: u64) -> bool {
        self.entries.read().await.get(key).map(|entry| entry.owner) == Some(owner)
    }
    /// Roll back installation `owner` of `key` after a failed publication: a
    /// token the fleet cannot answer must not stay installed, but a
    /// replacement made while the publication was in flight owns the entry
    /// now and publishes its own record.
    async fn roll_back(&self, key: &ChallengeKey, owner: u64, keepalive: &CancellationToken) {
        let mut entries = self.entries.write().await;
        if entries.get(key).is_some_and(|entry| entry.owner == owner) {
            entries.remove(key);
        }
        drop(entries);
        keepalive.cancel();
    }
    /// Re-publish `record` at half the ttl while installation `owner` is the
    /// key's current entry, until `cancel` fires or `SHARED_KEEPALIVE_LIMIT`
    /// passes. Every refresh holds the key's mutation lock until the store
    /// has completed it, so a replacement or removal that arrives meanwhile
    /// acts on the store only after it. A failed or skipped refresh is
    /// retried sooner (an eighth of the ttl).
    fn spawn_keepalive(
        &self,
        store: Arc<dyn ConfigStore>,
        key: ChallengeKey,
        record: String,
        cancel: CancellationToken,
        owner: u64,
        lock: MutationLock,
    ) {
        let entries = Arc::downgrade(&self.entries);
        let ttl = self.shared_ttl;
        let bounds = self.mutation_bounds;
        tokio::spawn(async move {
            let started = Instant::now();
            let mut delay = ttl / 2;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(delay) => {}
                }
                let Some(entries) = entries.upgrade() else {
                    return;
                };
                if started.elapsed() >= SHARED_KEEPALIVE_LIMIT {
                    tracing::warn!(
                        host = %key.host,
                        "ACME HTTP-01 challenge was never removed; its shared record now expires"
                    );
                    return;
                }
                let mut guard = tokio::select! {
                    // Replaced or removed while waiting for the lock; the
                    // successor's publication or withdrawal is already done or
                    // queued behind this lock, so there is nothing to refresh.
                    _ = cancel.cancelled() => return,
                    acquired = MutationGuard::acquire(&lock, bounds) => match acquired {
                        Some(guard) => guard,
                        None => {
                            tracing::warn!(
                                host = %key.host,
                                "ACME HTTP-01 challenge refresh skipped: a previous mutation of the token has not completed after {}s",
                                bounds.limit.as_secs()
                            );
                            delay = (ttl / 8).max(SHARED_PUBLISH_RETRY_DELAY);
                            continue;
                        }
                    },
                };
                if cancel.is_cancelled() {
                    return;
                }
                if entries.read().await.get(&key).map(|entry| entry.owner) != Some(owner) {
                    return;
                }
                match publish_acknowledged(&store, &key, &record, ttl, &mut guard).await {
                    Ok(()) => delay = ttl / 2,
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            host = %key.host,
                            "ACME HTTP-01 challenge refresh failed; other instances stop answering it when the record expires"
                        );
                        delay = (ttl / 8).max(SHARED_PUBLISH_RETRY_DELAY);
                    }
                }
                if cancel.is_cancelled() {
                    // Removed or replaced while the refresh was in flight. After
                    // a removal (no entry, or still ours) withdraw again so the
                    // refresh cannot resurrect the record for one more ttl. A
                    // replacement owns the key now: its record is published as
                    // soon as this lock is released and must not be deleted.
                    // An abandoned refresh took the lock with it; the removal's
                    // own withdrawal is queued behind it and lands after it.
                    let current = entries.read().await.get(&key).map(|entry| entry.owner);
                    if guard.held() && current.is_none_or(|current| current == owner) {
                        let _ = withdraw_acknowledged(&store, &key, &mut guard).await;
                    }
                    return;
                }
            }
        });
    }
    /// Uninstall a response. With a shared store the record is withdrawn as
    /// well, after any publication or refresh of it still in flight has
    /// completed in the store and only while no newer installation of the
    /// same key exists by then. The withdrawal is best effort and bounded
    /// (`SHARED_MUTATION_LIMIT` to wait for the key's turn, the same again
    /// for the store); a record that is not withdrawn expires on its own.
    pub async fn remove(&self, host: impl AsRef<str>, token: &str) -> Result<()> {
        let key = ChallengeKey {
            host: normalize_host(host.as_ref())?,
            token: token.to_owned(),
        };
        self.remove_local(&key).await;
        self.withdraw_shared(key).await
    }
    /// Stop serving and refreshing a challenge before its slower shared-store
    /// withdrawal. Cleanup calls this for every authorization first, so an
    /// overall withdrawal deadline never leaves unpolled local entries alive.
    async fn remove_local(&self, key: &ChallengeKey) {
        if let Some(entry) = self.entries.write().await.remove(key)
            && let Some(keepalive) = entry.keepalive
        {
            keepalive.cancel();
        }
    }
    async fn withdraw_shared(&self, key: ChallengeKey) -> Result<()> {
        let Some(store) = &self.shared else {
            return Ok(());
        };
        let lock = self.mutation_lock(&key);
        let Some(mut guard) = MutationGuard::acquire(&lock, self.mutation_bounds).await else {
            tracing::warn!(
                host = %key.host,
                "ACME HTTP-01 challenge withdrawal skipped: a previous mutation of the token has not completed after {}s; the record expires on its own",
                self.mutation_bounds.limit.as_secs()
            );
            return Ok(());
        };
        if self.entries.read().await.contains_key(&key) {
            // Reinstalled while this withdrawal waited for its turn: the new
            // installation's record must stay (its own removal withdraws it).
            return Ok(());
        }
        if let Err(error) = withdraw_acknowledged(store, &key, &mut guard).await {
            tracing::warn!(
                %error,
                host = %key.host,
                "ACME HTTP-01 challenge not withdrawn from the shared store; it expires on its own"
            );
        }
        Ok(())
    }
    /// Remove an order's HTTP-01 entries with fixed shared-store concurrency
    /// and an overall deadline. Local entries and keepalives are stopped first;
    /// active mutations that outlive the deadline keep their per-key locks,
    /// while records whose withdrawal never starts expire by TTL.
    async fn cleanup_many(&self, challenges: &[(String, String)]) {
        let mut keys = Vec::with_capacity(challenges.len());
        for (host, token) in challenges {
            let Ok(host) = normalize_host(host) else {
                continue;
            };
            let key = ChallengeKey {
                host,
                token: token.clone(),
            };
            self.remove_local(&key).await;
            keys.push(key);
        }
        if keys.is_empty() {
            return;
        }
        use futures_util::StreamExt;
        let this = self.clone();
        let withdrawals = futures_util::stream::iter(keys).for_each_concurrent(8, move |key| {
            let this = this.clone();
            async move {
                let _ = this.withdraw_shared(key).await;
            }
        });
        if tokio::time::timeout(Duration::from_secs(30), withdrawals)
            .await
            .is_err()
        {
            tracing::warn!(
                "ACME HTTP-01 cleanup exceeded 30 seconds; remaining shared records expire on their own"
            );
        }
    }
    pub async fn get(&self, host: impl AsRef<str>, token: &str) -> Option<String> {
        let host = normalize_host(host.as_ref()).ok()?;
        let key = ChallengeKey {
            host: host.clone(),
            token: token.to_owned(),
        };
        let local = self
            .entries
            .read()
            .await
            .get(&key)
            .map(|entry| entry.value.clone());
        if local.is_some() {
            return local;
        }
        let store = self.shared.as_ref()?;
        if !valid_token(token) {
            return None;
        }
        let Ok(_permit) = self.lookups.clone().try_acquire_owned() else {
            self.warn_lookup(format_args!(
                "shared ACME challenge lookups saturated ({SHARED_LOOKUP_CONCURRENCY} in flight)"
            ));
            return None;
        };
        let record = match tokio::time::timeout(
            SHARED_LOOKUP_TIMEOUT,
            store.lookup_challenge(&shared_store_key(&key)),
        )
        .await
        {
            Ok(Ok(Some(record))) => record,
            Ok(Ok(None)) => return None,
            Ok(Err(error)) => {
                self.warn_lookup(format_args!("shared ACME challenge lookup failed: {error}"));
                return None;
            }
            Err(_) => {
                self.warn_lookup(format_args!(
                    "shared ACME challenge lookup timed out after {}s",
                    SHARED_LOOKUP_TIMEOUT.as_secs()
                ));
                return None;
            }
        };
        // Only answer for the host the record was published for; a record
        // without a host (written by something else) is never served.
        let (stored_host, value) = record.split_once(SHARED_RECORD_SEPARATOR)?;
        if stored_host != host || value.is_empty() || value.len() > 1024 {
            return None;
        }
        Some(value.to_owned())
    }
    fn warn_lookup(&self, message: fmt::Arguments<'_>) {
        use std::sync::atomic::Ordering;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        let last = self.warned.load(Ordering::Relaxed);
        if now.saturating_sub(last) < SHARED_WARNING_INTERVAL
            || self
                .warned
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        tracing::warn!("{message}; answering 404 for tokens this instance does not own");
    }
    /// Resolve a listener request. Only GET and the exact ACME path are accepted.
    pub async fn response<B>(&self, request: &Request<B>) -> Option<Response<Full<Bytes>>> {
        if request.method() != hyper::http::Method::GET {
            return None;
        }
        let path = request.uri().path();
        let prefix = "/.well-known/acme-challenge/";
        let token = path.strip_prefix(prefix)?;
        if !valid_token(token) || path.len() != prefix.len() + token.len() {
            return None;
        }
        let host = request.headers().get(header::HOST)?.to_str().ok()?;
        let body = self.get(host, token).await?;
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::from(body)))
            .ok()
    }
}
/// Run one store mutation as its own task and wait for it to finish. The
/// task is never dropped: a mutation whose future is abandoned may still
/// execute (SQLite work runs on a blocking thread, a network store may still
/// apply the request), so the caller learns the real outcome — a late
/// acknowledgement is a success — and a mutation that outlives
/// `SHARED_MUTATION_LIMIT` is left running in the background with the key's
/// lock, which it releases only on completion. Requires a held guard: once
/// the lock went to the background nothing else may touch the key.
async fn mutate<T: Send + 'static>(
    guard: &mut MutationGuard,
    what: &'static str,
    key: &ChallengeKey,
    operation: impl Future<Output = StoreResult<T>> + Send + 'static,
) -> Mutated<T> {
    if !guard.held() {
        return Mutated::Abandoned;
    }
    let bounds = guard.bounds;
    let started = Instant::now();
    // The key's lock travels with the operation from launch: if this caller
    // is cancelled (its future dropped) the store's work continues and keeps
    // the key locked until it has really finished, so no successor can
    // interleave with a write that may still land. It comes back to the
    // caller with the result when the operation completes in time.
    let lock = guard.lock.take();
    let mut task = tokio::spawn(async move {
        let result = operation.await;
        (result, lock)
    });
    let joined = |joined: std::result::Result<
        (StoreResult<T>, Option<tokio::sync::OwnedMutexGuard<()>>),
        tokio::task::JoinError,
    >| {
        match joined {
            Ok((result, lock)) => (result, lock),
            Err(error) => (
                Err(StoreError::Indeterminate(
                    anyhow!(error).context("store mutation task failed"),
                )),
                None,
            ),
        }
    };
    if let Ok(result) = tokio::time::timeout(bounds.acknowledge, &mut task).await {
        let (result, lock) = joined(result);
        guard.lock = lock;
        return Mutated::Done {
            result,
            overdue: false,
        };
    }
    tracing::warn!(
        host = %key.host,
        "ACME HTTP-01 challenge {what} to the shared store is overdue after {}s; waiting up to {}s for it",
        bounds.acknowledge.as_secs(),
        bounds.limit.as_secs()
    );
    match tokio::time::timeout_at(started + bounds.limit, &mut task).await {
        Ok(result) => {
            let (result, lock) = joined(result);
            guard.lock = lock;
            Mutated::Done {
                result,
                overdue: true,
            }
        }
        Err(_) => {
            // The lock is still inside the task: whoever mutates this key
            // next waits until the store has really finished this one.
            let host = key.host.clone();
            tokio::spawn(async move {
                let outcome = match task.await {
                    Ok((Ok(_), _lock)) => "completed".to_owned(),
                    Ok((Err(error), _lock)) => format!("failed: {error}"),
                    Err(error) => format!("task failed: {error}"),
                };
                tracing::warn!(
                    host = %host,
                    "abandoned ACME HTTP-01 challenge {what} to the shared store {outcome} after {:.0?}",
                    started.elapsed()
                );
            });
            Mutated::Abandoned
        }
    }
}
/// Publish one record and wait for the store's acknowledgement, retrying a
/// transport failure reported within `SHARED_MUTATION_TIMEOUT` up to
/// `SHARED_PUBLISH_ATTEMPTS` times. A rejection of the content itself, the
/// outcome of an overdue attempt and an abandoned attempt are final: a
/// retry in parallel with a write that may still land is what the
/// completion wait exists to prevent.
async fn publish_acknowledged(
    store: &Arc<dyn ConfigStore>,
    key: &ChallengeKey,
    record: &str,
    ttl: Duration,
    guard: &mut MutationGuard,
) -> std::result::Result<(), String> {
    let mut last = String::new();
    for attempt in 1..=SHARED_PUBLISH_ATTEMPTS {
        let publish = {
            let store = store.clone();
            let token = shared_store_key(key);
            let record = record.to_owned();
            async move { store.publish_challenge(&token, &record, ttl).await }
        };
        match mutate(guard, "publication", key, publish).await {
            Mutated::Done { result: Ok(()), .. } => return Ok(()),
            Mutated::Done {
                result: Err(error), ..
            } if !error.is_transport() => return Err(error.to_string()),
            Mutated::Done {
                result: Err(error),
                overdue: false,
            } => last = error.to_string(),
            Mutated::Done {
                result: Err(error),
                overdue: true,
            } => {
                return Err(format!(
                    "{error} (reported after more than {}s, not retried)",
                    guard.bounds.acknowledge.as_secs()
                ));
            }
            Mutated::Abandoned => {
                return Err(format!(
                    "publication still unacknowledged after {}s; it keeps running in the \
                     background and later mutations of this token wait for it",
                    guard.bounds.limit.as_secs()
                ));
            }
        }
        if attempt < SHARED_PUBLISH_ATTEMPTS {
            tokio::time::sleep(SHARED_PUBLISH_RETRY_DELAY).await;
        }
    }
    Err(format!("{last} after {SHARED_PUBLISH_ATTEMPTS} attempts"))
}
/// Withdraw one record and wait for the store; the single attempt's
/// outcome, overdue or not, is final.
async fn withdraw_acknowledged(
    store: &Arc<dyn ConfigStore>,
    key: &ChallengeKey,
    guard: &mut MutationGuard,
) -> std::result::Result<(), String> {
    let withdraw = {
        let store = store.clone();
        let token = shared_store_key(key);
        async move { store.withdraw_challenge(&token).await }
    };
    match mutate(guard, "withdrawal", key, withdraw).await {
        Mutated::Done { result: Ok(()), .. } => Ok(()),
        Mutated::Done {
            result: Err(error), ..
        } => Err(error.to_string()),
        Mutated::Abandoned => Err(format!(
            "withdrawal still unacknowledged after {}s; it keeps running in the background",
            guard.bounds.limit.as_secs()
        )),
    }
}
fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
/// Opaque shared-store identity for one authorization. Backends historically
/// keyed challenges by the URL token alone, although the listener and local
/// ownership model key them by `(host, token)`. Include both inputs so a CA
/// reusing a token for two hosts cannot make one authorization overwrite or
/// withdraw the other. The base64url SHA-256 output is always 43 characters,
/// within every ConfigStore token bound even when the ACME URL token reaches
/// this module's 256-character limit.
fn shared_store_key(key: &ChallengeKey) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"hangang-acme-http01-v2\0");
    digest.update(key.host.as_bytes());
    digest.update(b"\0");
    digest.update(key.token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}
fn normalize_host(host: &str) -> Result<String> {
    let host = host.trim().trim_end_matches('.');
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host = host
        .rsplit_once(':')
        .map(|(h, p)| {
            if p.bytes().all(|b| b.is_ascii_digit()) {
                h
            } else {
                host
            }
        })
        .unwrap_or(host);
    ensure!(
        !host.is_empty() && host.len() <= 253 && host.is_ascii(),
        "invalid HTTP challenge host"
    );
    Ok(host.to_ascii_lowercase())
}

/// A DNS TXT record returned by a provider. Providers track ownership; callers
/// cannot manufacture a record that another provider will delete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    pub value: String,
}

#[async_trait]
pub trait TxtResolver: Send + Sync {
    async fn txt_values(&self, name: &str) -> Result<Vec<String>>;
}

/// DNS-over-HTTPS TXT resolver used for propagation checks.
#[derive(Clone)]
pub struct DohTxtResolver {
    client: Client,
    endpoint: String,
}
impl DohTxtResolver {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            client: http_client(),
            endpoint: endpoint.into(),
        }
    }
}
impl Default for DohTxtResolver {
    fn default() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }
}
#[async_trait]
impl TxtResolver for DohTxtResolver {
    async fn txt_values(&self, name: &str) -> Result<Vec<String>> {
        #[derive(Deserialize)]
        struct Answer {
            data: Option<String>,
            #[serde(rename = "type")]
            kind: u16,
        }
        #[derive(Deserialize)]
        struct Reply {
            #[serde(rename = "Answer", default)]
            answer: Vec<Answer>,
        }
        let reply: Reply = json_bounded(
            self.client
                .get(&self.endpoint)
                .query(&[("name", name), ("type", "TXT")])
                .header("accept", "application/dns-json")
                .send()
                .await?
                .error_for_status()?,
        )
        .await?;
        Ok(reply
            .answer
            .into_iter()
            .filter(|a| a.kind == 16)
            .filter_map(|a| a.data)
            .map(|s| s.trim_matches('"').to_owned())
            .collect())
    }
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn present(&self, name: &str, value: &str) -> Result<DnsRecord>;
    /// Cancellation-aware wrapper used by the engine. Providers may override
    /// this when they have a native cancellation API.
    async fn present_cancellable(
        &self,
        name: &str,
        value: &str,
        cancel: &CancellationToken,
    ) -> Result<DnsRecord> {
        tokio::select! {
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            result = tokio::time::timeout(Duration::from_secs(20), self.present(name, value)) => result.context("DNS provider request timed out")?,
        }
    }
    async fn wait_for_propagation(
        &self,
        name: &str,
        value: &str,
        timeout: Duration,
        interval: Duration,
        cancel: &CancellationToken,
    ) -> Result<()>;
    async fn cleanup(&self, record: DnsRecord) -> Result<()>;
    /// Queue a receipt whose cleanup failed for a later bounded retry.
    async fn defer_cleanup(&self, _record: DnsRecord) {}
    /// Retry queued cleanups and reconcile presentations whose remote outcome
    /// is unknown. Bounded in time and attempts; safe to call on every
    /// attempt or renewal tick.
    async fn retry_deferred_cleanups(&self, _cancel: &CancellationToken) {}
}

const MAX_CLEANUP_ATTEMPTS: u32 = 8;
const CLEANUP_RETRY_BATCH: usize = 32;
const CLEANUP_RETRY_INITIAL: Duration = Duration::from_secs(30);
const CLEANUP_RETRY_MAX: Duration = Duration::from_secs(3600);
const CLEANUP_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Retry bookkeeping shared by the HTTP DNS providers: cleanups that failed
/// and presentations whose remote outcome is unknown because the request was
/// dropped (cancelled or timed out) before its response was processed.
struct CleanupLedger {
    deferred: std::sync::Mutex<Vec<DeferredCleanup>>,
    uncertain: std::sync::Mutex<HashMap<String, UncertainPresentation>>,
    backoff_ms: std::sync::atomic::AtomicU64,
}
#[derive(Clone)]
struct DeferredCleanup {
    record: DnsRecord,
    attempts: u32,
    not_before: Instant,
}
#[derive(Clone)]
struct UncertainPresentation {
    name: String,
    value: String,
    attempts: u32,
    not_before: Instant,
}
impl CleanupLedger {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            deferred: std::sync::Mutex::new(Vec::new()),
            uncertain: std::sync::Mutex::new(HashMap::new()),
            backoff_ms: std::sync::atomic::AtomicU64::new(CLEANUP_RETRY_INITIAL.as_millis() as u64),
        })
    }
    fn backoff(&self, attempts: u32) -> Duration {
        let initial =
            Duration::from_millis(self.backoff_ms.load(std::sync::atomic::Ordering::Relaxed));
        initial
            .saturating_mul(1u32 << attempts.min(16))
            .min(CLEANUP_RETRY_MAX)
    }
    fn pending(&self) -> usize {
        self.uncertain.lock().map(|u| u.len()).unwrap_or(0)
    }
    fn begin_present(&self, name: &str, value: &str) -> PresentIntent<'_> {
        PresentIntent {
            ledger: self,
            name: name.to_owned(),
            value: value.to_owned(),
            confirmed: false,
        }
    }
    fn defer(&self, record: DnsRecord) {
        let Ok(mut deferred) = self.deferred.lock() else {
            return;
        };
        if deferred.iter().any(|entry| entry.record.id == record.id) {
            return;
        }
        deferred.push(DeferredCleanup {
            record,
            attempts: 0,
            not_before: Instant::now(),
        });
    }
    fn due_deferred(&self) -> Vec<DeferredCleanup> {
        let now = Instant::now();
        self.deferred
            .lock()
            .map(|deferred| {
                deferred
                    .iter()
                    .filter(|entry| entry.not_before <= now)
                    .take(CLEANUP_RETRY_BATCH)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }
    fn due_uncertain(&self) -> Vec<(String, UncertainPresentation)> {
        let now = Instant::now();
        self.uncertain
            .lock()
            .map(|uncertain| {
                uncertain
                    .iter()
                    .filter(|(_, entry)| entry.not_before <= now)
                    .take(CLEANUP_RETRY_BATCH)
                    .map(|(key, entry)| (key.clone(), entry.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    fn finish_deferred(&self, id: &str) {
        if let Ok(mut deferred) = self.deferred.lock() {
            deferred.retain(|entry| entry.record.id != id);
        }
    }
    /// Records a failed retry; returns true when the receipt is given up on.
    fn fail_deferred(&self, id: &str) -> bool {
        let Ok(mut deferred) = self.deferred.lock() else {
            return false;
        };
        let Some(entry) = deferred.iter_mut().find(|entry| entry.record.id == id) else {
            return false;
        };
        entry.attempts += 1;
        if entry.attempts >= MAX_CLEANUP_ATTEMPTS {
            deferred.retain(|entry| entry.record.id != id);
            return true;
        }
        entry.not_before = Instant::now() + self.backoff(entry.attempts);
        false
    }
    fn finish_uncertain(&self, key: &str) {
        if let Ok(mut uncertain) = self.uncertain.lock() {
            uncertain.remove(key);
        }
    }
    fn fail_uncertain(&self, key: &str) -> bool {
        let Ok(mut uncertain) = self.uncertain.lock() else {
            return false;
        };
        let Some(entry) = uncertain.get_mut(key) else {
            return false;
        };
        entry.attempts += 1;
        if entry.attempts >= MAX_CLEANUP_ATTEMPTS {
            uncertain.remove(key);
            return true;
        }
        entry.not_before = Instant::now() + self.backoff(entry.attempts);
        false
    }
}
/// Ownership is recorded before the remote call completes: dropping the
/// intent without confirmation (cancellation, timeout, transport error) keeps
/// the presentation as uncertain so a later retry reconciles it.
struct PresentIntent<'a> {
    ledger: &'a CleanupLedger,
    name: String,
    value: String,
    confirmed: bool,
}
impl PresentIntent<'_> {
    fn confirm(mut self) {
        self.confirmed = true;
    }
}
impl Drop for PresentIntent<'_> {
    fn drop(&mut self) {
        if self.confirmed {
            return;
        }
        if let Ok(mut uncertain) = self.ledger.uncertain.lock() {
            let key = format!("{}\0{}", self.name.to_ascii_lowercase(), self.value);
            uncertain.entry(key).or_insert(UncertainPresentation {
                name: std::mem::take(&mut self.name),
                value: std::mem::take(&mut self.value),
                attempts: 0,
                not_before: Instant::now(),
            });
        }
    }
}

/// Runs the bounded retry cycle for one provider: reconcile uncertain
/// presentations into concrete receipts, then retry deferred cleanups. Each
/// remote call is bounded by `CLEANUP_CALL_TIMEOUT`; calls run concurrently.
async fn run_cleanup_retries<P>(
    provider: &P,
    ledger: &CleanupLedger,
    owned: &RwLock<HashMap<String, DnsRecord>>,
    cancel: &CancellationToken,
) where
    P: DnsProvider + ReconcileUncertain + Sync,
{
    let uncertain = ledger.due_uncertain();
    if !uncertain.is_empty() {
        let reconciliations = uncertain.iter().map(|(key, entry)| async move {
            let result = tokio::time::timeout(
                CLEANUP_CALL_TIMEOUT,
                provider.reconcile_uncertain(&entry.name, &entry.value),
            )
            .await;
            (key.clone(), result)
        });
        let results = tokio::select! {
            _ = cancel.cancelled() => return,
            results = futures_util::future::join_all(reconciliations) => results,
        };
        for (key, result) in results {
            match result {
                Ok(Ok(records)) => {
                    let mut owned = owned.write().await;
                    for record in records {
                        owned.insert(record.id.clone(), record.clone());
                        ledger.defer(record);
                    }
                    ledger.finish_uncertain(&key);
                }
                Ok(Err(error)) => {
                    if ledger.fail_uncertain(&key) {
                        tracing::error!(%error, "giving up reconciling an uncertain ACME DNS presentation");
                    } else {
                        tracing::warn!(%error, "ACME DNS presentation reconciliation failed; will retry");
                    }
                }
                Err(_) => {
                    if ledger.fail_uncertain(&key) {
                        tracing::error!("giving up reconciling an uncertain ACME DNS presentation");
                    } else {
                        tracing::warn!(
                            "ACME DNS presentation reconciliation timed out; will retry"
                        );
                    }
                }
            }
        }
    }
    let deferred = ledger.due_deferred();
    if deferred.is_empty() {
        return;
    }
    let cleanups = deferred.iter().map(|entry| async move {
        let result =
            tokio::time::timeout(CLEANUP_CALL_TIMEOUT, provider.cleanup(entry.record.clone()))
                .await;
        (entry.record.id.clone(), result)
    });
    let results = tokio::select! {
        _ = cancel.cancelled() => return,
        results = futures_util::future::join_all(cleanups) => results,
    };
    for (id, result) in results {
        match result {
            Ok(Ok(())) => ledger.finish_deferred(&id),
            Ok(Err(error)) => {
                if ledger.fail_deferred(&id) {
                    owned.write().await.remove(&id);
                    tracing::error!(%error, "giving up on ACME DNS record cleanup after repeated failures");
                } else {
                    tracing::warn!(%error, "ACME DNS cleanup retry failed; will retry");
                }
            }
            Err(_) => {
                if ledger.fail_deferred(&id) {
                    owned.write().await.remove(&id);
                    tracing::error!("giving up on ACME DNS record cleanup after repeated timeouts");
                } else {
                    tracing::warn!("ACME DNS cleanup retry timed out; will retry");
                }
            }
        }
    }
}
/// Provider-specific recovery of a presentation with unknown outcome: return
/// the receipts that must now be cleaned up (empty when nothing exists or the
/// provider deleted the record directly).
#[async_trait]
trait ReconcileUncertain {
    async fn reconcile_uncertain(&self, name: &str, value: &str) -> Result<Vec<DnsRecord>>;
}

#[derive(Clone)]
pub struct CloudflareDnsProvider {
    client: Client,
    endpoint: String,
    zone_id: String,
    api_token: String,
    resolver: Arc<dyn TxtResolver>,
    owned: Arc<RwLock<HashMap<String, DnsRecord>>>,
    ledger: Arc<CleanupLedger>,
}
impl CloudflareDnsProvider {
    pub fn new(zone_id: impl Into<String>, api_token: impl Into<String>) -> Self {
        Self::with_resolver(zone_id, api_token, Arc::new(DohTxtResolver::default()))
    }
    pub fn with_resolver(
        zone_id: impl Into<String>,
        api_token: impl Into<String>,
        resolver: Arc<dyn TxtResolver>,
    ) -> Self {
        Self {
            client: http_client(),
            endpoint: "https://api.cloudflare.com/client/v4".to_owned(),
            zone_id: zone_id.into(),
            api_token: api_token.into(),
            resolver,
            owned: Arc::new(RwLock::new(HashMap::new())),
            ledger: CleanupLedger::new(),
        }
    }
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }
    /// Initial delay between retries of a failed cleanup (doubles per attempt).
    pub fn with_cleanup_retry_backoff(self, initial: Duration) -> Self {
        self.ledger.backoff_ms.store(
            initial.as_millis().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self
    }
    fn record_url(&self, id: &str) -> String {
        format!("{}/{}", self.records_url(), id)
    }
    fn records_url(&self) -> String {
        format!(
            "{}/zones/{}/dns_records",
            self.endpoint.trim_end_matches('/'),
            self.zone_id
        )
    }
}
#[derive(Deserialize)]
struct CfResponse<T> {
    success: bool,
    result: Option<T>,
}
#[derive(Deserialize)]
struct CfRecord {
    id: String,
    name: String,
    content: String,
}
#[derive(Serialize)]
struct CfCreate<'a> {
    r#type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}
#[async_trait]
impl DnsProvider for CloudflareDnsProvider {
    async fn present(&self, name: &str, value: &str) -> Result<DnsRecord> {
        ensure!(
            !name.is_empty() && name.len() <= 300 && !value.is_empty() && value.len() <= 256,
            "DNS challenge name or value exceeds limit"
        );
        // Reserve bookkeeping capacity before mutating the provider. Serializing
        // presents also makes the bound strict for callers sharing a provider.
        let mut owned_records = self.owned.write().await;
        ensure!(
            owned_records.len().saturating_add(self.ledger.pending()) < 4096,
            "DNS cleanup receipt capacity exhausted"
        );
        let intent = self.ledger.begin_present(name, value);
        let response = self
            .client
            .post(self.records_url())
            .bearer_auth(&self.api_token)
            .json(&CfCreate {
                r#type: "TXT",
                name,
                content: value,
                ttl: 60,
            })
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::BAD_REQUEST {
            // A previous attempt may have presented this exact proof and then
            // lost its cleanup receipt (for example, after a process restart).
            // Cloudflare rejects duplicate TXT content with HTTP 400. Adopt
            // only one record whose name and per-order value both match;
            // unrelated DNS records remain outside this provider's ownership.
            let mut existing = self.reconcile_uncertain(name, value).await?;
            if existing.len() == 1 {
                let record = existing.pop().expect("one exact record");
                owned_records.insert(record.id.clone(), record.clone());
                intent.confirm();
                tracing::info!(
                    name,
                    "ACME DNS challenge recovered from existing exact record"
                );
                return Ok(record);
            }
        }
        let response = response.error_for_status()?;
        let response: CfResponse<CfRecord> = json_bounded(response).await?;
        ensure!(response.success, "Cloudflare DNS record creation failed");
        let record = response
            .result
            .ok_or_else(|| anyhow!("Cloudflare returned no DNS record"))?;
        ensure!(
            record.name.eq_ignore_ascii_case(name) && record.content == value,
            "Cloudflare returned a different DNS record"
        );
        ensure!(
            !record.id.is_empty()
                && record.id.len() <= 128
                && record
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "Cloudflare returned an invalid DNS record ID"
        );
        let owned = DnsRecord {
            id: record.id,
            name: record.name,
            value: record.content,
        };
        owned_records.insert(owned.id.clone(), owned.clone());
        intent.confirm();
        Ok(owned)
    }
    async fn wait_for_propagation(
        &self,
        name: &str,
        value: &str,
        timeout: Duration,
        interval: Duration,
        cancel: &CancellationToken,
    ) -> Result<()> {
        wait_for_txt(
            self.resolver.clone(),
            name,
            value,
            timeout,
            interval,
            cancel,
        )
        .await
    }
    async fn cleanup(&self, record: DnsRecord) -> Result<()> {
        let owned = self
            .owned
            .read()
            .await
            .get(&record.id)
            .cloned()
            .ok_or_else(|| anyhow!("refusing to delete an unowned Cloudflare DNS record"))?;
        ensure!(
            owned.name.eq_ignore_ascii_case(&record.name) && owned.value == record.value,
            "refusing to delete a changed Cloudflare DNS record"
        );
        let lookup = self
            .client
            .get(self.record_url(&record.id))
            .bearer_auth(&self.api_token)
            .send()
            .await?;
        if lookup.status() == reqwest::StatusCode::NOT_FOUND {
            // Already gone (e.g. an earlier retry deleted it): nothing to own.
            self.owned.write().await.remove(&record.id);
            return Ok(());
        }
        let current: CfResponse<CfRecord> = json_bounded(lookup.error_for_status()?).await?;
        ensure!(current.success, "Cloudflare record lookup failed");
        let Some(current) = current.result else {
            self.owned.write().await.remove(&record.id);
            return Ok(());
        };
        ensure!(
            current.id == record.id
                && current.name.eq_ignore_ascii_case(&record.name)
                && current.content == record.value,
            "refusing to delete a modified Cloudflare DNS record"
        );
        let deleted: CfResponse<serde_json::Value> = json_bounded(
            self.client
                .delete(self.record_url(&record.id))
                .bearer_auth(&self.api_token)
                .send()
                .await?
                .error_for_status()?,
        )
        .await?;
        ensure!(deleted.success, "Cloudflare DNS record deletion failed");
        self.owned.write().await.remove(&record.id);
        Ok(())
    }
    async fn defer_cleanup(&self, record: DnsRecord) {
        self.ledger.defer(record);
    }
    async fn retry_deferred_cleanups(&self, cancel: &CancellationToken) {
        run_cleanup_retries(self, &self.ledger, &self.owned, cancel).await;
    }
}
#[async_trait]
impl ReconcileUncertain for CloudflareDnsProvider {
    /// Lists TXT records with exactly our challenge name and value; the value
    /// is a per-order key authorization digest, so matches are ours.
    async fn reconcile_uncertain(&self, name: &str, value: &str) -> Result<Vec<DnsRecord>> {
        let listed: CfResponse<Vec<CfRecord>> = json_bounded(
            self.client
                .get(self.records_url())
                .bearer_auth(&self.api_token)
                .query(&[
                    ("type", "TXT"),
                    ("name", name),
                    ("content", value),
                    ("per_page", "100"),
                ])
                .send()
                .await?
                .error_for_status()?,
        )
        .await?;
        ensure!(listed.success, "Cloudflare record listing failed");
        Ok(listed
            .result
            .unwrap_or_default()
            .into_iter()
            .filter(|record| {
                record.name.eq_ignore_ascii_case(name)
                    && record.content == value
                    && !record.id.is_empty()
                    && record.id.len() <= 128
                    && record
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
            .map(|record| DnsRecord {
                id: record.id,
                name: record.name,
                value: record.content,
            })
            .collect())
    }
}

/// Provider adapter for an operator-owned HTTP DNS webhook. It returns
/// { "id": "...", "name": "...", "value": "..." } for a present request.
#[derive(Clone)]
pub struct WebhookDnsProvider {
    client: Client,
    endpoint: String,
    bearer_token: String,
    resolver: Arc<dyn TxtResolver>,
    owned: Arc<RwLock<HashMap<String, DnsRecord>>>,
    ledger: Arc<CleanupLedger>,
}
impl WebhookDnsProvider {
    pub fn new(endpoint: impl Into<String>, bearer_token: impl Into<String>) -> Self {
        Self::with_resolver(endpoint, bearer_token, Arc::new(DohTxtResolver::default()))
    }
    pub fn with_resolver(
        endpoint: impl Into<String>,
        bearer_token: impl Into<String>,
        resolver: Arc<dyn TxtResolver>,
    ) -> Self {
        Self {
            client: http_client(),
            endpoint: endpoint.into(),
            bearer_token: bearer_token.into(),
            resolver,
            owned: Arc::new(RwLock::new(HashMap::new())),
            ledger: CleanupLedger::new(),
        }
    }
    /// Initial delay between retries of a failed cleanup (doubles per attempt).
    pub fn with_cleanup_retry_backoff(self, initial: Duration) -> Self {
        self.ledger.backoff_ms.store(
            initial.as_millis().min(u64::MAX as u128) as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self
    }
}
#[derive(Serialize)]
struct WebhookRequest<'a> {
    action: &'a str,
    id: Option<&'a str>,
    name: &'a str,
    value: &'a str,
}
#[derive(Deserialize)]
struct WebhookResponse {
    id: String,
    name: String,
    value: String,
}
#[async_trait]
impl DnsProvider for WebhookDnsProvider {
    async fn present(&self, name: &str, value: &str) -> Result<DnsRecord> {
        ensure!(
            !name.is_empty() && name.len() <= 300 && !value.is_empty() && value.len() <= 256,
            "DNS challenge name or value exceeds limit"
        );
        // Reserve bookkeeping capacity before mutating the provider. Serializing
        // presents also makes the bound strict for callers sharing a provider.
        let mut owned_records = self.owned.write().await;
        ensure!(
            owned_records.len().saturating_add(self.ledger.pending()) < 4096,
            "DNS cleanup receipt capacity exhausted"
        );
        let intent = self.ledger.begin_present(name, value);
        let reply = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .json(&WebhookRequest {
                action: "present",
                id: None,
                name,
                value,
            })
            .send()
            .await?
            .error_for_status()?;
        let reply: WebhookResponse = json_bounded(reply).await?;
        ensure!(
            reply.name.eq_ignore_ascii_case(name)
                && reply.value == value
                && !reply.id.is_empty()
                && reply.id.len() <= 256,
            "DNS webhook returned a different record"
        );
        let record = DnsRecord {
            id: reply.id,
            name: reply.name,
            value: reply.value,
        };
        owned_records.insert(record.id.clone(), record.clone());
        intent.confirm();
        Ok(record)
    }
    async fn wait_for_propagation(
        &self,
        name: &str,
        value: &str,
        timeout: Duration,
        interval: Duration,
        cancel: &CancellationToken,
    ) -> Result<()> {
        wait_for_txt(
            self.resolver.clone(),
            name,
            value,
            timeout,
            interval,
            cancel,
        )
        .await
    }
    async fn cleanup(&self, record: DnsRecord) -> Result<()> {
        let owned = self
            .owned
            .read()
            .await
            .get(&record.id)
            .cloned()
            .ok_or_else(|| anyhow!("refusing to delete an unowned DNS webhook record"))?;
        ensure!(
            owned.name.eq_ignore_ascii_case(&record.name) && owned.value == record.value,
            "refusing to delete a changed DNS webhook record"
        );
        self.client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .json(&WebhookRequest {
                action: "delete",
                id: Some(&record.id),
                name: &record.name,
                value: &record.value,
            })
            .send()
            .await?
            .error_for_status()?;
        self.owned.write().await.remove(&record.id);
        Ok(())
    }
    async fn defer_cleanup(&self, record: DnsRecord) {
        self.ledger.defer(record);
    }
    async fn retry_deferred_cleanups(&self, cancel: &CancellationToken) {
        run_cleanup_retries(self, &self.ledger, &self.owned, cancel).await;
    }
}
#[async_trait]
impl ReconcileUncertain for WebhookDnsProvider {
    /// The webhook protocol has no listing; ask it to delete by name/value
    /// (`id` null). A webhook that never created the record answers success
    /// for a no-op delete or an error, both of which are bounded by attempts.
    async fn reconcile_uncertain(&self, name: &str, value: &str) -> Result<Vec<DnsRecord>> {
        self.client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .json(&WebhookRequest {
                action: "delete",
                id: None,
                name,
                value,
            })
            .send()
            .await?
            .error_for_status()?;
        Ok(Vec::new())
    }
}
async fn wait_for_txt(
    resolver: Arc<dyn TxtResolver>,
    name: &str,
    value: &str,
    timeout: Duration,
    interval: Duration,
    cancel: &CancellationToken,
) -> Result<()> {
    ensure!(
        timeout > Duration::ZERO && interval > Duration::ZERO,
        "DNS propagation timeout and interval must be positive"
    );
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("DNS TXT propagation deadline exceeded for {name}")
        }
        let values = tokio::select! {
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            result = tokio::time::timeout(remaining, resolver.txt_values(name)) => result.context("DNS TXT propagation lookup timed out")??,
        };
        if values.iter().any(|v| v == value) {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("DNS TXT propagation deadline exceeded for {name}")
        }
        tokio::select! {
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            _ = tokio::time::sleep(interval.min(remaining)) => {}
        }
    }
}

/// Certificate delivered by an ACME order, after all validation.
#[derive(Clone)]
pub struct IssuedCertificate {
    pub domains: Vec<String>,
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
    pub not_after: SystemTime,
}
impl fmt::Debug for IssuedCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IssuedCertificate")
            .field("domains", &self.domains)
            .field("certificate_pem_len", &self.certificate_pem.len())
            .field("private_key_pem", &"[redacted]")
            .field("not_after", &self.not_after)
            .finish()
    }
}
#[async_trait]
pub trait CertificateSink: Send + Sync {
    async fn publish(
        &self,
        domains: &[String],
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<()>;
}

pub struct AcmeEngine {
    config: AcmeConfig,
    account: Account,
    http_challenges: Arc<HttpChallengeStore>,
    dns: Option<Arc<dyn DnsProvider>>,
}
impl AcmeEngine {
    /// Create an engine and restore/register its ACME account. The account
    /// file is bounded and atomically updated; private files are mode 0600.
    pub async fn new(
        config: AcmeConfig,
        http_challenges: Arc<HttpChallengeStore>,
        dns: Option<Arc<dyn DnsProvider>>,
    ) -> Result<Self> {
        config.validate()?;
        let domains = config.checked_domains()?;
        let directory = config.directory.url()?;
        if config.mode(&domains) == ChallengeMode::Dns01 {
            ensure!(dns.is_some(), "DNS-01 requires a configured DNS provider");
        }
        ensure!(
            !(config.certificate_path.is_some() ^ config.private_key_path.is_some()),
            "certificate and key paths must be configured together"
        );
        let (stored, key_der) = load_or_create_account(&config.account_path).await?;
        if let Some(previous_directory) = &stored.directory {
            ensure!(
                previous_directory == &directory,
                "ACME account belongs to a different directory"
            );
        }
        let builder = Account::builder_with_http(acme_http_client(config.ca_path.as_deref())?);
        let (account, credentials) = if let Some(credentials) = stored.credentials {
            ensure!(
                credentials.private_key().secret_pkcs8_der() == key_der.as_slice(),
                "account key and credentials do not match"
            );
            (builder.from_credentials(credentials).await?, None)
        } else {
            let key = Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(key_der.clone()))?;
            let result = if let Some(eab) = &config.eab {
                let external = ExternalAccountKey::new(eab.kid.clone(), &eab.key()?);
                let contacts = config
                    .contacts
                    .iter()
                    .map(|c| c.as_str())
                    .collect::<Vec<_>>();
                builder
                    .create(
                        &NewAccount {
                            contact: contacts.as_slice(),
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        directory.clone(),
                        Some(&external),
                    )
                    .await?
            } else {
                builder
                    .create_from_key(
                        (
                            key,
                            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone())),
                        ),
                        directory.clone(),
                    )
                    .await?
            };
            (result.0, Some(result.1))
        };
        if let Some(credentials) = credentials {
            persist_account_credentials(&config.account_path, credentials, directory).await?;
        }
        if !config.contacts.is_empty() {
            let contacts = config
                .contacts
                .iter()
                .map(|contact| contact.as_str())
                .collect::<Vec<_>>();
            tokio::time::timeout(Duration::from_secs(20), account.update_contacts(&contacts))
                .await
                .context("ACME contact update timed out")??;
        }
        Ok(Self {
            config,
            account,
            http_challenges,
            dns,
        })
    }
    pub fn http_challenges(&self) -> Arc<HttpChallengeStore> {
        self.http_challenges.clone()
    }
    pub async fn issue(&self, cancel: &CancellationToken) -> Result<IssuedCertificate> {
        let domains = self.config.checked_domains()?;
        if self.config.mode(&domains) == ChallengeMode::Dns01
            && let Some(provider) = &self.dns
        {
            // Clean up what earlier attempts could not before presenting new
            // records, so failed cleanups cannot accumulate into the receipt cap.
            provider.retry_deferred_cleanups(cancel).await;
        }
        let identifiers = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect::<Vec<_>>();
        let new_order = NewOrder::new(&identifiers);
        tracing::info!(identifiers = identifiers.len(), "ACME order starting");
        let mut order = tokio::select! {
            _ = cancel.cancelled() => bail!("ACME operation cancelled"),
            result = self.account.new_order(&new_order) => result?,
        };
        let mode = self.config.mode(&domains);
        let mut http_owned = Vec::new();
        let mut dns_owned = Vec::new();
        let challenge_result: Result<()> = async {
            let mut authorizations = order.authorizations();
            loop {
                let next = tokio::select! {
                    _ = cancel.cancelled() => bail!("ACME operation cancelled"),
                    result = authorizations.next() => result,
                };
                let Some(result) = next else { break };
                let mut authz = result?;
                if authz.status == AuthorizationStatus::Valid {
                    continue;
                }
                ensure!(
                    authz.status == AuthorizationStatus::Pending,
                    "unexpected ACME authorization status: {:?}",
                    authz.status
                );
                let challenge_type = if mode == ChallengeMode::Http01 {
                    ChallengeType::Http01
                } else {
                    ChallengeType::Dns01
                };
                let mut challenge = authz
                    .challenge(challenge_type)
                    .ok_or_else(|| anyhow!("ACME server did not offer the configured challenge"))?;
                let key_authorization = challenge.key_authorization();
                let identifier = challenge.identifier().to_string();
                tracing::info!(
                    identifier = %identifier,
                    challenge = if mode == ChallengeMode::Http01 { "http-01" } else { "dns-01" },
                    "ACME authorization pending"
                );
                if mode == ChallengeMode::Http01 {
                    let host = identifier.strip_prefix("*.").unwrap_or(&identifier);
                    // With a shared store this returns only once every
                    // instance can answer the token, and keeps the shared
                    // record alive until `cleanup`; a failure aborts the
                    // order here, before the CA is told the challenge is
                    // ready (`set_ready` below).
                    self.http_challenges
                        .insert(host, challenge.token.clone(), key_authorization.as_str())
                        .await?;
                    http_owned.push((host.to_owned(), challenge.token.clone()));
                    tracing::info!(identifier = %identifier, "ACME HTTP challenge presented");
                } else {
                    let provider = self.dns.as_ref().expect("checked in constructor");
                    let name = format!(
                        "_acme-challenge.{}",
                        identifier.strip_prefix("*.").unwrap_or(&identifier)
                    );
                    let record = provider
                        .present_cancellable(&name, &key_authorization.dns_value(), cancel)
                        .await?;
                    // Track the receipt before polling: a propagation timeout
                    // must still clean up the exact record we created.
                    dns_owned.push(record.clone());
                    tracing::info!(identifier = %identifier, "ACME DNS challenge presented");
                    provider
                        .wait_for_propagation(
                            &name,
                            &record.value,
                            self.config.dns_propagation_timeout,
                            self.config.dns_poll_interval,
                            cancel,
                        )
                        .await?;
                    tracing::info!(identifier = %identifier, "ACME DNS challenge propagated");
                }
                tokio::select! {
                    _ = cancel.cancelled() => bail!("ACME operation cancelled"),
                    result = challenge.set_ready() => result?,
                }
                tracing::info!(identifier = %identifier, "ACME challenge marked ready");
            }
            Ok(())
        }
        .await;
        if let Err(error) = challenge_result {
            self.cleanup(&http_owned, &dns_owned).await;
            return Err(error);
        }
        let retry = RetryPolicy::new()
            .initial_delay(Duration::from_millis(250))
            .backoff(2.0)
            .timeout(self.config.renewal.acme_timeout);
        let ready_result = tokio::select! {
            _ = cancel.cancelled() => { self.cleanup(&http_owned, &dns_owned).await; bail!("ACME operation cancelled") },
            result = order.poll_ready(&retry) => result
        };
        let ready = match ready_result {
            Ok(ready) => ready,
            Err(error) => {
                self.cleanup(&http_owned, &dns_owned).await;
                return Err(error.into());
            }
        };
        if ready != OrderStatus::Ready {
            self.cleanup(&http_owned, &dns_owned).await;
            bail!("ACME order did not become ready: {ready:?}");
        }
        tracing::info!("ACME order ready");
        let private_key_result = tokio::select! {
            _ = cancel.cancelled() => { self.cleanup(&http_owned, &dns_owned).await; bail!("ACME operation cancelled") },
            result = order.finalize() => result
        };
        let private_key = match private_key_result {
            Ok(key) => key,
            Err(error) => {
                self.cleanup(&http_owned, &dns_owned).await;
                return Err(error.into());
            }
        };
        let certificate_result = tokio::select! {
            _ = cancel.cancelled() => { self.cleanup(&http_owned, &dns_owned).await; bail!("ACME operation cancelled") },
            result = order.poll_certificate(&retry) => result
        };
        let certificate = match certificate_result {
            Ok(cert) => cert,
            Err(error) => {
                self.cleanup(&http_owned, &dns_owned).await;
                return Err(error.into());
            }
        };
        tracing::info!("ACME certificate received");
        self.cleanup(&http_owned, &dns_owned).await;
        // Parsing and key construction run off the async executor.
        tokio::task::spawn_blocking(move || {
            validate_certificate(&domains, certificate.as_bytes(), private_key.as_bytes())
        })
        .await
        .context("certificate validation task failed")?
    }
    pub async fn issue_and_publish(
        &self,
        sink: &dyn CertificateSink,
        cancel: &CancellationToken,
    ) -> Result<IssuedCertificate> {
        let cert = self.issue(cancel).await?;
        if let (Some(cert_path), Some(key_path)) =
            (&self.config.certificate_path, &self.config.private_key_path)
        {
            atomic_write(cert_path, cert.certificate_pem.clone(), 0o600).await?;
            atomic_write(key_path, cert.private_key_pem.clone(), 0o600).await?;
        }
        sink.publish(&cert.domains, &cert.certificate_pem, &cert.private_key_pem)
            .await?;
        Ok(cert)
    }
    pub async fn needs_renewal(&self) -> Result<bool> {
        let Some(path) = &self.config.certificate_path else {
            return Ok(true);
        };
        let Some(key_path) = &self.config.private_key_path else {
            return Ok(true);
        };
        let bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        let key = match fs::read(key_path).await {
            Ok(key) => key,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
            Err(error) => return Err(error.into()),
        };
        let domains = self.config.checked_domains()?;
        let validated =
            tokio::task::spawn_blocking(move || validate_certificate(&domains, &bytes, &key))
                .await
                .context("certificate validation task failed")?;
        let expiry = match validated {
            Ok(certificate) => certificate.not_after,
            Err(_) => return Ok(true),
        };
        Ok(expiry <= SystemTime::now() + self.config.renewal.renew_before)
    }
    /// Run renewal until cancelled. Failed attempts use capped exponential backoff.
    pub async fn run(&self, sink: &dyn CertificateSink, cancel: CancellationToken) -> Result<()> {
        let mut retry = self.config.renewal.retry_initial;
        loop {
            if self.needs_renewal().await? {
                match self.issue_and_publish(sink, &cancel).await {
                    Ok(_) => retry = self.config.renewal.retry_initial,
                    Err(error) => {
                        tracing::warn!(%error, "ACME issuance failed; retrying with backoff");
                        tokio::select! { _ = cancel.cancelled() => bail!("ACME renewal cancelled"), _ = tokio::time::sleep(retry) => {} }
                        retry = retry.saturating_mul(2).min(self.config.renewal.retry_max);
                        continue;
                    }
                }
            }
            tokio::select! { _ = cancel.cancelled() => return Ok(()), _ = tokio::time::sleep(self.config.renewal.check_interval) => {} }
        }
    }
    async fn cleanup(&self, http: &[(String, String)], dns: &[DnsRecord]) {
        self.http_challenges.cleanup_many(http).await;
        if let Some(provider) = &self.dns {
            // Cleanup is bounded and parallel across the maximum 100 ACME
            // identifiers. Cloudflare cleanup verifies a record with GET
            // before DELETE, so allow both requests within one 20-second
            // overall bound while keeping shutdown under its 35-second grace.
            let provider = provider.clone();
            let cleanup = dns.iter().cloned().map(|record| {
                let provider = provider.clone();
                async move {
                    let result = tokio::time::timeout(
                        Duration::from_secs(20),
                        provider.cleanup(record.clone()),
                    )
                    .await;
                    (record, result)
                }
            });
            for (record, result) in futures_util::future::join_all(cleanup).await {
                match result {
                    Ok(Ok(())) => continue,
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "ACME DNS cleanup failed; queued for retry")
                    }
                    Err(_) => tracing::warn!("ACME DNS cleanup timed out; queued for retry"),
                }
                provider.defer_cleanup(record).await;
            }
        }
        tracing::info!(
            http = http.len(),
            dns = dns.len(),
            "ACME challenge cleanup finished"
        );
    }
}

/// Parse and validate a returned chain/key before any publication callback.
pub fn validate_certificate(
    domains: &[String],
    cert: &[u8],
    key: &[u8],
) -> Result<IssuedCertificate> {
    ensure!(
        cert.len() <= MAX_PEM && key.len() <= MAX_PEM,
        "certificate material exceeds 1 MiB"
    );
    let chain = rustls_pemfile::certs(&mut std::io::Cursor::new(cert))
        .collect::<std::io::Result<Vec<_>>>()?;
    ensure!(
        !chain.is_empty(),
        "ACME returned an empty certificate chain"
    );
    let private = rustls_pemfile::private_key(&mut std::io::Cursor::new(key))?
        .context("ACME returned no private key")?;
    let certified = rustls::sign::CertifiedKey::from_der(
        chain.clone(),
        private,
        &rustls::crypto::ring::default_provider(),
    )?;
    let parsed = rustls::server::ParsedCertificate::try_from(certified.end_entity_cert()?)?;
    let (_, x509) = x509_parser::parse_x509_certificate(chain[0].as_ref())
        .map_err(|e| anyhow!("invalid issued certificate: {e}"))?;
    let san_names = x509
        .subject_alternative_name()
        .map_err(|e| anyhow!("invalid subject alternative names: {e}"))?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => {
                        Some(name.to_ascii_lowercase())
                    }
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    for domain in domains {
        if let Some(suffix) = domain.strip_prefix("*.") {
            ensure!(
                san_names.iter().any(|name| name == &format!("*.{suffix}")),
                "issued certificate does not contain the requested wildcard SAN"
            );
        }
        let probe = domain
            .strip_prefix("*.")
            .map(|s| format!("hangang-acme-check.{s}"))
            .unwrap_or_else(|| domain.clone());
        let name = rustls::pki_types::ServerName::try_from(probe)?;
        rustls::client::verify_server_name(&parsed, &name)
            .context("issued certificate does not cover requested domain")?;
    }
    let timestamp = x509.validity().not_after.timestamp();
    let not_before_timestamp = x509.validity().not_before.timestamp();
    let not_before = UNIX_EPOCH
        .checked_add(Duration::from_secs(not_before_timestamp.max(0) as u64))
        .ok_or_else(|| anyhow!("invalid certificate not-before"))?;
    ensure!(
        not_before <= SystemTime::now(),
        "issued certificate is not yet valid"
    );
    let not_after = UNIX_EPOCH
        .checked_add(Duration::from_secs(timestamp.max(0) as u64))
        .ok_or_else(|| anyhow!("invalid certificate expiry"))?;
    ensure!(
        not_after > SystemTime::now(),
        "issued certificate is already expired"
    );
    Ok(IssuedCertificate {
        domains: domains.to_vec(),
        certificate_pem: cert.to_vec(),
        private_key_pem: key.to_vec(),
        not_after,
    })
}
#[derive(Serialize, Deserialize)]
struct StoredAccount {
    key_pkcs8_der: String,
    #[serde(default)]
    credentials: Option<AccountCredentials>,
    #[serde(default)]
    directory: Option<String>,
}
async fn load_or_create_account(path: &Path) -> Result<(StoredAccount, Vec<u8>)> {
    match fs::metadata(path).await {
        Ok(_) => {
            let bytes = bounded_read(path, MAX_ACCOUNT_FILE as usize).await?;
            let stored: StoredAccount =
                serde_json::from_slice(&bytes).context("parse ACME account file")?;
            let key = URL_SAFE_NO_PAD
                .decode(&stored.key_pkcs8_der)
                .context("decode ACME account key")?;
            Key::from_pkcs8_der(PrivatePkcs8KeyDer::from(key.clone()))?;
            Ok((stored, key))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let (_, key) = Key::generate_pkcs8()?;
            let key = key.secret_pkcs8_der().to_vec();
            let stored = StoredAccount {
                key_pkcs8_der: URL_SAFE_NO_PAD.encode(&key),
                credentials: None,
                directory: None,
            };
            atomic_write(path, serde_json::to_vec(&stored)?, 0o600).await?;
            Ok((stored, key))
        }
        Err(error) => Err(error.into()),
    }
}
async fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let file = fs::File::open(path).await?;
    file.take(limit as u64 + 1).read_to_end(&mut bytes).await?;
    ensure!(
        bytes.len() <= limit,
        "ACME file exceeds configured size limit"
    );
    Ok(bytes)
}
async fn persist_account_credentials(
    path: &Path,
    credentials: AccountCredentials,
    directory: String,
) -> Result<()> {
    let key = credentials.private_key().secret_pkcs8_der();
    atomic_write(
        path,
        serde_json::to_vec(&StoredAccount {
            key_pkcs8_der: URL_SAFE_NO_PAD.encode(key),
            credentials: Some(credentials),
            directory: Some(directory),
        })?,
        0o600,
    )
    .await
}
async fn atomic_write(path: &Path, bytes: Vec<u8>, mode: u32) -> Result<()> {
    ensure!(bytes.len() <= MAX_PEM, "persisted material exceeds 1 MiB");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).await?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("acme"),
        std::process::id(),
        suffix
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true).mode(mode);
    use std::io::Write;
    let mut file = options.open(&tmp)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path).await?;
    if let Ok(dir) = fs::File::open(parent).await {
        let _ = dir.sync_all().await;
    }
    Ok(())
}
#[cfg(unix)]
trait OpenOptionsExt {
    fn mode(&mut self, mode: u32) -> &mut Self;
}
#[cfg(unix)]
impl OpenOptionsExt for std::fs::OpenOptions {
    fn mode(&mut self, mode: u32) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, mode);
        self
    }
}
#[cfg(not(unix))]
trait OpenOptionsExt {
    fn mode(&mut self, _: u32) -> &mut Self;
}
#[cfg(not(unix))]
impl OpenOptionsExt for std::fs::OpenOptions {
    fn mode(&mut self, _: u32) -> &mut Self {
        self
    }
}

#[cfg(test)]
mod receipt_limits {
    use super::*;

    struct SlowWithdrawalStore {
        withdrawals: std::sync::atomic::AtomicUsize,
    }
    #[async_trait]
    impl ConfigStore for SlowWithdrawalStore {
        async fn load_latest(&self) -> StoreResult<Option<crate::config_store::Stored>> {
            unreachable!()
        }
        async fn bootstrap(
            &self,
            _: crate::config::Config,
        ) -> StoreResult<crate::config_store::Stored> {
            unreachable!()
        }
        async fn compare_and_swap(
            &self,
            _: &str,
            _: u64,
            _: crate::config::Config,
        ) -> StoreResult<crate::config_store::CasResult> {
            unreachable!()
        }
        async fn publish_challenge(&self, _: &str, _: &str, _: Duration) -> StoreResult<()> {
            Ok(())
        }
        async fn lookup_challenge(&self, _: &str) -> StoreResult<Option<String>> {
            Ok(None)
        }
        async fn withdraw_challenge(&self, _: &str) -> StoreResult<()> {
            self.withdrawals
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(10)).await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn http_cleanup_is_parallel_bounded_and_abandoned_writes_keep_their_locks() {
        let backend = Arc::new(SlowWithdrawalStore {
            withdrawals: std::sync::atomic::AtomicUsize::new(0),
        });
        let challenges = HttpChallengeStore::default()
            .with_shared(backend.clone())
            .with_shared_mutation_bounds(Duration::from_millis(10), Duration::from_millis(100));
        let owned = (0..24)
            .map(|index| ("example.test".to_owned(), format!("token_{index}")))
            .collect::<Vec<_>>();
        for (_, token) in &owned {
            challenges
                .insert("example.test", token, format!("{token}.thumb"))
                .await
                .unwrap();
        }

        let started = Instant::now();
        challenges.cleanup_many(&owned).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "24 unanswered withdrawals should finish in three concurrent batches"
        );
        assert!(challenges.entries.read().await.is_empty());
        assert_eq!(
            backend
                .withdrawals
                .load(std::sync::atomic::Ordering::SeqCst),
            24
        );

        let error = challenges
            .insert("example.test", "token_0", "replacement.thumb")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("previous publication or withdrawal"),
            "an abandoned withdrawal must retain the token lock: {error}"
        );
        assert!(challenges.entries.read().await.is_empty());
    }

    #[tokio::test]
    async fn exhausted_cleanup_receipts_refuse_new_external_mutations() {
        let records: HashMap<_, _> = (0..4096)
            .map(|id| {
                let id = id.to_string();
                (
                    id.clone(),
                    DnsRecord {
                        id,
                        name: "_acme-challenge.example.test".into(),
                        value: "proof".into(),
                    },
                )
            })
            .collect();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let cloudflare = CloudflareDnsProvider::new("abc", "test").with_endpoint(&endpoint);
        *cloudflare.owned.write().await = records.clone();
        assert!(
            cloudflare
                .present("_acme-challenge.example.test", "proof")
                .await
                .unwrap_err()
                .to_string()
                .contains("receipt capacity")
        );
        let webhook = WebhookDnsProvider::new(&endpoint, "test");
        *webhook.owned.write().await = records;
        assert!(
            webhook
                .present("_acme-challenge.example.test", "proof")
                .await
                .unwrap_err()
                .to_string()
                .contains("receipt capacity")
        );
    }
}

#[cfg(test)]
mod cloudflare_receipt_recovery {
    use super::*;
    use hyper::{
        Method, Request, Response, StatusCode, body::Incoming, server::conn::http1,
        service::service_fn,
    };
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;

    #[derive(Default)]
    struct MockState {
        records: HashMap<String, (String, String)>,
        fail_next_delete: bool,
    }

    #[tokio::test]
    async fn failed_cleanup_retries_and_restart_adopts_only_exact_duplicate() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(tokio::sync::Mutex::new(MockState::default()));
        let stop = CancellationToken::new();
        let server = tokio::spawn({
            let state = state.clone();
            let stop = stop.clone();
            async move {
                loop {
                    let accepted = tokio::select! { _ = stop.cancelled() => break, accepted = listener.accept() => accepted.unwrap() };
                    let state = state.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let state = state.clone();
                            async move {
                                let method = request.method().clone();
                                let path = request.uri().path().to_owned();
                                let body = request.into_body().collect().await.unwrap().to_bytes();
                                let mut state = state.lock().await;
                                let mut status = StatusCode::OK;
                                let result = if method == Method::POST {
                                    let input: serde_json::Value =
                                        serde_json::from_slice(&body).unwrap();
                                    let name = input["name"].as_str().unwrap().to_owned();
                                    let value = input["content"].as_str().unwrap().to_owned();
                                    if state
                                        .records
                                        .values()
                                        .any(|pair| pair == &(name.clone(), value.clone()))
                                    {
                                        status = StatusCode::BAD_REQUEST;
                                        serde_json::json!({"success":false,"result":null})
                                    } else {
                                        let id = format!("r{}", state.records.len() + 1);
                                        state
                                            .records
                                            .insert(id.clone(), (name.clone(), value.clone()));
                                        serde_json::json!({"success":true,"result":{"id":id,"name":name,"content":value}})
                                    }
                                } else if method == Method::GET && path.ends_with("/dns_records") {
                                    let records: Vec<_> = state.records.iter().map(|(id,(name,value))|serde_json::json!({"id":id,"name":name,"content":value})).collect();
                                    serde_json::json!({"success":true,"result":records})
                                } else {
                                    let id = path.rsplit('/').next().unwrap();
                                    if method == Method::DELETE && state.fail_next_delete {
                                        state.fail_next_delete = false;
                                        status = StatusCode::INTERNAL_SERVER_ERROR;
                                        serde_json::json!({"success":false,"result":null})
                                    } else if method == Method::DELETE {
                                        state.records.remove(id);
                                        serde_json::json!({"success":true,"result":null})
                                    } else if let Some((name, value)) = state.records.get(id) {
                                        serde_json::json!({"success":true,"result":{"id":id,"name":name,"content":value}})
                                    } else {
                                        status = StatusCode::NOT_FOUND;
                                        serde_json::json!({"success":false,"result":null})
                                    }
                                };
                                let response = Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(result.to_string())))
                                    .unwrap();
                                Ok::<_, Infallible>(response)
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(accepted.0), service)
                            .await;
                    });
                }
            }
        });
        let name = "_acme-challenge.example.test";
        let provider = CloudflareDnsProvider::new("abc", "fixture").with_endpoint(&endpoint);
        let first = provider.present(name, "first-proof").await.unwrap();
        state.lock().await.fail_next_delete = true;
        assert!(provider.cleanup(first.clone()).await.is_err());
        provider.defer_cleanup(first).await;
        provider
            .retry_deferred_cleanups(&CancellationToken::new())
            .await;
        assert!(
            state.lock().await.records.is_empty(),
            "same-process retry must remove failed cleanup"
        );

        let second = provider.present(name, "second-proof").await.unwrap();
        state.lock().await.fail_next_delete = true;
        assert!(provider.cleanup(second.clone()).await.is_err());
        drop(provider);
        let restarted = CloudflareDnsProvider::new("abc", "fixture").with_endpoint(&endpoint);
        let adopted = restarted.present(name, "second-proof").await.unwrap();
        assert_eq!(
            adopted, second,
            "restart must recover exact duplicate receipt"
        );
        restarted.cleanup(adopted).await.unwrap();
        assert!(state.lock().await.records.is_empty());
        stop.cancel();
        server.await.unwrap();
    }
}
