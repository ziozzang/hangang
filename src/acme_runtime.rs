//! Opt-in ACME runtime. Certificate material is committed as one private bundle.
use crate::{
    acme::{self, CertificateSink, DnsProvider, IssuedCertificate},
    config_store::ConfigStore,
    tls::{ReloadingTls, SniCertificate},
};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{io::AsyncReadExt, sync::Mutex, task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;

/// How often the bundle file is checked for a replacement written by another
/// instance sharing the bundle path.
const BUNDLE_POLL: Duration = Duration::from_secs(5);
const MAX_BUNDLE: usize = 3 * 1024 * 1024;
/// Attempt outcome of an instance that is not the account lock holder.
const LOCK_HELD_ELSEWHERE: &str = "ACME account is being managed by another process";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(flatten)]
    acme: acme::AcmeFileConfig,
    dns: Option<DnsConfig>,
}
#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
enum DnsConfig {
    Cloudflare {
        zone_id: String,
        token_file: PathBuf,
    },
    Webhook {
        endpoint: String,
        token_file: PathBuf,
    },
}
struct Settings {
    config: acme::AcmeConfig,
    dns: Option<Arc<dyn DnsProvider>>,
    bundle: PathBuf,
    fingerprint: Vec<u8>,
}
async fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    tokio::fs::File::open(path)
        .await?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(bytes.len() <= limit, "ACME file exceeds size limit");
    Ok(bytes)
}
async fn settings(bytes: &[u8], http_enabled: bool) -> Result<Settings> {
    use sha2::{Digest, Sha256};
    let mut fingerprint = Sha256::new();
    fingerprint.update(bytes);
    let file: FileConfig =
        serde_json::from_slice(bytes).context("invalid ACME runtime configuration")?;
    let mut config = file.acme.into_config()?;
    if let Some(path) = &config.ca_path {
        crate::tls::client_config(Some(path))?;
    }
    let dns_mode = config.challenge == acme::ChallengeMode::Dns01
        || config.domains.iter().any(|d| d.starts_with("*."));
    ensure!(
        dns_mode || http_enabled,
        "HTTP-01 requires --acme-http-listen"
    );
    let dns: Option<Arc<dyn DnsProvider>> = match file.dns {
        None => None,
        Some(provider) => {
            let path = match &provider {
                DnsConfig::Cloudflare { token_file, .. }
                | DnsConfig::Webhook { token_file, .. } => token_file,
            };
            let token = String::from_utf8(bounded(path, 8192).await?)?
                .trim()
                .to_owned();
            hyper::header::HeaderValue::from_str(&format!("Bearer {token}"))
                .context("DNS credential is not a valid authorization value")?;
            fingerprint.update(token.as_bytes());
            ensure!(!token.is_empty(), "DNS provider credential file is empty");
            Some(match provider {
                DnsConfig::Cloudflare { zone_id, .. } => {
                    ensure!(
                        !zone_id.is_empty() && zone_id.bytes().all(|b| b.is_ascii_hexdigit()),
                        "invalid Cloudflare zone ID"
                    );
                    Arc::new(acme::CloudflareDnsProvider::new(zone_id, token))
                }
                DnsConfig::Webhook { endpoint, .. } => {
                    let url: reqwest::Url = endpoint.parse()?;
                    ensure!(
                        url.scheme() == "https"
                            && url.username().is_empty()
                            && url.password().is_none(),
                        "DNS webhook requires HTTPS without embedded credentials"
                    );
                    Arc::new(acme::WebhookDnsProvider::new(endpoint, token))
                }
            })
        }
    };
    ensure!(!dns_mode || dns.is_some(), "DNS-01 requires a DNS provider");
    // Never publish a separately committed certificate/key pair. The runtime's
    // single bundle is the restart authority; the module's pair API is unused.
    ensure!(
        config.certificate_path.is_none() && config.private_key_path.is_none(),
        "runtime ACME uses an atomic account-adjacent TLS bundle; omit certificate_path/private_key_path"
    );
    config.certificate_path = None;
    config.private_key_path = None;
    let bundle = config.account_path.with_extension("tls.json");
    Ok(Settings {
        config,
        dns,
        bundle,
        fingerprint: fingerprint.finalize().to_vec(),
    })
}
#[derive(Serialize, Deserialize)]
struct Bundle {
    domains: Vec<String>,
    certificate_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
    expires: u64,
}
#[derive(Clone, Default, Serialize)]
pub struct Status {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub expires_unix: Option<u64>,
    pub phase: String,
    /// A validated, unexpired certificate for the configured domains is
    /// loaded in the public resolver. False until the first bundle is
    /// restored or issued; HTTPS handshakes fail while it is false.
    pub tls_available: bool,
    /// SHA-256 (hex) of the bundle file whose material is loaded; empty when
    /// none is. Instances sharing a bundle path converge on the same value.
    pub bundle_digest: String,
    /// Why the last issuance attempt failed (full error chain); cleared by
    /// the next successful attempt. Instances that lose the account lock to
    /// another process report that here as well.
    pub last_error: Option<String>,
}

/// What the public resolver currently holds.
#[derive(Clone)]
struct Loaded {
    digest: [u8; 32],
    domains: Vec<String>,
    expires: u64,
}
/// Outcome of reading the bundle: the digest of the material that was read.
enum Restored {
    Loaded,
    Rejected(Option<[u8; 32]>, anyhow::Error),
}

pub struct Runtime {
    path: PathBuf,
    http_enabled: bool,
    pub challenges: Arc<acme::HttpChallengeStore>,
    tls: Arc<ReloadingTls>,
    pub status: Arc<std::sync::RwLock<Status>>,
    task: Mutex<Option<(CancellationToken, JoinHandle<()>)>>,
    /// Material issued by an earlier attempt whose publication failed. It is
    /// published before any new order is created so a broken bundle
    /// destination cannot turn into repeated CA issuances.
    pending: std::sync::Mutex<Option<PendingIssuance>>,
    /// Material currently published to the resolver, if any.
    loaded: std::sync::Mutex<Option<Loaded>>,
    /// Bundle replacements rejected by parsing since start; each distinct
    /// bad bundle counts once.
    rejected_bundles: std::sync::atomic::AtomicU64,
    bundle_poll: Duration,
}
struct PendingIssuance {
    issued: IssuedCertificate,
    expires: u64,
}
impl Runtime {
    /// `store`: the shared configuration store, when one is configured. Every
    /// HTTP-01 token this instance publishes is shared through it so any
    /// instance behind the load balancer can answer the CA.
    pub async fn new(
        path: PathBuf,
        http_enabled: bool,
        tls: Arc<ReloadingTls>,
        store: Option<Arc<dyn ConfigStore>>,
    ) -> Result<Arc<Self>> {
        let bytes = bounded(&path, 256 * 1024).await?;
        let config = settings(&bytes, http_enabled).await?;
        let challenges = match store {
            Some(store) => acme::HttpChallengeStore::default().with_shared(store),
            None => acme::HttpChallengeStore::default(),
        };
        let runtime = Arc::new(Self {
            path,
            http_enabled,
            challenges: Arc::new(challenges),
            tls,
            status: Arc::new(std::sync::RwLock::new(Status {
                enabled: true,
                phase: "pending".into(),
                ..Default::default()
            })),
            task: Mutex::new(None),
            pending: std::sync::Mutex::new(None),
            loaded: std::sync::Mutex::new(None),
            rejected_bundles: std::sync::atomic::AtomicU64::new(0),
            bundle_poll: BUNDLE_POLL,
        });
        runtime.restore(&config).await;
        Ok(runtime)
    }
    /// Bundle replacements rejected by parsing since start; identical bad
    /// material is parsed once.
    pub fn rejected_bundle_reloads(&self) -> u64 {
        self.rejected_bundles
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub async fn start(self: &Arc<Self>) {
        let mut task = self.task.lock().await;
        if task.is_some() {
            return;
        }
        let cancel = CancellationToken::new();
        let this = self.clone();
        let child = cancel.clone();
        *task = Some((
            cancel,
            tokio::spawn(async move {
                this.run(child).await;
            }),
        ));
    }
    /// Freeze issuance before passing the challenge listener to another generation.
    pub async fn stop(&self) {
        let mut task = self.task.lock().await;
        if let Some((cancel, handle)) = task.take() {
            cancel.cancel();
            let _ = handle.await;
        }
    }
    /// Load the bundle from disk into the resolver. On failure the resolver
    /// and the loaded-material record are left as they were; status reports
    /// `pending` so an issuance is scheduled.
    async fn restore(&self, settings: &Settings) -> Restored {
        let restored = self.load_bundle(settings).await;
        if let Restored::Rejected(..) = &restored {
            self.mark_pending(settings);
        }
        restored
    }
    /// Read, validate and publish the bundle without changing the issuance
    /// state on failure: the bundle watcher must never schedule an order
    /// because another writer left something unusable at the shared path.
    async fn load_bundle(&self, settings: &Settings) -> Restored {
        let bytes = match bounded(&settings.bundle, MAX_BUNDLE).await {
            Ok(bytes) => bytes,
            Err(error) => return Restored::Rejected(None, error),
        };
        let digest = digest(&bytes);
        let domains = settings.config.domains.clone();
        // Parsing and key construction run off the async executor.
        let parsed =
            tokio::task::spawn_blocking(move || -> Result<(Vec<String>, u64, ServerConfig)> {
                let bundle: Bundle = serde_json::from_slice(&bytes)?;
                ensure!(
                    bundle.domains == domains,
                    "stored certificate domain set changed"
                );
                let validated = acme::validate_certificate(
                    &bundle.domains,
                    &bundle.certificate_pem,
                    &bundle.private_key_pem,
                )?;
                let expires = validated.not_after.duration_since(UNIX_EPOCH)?.as_secs();
                ensure!(
                    bundle.expires == expires,
                    "stored certificate expiry metadata mismatch"
                );
                let config = crate::tls::sni_server_config(vec![SniCertificate {
                    hosts: bundle.domains.clone(),
                    default: false,
                    cert_pem: bundle.certificate_pem,
                    key_pem: bundle.private_key_pem,
                }])?;
                Ok((bundle.domains, expires, config))
            })
            .await
            .context("bundle validation task failed")
            .and_then(|result| result);
        match parsed {
            Ok((domains, expires, config)) => {
                self.publish_loaded(
                    config,
                    Loaded {
                        digest,
                        domains,
                        expires,
                    },
                );
                Restored::Loaded
            }
            Err(error) => Restored::Rejected(Some(digest), error),
        }
    }
    /// Replace the resolver with validated material and report it.
    fn publish_loaded(&self, config: ServerConfig, loaded: Loaded) {
        self.tls.current.store(Arc::new(config));
        *self.loaded.lock().expect("loaded lock") = Some(loaded.clone());
        *self.status.write().expect("status lock") = Status {
            enabled: true,
            domains: loaded.domains,
            expires_unix: Some(loaded.expires),
            phase: "ready".into(),
            tls_available: loaded.expires > now(),
            bundle_digest: hex(&loaded.digest),
            last_error: None,
        };
    }
    fn mark_pending(&self, settings: &Settings) {
        let (tls_available, bundle_digest) = self.availability(settings);
        let mut status = self.status.write().expect("status lock");
        status.phase = "pending".into();
        status.expires_unix = None;
        status.domains = settings.config.domains.clone();
        status.tls_available = tls_available;
        status.bundle_digest = bundle_digest;
    }
    /// Whether the resolver holds an unexpired certificate for exactly the
    /// configured domains, and the digest of what it holds.
    fn availability(&self, settings: &Settings) -> (bool, String) {
        match self.loaded.lock().expect("loaded lock").as_ref() {
            Some(loaded) => (
                loaded.domains == settings.config.domains && loaded.expires > now(),
                hex(&loaded.digest),
            ),
            None => (false, String::new()),
        }
    }
    fn loaded_digest(&self) -> Option<[u8; 32]> {
        self.loaded
            .lock()
            .expect("loaded lock")
            .as_ref()
            .map(|loaded| loaded.digest)
    }
    /// One bundle-watcher tick: a bundle whose digest differs from the loaded
    /// material (and from the last rejected replacement) is loaded, so a
    /// renewal written by another instance is served without an order here.
    /// A rejected replacement is logged and remembered but changes nothing
    /// else; this instance's own renewal schedule is the only thing that
    /// places orders. Expiry of the loaded material is reflected in
    /// `tls_available`.
    async fn watch_bundle(&self, settings: &Settings, rejected: &mut Option<[u8; 32]>) {
        let on_disk = bundle_digest_on_disk(&settings.bundle).await;
        if let Some(digest) = on_disk
            && Some(digest) != self.loaded_digest()
            && Some(digest) != *rejected
        {
            match self.load_bundle(settings).await {
                Restored::Loaded => {
                    *rejected = None;
                    tracing::info!(
                        bundle = %settings.bundle.display(),
                        "TLS bundle replaced on disk; serving the new certificate"
                    );
                }
                Restored::Rejected(read, error) => {
                    *rejected = read.or(Some(digest));
                    self.rejected_bundles
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tracing::warn!(
                        %error,
                        bundle = %settings.bundle.display(),
                        "TLS bundle replaced on disk but rejected; keeping the previous certificate"
                    );
                }
            }
        }
        let (tls_available, bundle_digest) = self.availability(settings);
        let mut status = self.status.write().expect("status lock");
        status.tls_available = tls_available;
        status.bundle_digest = bundle_digest;
    }
    async fn run(self: Arc<Self>, cancel: CancellationToken) {
        let mut current: Option<Arc<Settings>> = None;
        let mut flight: Option<(CancellationToken, JoinHandle<Result<()>>)> = None;
        let mut due = 0;
        let mut cleanup_due = 0;
        let mut backoff = 5u64;
        let mut bundle_due = Instant::now() + self.bundle_poll;
        let mut rejected_bundle: Option<[u8; 32]> = None;
        loop {
            if cancel.is_cancelled() {
                if let Some((child, handle)) = flight.take() {
                    child.cancel();
                    let _ = handle.await;
                }
                return;
            }
            let candidate: Result<Settings> = async {
                let bytes = bounded(&self.path, 256 * 1024).await?;
                settings(&bytes, self.http_enabled).await
            }
            .await;
            match candidate {
                Ok(value) => {
                    if current
                        .as_ref()
                        .is_none_or(|old| old.fingerprint != value.fingerprint)
                    {
                        if let Some((child, handle)) = flight.take() {
                            child.cancel();
                            let _ = handle.await;
                        }
                        self.restore(&value).await;
                        rejected_bundle = None;
                        bundle_due = Instant::now() + self.bundle_poll;
                        backoff = value.config.renewal.retry_initial.as_secs().max(1);
                        current = Some(Arc::new(value));
                        due = 0;
                    } else if self.status.read().expect("status lock").phase
                        == "configuration-error"
                    {
                        self.status.write().expect("status lock").phase =
                            if flight.is_some() { "issuing" } else { "ready" }.into();
                    }
                }
                Err(_) => {
                    self.status.write().expect("status lock").phase = "configuration-error".into()
                }
            }
            if flight
                .as_ref()
                .is_some_and(|(_, handle)| handle.is_finished())
            {
                let (_, handle) = flight.take().expect("finished task");
                let result = handle.await;
                let settings = current.as_ref().expect("active settings");
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(format!("{error:#}")),
                    Err(error) => Some(format!("issuance task failed: {error}")),
                };
                match failure {
                    None => {
                        backoff = settings.config.renewal.retry_initial.as_secs().max(1);
                        due =
                            now().saturating_add(settings.config.renewal.check_interval.as_secs());
                        self.status.write().expect("status lock").last_error = None;
                    }
                    Some(error) => {
                        // Losing the account lock to another instance is the
                        // normal follower path; anything else is a real failure.
                        if error.starts_with(LOCK_HELD_ELSEWHERE) {
                            tracing::info!(%error, "ACME issuance deferred to the lock holder");
                        } else {
                            tracing::warn!(%error, "ACME issuance attempt failed; retrying with backoff");
                        }
                        let mut status = self.status.write().expect("status lock");
                        status.phase = "retrying".into();
                        status.last_error = Some(error);
                        drop(status);
                        due = now().saturating_add(backoff);
                        backoff = backoff
                            .saturating_mul(2)
                            .min(settings.config.renewal.retry_max.as_secs().max(1));
                    }
                }
            }
            if let Some(settings) = &current
                && let Some(provider) = &settings.dns
                && flight.is_none()
                && now() >= cleanup_due
            {
                // Renewal tick: retry DNS cleanups that failed after an earlier
                // issuance even when no certificate work is due. Bounded by the
                // provider's own per-call timeouts and a hard cap here.
                tokio::select! {
                    _ = cancel.cancelled() => {}
                    _ = tokio::time::timeout(Duration::from_secs(10), provider.retry_deferred_cleanups(&cancel)) => {}
                }
                cleanup_due = now().saturating_add(
                    settings
                        .config
                        .renewal
                        .check_interval
                        .as_secs()
                        .clamp(60, 3600),
                );
            }
            if let Some(settings) = &current
                && Instant::now() >= bundle_due
            {
                self.watch_bundle(settings, &mut rejected_bundle).await;
                bundle_due = Instant::now() + self.bundle_poll;
            }
            if let Some(settings) = &current {
                let renew_at = self
                    .status
                    .read()
                    .expect("status lock")
                    .expires_unix
                    .unwrap_or(0)
                    .saturating_sub(settings.config.renewal.renew_before.as_secs());
                if flight.is_none() && now() >= due && now() >= renew_at {
                    let settings = settings.clone();
                    let this = self.clone();
                    let child = cancel.child_token();
                    let operation = child.clone();
                    flight = Some((
                        child,
                        tokio::spawn(async move { this.attempt(&settings, &operation).await }),
                    ));
                }
            }
            tokio::select! {_ = cancel.cancelled() => {}, _ = tokio::time::sleep(Duration::from_millis(500)) => {}}
        }
    }
    async fn attempt(&self, settings: &Settings, cancel: &CancellationToken) -> Result<()> {
        let config = settings.config.clone();
        let challenges = self.challenges.clone();
        let dns = settings.dns.clone();
        self.attempt_with(settings, cancel, move |cancel| async move {
            let engine = tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                result = tokio::time::timeout(
                    Duration::from_secs(8),
                    acme::AcmeEngine::new(config, challenges, dns),
                ) => result??,
            };
            engine.issue(&cancel).await.map(Some)
        })
        .await
    }
    /// One issuance attempt with an injectable issuer (`None` from the issuer
    /// means it was cancelled). Order of operations matters: previously issued
    /// but unpublished material is published first, and the bundle destination
    /// is validated before a new ACME order is created.
    async fn attempt_with<F, Fut>(
        &self,
        settings: &Settings,
        cancel: &CancellationToken,
        issue: F,
    ) -> Result<()>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: std::future::Future<Output = Result<Option<IssuedCertificate>>>,
    {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(settings.config.account_path.with_extension("acme.lock"))?;
        lock.try_lock().context(LOCK_HELD_ELSEWHERE)?;
        // Another process may have renewed while we waited for the account lock.
        self.restore(settings).await;
        let already_current = self
            .status
            .read()
            .expect("status lock")
            .expires_unix
            .is_some_and(|expiry| {
                expiry.saturating_sub(settings.config.renewal.renew_before.as_secs()) > now()
            });
        if already_current {
            self.pending.lock().expect("pending lock").take();
            return Ok(());
        }
        if let Some(pending) = self.take_pending(settings) {
            self.status.write().expect("status lock").phase = "publishing".into();
            let sink = Sink {
                runtime: self,
                path: &settings.bundle,
                expires: pending.expires,
            };
            let published = sink
                .publish(
                    &pending.issued.domains,
                    &pending.issued.certificate_pem,
                    &pending.issued.private_key_pem,
                )
                .await;
            if let Err(error) = published {
                *self.pending.lock().expect("pending lock") = Some(pending);
                return Err(error);
            }
            drop(lock);
            return Ok(());
        }
        validate_bundle_destination(&settings.bundle).await?;
        self.status.write().expect("status lock").phase = "issuing".into();
        let Some(issued) = issue(cancel.clone()).await? else {
            return Ok(());
        };
        let expires = issued.not_after.duration_since(UNIX_EPOCH)?.as_secs();
        *self.pending.lock().expect("pending lock") = Some(PendingIssuance {
            issued: issued.clone(),
            expires,
        });
        let sink = Sink {
            runtime: self,
            path: &settings.bundle,
            expires,
        };
        sink.publish(
            &issued.domains,
            &issued.certificate_pem,
            &issued.private_key_pem,
        )
        .await?;
        self.pending.lock().expect("pending lock").take();
        drop(lock);
        Ok(())
    }
    /// Returns retained material that is still worth publishing for these
    /// settings; anything stale (other domains, inside the renewal window) is
    /// discarded so a fresh order is placed instead.
    fn take_pending(&self, settings: &Settings) -> Option<PendingIssuance> {
        let pending = self.pending.lock().expect("pending lock").take()?;
        let usable = pending.issued.domains == settings.config.domains
            && pending
                .expires
                .saturating_sub(settings.config.renewal.renew_before.as_secs())
                > now();
        usable.then_some(pending)
    }
}
/// Rejects a bundle destination that cannot be published to (a directory at
/// the target path, or a parent that is missing or not writable) before any
/// CA order is created.
async fn validate_bundle_destination(bundle: &Path) -> Result<()> {
    let bundle = bundle.to_owned();
    tokio::task::spawn_blocking(move || -> Result<()> {
        if let Ok(metadata) = std::fs::metadata(&bundle) {
            ensure!(
                metadata.is_file(),
                "TLS bundle path {} is not a regular file",
                bundle.display()
            );
        }
        let parent = bundle
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let Ok(metadata) = std::fs::metadata(parent) else {
            bail!("TLS bundle directory {} does not exist", parent.display());
        };
        ensure!(
            metadata.is_dir(),
            "TLS bundle parent {} is not a directory",
            parent.display()
        );
        let probe = tempfile::NamedTempFile::new_in(parent).with_context(|| {
            format!("TLS bundle directory {} is not writable", parent.display())
        })?;
        drop(probe);
        Ok(())
    })
    .await?
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}
fn hex(digest: &[u8; 32]) -> String {
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}
/// Stat and digest the bundle off the executor. `None` when it is missing,
/// not a regular file, oversized or unreadable: nothing to load.
async fn bundle_digest_on_disk(bundle: &Path) -> Option<[u8; 32]> {
    let bundle = bundle.to_owned();
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let metadata = std::fs::metadata(&bundle).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_BUNDLE as u64 {
            return None;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        std::fs::File::open(&bundle)
            .ok()?
            .take(MAX_BUNDLE as u64 + 1)
            .read_to_end(&mut bytes)
            .ok()?;
        (bytes.len() <= MAX_BUNDLE).then(|| digest(&bytes))
    })
    .await
    .ok()
    .flatten()
}
struct Sink<'a> {
    runtime: &'a Runtime,
    path: &'a Path,
    expires: u64,
}
#[async_trait]
impl CertificateSink for Sink<'_> {
    async fn publish(
        &self,
        domains: &[String],
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<()> {
        let bundle = Bundle {
            domains: domains.to_vec(),
            certificate_pem: certificate_pem.to_vec(),
            private_key_pem: private_key_pem.to_vec(),
            expires: self.expires,
        };
        let path = self.path.to_owned();
        // Certificate parsing and the synced replacement both run off the
        // async executor.
        let (config, digest) =
            tokio::task::spawn_blocking(move || -> Result<(ServerConfig, [u8; 32])> {
                use std::io::Write;
                let config = crate::tls::sni_server_config(vec![SniCertificate {
                    hosts: bundle.domains.clone(),
                    default: false,
                    cert_pem: bundle.certificate_pem.clone(),
                    key_pem: bundle.private_key_pem.clone(),
                }])?;
                let bytes = serde_json::to_vec(&bundle)?;
                let parent = path
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new("."));
                let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
                temporary.write_all(&bytes)?;
                temporary.as_file().sync_all()?;
                temporary.persist(&path)?;
                std::fs::File::open(parent)?.sync_all()?;
                Ok((config, self::digest(&bytes)))
            })
            .await??;
        self.runtime.publish_loaded(
            config,
            Loaded {
                digest,
                domains: domains.to_vec(),
                expires: self.expires,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Harness {
        _temp: tempfile::TempDir,
        runtime: Arc<Runtime>,
        settings: Settings,
        issued: IssuedCertificate,
        orders: Arc<AtomicUsize>,
    }
    async fn harness() -> Harness {
        harness_with(|account| {
            serde_json::json!({
                "domains": ["localhost"],
                "account_path": account,
                "challenge": "http-01",
            })
        })
        .await
    }
    async fn harness_with(config: impl FnOnce(&Path) -> serde_json::Value) -> Harness {
        let temp = tempfile::tempdir().unwrap();
        let account = temp.path().join("account.json");
        let config = config(&account);
        let bytes = serde_json::to_vec(&config).unwrap();
        let path = temp.path().join("acme.json");
        std::fs::write(&path, &bytes).unwrap();
        let tls = Arc::new(ReloadingTls::dynamic(
            crate::tls::sni_server_config(Vec::new()).unwrap(),
        ));
        let runtime = Runtime::new(path, true, tls, None).await.unwrap();
        let settings = settings(&bytes, true).await.unwrap();
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let issued = acme::validate_certificate(
            &["localhost".to_owned()],
            pair.cert.pem().as_bytes(),
            pair.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        Harness {
            _temp: temp,
            runtime,
            settings,
            issued,
            orders: Arc::new(AtomicUsize::new(0)),
        }
    }
    impl Harness {
        /// Runs one attempt with a fake issuer that counts orders. `sabotage`
        /// breaks the bundle destination after issuance (before publication),
        /// modelling a destination that becomes a directory.
        async fn attempt(&self, sabotage: bool) -> Result<()> {
            let orders = self.orders.clone();
            let issued = self.issued.clone();
            let bundle = self.settings.bundle.clone();
            self.runtime
                .attempt_with(
                    &self.settings,
                    &CancellationToken::new(),
                    move |_| async move {
                        orders.fetch_add(1, Ordering::SeqCst);
                        if sabotage {
                            std::fs::create_dir_all(&bundle).unwrap();
                        }
                        Ok(Some(issued))
                    },
                )
                .await
        }
        fn phase(&self) -> String {
            self.runtime.status.read().unwrap().phase.clone()
        }
    }

    #[tokio::test]
    async fn publication_failure_retries_pending_material_before_ordering_again() {
        let h = harness().await;
        let before = h.runtime.tls.current.load_full();
        // Issuance succeeds but the bundle destination has become a directory.
        assert!(h.attempt(true).await.is_err());
        assert_eq!(h.orders.load(Ordering::SeqCst), 1);
        assert!(h.settings.bundle.is_dir());
        assert!(Arc::ptr_eq(&before, &h.runtime.tls.current.load_full()));
        // Retrying while the destination is still broken must not create a
        // second order: the retained material is retried instead.
        assert!(h.attempt(true).await.is_err());
        assert!(h.attempt(false).await.is_err());
        assert_eq!(
            h.orders.load(Ordering::SeqCst),
            1,
            "publication failure must not purchase another order"
        );
        // Once the destination is repaired the pending material is published.
        std::fs::remove_dir(&h.settings.bundle).unwrap();
        h.attempt(false).await.unwrap();
        assert_eq!(h.orders.load(Ordering::SeqCst), 1);
        assert!(h.settings.bundle.is_file());
        assert_eq!(h.phase(), "ready");
        assert!(!Arc::ptr_eq(&before, &h.runtime.tls.current.load_full()));
        // Later attempts find the bundle current and issue nothing.
        h.attempt(false).await.unwrap();
        assert_eq!(h.orders.load(Ordering::SeqCst), 1);
        assert!(h.runtime.pending.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn broken_bundle_destination_is_rejected_before_any_order() {
        let h = harness().await;
        std::fs::create_dir_all(&h.settings.bundle).unwrap();
        let error = h.attempt(false).await.unwrap_err().to_string();
        assert!(error.contains("not a regular file"), "{error}");
        assert_eq!(h.orders.load(Ordering::SeqCst), 0);
        assert_ne!(h.phase(), "issuing");
        // Missing parent directory is rejected too.
        std::fs::remove_dir(&h.settings.bundle).unwrap();
        let mut orphan = harness().await;
        orphan.settings.bundle = orphan._temp.path().join("missing").join("tls.json");
        let error = orphan.attempt(false).await.unwrap_err().to_string();
        assert!(error.contains("does not exist"), "{error}");
        assert_eq!(orphan.orders.load(Ordering::SeqCst), 0);
        // A healthy destination issues exactly once and publishes.
        h.attempt(false).await.unwrap();
        assert_eq!(h.orders.load(Ordering::SeqCst), 1);
        assert_eq!(h.phase(), "ready");
    }

    /// A self-signed `localhost` certificate, optionally short-lived, as the
    /// bundle another instance would publish plus the trust anchor a client
    /// needs to recognise it.
    fn leader_material(
        validity: Option<Duration>,
    ) -> (
        rustls::pki_types::CertificateDer<'static>,
        IssuedCertificate,
    ) {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
        if let Some(validity) = validity {
            params.not_before = (SystemTime::now() - Duration::from_secs(60)).into();
            params.not_after = (SystemTime::now() + validity).into();
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let issued = acme::validate_certificate(
            &["localhost".to_owned()],
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap();
        (cert.der().clone(), issued)
    }
    /// What another instance's `Sink::publish` leaves on the shared volume:
    /// a synced temporary renamed over the bundle path.
    fn publish_as_other_instance(bundle: &Path, issued: &IssuedCertificate) -> [u8; 32] {
        use std::io::Write;
        let bytes = serde_json::to_vec(&Bundle {
            domains: issued.domains.clone(),
            certificate_pem: issued.certificate_pem.clone(),
            private_key_pem: issued.private_key_pem.clone(),
            expires: issued
                .not_after
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        })
        .unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(bundle.parent().unwrap()).unwrap();
        temporary.write_all(&bytes).unwrap();
        temporary.as_file().sync_all().unwrap();
        temporary.persist(bundle).unwrap();
        digest(&bytes)
    }
    /// One loopback TLS handshake against the runtime's current resolver,
    /// trusting only `anchor`.
    async fn handshake(
        tls: &ReloadingTls,
        anchor: &rustls::pki_types::CertificateDer<'static>,
    ) -> bool {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(tls.current.load_full());
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(stream).await;
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(anchor.clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let stream = tokio::net::TcpStream::connect(address).await.unwrap();
        let result = connector
            .connect("localhost".try_into().unwrap(), stream)
            .await;
        let _ = server.await;
        result.is_ok()
    }
    async fn wait_until(deadline: Duration, mut condition: impl FnMut() -> bool) -> bool {
        let started = std::time::Instant::now();
        while started.elapsed() < deadline {
            if condition() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        condition()
    }

    /// Fleet follower: another instance holds the account lock and renews the
    /// shared bundle. This runtime must serve the new certificate from disk
    /// (no order, no CA contact), report it in `tls_available` /
    /// `bundle_digest`, parse a bad replacement once, and drop
    /// `tls_available` when the loaded certificate expires.
    #[tokio::test]
    async fn follower_serves_a_bundle_renewed_by_another_instance_without_ordering() {
        // Any CA contact from this runtime is a failure: the directory is a
        // loopback listener that counts connections.
        let directory = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let directory_url = format!("https://{}/directory", directory.local_addr().unwrap());
        let ca_contacts = Arc::new(AtomicUsize::new(0));
        let counter = ca_contacts.clone();
        let directory_task = tokio::spawn(async move {
            while let Ok((stream, _)) = directory.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let mut h = harness_with(|account| {
            serde_json::json!({
                "directory": directory_url,
                "domains": ["localhost"],
                "account_path": account,
                "challenge": "http-01",
                "retry_initial_secs": 1u64,
                "retry_max_secs": 1u64,
            })
        })
        .await;
        Arc::get_mut(&mut h.runtime).unwrap().bundle_poll = Duration::from_millis(200);
        // The leader holds the per-account lock for the whole test.
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        let leader_lock = options
            .open(h.settings.config.account_path.with_extension("acme.lock"))
            .unwrap();
        leader_lock.try_lock().unwrap();

        let empty = h.runtime.tls.current.load_full();
        {
            let status = h.runtime.status.read().unwrap();
            assert!(!status.tls_available, "no bundle yet: TLS is not available");
            assert_eq!(status.bundle_digest, "");
        }
        h.runtime.start().await;
        // The follower's own attempt fails at the lock, before any CA contact.
        assert!(
            wait_until(Duration::from_secs(10), || h.phase() == "retrying").await,
            "phase was {}",
            h.phase()
        );
        assert!(Arc::ptr_eq(&empty, &h.runtime.tls.current.load_full()));
        // The reason is reported, so an operator can tell a follower from a
        // broken issuer.
        let last_error = h.runtime.status.read().unwrap().last_error.clone();
        assert!(
            last_error
                .as_deref()
                .is_some_and(|error| error.starts_with(LOCK_HELD_ELSEWHERE)),
            "{last_error:?}"
        );

        // The leader publishes a certificate.
        let (first_anchor, first) = leader_material(None);
        let first_digest = publish_as_other_instance(&h.settings.bundle, &first);
        let runtime = h.runtime.clone();
        assert!(
            wait_until(Duration::from_secs(10), || {
                !Arc::ptr_eq(&empty, &runtime.tls.current.load_full())
            })
            .await,
            "follower did not pick up the leader's bundle"
        );
        {
            let status = h.runtime.status.read().unwrap();
            assert!(status.tls_available);
            assert_eq!(status.bundle_digest, hex(&first_digest));
            assert_eq!(status.phase, "ready");
            assert_eq!(
                status.last_error, None,
                "loaded material clears the failure"
            );
            assert_eq!(
                status.expires_unix,
                Some(
                    first
                        .not_after
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs()
                )
            );
        }
        assert!(handshake(&h.runtime.tls, &first_anchor).await);
        assert_eq!(h.orders.load(Ordering::SeqCst), 0);
        assert_eq!(ca_contacts.load(Ordering::SeqCst), 0, "an order was placed");

        // The leader renews: the resolver follows without an order.
        let (second_anchor, second) = leader_material(None);
        let second_digest = publish_as_other_instance(&h.settings.bundle, &second);
        let runtime = h.runtime.clone();
        assert!(
            wait_until(Duration::from_secs(10), || {
                runtime.status.read().unwrap().bundle_digest == hex(&second_digest)
            })
            .await
        );
        assert!(handshake(&h.runtime.tls, &second_anchor).await);
        assert!(!handshake(&h.runtime.tls, &first_anchor).await);
        assert!(h.runtime.status.read().unwrap().tls_available);

        // A corrupt replacement is parsed once and the certificate is kept.
        let loaded = h.runtime.tls.current.load_full();
        std::fs::write(&h.settings.bundle, b"not a bundle").unwrap();
        let runtime = h.runtime.clone();
        assert!(
            wait_until(Duration::from_secs(10), || runtime
                .rejected_bundle_reloads()
                == 1)
            .await
        );
        tokio::time::sleep(Duration::from_millis(900)).await;
        assert_eq!(
            h.runtime.rejected_bundle_reloads(),
            1,
            "identical bad bundle was re-parsed"
        );
        assert!(Arc::ptr_eq(&loaded, &h.runtime.tls.current.load_full()));
        {
            let status = h.runtime.status.read().unwrap();
            assert!(
                status.tls_available,
                "the previous certificate is still served"
            );
            assert_eq!(status.bundle_digest, hex(&second_digest));
            assert_eq!(
                status.phase, "ready",
                "a bad replacement must not schedule an issuance"
            );
            assert!(status.expires_unix.is_some());
        }
        assert!(handshake(&h.runtime.tls, &second_anchor).await);

        // A short-lived renewal is loaded, then expires: availability drops
        // although the material stays in the resolver.
        let (_, brief) = leader_material(Some(Duration::from_secs(4)));
        let brief_digest = publish_as_other_instance(&h.settings.bundle, &brief);
        let runtime = h.runtime.clone();
        assert!(
            wait_until(Duration::from_secs(10), || {
                runtime.status.read().unwrap().bundle_digest == hex(&brief_digest)
            })
            .await
        );
        assert!(h.runtime.status.read().unwrap().tls_available);
        let runtime = h.runtime.clone();
        assert!(
            wait_until(Duration::from_secs(10), || {
                !runtime.status.read().unwrap().tls_available
            })
            .await,
            "expiry of the loaded certificate must clear tls_available"
        );
        assert_eq!(
            h.runtime.status.read().unwrap().bundle_digest,
            hex(&brief_digest)
        );
        assert_eq!(ca_contacts.load(Ordering::SeqCst), 0);
        assert_eq!(h.orders.load(Ordering::SeqCst), 0);
        h.runtime.stop().await;
        directory_task.abort();
    }

    #[tokio::test]
    async fn rejects_unknown_runtime_options_and_invalid_replacements() {
        let config =
            br#"{"domains":["localhost"],"account_path":"account.json","challenge":"http-01"}"#;
        assert!(settings(config, true).await.is_ok());
        assert!(settings(config, false).await.is_err());
        let typo =
            br#"{"domains":["localhost"],"account_path":"account.json","challeng":"dns-01"}"#;
        assert!(settings(typo, true).await.is_err());
        let no_dns =
            br#"{"domains":["*.example.test"],"account_path":"account.json","challenge":"dns-01"}"#;
        assert!(settings(no_dns, true).await.is_err());
    }
}
