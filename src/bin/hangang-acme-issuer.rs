//! Standalone DNS-01 or HTTP-01 ACME issuer for one atomic TLS pair.
//! Run one independent process per certificate group; gateway --config-tls
//! reads current/*.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use hangang::acme::{
    self, AcmeConfig, AcmeEngine, AcmeFileConfig, ChallengeMode, CloudflareDnsProvider,
    DnsProvider, IssuedCertificate,
};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio_util::sync::CancellationToken;

const MAX_CONFIG: u64 = 256 * 1024;
const MAX_TOKEN: u64 = 8192;
const MAX_PEM: u64 = 1024 * 1024;
const MAX_STATUS: usize = 32 * 1024;
const STATUS_HEARTBEAT: Duration = Duration::from_secs(30);

#[derive(Parser)]
struct Args {
    /// Private JSON file specifying exactly one DNS zone and certificate set.
    #[arg(long)]
    config: PathBuf,
    /// HTTP-01 listener for ordinary names; expose only the challenge path.
    #[arg(long)]
    http_listen: Option<SocketAddr>,
    /// Validate local configuration and output location without contacting ACME or DNS.
    #[arg(long)]
    check: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerFile {
    #[serde(flatten)]
    acme: AcmeFileConfig,
    dns: Option<Dns>,
    output_directory: PathBuf,
}
#[derive(Deserialize)]
#[serde(tag = "provider", rename_all = "kebab-case", deny_unknown_fields)]
enum Dns {
    Cloudflare {
        zone_id: String,
        token_file: PathBuf,
    },
}
#[derive(Clone)]
struct Prepared {
    acme: AcmeConfig,
    dns: Option<CloudflareSettings>,
    output_directory: PathBuf,
}
#[derive(Clone)]
struct CloudflareSettings {
    zone_id: String,
    token_file: PathBuf,
}
fn absolute_normal(path: &Path, what: &str) -> Result<()> {
    ensure!(
        path.is_absolute()
            && path != Path::new("/")
            && path.as_os_str().as_encoded_bytes().len() <= 4096,
        "{what} requires a bounded absolute path"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "{what} must not contain dot components"
    );
    Ok(())
}
fn read_bounded(path: &Path, max: u64) -> Result<Vec<u8>> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open private file {}", path.display()))?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "private input is not a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "private input must not be accessible by other users"
        );
    }
    let mut result = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(max + 1)
        .read_to_end(&mut result)?;
    ensure!(
        result.len() as u64 <= max,
        "private input exceeds size limit"
    );
    Ok(result)
}
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

impl IssuerFile {
    fn prepare(self) -> Result<Prepared> {
        let mut config = self.acme.into_config()?;
        ensure!(
            config.challenge != ChallengeMode::Auto,
            "issuer challenge must explicitly select dns-01 or http-01"
        );
        ensure!(
            config.certificate_path.is_none() && config.private_key_path.is_none(),
            "use output_directory for atomic pair output"
        );
        absolute_normal(&config.account_path, "ACME account")?;
        if let Some(path) = &config.ca_path {
            absolute_normal(path, "ACME CA bundle")?;
        }
        absolute_normal(&self.output_directory, "TLS output directory")?;
        ensure!(
            (config.challenge == ChallengeMode::Dns01) == self.dns.is_some(),
            "dns-01 requires one DNS provider; http-01 must omit DNS provider"
        );
        let dns = self
            .dns
            .map(
                |Dns::Cloudflare {
                     zone_id,
                     token_file,
                 }|
                 -> Result<CloudflareSettings> {
                    ensure!(
                        !zone_id.is_empty()
                            && zone_id.len() <= 128
                            && zone_id.bytes().all(|c| c.is_ascii_hexdigit()),
                        "invalid Cloudflare zone ID"
                    );
                    absolute_normal(&token_file, "DNS token file")?;
                    Ok(CloudflareSettings {
                        zone_id,
                        token_file,
                    })
                },
            )
            .transpose()?;
        ensure!(
            self.output_directory != config.account_path
                && !config.account_path.starts_with(&self.output_directory),
            "account and public TLS directory must be separate"
        );
        // The gateway's one pair is never written separately by the engine.
        config.certificate_path = None;
        config.private_key_path = None;
        Ok(Prepared {
            acme: config,
            dns,
            output_directory: self.output_directory,
        })
    }
}
fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        meta.file_type().is_dir(),
        "TLS output is not a plain directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "TLS output directory must not be accessible by other users"
        );
    }
    Ok(())
}
fn ensure_target(path: &Path) -> Result<()> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        ensure!(
            meta.file_type().is_symlink(),
            "current TLS pointer is not a symlink"
        );
    }
    Ok(())
}
fn current_pair(root: &Path, domains: &[String]) -> Result<Option<SystemTime>> {
    Ok(current_certificate_meta(root, domains)?.map(|meta| meta.expires))
}

struct CertificateMeta {
    expires: SystemTime,
    fingerprint: String,
}

fn current_certificate_meta(root: &Path, domains: &[String]) -> Result<Option<CertificateMeta>> {
    let pointer = root.join("current");
    match std::fs::read_link(&pointer) {
        Ok(target) => {
            ensure!(
                target.components().count() == 1
                    && matches!(target.components().next(), Some(Component::Normal(_)))
                    && target
                        .to_str()
                        .is_some_and(|name| name.starts_with("generation-")),
                "invalid TLS generation pointer"
            );
            let cert = read_bounded(&root.join(&target).join("cert.pem"), MAX_PEM)?;
            let key = read_bounded(&root.join(&target).join("key.pem"), MAX_PEM)?;
            let validated = acme::validate_certificate(domains, &cert, &key)?;
            let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert))
                .next()
                .transpose()?
                .context("validated certificate has no leaf")?;
            use sha2::{Digest, Sha256};
            let fingerprint = Sha256::digest(leaf.as_ref())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            Ok(Some(CertificateMeta {
                expires: validated.not_after,
                fingerprint,
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[derive(Serialize)]
struct IssuerStatus {
    version: u8,
    manager: &'static str,
    challenge: &'static str,
    domains: Vec<String>,
    phase: &'static str,
    certificate_fingerprint_sha256: Option<String>,
    expires_unix_ms: Option<u64>,
    checked_at_unix_ms: u64,
    renew_before_unix_ms: Option<u64>,
    retry_next_unix_ms: Option<u64>,
}

fn unix_ms(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

fn status_for(config: &Prepared, phase: &'static str, retry: Option<Duration>) -> IssuerStatus {
    let now = unix_ms(SystemTime::now()).unwrap_or(0);
    let certificate = current_certificate_meta(&config.output_directory, &config.acme.domains)
        .ok()
        .flatten();
    let expires = certificate.as_ref().and_then(|meta| unix_ms(meta.expires));
    let renew_before = expires.map(|expiry| {
        expiry.saturating_sub(
            config
                .acme
                .renewal
                .renew_before
                .as_millis()
                .min(u128::from(u64::MAX)) as u64,
        )
    });
    IssuerStatus {
        version: 1,
        manager: "hangang-acme-issuer",
        challenge: match config.acme.challenge {
            ChallengeMode::Dns01 => "dns-01",
            ChallengeMode::Http01 => "http-01",
            ChallengeMode::Auto => unreachable!("standalone issuer requires explicit challenge"),
        },
        domains: config
            .acme
            .domains
            .iter()
            .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
            .collect(),
        phase,
        certificate_fingerprint_sha256: certificate.map(|meta| meta.fingerprint),
        expires_unix_ms: expires,
        checked_at_unix_ms: now,
        renew_before_unix_ms: renew_before,
        retry_next_unix_ms: retry
            .map(|delay| now.saturating_add(delay.as_millis().min(u128::from(u64::MAX)) as u64)),
    }
}

fn write_status(config: &Prepared, phase: &'static str, retry: Option<Duration>) -> Result<()> {
    let status = status_for(config, phase, retry);
    let body = serde_json::to_vec(&status)?;
    anyhow::ensure!(body.len() <= 32 * 1024, "issuer status exceeds size limit");
    ensure!(body.len() <= MAX_STATUS, "issuer status exceeds size limit");
    let path = config.output_directory.join("issuer-status.json");
    if let Ok(existing) = std::fs::symlink_metadata(&path) {
        ensure!(
            existing.is_file(),
            "issuer status target is not a regular file"
        );
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".issuer-status-")
        .tempfile_in(&config.output_directory)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&body)?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path).map_err(|error| error.error)?;
    std::fs::File::open(&config.output_directory)?.sync_all()?;
    Ok(())
}

fn publish_status(config: &Prepared, phase: &'static str, retry: Option<Duration>) {
    if write_status(config, phase, retry).is_err() {
        tracing::warn!("issuer status manifest unavailable");
    }
}

fn current_phase(config: &Prepared) -> &'static str {
    let ready = current_pair(&config.output_directory, &config.acme.domains)
        .ok()
        .flatten()
        .is_some_and(|expiry| expiry > SystemTime::now() + config.acme.renewal.renew_before);
    if ready { "ready" } else { "renewing" }
}
fn write_generation(root: &Path, issued: &IssuedCertificate) -> Result<()> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{PermissionsExt, symlink};
    ensure_private_dir(root)?;
    ensure_target(&root.join("current"))?;
    let validated = acme::validate_certificate(
        &issued.domains,
        &issued.certificate_pem,
        &issued.private_key_pem,
    )?;
    ensure!(
        validated.not_after == issued.not_after,
        "issued certificate expiry changed"
    );
    let id = hex_prefix(&Sha256::digest(
        [
            issued.certificate_pem.as_slice(),
            issued.private_key_pem.as_slice(),
        ]
        .concat(),
    ));
    let name = format!("generation-{id}");
    let destination = root.join(&name);
    if destination.exists() {
        ensure!(
            current_pair_for(&destination, &issued.domains)?
                .is_some_and(|expiry| expiry == issued.not_after),
            "existing generation content differs"
        );
    } else {
        let directory = tempfile::Builder::new()
            .prefix(".pending-")
            .tempdir_in(root)?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        for (filename, contents) in [
            ("cert.pem", issued.certificate_pem.as_slice()),
            ("key.pem", issued.private_key_pem.as_slice()),
        ] {
            let path = directory.path().join(filename);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(contents)?;
            file.sync_all()?;
        }
        std::fs::File::open(directory.path())?.sync_all()?;
        std::fs::rename(directory.path(), &destination)?;
        // The renamed generation must survive TempDir's automatic cleanup.
        let _ = directory.keep();
        std::fs::File::open(root)?.sync_all()?;
    }
    let temporary = root.join(format!(".pointer-{}-{}", std::process::id(), id));
    symlink(&name, &temporary)?;
    std::fs::rename(&temporary, root.join("current"))?;
    std::fs::File::open(root)?.sync_all()?;
    Ok(())
}
fn current_pair_for(path: &Path, domains: &[String]) -> Result<Option<SystemTime>> {
    let cert = read_bounded(&path.join("cert.pem"), MAX_PEM)?;
    let key = read_bounded(&path.join("key.pem"), MAX_PEM)?;
    Ok(Some(
        acme::validate_certificate(domains, &cert, &key)?.not_after,
    ))
}
fn hex_prefix(bytes: &[u8]) -> String {
    bytes[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn issuance_error_class(error: &anyhow::Error) -> &'static str {
    let detail = format!("{error:#}");
    if detail.contains("DNS TXT propagation deadline exceeded") {
        "dns-propagation-timeout"
    } else if detail.contains("400 Bad Request") && detail.contains("api.cloudflare.com") {
        "dns-provider-bad-request"
    } else if detail.contains("DNS provider request timed out") {
        "dns-provider-timeout"
    } else if detail.contains("ACME operation cancelled") {
        "cancelled"
    } else if detail.contains("timed out") {
        "timeout"
    } else {
        "other"
    }
}
async fn provider_for(
    config: &Prepared,
    providers: &tokio::sync::Mutex<Option<Arc<dyn DnsProvider>>>,
) -> Result<Option<Arc<dyn DnsProvider>>> {
    let mut cached = providers.lock().await;
    if let Some(existing) = cached.as_ref() {
        return Ok(Some(existing.clone()));
    }
    let Some(dns) = &config.dns else {
        return Ok(None);
    };
    let bytes = read_bounded(&dns.token_file, MAX_TOKEN)?;
    let token = String::from_utf8(bytes)?.trim().to_owned();
    ensure!(!token.is_empty(), "DNS credential file is empty");
    hyper::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
    let provider: Arc<dyn DnsProvider> =
        Arc::new(CloudflareDnsProvider::new(dns.zone_id.clone(), token));
    *cached = Some(provider.clone());
    Ok(Some(provider))
}
async fn run_one(
    config: &Prepared,
    challenges: Arc<acme::HttpChallengeStore>,
    providers: &tokio::sync::Mutex<Option<Arc<dyn DnsProvider>>>,
    cancel: &CancellationToken,
) -> Result<()> {
    // The account lock covers account registration, order placement and
    // certificate publication. Another issuer process backs off without
    // contacting the CA; the gateway only reads the immutable pair.
    let lock_path = config.acme.account_path.with_extension("acme.lock");
    ensure_private_dir(lock_path.parent().context("account directory missing")?)?;
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
        .open(lock_path)?;
    let metadata = lock.metadata()?;
    ensure!(
        metadata.is_file() && metadata.permissions().mode() & 0o077 == 0,
        "ACME account lock must be a private regular file"
    );
    if let Err(error) = lock.try_lock() {
        if matches!(error, std::fs::TryLockError::WouldBlock) {
            return Ok(());
        }
        return Err(error.into());
    }
    ensure_private_dir(&config.output_directory)?;
    let expiry = match current_pair(&config.output_directory, &config.acme.domains) {
        Ok(expiry) => expiry,
        Err(error) => {
            tracing::warn!(%error,"existing TLS pair is unusable; requesting replacement");
            None
        }
    };
    if expiry.is_some_and(|at| at > SystemTime::now() + config.acme.renewal.renew_before) {
        return Ok(());
    }
    let provider = provider_for(config, providers).await?;
    let engine = tokio::select! {
        _=cancel.cancelled()=>return Ok(()),
        result=tokio::time::timeout(Duration::from_secs(30),AcmeEngine::new(config.acme.clone(),challenges,provider)) => result??,
    };
    let issued = engine.issue(cancel).await?;
    tokio::task::spawn_blocking({
        let root = config.output_directory.clone();
        move || write_generation(&root, &issued)
    })
    .await??;
    Ok(())
}
/// Challenge-only HTTP listener: no application routes, no administration, no
/// redirect. Bound connections, handshake time, header bytes, and lifetime.
async fn serve_http(
    listener: tokio::net::TcpListener,
    challenges: Arc<acme::HttpChallengeStore>,
    cancel: CancellationToken,
) -> Result<()> {
    use http_body_util::Full;
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::{TokioIo, TokioTimer};
    let permits = Arc::new(tokio::sync::Semaphore::new(64));
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _=cancel.cancelled()=>break,
            Some(result)=connections.join_next(),if !connections.is_empty()=>{if let Err(error)=result{tracing::warn!(%error,"HTTP-01 connection failed");}},
            accepted=listener.accept()=>{
                let (socket,_) = accepted?;
                let Ok(permit)=permits.clone().try_acquire_owned() else {continue};
                let challenges=challenges.clone();
                connections.spawn(async move {
                    let service=service_fn(move |request:hyper::Request<hyper::body::Incoming>|{
                        let store=challenges.clone();
                        async move {
                            let response=store.response(&request).await.unwrap_or_else(||{
                                hyper::Response::builder().status(404).body(Full::new(bytes::Bytes::new())).expect("constant response")
                            });
                            Ok::<_,std::convert::Infallible>(response)
                        }
                    });
                    let mut builder=http1::Builder::new();
                    builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5)).max_buf_size(8192).keep_alive(false);
                    let _=tokio::time::timeout(Duration::from_secs(15),builder.serve_connection(TokioIo::new(socket),service)).await;
                    drop(permit);
                });
            },
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    Ok(())
}
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hangang_acme_issuer=info,hangang=info".into()),
        )
        .init();
    absolute_normal(&args.config, "issuer config")?;
    let bytes = read_bounded(&args.config, MAX_CONFIG)?;
    let config = serde_json::from_slice::<IssuerFile>(&bytes)?.prepare()?;
    ensure_private_dir(&config.output_directory)?;
    ensure_target(&config.output_directory.join("current"))?;
    ensure!(
        (config.acme.challenge == ChallengeMode::Http01) == args.http_listen.is_some(),
        "http-01 requires --http-listen; dns-01 must omit it"
    );
    if args.check {
        if let Some(dns) = &config.dns {
            let credential = read_bounded(&dns.token_file, MAX_TOKEN)?;
            ensure!(!credential.is_empty(), "DNS credential file is empty");
        }
        return Ok(());
    }
    let challenges = Arc::new(acme::HttpChallengeStore::default());
    let listener = match args.http_listen {
        Some(address) => Some(
            tokio::net::TcpListener::bind(address)
                .await
                .context("bind HTTP-01 listener before ACME order")?,
        ),
        None => None,
    };
    let cancel = CancellationToken::new();
    let stop = cancel.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {_=term.recv()=>{},_=tokio::signal::ctrl_c()=>{}}
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        stop.cancel();
    });
    let server = listener.map(|listener| {
        let challenges = challenges.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { serve_http(listener, challenges, cancel).await })
    });
    let result = supervise(
        args.config,
        bytes,
        config,
        challenges,
        args.http_listen.is_some(),
        cancel.clone(),
    )
    .await;
    cancel.cancel();
    if let Some(server) = server {
        server.await??;
    }
    result
}

/// Never detach an issuer when its configuration is replaced. A changed file
/// cancels its DNS order, awaits cleanup/publication, and only then starts the
/// next settings; bad candidates leave the preceding configuration active.
async fn supervise(
    path: PathBuf,
    mut previous: Vec<u8>,
    mut config: Prepared,
    challenges: Arc<acme::HttpChallengeStore>,
    http_enabled: bool,
    cancel: CancellationToken,
) -> Result<()> {
    let mut backoff = config.acme.renewal.retry_initial;
    let mut poll = tokio::time::interval(Duration::from_secs(2));
    let mut retry = Duration::ZERO;
    let mut providers = Arc::new(tokio::sync::Mutex::new(None));
    loop {
        // A restored valid pair is visible immediately, before any CA/provider
        // request; status is advisory and cannot block issuance.
        publish_status(&config, current_phase(&config), None);
        let mut last_status = tokio::time::Instant::now();
        let mut status_phase = "renewing";
        let child = cancel.child_token();
        let copy = config.clone();
        let token = child.clone();
        let store = challenges.clone();
        let cache = providers.clone();
        let mut active = tokio::spawn(async move { run_one(&copy, store, &cache, &token).await });
        let next = loop {
            tokio::select! {
                biased;
                result=&mut active => {
                    match result? {
                        Ok(())=>{
                            backoff=config.acme.renewal.retry_initial;
                            retry=config.acme.renewal.check_interval;
                            status_phase=current_phase(&config);
                            publish_status(&config,status_phase,(status_phase=="renewing").then_some(retry));
                        },
                        Err(error)=>{
                            retry=backoff.max(Duration::from_secs(5));
                            status_phase="retrying";
                            publish_status(&config,status_phase,Some(retry));
                            tracing::warn!(error_class=issuance_error_class(&error),retry_secs=retry.as_secs(),"ACME issuer attempt failed; retry scheduled");
                            backoff=backoff.saturating_mul(2).min(config.acme.renewal.retry_max);
                        },
                    }
                    last_status=tokio::time::Instant::now();
                    break None;
                },
                _=cancel.cancelled()=>{child.cancel();let _=active.await;return Ok(());},
                _=poll.tick()=>{
                    if last_status.elapsed()>=STATUS_HEARTBEAT {
                        publish_status(&config,"renewing",None);
                        last_status=tokio::time::Instant::now();
                    }
                    match read_bounded(&path,MAX_CONFIG) {
                        Ok(bytes) if bytes != previous => {
                            match serde_json::from_slice::<IssuerFile>(&bytes).context("parse issuer config").and_then(IssuerFile::prepare).and_then(|next|{
                                ensure_private_dir(&next.output_directory)?;
                                ensure_target(&next.output_directory.join("current"))?;
                                Ok(next)
                            }) {
                                Ok(next) if (next.acme.challenge==ChallengeMode::Http01)==http_enabled => {previous=bytes;break Some(next);},
                                Ok(_)=>tracing::warn!("issuer challenge mode cannot change without restarting its HTTP listener"),
                                Err(error)=>tracing::warn!(%error,"invalid issuer config replacement; retaining last good settings"),
                            }
                        },
                        Ok(_)=>{},
                        Err(error)=>tracing::warn!(%error,"issuer config unavailable; retaining last good settings"),
                    }
                },
            }
        };
        if let Some(next) = next {
            child.cancel();
            let _ = active.await;
            config = next;
            providers = Arc::new(tokio::sync::Mutex::new(None));
            backoff = config.acme.renewal.retry_initial;
            retry = Duration::ZERO;
            continue;
        }
        // Poll for configuration changes during the normal renewal wait too.
        // Changed settings are applied without waiting for the day-long check
        // interval, and invalid candidates never trigger a fresh order.
        let until = tokio::time::Instant::now() + retry;
        loop {
            tokio::select! {
                _=cancel.cancelled()=>return Ok(()),
                _=tokio::time::sleep_until(until)=>break,
                _=poll.tick()=>{
                    if last_status.elapsed()>=STATUS_HEARTBEAT {
                        if status_phase=="ready" {
                            status_phase=current_phase(&config);
                        }
                        let remaining=until.saturating_duration_since(tokio::time::Instant::now());
                        publish_status(&config,status_phase,(status_phase!="ready").then_some(remaining));
                        last_status=tokio::time::Instant::now();
                    }
                    match read_bounded(&path,MAX_CONFIG) {
                        Ok(bytes) if bytes != previous => {
                            match serde_json::from_slice::<IssuerFile>(&bytes).context("parse issuer config").and_then(IssuerFile::prepare).and_then(|next|{
                                ensure_private_dir(&next.output_directory)?;
                                ensure_target(&next.output_directory.join("current"))?;
                                Ok(next)
                            }) {
                                Ok(next) if (next.acme.challenge==ChallengeMode::Http01)==http_enabled => {previous=bytes;config=next;providers=Arc::new(tokio::sync::Mutex::new(None));backoff=config.acme.renewal.retry_initial;break;},
                                Ok(_)=>tracing::warn!("issuer challenge mode cannot change without restarting its HTTP listener"),
                                Err(error)=>tracing::warn!(%error,"invalid issuer config replacement; retaining last good settings"),
                            }
                        },
                        Ok(_)=>{},
                        Err(error)=>tracing::warn!(%error,"issuer config unavailable; retaining last good settings"),
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn issued(names: Vec<String>) -> IssuedCertificate {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(names.clone())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        acme::validate_certificate(
            &names,
            cert.pem().as_bytes(),
            key.serialize_pem().as_bytes(),
        )
        .unwrap()
    }
    fn private_output(parent: &Path, name: &str) -> PathBuf {
        let result = parent.join(name);
        std::fs::create_dir(&result).unwrap();
        std::fs::set_permissions(&result, std::fs::Permissions::from_mode(0o700)).unwrap();
        result
    }

    fn prepared_status_fixture(root: PathBuf, names: Vec<String>) -> Prepared {
        let mut acme = AcmeConfig::new(names, root.join("account.json"));
        acme.challenge = ChallengeMode::Dns01;
        Prepared {
            acme,
            dns: None,
            output_directory: root,
        }
    }

    #[test]
    fn status_is_private_atomic_and_matches_leaf_der() {
        use sha2::{Digest, Sha256};
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone");
        let names = vec!["Example.Test".to_owned()];
        let certificate = issued(vec!["example.test".to_owned()]);
        write_generation(&root, &certificate).unwrap();
        let prepared = prepared_status_fixture(root.clone(), names);
        write_status(&prepared, "ready", None).unwrap();
        let path = root.join("issuer-status.json");
        let body = std::fs::read(&path).unwrap();
        let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(&certificate.certificate_pem))
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(status["version"], 1);
        assert_eq!(status["manager"], "hangang-acme-issuer");
        assert_eq!(status["challenge"], "dns-01");
        assert_eq!(status["domains"], serde_json::json!(["example.test"]));
        assert_eq!(status["phase"], "ready");
        assert_eq!(
            status["certificate_fingerprint_sha256"],
            format!("{:x}", Sha256::digest(leaf.as_ref()))
        );
        assert_eq!(
            status["expires_unix_ms"],
            unix_ms(certificate.not_after).unwrap()
        );
        assert!(status["renew_before_unix_ms"].as_u64().is_some());
        assert!(status["checked_at_unix_ms"].as_u64().is_some());
        assert!(status["retry_next_unix_ms"].is_null());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(body.len() <= MAX_STATUS);
        assert!(!String::from_utf8_lossy(&body).contains("account.json"));
        write_status(&prepared, "retrying", Some(Duration::from_secs(10))).unwrap();
        let retrying: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(retrying["phase"], "retrying");
        assert!(
            retrying["retry_next_unix_ms"].as_u64().unwrap()
                >= retrying["checked_at_unix_ms"].as_u64().unwrap() + 10_000
        );
    }

    #[test]
    fn status_rejects_symlink_without_following_it() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone");
        let outside = temp.path().join("outside");
        std::fs::write(&outside, b"sentinel").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("issuer-status.json")).unwrap();
        let prepared = prepared_status_fixture(root, vec!["example.test".into()]);
        assert!(write_status(&prepared, "renewing", None).is_err());
        assert_eq!(std::fs::read(outside).unwrap(), b"sentinel");
    }

    #[test]
    fn status_describes_first_issuance_without_claiming_a_certificate() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone");
        let prepared = prepared_status_fixture(root.clone(), vec!["example.test".into()]);
        write_status(&prepared, "renewing", None).unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("issuer-status.json")).unwrap())
                .unwrap();
        assert_eq!(status["phase"], "renewing");
        assert!(status["certificate_fingerprint_sha256"].is_null());
        assert!(status["expires_unix_ms"].is_null());
        assert!(status["renew_before_unix_ms"].is_null());
    }

    #[tokio::test]
    async fn supervisor_reports_restored_pair_before_any_ca_order() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone");
        let names = vec!["example.test".to_owned()];
        let certificate = issued(names.clone());
        write_generation(&root, &certificate).unwrap();
        let mut prepared = prepared_status_fixture(root.clone(), names);
        prepared.dns = Some(CloudflareSettings {
            zone_id: "a".repeat(32),
            token_file: temp.path().join("missing-token"),
        });
        let path = temp.path().join("issuer.json");
        std::fs::write(&path, b"unchanged-fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(supervise(
            path,
            b"unchanged-fixture".to_vec(),
            prepared.clone(),
            Arc::new(acme::HttpChallengeStore::default()),
            false,
            cancel.clone(),
        ));
        let status_path = root.join("issuer-status.json");
        tokio::time::timeout(Duration::from_secs(2), async {
            while !status_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(status_path).unwrap()).unwrap();
        assert_eq!(status["phase"], "ready");
        assert_eq!(
            status["expires_unix_ms"],
            unix_ms(certificate.not_after).unwrap()
        );
        assert!(
            !prepared.acme.account_path.exists(),
            "restored certificate contacted CA"
        );
        cancel.cancel();
        task.await.unwrap().unwrap();
    }

    #[test]
    fn generation_switch_is_atomic_private_and_restorable() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone-a");
        let names = vec!["example.test".into(), "*.example.test".into()];
        let first = issued(names.clone());
        write_generation(&root, &first).unwrap();
        let first_pointer = std::fs::read_link(root.join("current")).unwrap();
        assert_eq!(current_pair(&root, &names).unwrap(), Some(first.not_after));
        let files = [hangang::certificates::CertificateFiles {
            id: "zone-a".into(),
            hosts: names.clone(),
            default: false,
            enabled: true,
            cert_file: root.join("current/cert.pem"),
            key_file: root.join("current/key.pem"),
            issuer_status_file: None,
        }];
        hangang::certificates::load(&files).expect("gateway config-tls loads the symlinked pair");
        for path in [root.join("current/cert.pem"), root.join("current/key.pem")] {
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let next = issued(names.clone());
        write_generation(&root, &next).unwrap();
        let next_pointer = std::fs::read_link(root.join("current")).unwrap();
        assert_ne!(first_pointer, next_pointer);
        assert_eq!(current_pair(&root, &names).unwrap(), Some(next.not_after));
        hangang::certificates::load(&files).expect("gateway config-tls loads the replacement pair");
        assert!(
            current_pair_for(&root.join(first_pointer), &names).is_ok(),
            "previous generation remains available as rollback material"
        );
        assert_eq!(
            std::fs::metadata(root.join(next_pointer))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn one_zones_failed_publication_does_not_change_another_zones_pair() {
        let temp = tempfile::tempdir().unwrap();
        let a = private_output(temp.path(), "zone-a");
        let b = private_output(temp.path(), "zone-b");
        let a_names = vec!["a.example.test".into()];
        let b_names = vec!["b.example.test".into()];
        let a_cert = issued(a_names.clone());
        let b_cert = issued(b_names.clone());
        write_generation(&a, &a_cert).unwrap();
        write_generation(&b, &b_cert).unwrap();
        let before = std::fs::read_link(b.join("current")).unwrap();
        std::fs::remove_file(a.join("current")).unwrap();
        std::fs::create_dir(a.join("current")).unwrap();
        assert!(write_generation(&a, &issued(a_names)).is_err());
        assert_eq!(std::fs::read_link(b.join("current")).unwrap(), before);
        assert_eq!(current_pair(&b, &b_names).unwrap(), Some(b_cert.not_after));
    }

    #[test]
    fn rejects_public_config_or_token_and_unsafe_pointer() {
        let temp = tempfile::tempdir().unwrap();
        let config = temp.path().join("config.json");
        std::fs::write(&config, b"secret").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_bounded(&config, MAX_CONFIG).is_err());
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_bounded(&config, MAX_CONFIG).is_ok());
        let root = private_output(temp.path(), "zone");
        std::os::unix::fs::symlink("../escape", root.join("current")).unwrap();
        assert!(current_pair(&root, &["example.test".into()]).is_err());
    }

    #[tokio::test]
    async fn restart_with_current_pair_never_contacts_ca_or_dns() {
        let temp = tempfile::tempdir().unwrap();
        let root = private_output(temp.path(), "zone");
        let names = vec!["example.test".to_owned()];
        write_generation(&root, &issued(names.clone())).unwrap();
        let accounts = private_output(temp.path(), "accounts");
        let mut config = AcmeConfig::new(names, accounts.join("account.json"));
        config.challenge = ChallengeMode::Dns01;
        config.renewal.renew_before = Duration::ZERO;
        let prepared = Prepared {
            acme: config,
            dns: Some(CloudflareSettings {
                zone_id: "a".repeat(32),
                token_file: temp.path().join("missing-token"),
            }),
            output_directory: root,
        };
        run_one(
            &prepared,
            Arc::new(acme::HttpChallengeStore::default()),
            &tokio::sync::Mutex::new(None),
            &CancellationToken::new(),
        )
        .await
        .unwrap();
        assert!(
            !prepared.acme.account_path.exists(),
            "valid restored pair must not register an ACME account"
        );
    }

    #[tokio::test]
    async fn unchanged_issuer_settings_reuse_dns_provider_between_attempts() {
        let temp = tempfile::tempdir().unwrap();
        let private = private_output(temp.path(), "private");
        let token_file = private.join("token");
        std::fs::write(&token_file, b"fixture-token").unwrap();
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = Prepared {
            acme: AcmeConfig::new(vec!["example.test".into()], private.join("account.json")),
            dns: Some(CloudflareSettings {
                zone_id: "a".repeat(32),
                token_file: token_file.clone(),
            }),
            output_directory: private,
        };
        let providers = tokio::sync::Mutex::new(None);
        let first = provider_for(&config, &providers).await.unwrap().unwrap();
        std::fs::remove_file(token_file).unwrap();
        let second = provider_for(&config, &providers).await.unwrap().unwrap();
        assert!(
            Arc::ptr_eq(&first, &second),
            "retry must retain cleanup receipts"
        );
    }

    #[tokio::test]
    async fn config_replacement_is_detected_while_waiting_and_invalid_change_is_ignored() {
        let temp = tempfile::tempdir().unwrap();
        let accounts = private_output(temp.path(), "accounts");
        let zone_a = private_output(temp.path(), "zone-a");
        let zone_b = private_output(temp.path(), "zone-b");
        let names = vec!["example.test".to_owned()];
        write_generation(&zone_a, &issued(names.clone())).unwrap();
        write_generation(&zone_b, &issued(names.clone())).unwrap();
        let path = temp.path().join("issuer.json");
        let payload = |account: &str, output: &Path| {
            serde_json::to_vec(&serde_json::json!({
                "directory":"letsencrypt-production","domains":names,
                "challenge":"http-01","account_path":accounts.join(account),
                "output_directory":output,"check_interval_secs":3600,"renew_before_secs":0
            }))
            .unwrap()
        };
        let first = payload("first.json", &zone_a);
        std::fs::write(&path, &first).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = serde_json::from_slice::<IssuerFile>(&first)
            .unwrap()
            .prepare()
            .unwrap();
        let cancel = CancellationToken::new();
        let task = tokio::spawn(supervise(
            path.clone(),
            first,
            config,
            Arc::new(acme::HttpChallengeStore::default()),
            true,
            cancel.clone(),
        ));
        let first_lock = accounts.join("first.acme.lock");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !first_lock.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
        })
        .await
        .unwrap();
        std::fs::write(&path, payload("second.json", &zone_b)).unwrap();
        let second_lock = accounts.join("second.acme.lock");
        tokio::time::timeout(Duration::from_secs(6), async {
            while !second_lock.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await
            }
        })
        .await
        .unwrap();
        std::fs::write(&path, b"{invalid").unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(!accounts.join("third.acme.lock").exists());
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn http01_listener_only_serves_exact_host_and_token_and_stops() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let challenges = Arc::new(acme::HttpChallengeStore::default());
        challenges
            .insert("example.test", "owned_01", "owned_01.account")
            .await
            .unwrap();
        let cancel = CancellationToken::new();
        let child = cancel.clone();
        let task = tokio::spawn(serve_http(listener, challenges, child));
        let client = reqwest::Client::new();
        let url = format!("http://{address}/.well-known/acme-challenge/owned_01");
        let correct = client
            .get(&url)
            .header("host", "example.test")
            .send()
            .await
            .unwrap();
        assert_eq!(correct.status(), 200);
        assert_eq!(correct.text().await.unwrap(), "owned_01.account");
        assert_eq!(
            client
                .get(&url)
                .header("host", "other.test")
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            client
                .post(&url)
                .header("host", "example.test")
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        assert_eq!(
            client
                .get(format!("http://{address}/healthz"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
