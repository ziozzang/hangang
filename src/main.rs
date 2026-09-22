use anyhow::{Context, Result};
use clap::Parser;
use hangang::{
    admin::{Admin, Manager},
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
    store,
    tcp::TcpManager,
};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, Semaphore},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
#[derive(Parser, Debug)]
#[command(version, author, about = "Hangang asynchronous L4/L7 reverse proxy",
    after_help = "Source: https://github.com/ziozzang/hangang\nAuthor: Jioh Jung <jung@jioh.net>",
    group(clap::ArgGroup::new("update_source").args(["update_manifest", "update_github"])))]
struct Args {
    /// Print version, project URL, and author without starting the gateway.
    #[arg(long)]
    about: bool,
    /// Read the latest stable public GitHub release; does not install anything.
    #[arg(long)]
    check_update: bool,

    /// Enable native ACME using a dynamically reloaded private JSON file.
    #[arg(long, conflicts_with_all=["tls_cert", "tls_key", "kubernetes_tls"])]
    acme_config: Option<PathBuf>,
    /// HTTP-01 listener; publicly map port 80 to this address.
    #[arg(long, requires = "acme_config")]
    acme_http_listen: Option<SocketAddr>,
    #[arg(long, conflicts_with_all=["database","import_ingress"])]
    kubernetes_controller: bool,
    #[arg(long, requires = "kubernetes_controller")]
    kubernetes_api: Option<String>,
    #[arg(
        long,
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    )]
    kubernetes_ca: PathBuf,
    #[arg(
        long,
        default_value = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    )]
    kubernetes_token: PathBuf,
    #[arg(long, requires = "kubernetes_controller")]
    kubernetes_namespace: Option<String>,
    #[arg(long, requires="kubernetes_controller", conflicts_with_all=["tls_cert","tls_key"])]
    kubernetes_tls: bool,
    #[arg(long, requires = "kubernetes_controller")]
    kubernetes_publish_address: Option<String>,
    /// Seconds a watched Kubernetes kind may go without a list, watch event,
    /// bookmark, or watch closure before this replica reports itself not
    /// ready (it keeps serving its last snapshot). Must exceed the 30-second
    /// watch timeout.
    #[arg(long, default_value_t = 60, requires = "kubernetes_controller")]
    kubernetes_stale_seconds: u64,
    /// Explicit override for plaintext administration outside loopback.
    #[arg(long)]
    allow_insecure_admin: bool,
    #[arg(long, default_value = "hangang:config")]
    redis_key: String,
    /// Convert a Kubernetes JSON List of Ingress and Service resources to config.
    #[arg(long)]
    import_ingress: Option<PathBuf>,
    #[arg(long, default_value = "hangang")]
    ingress_class: String,
    #[arg(long, default_value = "hangang.json")]
    config: PathBuf,
    /// Keep a stable supervisor PID; SIGHUP replaces the serving generation.
    #[arg(long)]
    supervised: bool,
    /// Signed HTTPS release manifest; enables periodic updates under --supervised.
    #[arg(long,requires_all=["supervised","update_key"])]
    update_manifest: Option<String>,
    /// Discover signed release assets from ziozzang/hangang on GitHub.
    #[arg(long, requires_all=["supervised", "update_key"], conflicts_with="update_ca")]
    update_github: bool,
    #[arg(long, env = "HANGANG_UPDATE_KEY", hide_env_values = true)]
    update_key: Option<String>,
    #[arg(long, requires = "update_source")]
    update_ca: Option<PathBuf>,
    #[arg(long, default_value_t = 300)]
    update_interval_seconds: u64,
    #[arg(long)]
    update_status_file: Option<PathBuf>,
    #[arg(long, hide = true)]
    serve_child: bool,
    /// SQL config store: sqlite:/path.db or PostgreSQL connection string.
    #[arg(long, env = "HANGANG_DATABASE", hide_env_values = true)]
    database: Option<String>,
    #[arg(long, requires = "database")]
    database_ca: Option<PathBuf>,
    /// Explicitly allow unencrypted PostgreSQL on loopback/Unix sockets only.
    #[arg(long, requires = "database", conflicts_with = "database_ca")]
    database_plaintext: bool,
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:9000")]
    admin: SocketAddr,
    /// Serve administration only on this private Unix socket, with no TCP admin listener.
    #[arg(long, conflicts_with_all = ["admin", "admin_tls_cert", "admin_tls_key"])]
    admin_socket: Option<PathBuf>,
    #[arg(long, env = "HANGANG_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
    /// Private dynamically reloaded local fleet observer credential file.
    #[arg(long)]
    fleet_observer_config: Option<PathBuf>,
    /// Private dynamically reloaded allowlist of remote fleet observers.
    #[arg(long)]
    fleet_inventory_config: Option<PathBuf>,
    /// Instance-local administrator account database (private SQLite file).
    #[arg(long)]
    admin_users_db: Option<PathBuf>,
    /// Opt-in inspect-only Unix socket access.
    #[arg(long)]
    docker_socket: Option<PathBuf>,
    /// Instance-local Docker connection state. Use a distinct path per process.
    #[arg(long)]
    docker_connection_state: Option<PathBuf>,
    /// Lua policy worker processes. Defaults to the available CPU
    /// parallelism, clamped to 2..=8 (override for larger policy loads).
    #[arg(long, default_value_t = default_lua_workers())]
    lua_workers: usize,
    #[arg(long, default_value_t = 4096)]
    max_connections: usize,
    #[arg(long, default_value_t = 4096)]
    max_requests: usize,
    /// Maximum buffered JSON inspections; each raw body is bounded to 1 MiB.
    #[arg(long, default_value_t = 32)]
    max_json_inspections: usize,
    /// Concurrent body transformations; each direction has bounded per-record buffers.
    #[arg(long, default_value_t = 32)]
    max_body_transforms: usize,
    #[arg(long, default_value_t = 60)]
    connection_idle_seconds: u64,
    /// Idle bound for established L4/TCP sessions, in seconds. 0 disables it
    /// (unbounded, the default, to preserve long-lived idle TCP such as
    /// database pools). Set a positive value on public TCP listeners to bound
    /// silent connections (L4 slowloris). Any byte in either direction resets
    /// the timer.
    #[arg(long, default_value_t = 0)]
    tcp_idle_seconds: u64,
    /// Default time budget, in seconds, for an upstream to return response
    /// headers (covers request-body upload plus time-to-first-byte). Routes may
    /// override per route with `upstream_timeout_ms`. Raise this for large
    /// uploads or slow-first-byte upstreams; response body streaming afterwards
    /// is bounded by the transport idle timeout.
    #[arg(long, default_value_t = 15)]
    upstream_timeout_seconds: u64,
    /// Parent-side hard time budget, in milliseconds, for a single Lua worker
    /// operation. This bounds Lua work the in-VM 25ms deadline cannot interrupt
    /// (C-side string pattern matching: find/match/gmatch/gsub). Lower it on
    /// hostile-facing routes to bound pattern-matching CPU amplification; keep
    /// headroom above legitimate policy/transform time.
    #[arg(long, default_value_t = 200)]
    lua_timeout_ms: u64,
    #[arg(long, default_value_t = 30)]
    drain_seconds: u64,
    /// Seconds to keep accepting connections after readiness has been
    /// withdrawn on shutdown, so an external load balancer observes the 503
    /// health answer and stops routing before the listener closes. 0 closes
    /// the listener immediately (single-instance behavior).
    #[arg(long, default_value_t = 0)]
    lame_duck_seconds: u64,
    /// Shared-store mode: seconds a store read failure (unreachable, timed
    /// out, unreadable, empty) is tolerated since the last confirmation before
    /// this instance withdraws readiness. Serving continues on the last good
    /// snapshot either way. 0 withdraws on the first failed poll. Authority
    /// disagreements (rollback, divergence, epoch change) always withdraw
    /// immediately.
    #[arg(long, default_value_t = 30)]
    store_grace_seconds: u64,
    /// Shared-store mode: never seed an empty store from the configuration
    /// file; fail startup instead. Recommended for established deployments so
    /// that an accidentally emptied store cannot be re-seeded by a restart.
    #[arg(long, requires = "database")]
    no_bootstrap: bool,
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Public TLS certificate chain (PEM), automatically reloaded.
    #[arg(long, requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// Use the configuration certificate set for public TLS; empty sets reject handshakes.
    #[arg(long, conflicts_with_all=["tls_cert", "tls_key", "kubernetes_tls", "kubernetes_controller", "acme_config"])]
    config_tls: bool,
    #[arg(long, requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    #[arg(long, requires = "admin_tls_key")]
    admin_tls_cert: Option<PathBuf>,
    #[arg(long, requires = "admin_tls_cert")]
    admin_tls_key: Option<PathBuf>,
    /// Maximum reusable idle upstream connections per authority (60s expiry).
    #[arg(long, default_value_t = 256)]
    upstream_idle_per_host: usize,
    /// Additional trusted CA certificates for HTTPS upstreams.
    #[arg(long)]
    upstream_ca: Option<PathBuf>,
    /// Validate configuration including Lua in isolated workers, then exit.
    #[arg(long)]
    check: bool,
    /// Serve an unauthenticated health probe at this exact path on the public
    /// listener (e.g. "/healthz") for external load balancers that cannot
    /// present the admin token. 200 when ready, 503 while draining/not ready.
    /// Choose a path that does not collide with a real route.
    #[arg(long)]
    health_path: Option<String>,
    /// Forward request paths containing `.`/`..` dot segments (raw or
    /// percent-encoded) instead of rejecting them with 400. Rejection is the
    /// default; it keeps route matching and the forwarded path in agreement and
    /// prevents a normalizing backend from being reached under a less-privileged
    /// prefix route. Enable only if a backend legitimately needs raw dot segments.
    #[arg(long)]
    allow_dot_segments: bool,
    /// Comma-separated CIDRs of trusted fronting proxies. When the socket peer
    /// is in this set, the client IP/proto/host/port are taken from the incoming
    /// X-Forwarded-* headers (rightmost non-trusted XFF entry) instead of the
    /// socket, so `deny_cidrs`, external-auth client IP, the cache partition and
    /// regenerated forwarding headers reflect the real client. Empty (default)
    /// ignores all inbound forwarding headers.
    #[arg(long, value_delimiter = ',')]
    trusted_proxy_cidrs: Vec<ipnet::IpNet>,
    /// Comma-separated response header names removed from every upstream
    /// response (streaming-safe), for example `server,x-powered-by`. Per-route
    /// `response_set_headers`/`response_remove_headers` apply additionally.
    #[arg(long, value_delimiter = ',')]
    remove_response_headers: Vec<String>,
    /// Status used to send a plaintext request on a `require_tls` route to
    /// HTTPS: 301/302/307/308 redirect to the https URL, or 426 (Upgrade
    /// Required). Default 308.
    #[arg(long, default_value_t = 308)]
    https_redirect_code: u16,
    /// Maximum request/response header bytes (HTTP/1 read buffer and HTTP/2
    /// header list) on the public and admin listeners. Default 32768. Raise it
    /// for backends that send very large headers or cookies.
    #[arg(long, default_value_t = 32768)]
    max_header_bytes: usize,
    /// TCP/TLS connect timeout to upstreams, in milliseconds (default client
    /// path). Default 3000. Raise it for slow-connecting backends.
    #[arg(long, default_value_t = 3000)]
    connect_timeout_ms: u64,
    /// Emit a per-request access log line (tracing target `hangang::access`)
    /// with client, method, host, path, status and latency.
    #[arg(long)]
    access_log: bool,
}
/// Produce a `username:salt_hex:sha256_hex` Basic-auth credential entry using a
/// random salt from the system CSPRNG.
fn default_lua_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(2, 8)
}

fn hash_basic_credential(username: &str, password: &str) -> Result<String> {
    hangang::basic_auth::hash_credential(username, password)
}

fn main() -> Result<()> {
    if hangang::cli_about::print_if_requested("hangang") {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if std::env::args().nth(1).as_deref() == Some("--lua-sandbox-check") {
        return hangang::sandbox::self_check();
    }
    if std::env::args().nth(1).as_deref() == Some("--lua-worker") {
        return hangang::policy::worker_main();
    }
    if std::env::args().nth(1).as_deref() == Some("--hash-password") {
        let argv: Vec<String> = std::env::args().collect();
        let username = argv
            .get(2)
            .context("usage: --hash-password <username> <password>")?;
        let password = argv
            .get(3)
            .context("usage: --hash-password <username> <password>")?;
        println!("{}", hash_basic_credential(username, password)?);
        return Ok(());
    }
    let args = Args::parse();
    if args.about {
        println!(
            "Hangang {}\nSource: {}\nAuthor: {}",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_REPOSITORY"),
            env!("CARGO_PKG_AUTHORS")
        );
        return Ok(());
    }
    if args.check_update {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let release = runtime.block_on(hangang::github_release::latest())?;
        let check = release.check(
            semver::Version::parse(env!("CARGO_PKG_VERSION"))?,
            env!("HANGANG_TARGET"),
        )?;
        println!("{}", serde_json::to_string_pretty(&check)?);
        return Ok(());
    }
    anyhow::ensure!(
        args.update_key.is_none() || args.update_manifest.is_some() || args.update_github,
        "--update-key requires --update-manifest or --update-github for gateway startup"
    );
    anyhow::ensure!(
        args.admin_socket.is_none() || (!args.supervised && !args.serve_child),
        "--admin-socket does not support supervised hot restart"
    );
    anyhow::ensure!(
        args.admin_socket.is_some()
            || args.admin.ip().is_loopback()
            || args.admin_tls_cert.is_some()
            || args.allow_insecure_admin,
        "non-loopback administration requires TLS or --allow-insecure-admin"
    );
    if let Some(path) = &args.import_ingress {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "Ingress input exceeds 16 MiB"
        );
        let config =
            hangang::ingress::import(&serde_json::from_slice(&bytes)?, &args.ingress_class)?;
        println!("{}", serde_json::to_string_pretty(&config)?);
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "hangang=info".into()),
        )
        .init();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        repository = env!("CARGO_PKG_REPOSITORY"),
        author = env!("CARGO_PKG_AUTHORS"),
        "starting Hangang"
    );
    anyhow::ensure!(
        (1..=64).contains(&args.lua_workers),
        "lua-workers must be 1..64"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&args.max_connections),
        "max-connections must be 1..1000000"
    );
    anyhow::ensure!(
        (1..=1_000_000).contains(&args.max_requests),
        "max-requests must be 1..1000000"
    );
    anyhow::ensure!(
        (1..=1024).contains(&args.max_json_inspections),
        "max-json-inspections must be 1..1024"
    );
    anyhow::ensure!(args.threads <= 128, "threads must be <=128");
    anyhow::ensure!(
        (1..=86400).contains(&args.connection_idle_seconds),
        "connection-idle-seconds must be 1..86400"
    );
    anyhow::ensure!(
        args.tcp_idle_seconds <= 86400,
        "tcp-idle-seconds must be 0..86400 (0 disables)"
    );
    anyhow::ensure!(
        (1..=86400).contains(&args.upstream_timeout_seconds),
        "upstream-timeout-seconds must be 1..86400"
    );
    anyhow::ensure!(
        (25..=5000).contains(&args.lua_timeout_ms),
        "lua-timeout-ms must be 25..5000"
    );
    anyhow::ensure!(
        (4096..=1_048_576).contains(&args.max_header_bytes),
        "max-header-bytes must be 4096..1048576"
    );
    anyhow::ensure!(
        (100..=60_000).contains(&args.connect_timeout_ms),
        "connect-timeout-ms must be 100..60000"
    );
    anyhow::ensure!(
        matches!(args.https_redirect_code, 301 | 302 | 307 | 308 | 426),
        "https-redirect-code must be one of 301,302,307,308,426"
    );
    anyhow::ensure!(
        (1..=4096).contains(&args.upstream_idle_per_host),
        "upstream-idle-per-host must be 1..4096"
    );
    if let Some(path) = &args.health_path {
        anyhow::ensure!(
            path.starts_with('/') && !path.contains(['?', '#', ' ']) && path.len() <= 256,
            "health-path must be an absolute path without query, fragment or spaces (max 256 bytes)"
        );
    }
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();
    if args.threads > 0 {
        builder.worker_threads(args.threads);
    }
    let runtime = builder.build()?;
    if args.supervised && !args.serve_child && !args.check {
        anyhow::ensure!(
            args.update_interval_seconds >= 10,
            "update interval must be at least 10 seconds"
        );
        let update = (args.update_manifest.is_some() || args.update_github).then(|| {
            hangang::supervisor::UpdateOptions {
                manifest_url: args.update_manifest.clone(),
                github: args.update_github,
                public_key: args.update_key.clone().unwrap(),
                additional_ca: args.update_ca.clone(),
                interval: Duration::from_secs(args.update_interval_seconds),
                status_path: args
                    .update_status_file
                    .clone()
                    .unwrap_or_else(|| args.config.with_extension("update-status.json")),
            }
        });
        runtime.block_on(hangang::supervisor::run(
            std::env::current_exe()?,
            std::env::args_os().skip(1).collect(),
            Duration::from_secs(args.drain_seconds),
            Duration::from_secs(args.lame_duck_seconds),
            update,
        ))
    } else {
        runtime.block_on(run(args))
    }
}
async fn run(args: Args) -> Result<()> {
    hangang::admin::initialize_clock();
    use hangang::restart::{ControlChannel, ControlMessage, DescriptorRole, ProtocolMessage};
    let channel = if args.serve_child {
        let raw: i32 = std::env::var("HANGANG_CONTROL_FD")
            .context("missing inherited control channel")?
            .parse()?;
        Some(Arc::new(unsafe { ControlChannel::from_child_fd(raw)? }))
    } else {
        None
    };
    let mut inherited_acme = None;
    let mut inherited_public = None;
    let mut inherited_admin = None;
    let mut inherited_lock = None;
    let mut inherited_docker_lock = None;
    let mut inherited_config = None;
    let mut inherited_tcp = Vec::new();
    let mut inherited_public_http_addresses = std::collections::HashSet::new();
    let mut inherited_workload_addresses = std::collections::HashSet::new();
    if let Some(channel) = &channel {
        let channel = channel.clone();
        let descriptors = tokio::task::spawn_blocking(move || -> Result<_> {
            match channel.recv_timeout(Duration::from_secs(15))? {
                ProtocolMessage::Control(ControlMessage::Commit) => Ok(None),
                ProtocolMessage::Control(ControlMessage::FreezeExport) => {
                    Ok(Some(channel.receive_export(Duration::from_secs(15))?))
                }
                _ => anyhow::bail!("invalid supervisor startup message"),
            }
        })
        .await??;
        if let Some(descriptors) = descriptors {
            use std::io::{Read, Seek};
            for descriptor in descriptors {
                match descriptor.role {
                    DescriptorRole::AcmeHttp(address) => {
                        anyhow::ensure!(
                            Some(address) == args.acme_http_listen,
                            "ACME listener address mismatch"
                        );
                        inherited_acme = Some(descriptor.fd);
                    }
                    DescriptorRole::Public(address) => {
                        anyhow::ensure!(address == args.listen, "public listener address mismatch");
                        inherited_public = Some(descriptor.fd);
                    }
                    DescriptorRole::Admin(address) => {
                        anyhow::ensure!(address == args.admin, "admin listener address mismatch");
                        inherited_admin = Some(descriptor.fd);
                    }
                    DescriptorRole::Tcp(address) => inherited_tcp.push((address, descriptor.fd)),
                    DescriptorRole::PublicHttp(address) => {
                        inherited_public_http_addresses.insert(address);
                        inherited_tcp.push((address, descriptor.fd));
                    }
                    DescriptorRole::WorkloadHttp(address) => {
                        inherited_workload_addresses.insert(address);
                        inherited_tcp.push((address, descriptor.fd));
                    }
                    DescriptorRole::ConfigLock => {
                        inherited_lock = Some(std::fs::File::from(descriptor.fd))
                    }
                    DescriptorRole::DockerLock => {
                        inherited_docker_lock = Some(std::fs::File::from(descriptor.fd))
                    }
                    DescriptorRole::ConfigSnapshot => {
                        let mut file = std::fs::File::from(descriptor.fd);
                        anyhow::ensure!(
                            file.metadata()?.is_file() && file.metadata()?.len() <= 1024 * 1024,
                            "invalid inherited configuration descriptor"
                        );
                        file.rewind()?;
                        let mut bytes = Vec::new();
                        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
                        anyhow::ensure!(
                            bytes.len() <= 1024 * 1024,
                            "inherited configuration too large"
                        );
                        inherited_config =
                            Some(match serde_json::from_slice::<InheritedSnapshot>(&bytes) {
                                Ok(snapshot) => snapshot,
                                Err(_) => InheritedSnapshot {
                                    config: serde_json::from_slice::<Config>(&bytes)?,
                                    epoch: None,
                                },
                            });
                    }
                }
            }
        }
    }
    if let Some(inherited) = &inherited_config {
        for (address, _) in &inherited_tcp {
            let workload = inherited
                .config
                .workload_http
                .iter()
                .any(|listener| listener.enabled && listener.listen == *address);
            let tcp = inherited
                .config
                .tcp
                .iter()
                .any(|route| route.enabled && route.listen == *address);
            let public_http = inherited
                .config
                .public_http
                .iter()
                .any(|listener| listener.enabled && listener.listen == *address);
            anyhow::ensure!(
                usize::from(workload) + usize::from(tcp) + usize::from(public_http) == 1
                    && workload == inherited_workload_addresses.contains(address)
                    && public_http == inherited_public_http_addresses.contains(address),
                "inherited listener role disagrees with frozen configuration"
            );
        }
    }
    let replacing = inherited_config.is_some();
    let inherited_epoch = inherited_config.as_ref().and_then(|s| s.epoch.clone());
    let mut config = if let Some(inherited) = inherited_config {
        inherited.config.validate()?;
        inherited.config
    } else if args.database.is_some() || args.kubernetes_controller {
        Config::default()
    } else if args.config.exists() {
        store::load(&args.config)?
    } else {
        anyhow::ensure!(
            !args.check || args.database.is_some(),
            "configuration does not exist"
        );
        Config::default()
    };
    anyhow::ensure!(
        !args.kubernetes_controller
            || (config.public_http.is_empty()
                && config
                    .http
                    .iter()
                    .all(|route| route.listener_ids.is_empty())),
        "public listener scopes require local file authority"
    );
    anyhow::ensure!(
        (1..=1024).contains(&args.max_body_transforms),
        "max-body-transforms must be 1..1024"
    );
    anyhow::ensure!(
        args.lame_duck_seconds <= 300,
        "lame-duck-seconds must be 0..300"
    );
    anyhow::ensure!(
        args.store_grace_seconds <= 3600,
        "store-grace-seconds must be 0..3600"
    );
    hangang::policy::set_operation_timeout(Duration::from_millis(args.lua_timeout_ms));
    hangang::proxy::set_connect_timeout(Duration::from_millis(args.connect_timeout_ms));
    let pool = Arc::new(PolicyPool::new(std::env::current_exe()?, args.lua_workers));
    // Configuration validation must remain available while data-plane policy slots are busy.
    let validation_pool = Arc::new(PolicyPool::new(std::env::current_exe()?, 1));
    // A shared-store bootstrap prepares the seed's runtime resources first;
    // the prepared snapshot is reused below instead of preparing it twice.
    let mut prepared_snapshot: Option<Snapshot> = None;
    // The authority epoch of the shared store this instance follows. A
    // replacement inherits it; without one (older exporter) the first poll
    // attaches to whatever the store holds, like a fresh start.
    let mut authority_epoch: Option<String> = inherited_epoch;
    let config_store: Option<Arc<dyn hangang::config_store::ConfigStore>> = if let Some(database) =
        &args.database
    {
        use hangang::config_store::{PostgresConfigStore, SqliteConfigStore};
        let store: Arc<dyn hangang::config_store::ConfigStore> = if let Some(path) =
            database.strip_prefix("sqlite:")
        {
            anyhow::ensure!(!path.is_empty(), "SQLite path is empty");
            Arc::new(SqliteConfigStore::open(path).await?)
        } else if database.starts_with("redis://") || database.starts_with("rediss://") {
            use hangang::redis_store::RedisConfigStore;
            if args.database_plaintext {
                Arc::new(
                    RedisConfigStore::connect_unencrypted(database, args.redis_key.clone()).await?,
                )
            } else if let Some(path) = &args.database_ca {
                use std::io::Read;
                let mut bytes = Vec::new();
                std::fs::File::open(path)?
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes)?;
                anyhow::ensure!(bytes.len() <= 1024 * 1024, "Redis CA exceeds 1 MiB");
                Arc::new(
                    RedisConfigStore::connect_with_ca(database, args.redis_key.clone(), bytes)
                        .await?,
                )
            } else {
                Arc::new(RedisConfigStore::connect(database, args.redis_key.clone()).await?)
            }
        } else {
            if args.database_plaintext {
                Arc::new(PostgresConfigStore::connect_unencrypted(database).await?)
            } else {
                Arc::new(
                    PostgresConfigStore::connect(
                        database,
                        hangang::tls::client_config(args.database_ca.as_deref())?,
                    )
                    .await?,
                )
            }
        };
        config = if replacing {
            config
        } else if args.check {
            let stored = store
                .load_latest()
                .await?
                .context("SQL configuration does not exist")?;
            authority_epoch = Some(stored.epoch);
            stored.config
        } else if let Some(stored) = store.load_latest().await? {
            authority_epoch = Some(stored.epoch);
            stored.config
        } else {
            anyhow::ensure!(
                !args.no_bootstrap,
                "shared configuration store is empty and --no-bootstrap forbids seeding it"
            );
            let seed = if args.config.exists() {
                crate::store::load(&args.config)?
            } else {
                Config::default()
            };
            for route in &seed.http {
                for script in route.scripts() {
                    validation_pool
                        .validate(script)
                        .await
                        .context("Lua bootstrap validation")?;
                }
            }
            // Every startup resource is checked before the seed can become
            // the shared authority: certificates and upstream TLS material
            // (below), and TCP listen addresses here — a seed whose listener
            // collides with the public/admin/ACME listener or an occupied
            // port could otherwise be persisted for every instance although
            // none can start with it.
            let reserved: Vec<SocketAddr> = [
                Some(args.listen),
                (args.admin_socket.is_none()).then_some(args.admin),
                args.acme_http_listen,
            ]
            .into_iter()
            .flatten()
            .collect();
            hangang::tcp::TcpManager::probe_bindable(&seed, &reserved)
                .await
                .context("seed configuration cannot be served by this instance")?;
            let bootstrapped = hangang::config_store::bootstrap_prepared(&*store, seed).await?;
            let config = bootstrapped.snapshot.config.clone();
            authority_epoch = Some(bootstrapped.epoch);
            prepared_snapshot = Some(bootstrapped.snapshot);
            config
        };
        Some(store)
    } else {
        None
    };
    let shared_store = config_store.is_some();
    let controller_options = if args.kubernetes_controller {
        let mut options = if let Some(api) = &args.kubernetes_api {
            hangang::kubernetes::ControllerOptions {
                api_server: api.parse()?,
                ca_path: args.kubernetes_ca.clone(),
                token_path: args.kubernetes_token.clone(),
                namespace: None,
                ingress_class: args.ingress_class.clone(),
                watch_secrets: false,
                publish_address: None,
                list_page_size: 500,
                max_objects: 10_000,
                watch_timeout: Duration::from_secs(30),
                request_timeout: Duration::from_secs(40),
                stale_after: Duration::from_secs(args.kubernetes_stale_seconds),
            }
        } else {
            hangang::kubernetes::ControllerOptions::in_cluster(args.ingress_class.clone())?
        };
        options.stale_after = Duration::from_secs(args.kubernetes_stale_seconds);
        options.ca_path = args.kubernetes_ca.clone();
        options.token_path = args.kubernetes_token.clone();
        options.namespace = args.kubernetes_namespace.clone();
        options.watch_secrets = args.kubernetes_tls;
        options.publish_address = args.kubernetes_publish_address.clone();
        Some(options)
    } else {
        None
    };
    let public_tls = if args.kubernetes_tls || args.acme_config.is_some() {
        Some(Arc::new(hangang::tls::ReloadingTls::dynamic(
            hangang::tls::sni_server_config(Vec::new())?,
        )))
    } else {
        match (&args.tls_cert, &args.tls_key) {
            (Some(cert), Some(key)) => Some(Arc::new(hangang::tls::ReloadingTls::new(
                cert.clone(),
                key.clone(),
            )?)),
            _ => None,
        }
    };
    let admin_tls = match (&args.admin_tls_cert, &args.admin_tls_key) {
        (Some(cert), Some(key)) => Some(Arc::new(hangang::tls::ReloadingTls::new(
            cert.clone(),
            key.clone(),
        )?)),
        _ => None,
    };
    let acme = if let Some(path) = args.acme_config.clone() {
        Some(
            hangang::acme_runtime::Runtime::new(
                path,
                args.acme_http_listen.is_some(),
                public_tls.clone().unwrap(),
                config_store.clone(),
            )
            .await?,
        )
    } else {
        None
    };
    anyhow::ensure!(
        config.udp.is_empty()
            || (!args.supervised
                && !args.serve_child
                && !shared_store
                && !args.kubernetes_controller),
        "UDP routes require local file authority without supervised restart"
    );
    let upstream_tls = hangang::tls::client_config(args.upstream_ca.as_deref())?;
    for route in &config.http {
        for script in route.scripts() {
            validation_pool
                .validate(script)
                .await
                .context("Lua validation")?;
        }
    }
    if args.check {
        if let Some(path) = args.fleet_observer_config.clone() {
            let _ =
                hangang::fleet_observer::Runtime::open(path, args.admin_token.as_deref()).await?;
        }
        if let Some(path) = args.fleet_inventory_config.clone() {
            let _ =
                hangang::fleet_collector::Runtime::open(path, args.admin_token.as_deref()).await?;
        }
        config.validate()?;
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            hangang::certificates::load(&config.certificates)?;
            config.prepare_upstream_tls()?;
            config.prepare_host_regexes()?;
            Ok(())
        })
        .await??;
        pool.shutdown().await;
        validation_pool.shutdown().await;
        println!("configuration valid");
        return Ok(());
    }
    let token = args
        .admin_token
        .clone()
        .context("set HANGANG_ADMIN_TOKEN (at least 16 bytes)")?;
    anyhow::ensure!(
        token.len() >= 16,
        "admin token must contain at least 16 bytes"
    );
    let fleet_observer = match args.fleet_observer_config.clone() {
        Some(path) => Some(hangang::fleet_observer::Runtime::open(path, Some(&token)).await?),
        None => None,
    };
    let fleet_collector = match args.fleet_inventory_config.clone() {
        Some(path) => Some(hangang::fleet_collector::Runtime::open(path, Some(&token)).await?),
        None => None,
    };
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = if let Some(lock) = inherited_lock {
        Some(lock)
    } else if config_store.is_none() && !args.kubernetes_controller {
        let lock = options
            .open(args.config.with_extension("lock"))
            .context("open configuration writer lock")?;
        lock.try_lock()
            .context("another process owns the configuration file")?;
        Some(lock)
    } else {
        None
    };
    let metrics = Arc::new(Metrics::default());
    let active = Arc::new(arc_swap::ArcSwap::from_pointee(
        match prepared_snapshot.take().filter(|s| s.config == config) {
            Some(snapshot) => snapshot,
            None => Snapshot::new(config.clone())?,
        },
    ));
    active.load().activated();
    let docker_state = match args.docker_connection_state.clone() {
        Some(path) => path,
        None => {
            let mut filename = args
                .config
                .file_name()
                .context("configuration path needs a filename")?
                .to_os_string();
            filename.push(".docker-connection.json");
            args.config.with_file_name(filename)
        }
    };
    let docker_state = if docker_state.is_absolute() {
        docker_state
    } else {
        std::env::current_dir()?.join(docker_state)
    };
    let docker = Arc::new(
        hangang::docker_connections::DockerConnections::open_with_lock(
            docker_state,
            args.docker_socket.clone(),
            inherited_docker_lock,
        )?,
    );
    let discovery = Arc::new(hangang::discovery::Discovery::managed(docker.clone()));
    if let Err(error) = discovery.refresh(&config).await {
        tracing::warn!(%error,"some Docker backends are unavailable");
    }
    let tcp = TcpManager::with_idle_timeout(
        active.clone(),
        metrics.clone(),
        args.max_connections,
        Duration::from_secs(args.tcp_idle_seconds),
    )
    .with_discovery(discovery.clone())
    .with_datagrams_allowed(channel.is_none() && !shared_store && !args.kubernetes_controller);
    // A shared-store or Kubernetes generation must not accept TCP traffic
    // before its authority confirms the initial snapshot. This also covers
    // a replacement that inherited a snapshot from the previous process.
    // The gate opens only after await_readiness succeeds below.
    let tcp = Arc::new(tcp.with_gate_closed());
    let public_listener = if let Some(fd) = inherited_public {
        adopt_listener(fd, args.listen)?
    } else {
        TcpListener::bind(args.listen)
            .await
            .context("bind HTTP listener")?
    };
    let admin_socket_listener = if let Some(path) = &args.admin_socket {
        Some(hangang::admin_socket::BoundAdminSocket::bind(path)?)
    } else {
        None
    };
    let admin_listener = if args.admin_socket.is_some() {
        None
    } else if let Some(fd) = inherited_admin {
        Some(adopt_listener(fd, args.admin)?)
    } else {
        Some(
            TcpListener::bind(args.admin)
                .await
                .context("bind admin listener")?,
        )
    };
    let (acme_listener, acme_export) = if let Some(address) = args.acme_http_listen {
        let listener = if let Some(fd) = inherited_acme {
            adopt_listener(fd, address)?
        } else {
            TcpListener::bind(address)
                .await
                .context("bind ACME HTTP listener")?
        };
        let (listener, export) = retain_listener(listener, channel.is_some())?;
        (Some(listener), export)
    } else {
        (None, None)
    };
    let (public_listener, public_export) = retain_listener(public_listener, channel.is_some())?;
    let (admin_listener, admin_export) = if let Some(listener) = admin_listener {
        let (listener, export) = retain_listener(listener, channel.is_some())?;
        (Some(listener), export)
    } else {
        (None, None)
    };
    let prepared = if replacing {
        tcp.prepare_with_inherited(&config, inherited_tcp).await?
    } else {
        tcp.prepare(&config).await?
    };
    if replacing {
        let channel = channel.as_ref().unwrap().clone();
        channel.send_control(ControlMessage::Prepared)?;
        tokio::task::spawn_blocking(move || -> Result<()> {
            anyhow::ensure!(
                matches!(
                    channel.recv_timeout(Duration::from_secs(15))?,
                    ProtocolMessage::Control(ControlMessage::Commit)
                ),
                "supervisor did not commit candidate"
            );
            Ok(())
        })
        .await??;
    }
    tcp.commit(prepared).await;
    let removed_response_headers = args
        .remove_response_headers
        .iter()
        .map(|name| {
            anyhow::ensure!(
                !hangang::config::is_protected_response_header(name),
                "--remove-response-headers cannot remove protected header: {name}"
            );
            hyper::header::HeaderName::from_bytes(name.as_bytes())
                .with_context(|| format!("invalid --remove-response-headers name: {name}"))
        })
        .collect::<Result<Vec<_>>>()?;
    // File mode is locally authoritative. Controller and shared-store modes
    // must first reconcile with their authority: a replacement generation
    // inherits its predecessor's snapshot, which the store may since have
    // rolled back, replaced or lost.
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(
        !args.kubernetes_controller && !shared_store,
    ));
    let traffic = Arc::new(hangang::traffic::TrafficHistory::default());
    let proxy = Proxy::with_client_config_and_idle_limit(
        active.clone(),
        pool.clone(),
        metrics.clone(),
        upstream_tls,
        args.upstream_idle_per_host,
    )
    .with_request_limit(args.max_requests)
    .with_inspection_limit(args.max_json_inspections)
    .with_transform_limit(args.max_body_transforms)
    .with_discovery(discovery.clone())
    .with_health_path(args.health_path.clone())
    .with_readiness(ready.clone())
    .with_dot_segments_allowed(args.allow_dot_segments)
    .with_upstream_timeout(Duration::from_secs(args.upstream_timeout_seconds))
    .with_trusted_proxies(args.trusted_proxy_cidrs.clone())
    .with_removed_response_headers(removed_response_headers.clone())
    .with_https_redirect_code(args.https_redirect_code)
    .with_traffic_history(traffic.clone())
    .with_access_log(args.access_log)
    .with_tunnel_idle_timeout(Duration::from_secs(args.connection_idle_seconds));
    tcp.set_workload_http(Arc::new(proxy.clone()), args.max_header_bytes)?;
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: tcp.clone(),
        policy: validation_pool.clone(),
        metrics: metrics.clone(),
        state_path: args.config,
        config_store,
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed: args.kubernetes_controller,
        ready: ready.clone(),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        store_health: hangang::admin::StoreHealth::new(Duration::from_secs(
            args.store_grace_seconds,
        )),
        authority_epoch: std::sync::Mutex::new(authority_epoch),
    });
    let users_db_path = if let Some(path) = args.admin_users_db.clone() {
        if path.is_absolute() {
            path
        } else {
            std::env::current_dir()?.join(path)
        }
    } else {
        // The configuration itself may live in a normal group-writable
        // project directory. Keep the default account database inside its
        // own private directory, scoped to this configuration file.
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let config_parent = manager
            .state_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let config_parent = std::fs::canonicalize(config_parent)?;
        let mut directory_name = manager
            .state_path
            .file_name()
            .context("configuration path has no filename")?
            .to_os_string();
        directory_name.push(".admin");
        let directory = config_parent.join(directory_name);
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        anyhow::ensure!(
            metadata.file_type().is_dir()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.uid() == unsafe { libc::geteuid() },
            "default administrator account directory must be a private directory owned by this process"
        );
        directory.join("users.sqlite3")
    };
    let users = Arc::new(hangang::admin_users::Store::open(users_db_path)?);
    let admin = Admin {
        fleet_collector: fleet_collector.clone(),
        fleet_observer: fleet_observer.clone(),
        traffic,
        events: Arc::new(tokio::sync::Semaphore::new(32)),
        acme_status: acme.as_ref().map(|runtime| runtime.status.clone()),
        file_tls_enabled: args.config_tls,
        requests: Arc::new(tokio::sync::Semaphore::new(64)),
        public_requests: Arc::new(tokio::sync::Semaphore::new(Admin::PUBLIC_REQUEST_LIMIT)),
        auth_requests: Arc::new(tokio::sync::Semaphore::new(Admin::AUTH_REQUEST_LIMIT)),
        observer_requests: Arc::new(tokio::sync::Semaphore::new(Admin::OBSERVER_REQUEST_LIMIT)),
        manager: manager.clone(),
        token: Arc::new(token),
        users,
        lifecycle: channel.clone(),
        update_status_path: (args.update_manifest.is_some() || args.update_github).then(|| {
            args.update_status_file
                .clone()
                .unwrap_or_else(|| manager.state_path.with_extension("update-status.json"))
        }),
        docker: Some(docker.clone()),
    };
    let cancel = CancellationToken::new();
    let fleet_observer_task =
        fleet_observer.map(|runtime| tokio::spawn(runtime.watch(cancel.clone())));
    let fleet_collector_task =
        fleet_collector.map(|runtime| tokio::spawn(runtime.watch(cancel.clone())));
    let discovery_task = tokio::spawn(discovery.watch(manager.active.clone(), cancel.clone()));
    let watcher = if let Some(options) = controller_options {
        let sink = Arc::new(KubernetesSink {
            manager: manager.clone(),
            tls: if args.kubernetes_tls {
                public_tls.clone()
            } else {
                None
            },
        });
        let controller = hangang::kubernetes::Controller::new(options, sink)?;
        let cancel = cancel.clone();
        tokio::spawn(async move { controller.run(cancel).await })
    } else {
        tokio::spawn(hangang::admin::watch_config(
            manager.clone(),
            cancel.clone(),
        ))
    };
    let authority = if args.kubernetes_controller {
        Some("Kubernetes initial configuration")
    } else if shared_store {
        Some("shared configuration store")
    } else {
        None
    };
    if let Some(authority) = authority
        && !hangang::admin::await_readiness(&ready, Duration::from_secs(10)).await
    {
        // Lifecycle `Ready` is sent only below; a supervisor sees this failure
        // as a rejected replacement and keeps the previous generation.
        cancel.cancel();
        anyhow::bail!("{authority} did not become ready within 10 seconds");
    }
    // Trust withdrawal must remain active while old connections drain, even
    // after the global accept/configuration cancellation token is cancelled.
    let workload_cancel = CancellationToken::new();
    let workload_watcher = tokio::spawn(hangang::workload_material::watch(
        active.clone(),
        workload_cancel.clone(),
    ));
    // The GeoIP source is node-local. Keep exactly one verifier for the
    // published slot, and retain it through the connection drain so a
    // withdrawal remains observable by in-flight work.
    let geoip_cancel = CancellationToken::new();
    let geoip_watcher = tokio::spawn(watch_geoip_slot(active.clone(), geoip_cancel.clone()));
    let mut tls_watchers = Vec::new();
    // New slots are quarantined until the watcher verifies their files after
    // publication. Do not signal startup readiness or accept traffic earlier.
    if tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = active.load_full();
            if snapshot
                .tcp_inbound_tls
                .values()
                .chain(snapshot.http_workload_tls.values())
                .all(|slot| slot.load().is_some())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_err()
    {
        cancel.cancel();
        workload_cancel.cancel();
        geoip_cancel.cancel();
        let _ = workload_watcher.await;
        let _ = geoip_watcher.await;
        anyhow::bail!("workload TLS material did not become ready within 10 seconds");
    }
    tcp.open_gate();
    tls_watchers.push(tokio::spawn(hangang::certificates::watch_public(
        active.clone(),
        cancel.clone(),
    )));
    if args.config_tls {
        tls_watchers.push(tokio::spawn(hangang::certificates::watch(
            active.clone(),
            cancel.clone(),
        )));
    }
    for tls in [public_tls.clone(), admin_tls.clone()]
        .into_iter()
        .flatten()
    {
        tls_watchers.push(tokio::spawn(tls.watch(cancel.clone())));
    }
    let grace = Duration::from_secs(args.drain_seconds);
    let public_task = tokio::spawn(serve(
        public_listener,
        Handler::Proxy(Arc::new(proxy.clone())),
        cancel.clone(),
        metrics.clone(),
        ListenerPolicy {
            limit: args.max_connections,
            grace,
            config_tls: (args.config_tls || args.kubernetes_tls).then(|| active.clone()),
            tls: public_tls,
            idle_timeout: Duration::from_secs(args.connection_idle_seconds),
            header_bytes: args.max_header_bytes,
        },
    ));
    let admin = Arc::new(admin);
    let admin_task = if let Some(bound) = admin_socket_listener {
        tokio::spawn(hangang::admin_socket::serve(
            bound,
            admin,
            cancel.clone(),
            metrics.clone(),
            grace,
            args.max_header_bytes,
        ))
    } else {
        tokio::spawn(serve(
            admin_listener.expect("TCP admin listener in TCP mode"),
            Handler::Admin(admin),
            cancel.clone(),
            metrics.clone(),
            ListenerPolicy {
                limit: 64,
                grace,
                config_tls: None,
                tls: admin_tls,
                idle_timeout: Duration::from_secs(10),
                header_bytes: args.max_header_bytes,
            },
        ))
    };
    let acme_http_task = acme_listener.map(|listener| {
        tokio::spawn(serve(
            listener,
            Handler::Acme(acme.as_ref().unwrap().challenges.clone()),
            cancel.clone(),
            metrics.clone(),
            ListenerPolicy {
                limit: 128,
                grace,
                config_tls: None,
                tls: None,
                idle_timeout: Duration::from_secs(10),
                header_bytes: 32768,
            },
        ))
    });
    if let Some(acme) = &acme {
        acme.start().await;
    }
    if args.admin_socket.is_some() {
        tracing::info!(http=%args.listen,admin_transport="unix","hangang ready");
    } else {
        tracing::info!(http=%args.listen,admin=%args.admin,"hangang ready");
    }
    // How this generation ends: a direct signal (unsupervised) withdraws
    // readiness, keeps accepting for the lame-duck window, then drains; a
    // supervisor drives the same phases itself (`Withdraw`, then `Drain`) or
    // retires a replaced generation with `Drain` alone, in which case the
    // endpoint stays healthy through the successor and this generation must
    // not advertise failure on connections it still owns.
    let ending = if let Some(channel) = channel {
        channel.send_control(ControlMessage::Ready)?;
        lifecycle_wait(
            channel,
            &manager,
            &tcp,
            HandoffFiles {
                public: public_export.as_ref().unwrap(),
                admin: admin_export.as_ref().unwrap(),
                lock: lock.as_ref(),
                docker: &docker,
                acme_listener: acme_export.as_ref(),
            },
            acme.as_ref(),
        )
        .await?
    } else {
        shutdown_signal().await?;
        Ending::Local
    };
    // Nothing below waits for an in-flight transaction or poll before the
    // accept loops are closed: readiness/freeze flags flip immediately, the
    // lame-duck window (if any) elapses, the listeners close, and only then
    // are writers and background tasks awaited.
    match ending {
        Ending::Retire => {
            // Readiness is left as it is because the endpoint is served by
            // the successor.
            manager.freeze_now();
        }
        Ending::Directed => {
            // Readiness was withdrawn by the supervisor and the lame-duck
            // window already elapsed there.
            manager.withdraw_now();
        }
        Ending::Local => {
            // Withdraw readiness first while the listeners stay open, so a
            // load balancer that probes health sees 503 and stops routing
            // here before accepts stop; then close the listeners and drain.
            manager.withdraw_now();
            if args.lame_duck_seconds > 0 {
                tracing::info!(
                    seconds = args.lame_duck_seconds,
                    "lame duck: readiness withdrawn, still accepting"
                );
                tokio::time::sleep(Duration::from_secs(args.lame_duck_seconds)).await;
            }
        }
    }
    tracing::info!("draining connections");
    cancel.cancel();
    // Close every accept loop before waiting for background work (a stalled
    // authority poll, a slow writer, ACME, watchers): a retiring or draining
    // generation must not keep taking connections meanwhile.
    tcp.stop_accepting().await;
    if ending != Ending::Retire {
        // Now wait for an admitted write to complete (it keeps its CAS).
        manager.stop_updates().await;
    }
    if let Some(acme) = &acme {
        acme.stop().await;
    }
    if let Some(task) = acme_http_task {
        let _ = task.await;
    }
    let _ = watcher.await;
    let _ = discovery_task.await;
    if let Some(task) = fleet_observer_task {
        let _ = task.await;
    }
    if let Some(task) = fleet_collector_task {
        let _ = task.await;
    }
    for watcher in tls_watchers {
        let _ = watcher.await;
    }
    let (_, _, _, _) = tokio::join!(
        public_task,
        admin_task,
        tcp.shutdown(grace),
        proxy.shutdown(grace)
    );
    workload_cancel.cancel();
    let _ = workload_watcher.await;
    geoip_cancel.cancel();
    let _ = geoip_watcher.await;
    pool.shutdown().await;
    validation_pool.shutdown().await;
    drop(lock);
    Ok(())
}

/// Switch node-local GeoIP verification only after the predecessor has
/// stopped and its in-flight blocking read has drained. A candidate slot may
/// receive a database only while that exact Arc is in the active snapshot.
async fn watch_geoip_slot(active: Arc<arc_swap::ArcSwap<Snapshot>>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut current: Option<Arc<hangang::geoip_runtime::Slot>> = None;
    let mut child_cancel: Option<CancellationToken> = None;
    let mut child: Option<tokio::task::JoinHandle<()>> = None;
    loop {
        tokio::select! { biased; _ = cancel.cancelled() => break, _ = tick.tick() => {} }
        let selected = active.load().geoip.clone();
        let same = match (&current, &selected) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            (None, None) => true,
            _ => false,
        };
        if same && child.as_ref().is_none_or(|task| !task.is_finished()) {
            continue;
        }
        if let Some(token) = child_cancel.take() {
            token.cancel();
        }
        if let Some(task) = child.take() {
            let _ = task.await;
        }
        current = None;
        if cancel.is_cancelled() {
            break;
        }
        // A publication may have changed while the previous verifier drained.
        // Re-read it before starting work on a new source.
        let selected = active.load().geoip.clone();
        if let Some(slot) = selected {
            let published_active = active.clone();
            let published: Arc<hangang::geoip_runtime::Published> = Arc::new(move |candidate| {
                published_active
                    .load()
                    .geoip
                    .as_ref()
                    .is_some_and(|active_slot| Arc::ptr_eq(active_slot, candidate))
            });
            let token = CancellationToken::new();
            child = Some(tokio::spawn(hangang::geoip_runtime::watch(
                slot.clone(),
                published,
                token.clone(),
            )));
            child_cancel = Some(token);
            current = Some(slot);
        }
    }
    if let Some(token) = child_cancel {
        token.cancel();
    }
    if let Some(task) = child {
        let _ = task.await;
    }
}
#[derive(Clone)]
enum Handler {
    Proxy(Arc<Proxy>),
    Admin(Arc<Admin>),
    Acme(Arc<hangang::acme::HttpChallengeStore>),
}
struct ListenerPolicy {
    config_tls: Option<Arc<arc_swap::ArcSwap<Snapshot>>>,
    limit: usize,
    grace: Duration,
    tls: Option<Arc<hangang::tls::ReloadingTls>>,
    idle_timeout: Duration,
    header_bytes: usize,
}
async fn serve(
    listener: TcpListener,
    handler: Handler,
    cancel: CancellationToken,
    metrics: Arc<Metrics>,
    policy: ListenerPolicy,
) {
    let local_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    let ListenerPolicy {
        config_tls,
        limit,
        grace,
        tls,
        idle_timeout,
        header_bytes,
    } = policy;
    let permits = Arc::new(Semaphore::new(limit));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _=cancel.cancelled()=>break,
            Some(result)=tasks.join_next(),if !tasks.is_empty()=>{if let Err(e)=result{tracing::warn!(error=%e,"connection task failed");}},
            accepted=listener.accept()=>{
                let (stream,peer)=match accepted {Ok(v)=>v,Err(e)=>{tracing::warn!(error=%e,"accept failed");tokio::time::sleep(Duration::from_millis(50)).await;continue;}};
                let Ok(permit)=permits.clone().try_acquire_owned() else {metrics.rejected_connections.fetch_add(1,Ordering::Relaxed);continue;};
                let _=stream.set_nodelay(true);let handler=handler.clone();let cancel=cancel.clone();let metrics=metrics.clone();
                let lease=Arc::new(hangang::metrics::ConnectionLease::new(permit,metrics.clone()));
                let tls_config = if let Some(active) = &config_tls {
                    let snapshot = active.load();
                    let Some(certificates) = &snapshot.certificates else { metrics.rejected_connections.fetch_add(1,Ordering::Relaxed); continue; };
                    Some(certificates.load_full())
                } else { tls.as_ref().map(|tls|tls.current.load_full()) };
                tasks.spawn(async move {
                    let connection_lease=lease.clone();
                    let transport_tls=tls_config.is_some();
                    let io:Box<dyn TransportIo>=if let Some(config)=tls_config {
                        let acceptor=tokio_rustls::TlsAcceptor::from(config);
                        let accepted=tokio::select!{_=cancel.cancelled()=>return,result=tokio::time::timeout(Duration::from_secs(5),acceptor.accept(stream))=>result};
                        match accepted {Ok(Ok(stream))=>Box::new(stream),_=>{metrics.rejected_connections.fetch_add(1,Ordering::Relaxed);return}}
                    } else {Box::new(stream)};
                    let (io, idle_watch)=hangang::idle::IdleIo::new(io,idle_timeout);
                    let service=service_fn(move |mut request:hyper::Request<hyper::body::Incoming>| {
                        request.extensions_mut().insert(lease.clone());
                        request.extensions_mut().insert(hangang::tls::TransportInfo{tls:transport_tls,local_port});
                        let handler=handler.clone();
                        let future:std::pin::Pin<Box<dyn std::future::Future<Output=Result<hyper::Response<hangang::proxy::Body>,std::convert::Infallible>>+Send>>=Box::pin(async move {match handler {Handler::Proxy(p)=>p.handle(request,peer).await,Handler::Admin(a)=>a.handle(request).await,Handler::Acme(store)=>{use http_body_util::BodyExt; let response=store.response(&request).await.unwrap_or_else(||hyper::Response::builder().status(404).body(http_body_util::Full::new(bytes::Bytes::new())).unwrap()); Ok(response.map(|b|b.map_err(|never|match never {}).boxed_unsync()))}}});
                        future
                    });
                    let mut builder=hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(header_bytes);
                    builder.http2().timer(TokioTimer::new()).max_concurrent_streams(64).max_header_list_size(header_bytes as u32).keep_alive_interval(Some(Duration::from_secs(30))).keep_alive_timeout(Duration::from_secs(10));
                    let connection=builder.serve_connection_with_upgrades(TokioIo::new(io),service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _=&mut connection=>{},
                        _=idle_watch.expired()=>{},
                        _=cancel.cancelled()=>{connection.as_mut().graceful_shutdown();let _=connection.await;}
                    }
                    drop(connection_lease);
                });
            }
        }
    }
    drop(listener);
    if tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} })
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}
async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {r=tokio::signal::ctrl_c()=>r?,_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

trait TransportIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TransportIo for T {}

fn retain_listener(
    listener: TcpListener,
    retain: bool,
) -> Result<(TcpListener, Option<std::net::TcpListener>)> {
    if !retain {
        return Ok((listener, None));
    }
    let listener = listener.into_std()?;
    let duplicate = listener.try_clone()?;
    Ok((TcpListener::from_std(listener)?, Some(duplicate)))
}

/// How a generation ends.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Ending {
    /// A signal reached this (unsupervised) process: withdraw readiness,
    /// keep accepting for the lame-duck window, then drain.
    Local,
    /// The supervisor already withdrew readiness (`Withdraw`) and waited
    /// the lame-duck window itself; drain now.
    Directed,
    /// Retired after a successful handoff (or aborted as a candidate): the
    /// endpoint stays served by another generation, so close the accept loops
    /// at once, keep readiness as it is, and drain.
    Retire,
}

/// The configuration handed to a replacement generation, with the shared
/// store's authority epoch the previous generation followed so the successor
/// judges the store against the same history. Older generations exported a
/// bare `Config`; both forms are accepted on import.
#[derive(serde::Serialize, serde::Deserialize)]
struct InheritedSnapshot {
    config: Config,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    epoch: Option<String>,
}

struct HandoffFiles<'a> {
    public: &'a std::net::TcpListener,
    admin: &'a std::net::TcpListener,
    lock: Option<&'a std::fs::File>,
    docker: &'a hangang::docker_connections::DockerConnections,
    acme_listener: Option<&'a std::net::TcpListener>,
}
async fn lifecycle_wait(
    channel: Arc<hangang::restart::ControlChannel>,
    manager: &Arc<Manager>,
    tcp: &Arc<TcpManager>,
    files: HandoffFiles<'_>,
    acme: Option<&Arc<hangang::acme_runtime::Runtime>>,
) -> Result<Ending> {
    let HandoffFiles {
        public,
        admin,
        lock,
        docker,
        acme_listener,
    } = files;
    use hangang::restart::{ControlMessage as Control, DescriptorRole, ProtocolMessage};
    use std::{
        io::{Seek, Write},
        os::fd::AsFd,
    };
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    // `Drain` after `Withdraw` is a supervisor-directed endpoint shutdown;
    // `Drain`/`Abort` without it retires this generation behind a successor.
    let mut withdrawn = false;
    loop {
        let reader = channel.clone();
        let event =
            tokio::task::spawn_blocking(move || reader.recv_timeout(Duration::from_millis(100)))
                .await?;
        tokio::select! {biased;result=&mut shutdown=>{result?;return Ok(Ending::Local);},_=std::future::ready(())=>{}}
        match event {
            Ok(ProtocolMessage::Control(Control::Drain | Control::Abort)) => {
                return Ok(if withdrawn {
                    Ending::Directed
                } else {
                    Ending::Retire
                });
            }
            Ok(ProtocolMessage::Control(Control::Withdraw)) => {
                // Endpoint shutdown, phase one: answer 503 on health while
                // still accepting, so the load balancer deregisters before
                // the supervisor sends `Drain`.
                withdrawn = true;
                // Immediate: the supervisor's lame-duck window must not wait
                // behind an in-flight transaction or poll.
                manager.withdraw_now();
                tracing::info!("lame duck: readiness withdrawn by the supervisor, still accepting");
            }
            Ok(ProtocolMessage::Control(Control::Resume)) => {
                manager.resume_updates();
                docker.resume();
                if let Some(acme) = acme {
                    acme.start().await;
                }
            }
            Ok(ProtocolMessage::Control(Control::FreezeExport)) => {
                // Writes are frozen for the handoff; this generation keeps
                // serving (and answering ready) from the shared sockets until
                // it is told to drain.
                manager.freeze_updates().await;
                docker.freeze().await;
                if let Some(acme) = acme {
                    acme.stop().await;
                }
                let snapshot = manager.active.load_full();
                let mut file = snapshot_file()?;
                file.write_all(&serde_json::to_vec(&InheritedSnapshot {
                    config: snapshot.config.clone(),
                    epoch: manager.recorded_epoch(),
                })?)?;
                file.rewind()?;
                channel.send_descriptor(DescriptorRole::ConfigSnapshot, file.as_fd())?;
                channel.send_descriptor(
                    DescriptorRole::Public(public.local_addr()?),
                    public.as_fd(),
                )?;
                channel
                    .send_descriptor(DescriptorRole::Admin(admin.local_addr()?), admin.as_fd())?;
                if let Some(lock) = lock {
                    channel.send_descriptor(DescriptorRole::ConfigLock, lock.as_fd())?;
                }
                channel.send_descriptor(DescriptorRole::DockerLock, docker.lock_file().as_fd())?;
                if let Some(listener) = acme_listener {
                    channel.send_descriptor(
                        DescriptorRole::AcmeHttp(listener.local_addr()?),
                        listener.as_fd(),
                    )?;
                }
                for (address, fd) in tcp.export_listeners().await? {
                    let role = if snapshot
                        .config
                        .workload_http
                        .iter()
                        .any(|listener| listener.enabled && listener.listen == address)
                    {
                        DescriptorRole::WorkloadHttp(address)
                    } else if snapshot
                        .config
                        .public_http
                        .iter()
                        .any(|listener| listener.enabled && listener.listen == address)
                    {
                        DescriptorRole::PublicHttp(address)
                    } else {
                        DescriptorRole::Tcp(address)
                    };
                    channel.send_descriptor(role, fd.as_fd())?;
                }
                channel.send_control(Control::ExportDone)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return Ok(Ending::Local),
            _ => anyhow::bail!("unexpected supervisor control message"),
        }
    }
}

fn adopt_listener(fd: std::os::fd::OwnedFd, expected: SocketAddr) -> Result<TcpListener> {
    use std::os::fd::AsRawFd;
    let listener = std::net::TcpListener::from(fd);
    anyhow::ensure!(
        listener.local_addr()? == expected,
        "inherited listener address mismatch"
    );
    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&accepting) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            listener.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    anyhow::ensure!(
        result == 0 && accepting == 1,
        "inherited descriptor is not a listening socket"
    );
    listener.set_nonblocking(true)?;
    Ok(TcpListener::from_std(listener)?)
}

// Linux deployments can keep the root filesystem read-only and omit /tmp.
// The private control socket transfers this anonymous, bounded snapshot file.
fn snapshot_file() -> Result<std::fs::File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        // SAFETY: a static NUL-terminated name and supported flag are passed;
        // the returned descriptor becomes uniquely owned by File.
        let fd = unsafe { libc::memfd_create(c"hangang-snapshot".as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(tempfile::tempfile()?)
    }
}

struct KubernetesSink {
    manager: Arc<Manager>,
    tls: Option<Arc<hangang::tls::ReloadingTls>>,
}
#[async_trait::async_trait]
impl hangang::kubernetes::ConfigSink for KubernetesSink {
    async fn apply(&self, snapshot: hangang::kubernetes::ControllerSnapshot) -> Result<()> {
        let tls_config = if self.tls.is_some() {
            let material = snapshot
                .certificates
                .into_iter()
                .map(|certificate| hangang::tls::SniCertificate {
                    hosts: certificate.hosts,
                    default: false,
                    cert_pem: certificate.cert_pem,
                    key_pem: certificate.key_pem,
                })
                .collect();
            Some(
                tokio::task::spawn_blocking(move || hangang::tls::sni_server_config(material))
                    .await??,
            )
        } else {
            None
        };
        if let Some(config) = tls_config {
            self.manager
                .apply_external_with_tls(snapshot.config, Arc::new(config))
                .await?;
        } else {
            self.manager.apply_external(snapshot.config).await?;
        }
        Ok(())
    }

    /// Readiness follows the controller's authority over the API: a replica
    /// whose watches went stale or whose cache is incomplete keeps serving its
    /// last snapshot but stops advertising itself to the load balancer.
    async fn report_authority(&self, healthy: bool, reason: &str) {
        let previous = self.manager.ready.load(Ordering::Acquire);
        self.manager.report_controller_authority(healthy);
        let healthy = self.manager.ready.load(Ordering::Acquire);
        if previous != healthy {
            if healthy {
                tracing::info!(%reason, "Kubernetes controller ready");
            } else {
                tracing::warn!(%reason, "Kubernetes controller not ready");
            }
        }
    }
}
