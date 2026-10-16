use clap::Parser;
use std::path::PathBuf;
use std::time::Duration;

/// Independent hangang.decision.v1 exporter and bounded local store.
///
/// It holds no policy credential and no pseudonymization key.
#[derive(Parser, Debug)]
#[command(version)]
struct Args {
    /// Unix socket Hangang drains decision batches into.
    #[arg(long, env = "HANGANG_DECISION_INGEST_SOCKET")]
    ingest_socket: PathBuf,
    /// Unix socket of the read-only query service used by the Hangang broker.
    #[arg(long, env = "HANGANG_DECISION_QUERY_SOCKET")]
    query_socket: PathBuf,
    /// SQLite store path (WAL mode).
    #[arg(long, env = "HANGANG_DECISION_STORE")]
    store: PathBuf,
    /// Store byte cap; whole partitions are dropped, oldest first.
    #[arg(long, default_value_t = 2048)]
    max_store_mib: u64,
    /// Retention in hours (1 to 2160, i.e. 90 days).
    #[arg(long, default_value_t = 168)]
    retention_hours: u64,
    /// Concurrent ingest connections.
    #[arg(long, default_value_t = 8)]
    max_connections: usize,
    /// Octal permission bits for both sockets.
    #[arg(long, default_value = "600")]
    socket_mode: String,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    let socket_mode = u32::from_str_radix(&args.socket_mode, 8)
        .ok()
        .filter(|mode| *mode & 0o007 == 0 && *mode <= 0o777)
        .ok_or_else(|| anyhow::anyhow!("socket mode must be octal without other-user bits"))?;
    let config = hangang_decision_exporter::Config {
        ingest_socket: args.ingest_socket,
        query_socket: args.query_socket,
        store: args.store,
        limits: hangang_decision_exporter::store::Limits {
            max_bytes: args.max_store_mib.saturating_mul(1024 * 1024),
            max_age: Duration::from_secs(args.retention_hours.saturating_mul(3600)),
        },
        max_connections: args.max_connections,
        socket_mode,
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    hangang_decision_exporter::run(config, async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    })
    .await
}
