//! Independent decision-event exporter (ADR 0019).
//!
//! The exporter is a separate process with bounded ingest, its own store and
//! no policy credential. Hangang drains its in-memory rings to the ingest
//! socket; the read-only query socket serves the console APIs through the
//! Hangang administration broker.

pub mod query;
pub mod store;

use anyhow::{Context, Result};
use bytes::Bytes;
use hangang_decision_event as schema;
use http_body_util::Full;
use hyper::{Request, Response, StatusCode};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc};

/// Events older than the retention window or more than this far in the
/// future are refused at ingest.
pub const MAX_FUTURE_SKEW_MS: u64 = 10 * 60 * 1000;
pub const INGEST_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
pub const WRITER_QUEUE_BATCHES: usize = 64;

#[derive(Clone, Debug)]
pub struct Config {
    pub ingest_socket: PathBuf,
    pub query_socket: PathBuf,
    pub store: PathBuf,
    pub limits: store::Limits,
    pub max_connections: usize,
    pub socket_mode: u32,
}

#[derive(Default)]
pub struct Counters {
    pub frames: AtomicU64,
    pub received: AtomicU64,
    pub inserted: AtomicU64,
    pub duplicates: AtomicU64,
    pub rejected_invalid: AtomicU64,
    pub rejected_time: AtomicU64,
    pub rejected_frames: AtomicU64,
    pub refused_connections: AtomicU64,
    pub write_errors: AtomicU64,
    pub partitions_dropped: AtomicU64,
    pub rows_dropped: AtomicU64,
    pub queries: AtomicU64,
    pub query_errors: AtomicU64,
    pub newest_event_ms: AtomicU64,
    pub last_ingest_ms: AtomicU64,
}

impl Counters {
    pub fn render(&self, store_bytes: u64) -> String {
        let mut out = String::new();
        for (name, help, value) in [
            ("frames_total", "Accepted ingest frames.", &self.frames),
            ("received_total", "Events received.", &self.received),
            ("inserted_total", "Events stored.", &self.inserted),
            (
                "duplicates_total",
                "Events ignored by event_id uniqueness.",
                &self.duplicates,
            ),
            (
                "rejected_invalid_total",
                "Events refused by schema validation.",
                &self.rejected_invalid,
            ),
            (
                "rejected_time_total",
                "Events refused for time outside retention.",
                &self.rejected_time,
            ),
            (
                "rejected_frames_total",
                "Malformed or oversized frames.",
                &self.rejected_frames,
            ),
            (
                "refused_connections_total",
                "Ingest connections refused at capacity.",
                &self.refused_connections,
            ),
            (
                "write_errors_total",
                "Store write failures.",
                &self.write_errors,
            ),
            (
                "partitions_dropped_total",
                "Partitions dropped by retention.",
                &self.partitions_dropped,
            ),
            (
                "rows_dropped_total",
                "Events dropped by retention.",
                &self.rows_dropped,
            ),
            ("queries_total", "Query requests.", &self.queries),
            (
                "query_errors_total",
                "Failed query requests.",
                &self.query_errors,
            ),
        ] {
            out.push_str(&format!(
                "# HELP hangang_decision_exporter_{name} {help}\n# TYPE hangang_decision_exporter_{name} counter\nhangang_decision_exporter_{name} {}\n",
                value.load(Ordering::Relaxed)
            ));
        }
        let newest = self.newest_event_ms.load(Ordering::Relaxed);
        let lag = if newest == 0 {
            0.0
        } else {
            now_ms().saturating_sub(newest) as f64 / 1000.0
        };
        out.push_str(&format!(
            "# HELP hangang_decision_exporter_lag_seconds Age of the newest stored traffic event.\n# TYPE hangang_decision_exporter_lag_seconds gauge\nhangang_decision_exporter_lag_seconds {lag}\n# HELP hangang_decision_exporter_store_bytes Bytes used by the local store.\n# TYPE hangang_decision_exporter_store_bytes gauge\nhangang_decision_exporter_store_bytes {store_bytes}\n"
        ));
        out
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

type Batch = Vec<(schema::v1::DecisionEvent, Vec<u8>)>;

/// Validates one frame payload into a batch. Invalid events are counted and
/// skipped; a malformed frame refuses the whole connection.
pub fn accept_payload(
    payload: &[u8],
    counters: &Counters,
    max_age: Duration,
    now: u64,
) -> Result<Batch, schema::Invalid> {
    let events = schema::split_payload(payload)?;
    let floor = now.saturating_sub(max_age.as_millis() as u64);
    let mut batch = Vec::with_capacity(events.len());
    counters
        .received
        .fetch_add(events.len() as u64, Ordering::Relaxed);
    for bytes in events {
        match schema::decode(bytes) {
            Ok(event)
                if event.time_unix_ms < floor || event.time_unix_ms > now + MAX_FUTURE_SKEW_MS =>
            {
                counters.rejected_time.fetch_add(1, Ordering::Relaxed);
            }
            Ok(event) => batch.push((event, bytes.to_vec())),
            Err(_) => {
                counters.rejected_invalid.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(batch)
}

fn bind_unix(path: &Path, mode: u32) -> Result<UnixListener> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        anyhow::ensure!(
            metadata.file_type().is_socket(),
            "{} exists and is not a socket",
            path.display()
        );
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

async fn ingest_connection(
    mut stream: UnixStream,
    writer: mpsc::Sender<Batch>,
    counters: Arc<Counters>,
    max_age: Duration,
) {
    let mut header = [0u8; 4];
    loop {
        match tokio::time::timeout(INGEST_IDLE_TIMEOUT, stream.read_exact(&mut header)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let len = u32::from_be_bytes(header) as usize;
        if len > schema::MAX_FRAME_BYTES {
            counters.rejected_frames.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut payload = vec![0u8; len];
        match tokio::time::timeout(INGEST_IDLE_TIMEOUT, stream.read_exact(&mut payload)).await {
            Ok(Ok(_)) => {}
            _ => return,
        }
        let batch = match accept_payload(&payload, &counters, max_age, now_ms()) {
            Ok(batch) => batch,
            Err(_) => {
                counters.rejected_frames.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        counters.frames.fetch_add(1, Ordering::Relaxed);
        counters.last_ingest_ms.store(now_ms(), Ordering::Relaxed);
        if !batch.is_empty() && writer.send(batch).await.is_err() {
            return;
        }
    }
}

fn writer_loop(
    mut store: store::Store,
    mut batches: mpsc::Receiver<Batch>,
    counters: Arc<Counters>,
) {
    let mut last_age_check = 0u64;
    loop {
        let batch = match batches.blocking_recv() {
            Some(batch) => batch,
            None => return,
        };
        match store.insert(&batch) {
            Ok(outcome) => {
                counters
                    .inserted
                    .fetch_add(outcome.inserted, Ordering::Relaxed);
                counters
                    .duplicates
                    .fetch_add(outcome.duplicates, Ordering::Relaxed);
                if let Some(newest) = batch
                    .iter()
                    .filter(|(e, _)| store::Lane::of(e.kind) == store::Lane::Traffic)
                    .map(|(e, _)| e.time_unix_ms)
                    .max()
                {
                    counters
                        .newest_event_ms
                        .fetch_max(newest, Ordering::Relaxed);
                }
            }
            Err(error) => {
                counters.write_errors.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(%error, "decision store write failed; batch dropped");
            }
        }
        let now = now_ms();
        // Byte caps are checked after every batch; age once a minute.
        let over = store
            .used_bytes()
            .map(|b| b > store.limits().max_bytes)
            .unwrap_or(true);
        if over || now.saturating_sub(last_age_check) >= 60_000 {
            last_age_check = now;
            match store.enforce(now) {
                Ok(enforced) => {
                    counters
                        .partitions_dropped
                        .fetch_add(enforced.partitions_dropped, Ordering::Relaxed);
                    counters
                        .rows_dropped
                        .fetch_add(enforced.rows_dropped, Ordering::Relaxed);
                }
                Err(error) => tracing::warn!(%error, "decision store retention failed"),
            }
        }
    }
}

fn json_response(status: StatusCode, value: &serde_json::Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(value.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response
}

fn problem(status: StatusCode, detail: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        &serde_json::json!({"status": status.as_u16(), "detail": detail}),
    )
}

/// Query service request handler (also used directly by tests).
pub async fn handle_query<B>(
    request: Request<B>,
    store_path: Arc<PathBuf>,
    counters: Arc<Counters>,
) -> Response<Full<Bytes>> {
    counters.queries.fetch_add(1, Ordering::Relaxed);
    if request.method() != hyper::Method::GET {
        return problem(StatusCode::METHOD_NOT_ALLOWED, "GET required");
    }
    let path = request.uri().path().to_owned();
    let query = request.uri().query().map(str::to_owned);
    let now = now_ms();
    let result = match path.as_str() {
        "/v1/decisions" | "/v1/decisions/facets" | "/v1/decisions/timeseries" => {
            let filters = match query::Filters::parse(query.as_deref(), now) {
                Ok(filters) => filters,
                Err(query::BadRequest(detail)) => {
                    return problem(StatusCode::BAD_REQUEST, detail);
                }
            };
            query::with_reader(&store_path, move |conn| match path.as_str() {
                "/v1/decisions" => query::list(conn, &filters),
                "/v1/decisions/facets" => query::facets(conn, &filters),
                _ => query::timeseries(conn, &filters),
            })
            .await
        }
        "/v1/status" | "/metrics" => {
            let metrics = path == "/metrics";
            let counters = counters.clone();
            let status = query::with_reader(&store_path, |conn| {
                let bytes: i64 =
                    conn.query_row("SELECT COALESCE(SUM(bytes),0) FROM partitions", [], |r| {
                        r.get(0)
                    })?;
                let rows: i64 =
                    conn.query_row("SELECT COALESCE(SUM(rows),0) FROM partitions", [], |r| {
                        r.get(0)
                    })?;
                Ok((bytes as u64, rows as u64))
            })
            .await;
            return match status {
                Ok((bytes, _)) if metrics => {
                    let mut response =
                        Response::new(Full::new(Bytes::from(counters.render(bytes))));
                    response.headers_mut().insert(
                        hyper::header::CONTENT_TYPE,
                        hyper::header::HeaderValue::from_static("text/plain; version=0.0.4"),
                    );
                    response
                }
                Ok((bytes, rows)) => json_response(
                    StatusCode::OK,
                    &serde_json::json!({
                        "state": "enabled",
                        "rows": rows,
                        "accounted_bytes": bytes,
                        "newest_event_ms": counters.newest_event_ms.load(Ordering::Relaxed),
                        "last_ingest_ms": counters.last_ingest_ms.load(Ordering::Relaxed),
                        "inserted_total": counters.inserted.load(Ordering::Relaxed),
                        "rejected_total": counters.rejected_invalid.load(Ordering::Relaxed)
                            + counters.rejected_time.load(Ordering::Relaxed),
                        "partitions_dropped_total": counters.partitions_dropped.load(Ordering::Relaxed),
                    }),
                ),
                Err(_) => {
                    counters.query_errors.fetch_add(1, Ordering::Relaxed);
                    problem(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "decision store unavailable",
                    )
                }
            };
        }
        other => match other.strip_prefix("/v1/requests/") {
            Some(id) if query::valid_request_id(id) => {
                if query.is_some() {
                    return problem(StatusCode::BAD_REQUEST, "query parameters unsupported");
                }
                let id = id.to_owned();
                query::with_reader(&store_path, move |conn| query::request(conn, &id)).await
            }
            Some(_) => return problem(StatusCode::BAD_REQUEST, "invalid request_id"),
            None => return problem(StatusCode::NOT_FOUND, "unknown operation"),
        },
    };
    match result {
        Ok(value) => json_response(StatusCode::OK, &value),
        Err(error) => {
            counters.query_errors.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(%error, "decision query failed");
            problem(StatusCode::SERVICE_UNAVAILABLE, "decision query failed")
        }
    }
}

async fn serve_queries(
    listener: UnixListener,
    store_path: Arc<PathBuf>,
    counters: Arc<Counters>,
    slots: Arc<Semaphore>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let store_path = store_path.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(move |request| {
                let store_path = store_path.clone();
                let counters = counters.clone();
                async move {
                    Ok::<_, std::convert::Infallible>(
                        handle_query(request, store_path, counters).await,
                    )
                }
            });
            let connection = hyper::server::conn::http1::Builder::new()
                .max_buf_size(64 * 1024)
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service);
            let _ = tokio::time::timeout(Duration::from_secs(30), connection).await;
        });
    }
}

pub async fn run(config: Config, shutdown: impl std::future::Future<Output = ()>) -> Result<()> {
    let store = store::Store::open(&config.store, config.limits.clone())?;
    let max_age = config.limits.max_age;
    let counters = Arc::new(Counters::default());
    let (writer_tx, writer_rx) = mpsc::channel(WRITER_QUEUE_BATCHES);
    let writer_counters = counters.clone();
    let writer =
        tokio::task::spawn_blocking(move || writer_loop(store, writer_rx, writer_counters));
    let ingest = bind_unix(&config.ingest_socket, config.socket_mode)?;
    let queries = bind_unix(&config.query_socket, config.socket_mode)?;
    let store_path = Arc::new(config.store.clone());
    let query_task = tokio::spawn(serve_queries(
        queries,
        store_path,
        counters.clone(),
        Arc::new(Semaphore::new(16)),
    ));
    let slots = Arc::new(Semaphore::new(config.max_connections.max(1)));
    tracing::info!(
        ingest = %config.ingest_socket.display(),
        query = %config.query_socket.display(),
        "decision exporter ready"
    );
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = ingest.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    counters.refused_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let writer = writer_tx.clone();
                let counters = counters.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    ingest_connection(stream, writer, counters, max_age).await;
                });
            }
        }
    }
    query_task.abort();
    drop(writer_tx);
    let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
    let _ = std::fs::remove_file(&config.ingest_socket);
    let _ = std::fs::remove_file(&config.query_socket);
    Ok(())
}
