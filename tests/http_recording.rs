use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
    traffic::TrafficHistory,
};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle};
use tracing_subscriber::fmt::MakeWriter;

struct Fixture {
    front: String,
    active: Arc<ArcSwap<Snapshot>>,
    traffic: Arc<TrafficHistory>,
    metrics: Arc<Metrics>,
    origin_hits: Arc<AtomicUsize>,
    held: tokio::sync::mpsc::UnboundedReceiver<()>,
    release: Arc<Semaphore>,
    policy_pool: Arc<PolicyPool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn close(self) {
        self.policy_pool.shutdown().await;
    }

    fn batch(&self) -> Value {
        serde_json::to_value(self.traffic.snapshot_since(None, 128)).unwrap()
    }

    fn publish(&self, recording: Value) {
        let current = self.active.load_full();
        let mut document = serde_json::to_value(&current.config).unwrap();
        document["revision"] = json!(current.config.revision + 1);
        document["settings"]["http_recording"] = recording;
        let next: Config = serde_json::from_value(document).unwrap();
        let next = Arc::new(Snapshot::replace(next, &current).unwrap());
        next.activated();
        self.active.store(next);
    }

    async fn wait_for_held_origin(&mut self) {
        tokio::time::timeout(Duration::from_secs(2), self.held.recv())
            .await
            .expect("held request reached the origin")
            .expect("origin notification closed");
    }
}

async fn fixture(recording: Value, trusted: bool, request_limit: usize, ipv6: bool) -> Fixture {
    fixture_with_history(recording, trusted, request_limit, ipv6, true).await
}

async fn fixture_with_history(
    recording: Value,
    trusted: bool,
    request_limit: usize,
    ipv6: bool,
    with_history: bool,
) -> Fixture {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_hits = Arc::new(AtomicUsize::new(0));
    let (held_tx, held) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let hits = origin_hits.clone();
    let release_for_origin = release.clone();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            let hits = hits.clone();
            let held_tx = held_tx.clone();
            let release = release_for_origin.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let hits = hits.clone();
                    let held_tx = held_tx.clone();
                    let release = release.clone();
                    async move {
                        hits.fetch_add(1, Ordering::SeqCst);
                        if request.uri().path() == "/hold" {
                            let _ = held_tx.send(());
                            let permit = release.acquire().await.expect("fixture release");
                            permit.forget();
                        }
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"origin"))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let config: Config = serde_json::from_value(json!({
        "revision": 1,
        "settings": {
            "http_recording": recording,
            "health_path": "/health",
            "trusted_proxy_cidrs": if trusted { vec!["127.0.0.0/8"] } else { vec![] }
        },
        "http": [
            {"id":"main","path_prefix":"/ok","backends":[format!("http://{origin_address}")]},
            {"id":"blocked","path_prefix":"/blocked","deny_cidrs":["127.0.0.0/8"],"backends":[format!("http://{origin_address}")]},
            {"id":"held","path_prefix":"/hold","backends":[format!("http://{origin_address}")]},
            {"id":"long","path_prefix":"/long","backends":[format!("http://{origin_address}")]}
        ]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy_pool = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let traffic = Arc::new(TrafficHistory::default());
    let metrics = Arc::new(Metrics::default());
    let mut proxy = Proxy::new(active.clone(), policy_pool.clone(), metrics.clone())
        .with_access_log(true)
        .with_request_limit(request_limit);
    if with_history {
        proxy = proxy.with_traffic_history(traffic.clone());
    }
    let front_listener = TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
        .await
        .unwrap();
    let front = format!("http://{}", front_listener.local_addr().unwrap());
    let front_task = tokio::spawn(async move {
        while let Ok((stream, peer)) = front_listener.accept().await {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Fixture {
        front,
        active,
        traffic,
        metrics,
        origin_hits,
        held,
        release,
        policy_pool,
        tasks: vec![origin_task, front_task],
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

async fn status(fixture: &Fixture, path: &str, headers: &[(&str, &str)]) -> u16 {
    let mut request = client().get(format!("{}{path}", fixture.front));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    response.bytes().await.unwrap();
    status
}

fn rule(id: &str, action: &str, criteria: Value) -> Value {
    json!({"id":id,"action":action,"match":criteria})
}

fn recording(default_action: &str, rules: Vec<Value>) -> Value {
    json!({"default_action":default_action,"rules":rules})
}

#[derive(Clone, Default)]
struct TraceCapture(Arc<Mutex<Vec<u8>>>);

struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for TraceCapture {
    type Writer = TraceWriter;

    fn make_writer(&'a self) -> Self::Writer {
        TraceWriter(self.0.clone())
    }
}

impl TraceCapture {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

#[tokio::test]
async fn response_head_filter_is_first_match_and_keeps_cursors_and_forwarding_intact() {
    let f = fixture(
        recording(
            "drop",
            vec![
                rule("private-first", "drop", json!({"path_prefixes":["/ok/private"]})),
                rule("allowed", "record", json!({"methods":["GET"],"route_ids":["main"],"status_ranges":[{"min":200,"max":299}],"path_prefixes":["/ok"]})),
                rule("denial", "record", json!({"route_ids":["blocked"],"status_ranges":[{"min":403,"max":403}]})),
                rule("unmatched", "record", json!({"route_matched":false,"status_ranges":[{"min":404,"max":404}]})),
            ],
        ),
        false,
        8,
        false,
    )
    .await;
    assert_eq!(status(&f, "/ok/one", &[]).await, 200);
    assert_eq!(status(&f, "/ok/private", &[]).await, 200);
    assert_eq!(status(&f, "/blocked", &[]).await, 403);
    assert_eq!(status(&f, "/missing", &[]).await, 404);
    assert_eq!(status(&f, "/ok/two", &[]).await, 200);
    assert_eq!(status(&f, "/health", &[]).await, 200);
    let batch = f.batch();
    let rows = batch["records"].as_array().unwrap();
    assert_eq!(rows.len(), 4, "{batch}");
    assert_eq!(
        rows.iter()
            .map(|row| row["status"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![200, 403, 404, 200]
    );
    assert_eq!(
        rows.iter()
            .map(|row| row["id"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(rows[1]["route_id"], "blocked");
    assert!(rows[2]["route_id"].is_null());
    assert_eq!(batch["filtered_total"], 1);
    assert_eq!(batch["dropped_total"], 0);
    assert_eq!(f.origin_hits.load(Ordering::SeqCst), 3);
    assert_eq!(f.metrics.requests.load(Ordering::SeqCst), 5);
    f.close().await;
}

#[tokio::test]
async fn matcher_uses_full_method_before_ring_truncation_and_literal_path_prefix() {
    let recorded_method = "ABCDEFGHIJKLMNOPQ";
    let dropped_method = "ABCDEFGHIJKLMNOPR";
    let f = fixture(
        recording(
            "drop",
            vec![rule(
                "full-method",
                "record",
                json!({"methods":[recorded_method],"path_prefixes":["/ok/thing"]}),
            )],
        ),
        false,
        8,
        false,
    )
    .await;
    // The methods have the same first 16 bytes, which is all the ring stores.
    // A literal path prefix also matches /ok/thingExtra, not only a segment.
    for method in [recorded_method, dropped_method] {
        let method = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let reply = client()
            .request(method, format!("{}/ok/thingExtra", f.front))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), 200);
        reply.bytes().await.unwrap();
    }
    let batch = f.batch();
    assert_eq!(batch["records"].as_array().unwrap().len(), 1, "{batch}");
    assert_eq!(batch["filtered_total"], 1);
    assert_eq!(batch["records"][0]["method"], "ABCDEFGHIJKLMNOP");
    assert_eq!(batch["records"][0]["path"], "/ok/thingExtra");
    f.close().await;
}

#[tokio::test]
async fn current_policy_at_response_head_controls_held_request_and_capacity_rejection() {
    let capture = TraceCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_env_filter("hangang::access=info")
        .with_writer(capture.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let mut f = fixture(recording("record", vec![]), true, 1, false).await;
    let front = f.front.clone();
    let held = tokio::spawn(async move {
        client()
            .get(format!("{front}/hold"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    });
    f.wait_for_held_origin().await;
    f.publish(recording(
        "drop",
        vec![rule(
            "capacity",
            "record",
            json!({"status_ranges":[{"min":503,"max":503}],"client_cidrs":["198.51.100.0/24"]}),
        )],
    ));
    assert_eq!(
        status(&f, "/ok/busy", &[("x-forwarded-for", "198.51.100.7")]).await,
        503
    );
    f.release.add_permits(1);
    assert_eq!(held.await.unwrap(), 200);
    let batch = f.batch();
    assert_eq!(batch["records"].as_array().unwrap().len(), 1, "{batch}");
    assert_eq!(batch["records"][0]["status"], 503);
    assert_eq!(batch["records"][0]["client_ip"], "198.51.100.7");
    assert_eq!(batch["records"][0]["policy_revision"], 2);
    assert_eq!(batch["filtered_total"], 1);
    assert_eq!(batch["next_after"], 1);
    assert_eq!(f.origin_hits.load(Ordering::SeqCst), 1);
    assert_eq!(f.metrics.requests.load(Ordering::SeqCst), 1);
    let trace = capture.text();
    assert_eq!(trace.matches("hangang::access").count(), 1, "{trace}");
    assert!(trace.contains("status=503"), "{trace}");
    assert!(!trace.contains("/hold"), "{trace}");
    f.close().await;
}

#[tokio::test]
async fn client_cidr_filter_uses_only_trusted_forwarding_and_ipv6_peer() {
    let policy = recording(
        "drop",
        vec![rule(
            "trusted-client",
            "record",
            json!({"peer_cidrs":["127.0.0.0/8"],"client_cidrs":["198.51.100.0/24"]}),
        )],
    );
    let trusted = fixture(policy.clone(), true, 8, false).await;
    assert_eq!(
        status(&trusted, "/ok", &[("x-forwarded-for", "198.51.100.7")]).await,
        200
    );
    assert_eq!(trusted.batch()["records"][0]["client_ip"], "198.51.100.7");
    trusted.close().await;

    let untrusted = fixture(policy, false, 8, false).await;
    assert_eq!(
        status(&untrusted, "/ok", &[("x-forwarded-for", "198.51.100.7")]).await,
        200
    );
    assert_eq!(untrusted.batch()["records"].as_array().unwrap().len(), 0);
    assert_eq!(untrusted.batch()["filtered_total"], 1);
    untrusted.close().await;

    let v6 = fixture(
        recording(
            "drop",
            vec![rule("v6-peer", "record", json!({"peer_cidrs":["::1/128"]}))],
        ),
        false,
        8,
        true,
    )
    .await;
    assert_eq!(status(&v6, "/ok", &[]).await, 200);
    assert_eq!(v6.batch()["records"][0]["peer_ip"], "::1");
    v6.close().await;
}

#[tokio::test]
async fn access_trace_shares_the_ring_decision_and_never_emits_query_or_raw_host() {
    let capture = TraceCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_env_filter("hangang::access=info")
        .with_writer(capture.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let f = fixture(
        recording(
            "drop",
            vec![rule(
                "visible",
                "record",
                json!({"path_prefixes":["/ok/visible"]}),
            )],
        ),
        false,
        8,
        false,
    )
    .await;
    assert_eq!(
        status(
            &f,
            "/ok/hidden?token=private-value",
            &[("host", "secret.example")]
        )
        .await,
        200
    );
    assert_eq!(
        status(
            &f,
            "/ok/visible?token=another-private-value",
            &[("host", "secret.example")]
        )
        .await,
        200
    );
    let trace = capture.text();
    assert_eq!(trace.matches("hangang::access").count(), 1, "{trace}");
    assert!(trace.contains("/ok/visible"), "{trace}");
    assert!(!trace.contains("/ok/hidden"), "{trace}");
    assert!(
        !trace.contains("private-value") && !trace.contains("secret.example"),
        "{trace}"
    );
    assert_eq!(f.batch()["records"].as_array().unwrap().len(), 1);
    assert_eq!(f.batch()["filtered_total"], 1);
    f.close().await;
}

#[tokio::test]
async fn access_trace_only_still_applies_recording_filter_without_a_traffic_ring() {
    let capture = TraceCapture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_env_filter("hangang::access=info")
        .with_writer(capture.clone())
        .finish();
    let _subscriber = tracing::subscriber::set_default(subscriber);
    let f = fixture_with_history(
        recording(
            "drop",
            vec![rule(
                "visible",
                "record",
                json!({"path_prefixes":["/ok/visible"]}),
            )],
        ),
        false,
        8,
        false,
        false,
    )
    .await;
    assert_eq!(status(&f, "/ok/hidden?token=hidden-secret", &[]).await, 200);
    assert_eq!(
        status(&f, "/ok/visible?token=visible-secret", &[]).await,
        200
    );
    let trace = capture.text();
    assert_eq!(trace.matches("hangang::access").count(), 1, "{trace}");
    assert!(trace.contains("/ok/visible"), "{trace}");
    assert!(!trace.contains("/ok/hidden"), "{trace}");
    assert!(
        !trace.contains("hidden-secret") && !trace.contains("visible-secret"),
        "{trace}"
    );
    assert!(f.batch()["records"].as_array().unwrap().is_empty());
    assert_eq!(f.origin_hits.load(Ordering::SeqCst), 2);
    assert_eq!(f.metrics.requests.load(Ordering::SeqCst), 2);
    f.close().await;
}
