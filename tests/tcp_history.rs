#![cfg(unix)]
use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    os::fd::OwnedFd,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

struct Fixture {
    front: SocketAddr,
    active: Arc<ArcSwap<Snapshot>>,
    metrics: Arc<Metrics>,
    manager: TcpManager,
}
impl Fixture {
    async fn new(backend: SocketAddr, extra: Value, idle: Duration, capacity: usize) -> Self {
        Self::with_tracking(backend, extra, idle, capacity, 4096).await
    }
    async fn with_tracking(
        backend: SocketAddr,
        extra: Value,
        idle: Duration,
        capacity: usize,
        tracked: usize,
    ) -> Self {
        let socket = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let front = socket.local_addr().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut route = json!({"id":"observed", "listen":front, "backends":[backend.to_string()]});
        route
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let config: Config =
            serde_json::from_value(json!({"revision":0,"http":[],"tcp":[route]})).unwrap();
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(config.clone()).unwrap(),
        ));
        let metrics = Arc::new(Metrics {
            tcp_history: Arc::new(hangang::tcp_history::History::with_limits(
                Duration::from_secs(60),
                tracked,
                4096,
            )),
            ..Metrics::default()
        });
        let manager =
            TcpManager::with_idle_timeout(active.clone(), metrics.clone(), capacity, idle);
        let prepared = manager
            .prepare_with_inherited(&config, vec![(front, OwnedFd::from(socket))])
            .await
            .unwrap();
        manager.commit(prepared).await;
        Self {
            front,
            active,
            metrics,
            manager,
        }
    }
    fn active_rows(&self) -> Value {
        serde_json::to_value(self.metrics.tcp_history.active(None, 128)).unwrap()
    }
    fn recent(&self) -> Value {
        serde_json::to_value(self.metrics.tcp_history.recent(None, 128)).unwrap()
    }
}
async fn until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn echo_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await.unwrap();
                let _ = stream.write_all(&bytes).await;
            });
        }
    });
    (address, task)
}

async fn publish_recording_policy(fixture: &Fixture, revision: u64, policy: Value) {
    let mut document = serde_json::to_value(fixture.active.load().config.clone()).unwrap();
    document["revision"] = json!(revision);
    if !document["settings"].is_object() {
        document["settings"] = json!({});
    }
    document["settings"]["tcp_recent_recording"] = policy;
    let config: Config = serde_json::from_value(document).unwrap();
    let prepared = fixture.manager.prepare(&config).await.unwrap();
    fixture
        .active
        .store(Arc::new(Snapshot::new(config).unwrap()));
    fixture.manager.commit(prepared).await;
}

#[tokio::test]
async fn held_completion_uses_current_policy_without_consuming_filtered_event_id() {
    let (backend, origin) = echo_origin().await;
    let fixture = Fixture::new(backend, json!({}), Duration::ZERO, 8).await;
    let mut first = TcpStream::connect(fixture.front).await.unwrap();
    first.write_all(b"held").await.unwrap();
    until(|| fixture.active_rows()["records"][0]["phase"] == "forwarding").await;
    publish_recording_policy(
        &fixture,
        1,
        json!({
            "default_action":"record",
            "rules":[{"id":"drop-completed-route","action":"drop",
                      "match":{"route_ids":["observed"],"route_matched":true,
                               "outcomes":["eof"]}}]
        }),
    )
    .await;
    first.shutdown().await.unwrap();
    let mut answer = Vec::new();
    first.read_to_end(&mut answer).await.unwrap();
    assert_eq!(answer, b"held");
    until(|| {
        fixture.active_rows()["records"]
            .as_array()
            .unwrap()
            .is_empty()
    })
    .await;
    let dropped = fixture.recent();
    assert!(dropped["records"].as_array().unwrap().is_empty());
    assert_eq!(dropped["latest_event_id"], "0");
    assert_eq!(dropped["filtered_total"], "1");
    assert_eq!(dropped["omitted_total"], "0");
    publish_recording_policy(&fixture, 2, json!({"default_action":"record","rules":[]})).await;
    let mut second = TcpStream::connect(fixture.front).await.unwrap();
    second.write_all(b"next").await.unwrap();
    second.shutdown().await.unwrap();
    let mut next = Vec::new();
    second.read_to_end(&mut next).await.unwrap();
    until(|| fixture.recent()["records"].as_array().unwrap().len() == 1).await;
    let recorded = fixture.recent();
    assert_eq!(recorded["records"][0]["event_id"], "1");
    assert_eq!(recorded["records"][0]["policy_revision"], "2");
    assert_eq!(recorded["filtered_total"], "1");
    fixture.manager.shutdown(Duration::ZERO).await;
    origin.abort();
}

#[tokio::test]
async fn early_ip_denial_uses_canonical_peer_and_final_outcome_filter() {
    let (backend, origin) = echo_origin().await;
    let fixture = Fixture::new(
        backend,
        json!({"deny_cidrs":["127.0.0.0/8"]}),
        Duration::ZERO,
        8,
    )
    .await;
    publish_recording_policy(
        &fixture,
        1,
        json!({
            "default_action":"record",
            "rules":[{"id":"hide-denied-local","action":"drop","match":{
                "listen_addresses":[fixture.front],"peer_cidrs":["127.0.0.0/8"],
                "route_matched":false,"outcomes":["ip_denied"]}}]
        }),
    )
    .await;
    let _client = TcpStream::connect(fixture.front).await.unwrap();
    until(|| fixture.recent()["filtered_total"] == "1").await;
    assert_eq!(fixture.recent()["latest_event_id"], "0");
    assert!(
        fixture.active_rows()["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    publish_recording_policy(&fixture, 2, json!({"default_action":"record","rules":[]})).await;
    let _client = TcpStream::connect(fixture.front).await.unwrap();
    until(|| fixture.recent()["records"].as_array().unwrap().len() == 1).await;
    let row = &fixture.recent()["records"][0];
    assert_eq!(row["outcome"], "ip_denied");
    assert_eq!(row["policy_revision"], "2");
    assert_eq!(fixture.recent()["filtered_total"], "1");
    fixture.manager.shutdown(Duration::ZERO).await;
    origin.abort();
}

#[tokio::test]
async fn active_then_half_close_records_exact_both_directions_and_pinned_route() {
    let (backend, origin) = echo_origin().await;
    let fixture = Fixture::new(backend, json!({}), Duration::ZERO, 8).await;
    let mut client = TcpStream::connect(fixture.front).await.unwrap();
    client.write_all(b"payload").await.unwrap();
    until(|| fixture.active_rows()["records"][0]["bytes_upstream"] == "7").await;
    let row = fixture.active_rows()["records"][0].clone();
    assert_eq!(row["phase"], "forwarding");
    assert_eq!(row["route_id"], "observed");
    assert_eq!(row["peer_ip"], "127.0.0.1");
    assert_eq!(row["geoip"]["state"], "not_configured");
    let mut changed = fixture.active.load().config.clone();
    changed.revision += 1;
    changed.tcp[0].id = "replacement".into();
    let prepared = fixture.manager.prepare(&changed).await.unwrap();
    fixture
        .active
        .store(Arc::new(Snapshot::new(changed).unwrap()));
    fixture.manager.commit(prepared).await;
    client.shutdown().await.unwrap();
    let mut answer = Vec::new();
    client.read_to_end(&mut answer).await.unwrap();
    assert_eq!(answer, b"payload");
    until(|| fixture.recent()["records"].as_array().unwrap().len() == 1).await;
    let recent = fixture.recent();
    let row = &recent["records"][0];
    assert_eq!(row["route_id"], "observed");
    assert_eq!(row["outcome"], "eof");
    assert_eq!(row["bytes_upstream"], "7");
    assert_eq!(row["bytes_downstream"], "7");
    assert!(
        fixture.active_rows()["records"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    fixture.manager.shutdown(Duration::ZERO).await;
    origin.abort();
}

#[tokio::test]
async fn idle_and_forced_shutdown_are_distinct_from_eof_and_preserve_progress() {
    let (backend, origin) = echo_origin().await;
    for (idle, outcome) in [
        (Duration::from_millis(100), "idle_timeout"),
        (Duration::ZERO, "shutdown"),
    ] {
        let fixture = Fixture::new(backend, json!({}), idle, 8).await;
        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        client.write_all(b"sent").await.unwrap();
        until(|| fixture.active_rows()["records"][0]["bytes_upstream"] == "4").await;
        if outcome == "shutdown" {
            fixture.manager.shutdown(Duration::ZERO).await;
        }
        until(|| fixture.recent()["records"][0]["outcome"] == outcome).await;
        assert_eq!(fixture.recent()["records"][0]["bytes_upstream"], "4");
        fixture.manager.shutdown(Duration::ZERO).await;
    }
    origin.abort();
}

#[tokio::test]
async fn pre_task_ip_and_capacity_rejections_and_failed_dial_are_visible() {
    let (backend, origin) = echo_origin().await;
    for (extra, capacity, outcome) in [
        (json!({"deny_cidrs":["127.0.0.0/8"]}), 8, "ip_denied"),
        (json!({}), 0, "capacity"),
    ] {
        let fixture = Fixture::new(backend, extra, Duration::ZERO, capacity).await;
        let _client = TcpStream::connect(fixture.front).await.unwrap();
        until(|| fixture.recent()["records"][0]["outcome"] == outcome).await;
        assert_eq!(fixture.recent()["records"][0]["bytes_upstream"], "0");
        assert!(
            fixture.active_rows()["records"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        fixture.manager.shutdown(Duration::ZERO).await;
    }
    // Keep a bound, non-listening socket to guarantee local connection refusal
    // without a released-port allocation race.
    let reserved = tokio::net::TcpSocket::new_v4().unwrap();
    reserved
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .unwrap();
    let address = reserved.local_addr().unwrap();
    let fixture = Fixture::new(address, json!({}), Duration::ZERO, 8).await;
    let _client = TcpStream::connect(fixture.front).await.unwrap();
    until(|| fixture.recent()["records"][0]["outcome"] == "dial_failed").await;
    assert_eq!(fixture.recent()["records"][0]["bytes_upstream"], "0");
    fixture.manager.shutdown(Duration::ZERO).await;
    origin.abort();
}

#[tokio::test]
async fn tracking_capacity_does_not_become_a_traffic_admission_limit() {
    let (backend, origin) = echo_origin().await;
    let fixture = Fixture::with_tracking(backend, json!({}), Duration::ZERO, 8, 1).await;
    let mut first = TcpStream::connect(fixture.front).await.unwrap();
    first.write_all(b"one").await.unwrap();
    until(|| fixture.active_rows()["records"][0]["bytes_upstream"] == "3").await;
    let mut second = TcpStream::connect(fixture.front).await.unwrap();
    second.write_all(b"two").await.unwrap();
    until(|| fixture.active_rows()["active_untracked"] == 1).await;
    assert_eq!(fixture.active_rows()["omitted_total"], "1");
    for (mut stream, expected) in [(second, b"two"), (first, b"one")] {
        stream.shutdown().await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, expected);
    }
    fixture.manager.shutdown(Duration::from_secs(1)).await;
    assert_eq!(fixture.active_rows()["active_untracked"], 0);
    assert_eq!(fixture.recent()["records"].as_array().unwrap().len(), 1);
    assert_eq!(fixture.recent()["records"][0]["outcome"], "eof");
    assert_eq!(fixture.recent()["omitted_total"], "1");
    origin.abort();
}

#[tokio::test]
async fn malformed_and_timed_out_client_hello_have_distinct_zero_byte_outcomes() {
    let (backend, origin) = echo_origin().await;
    for (payload, outcome) in [
        (Some(b"GET /".as_slice()), "sni_rejected"),
        (None, "sni_timeout"),
    ] {
        let fixture = Fixture::new(backend, json!({"sni":{"hosts":["tls.example.test"],"max_client_hello_bytes":4096,"hello_timeout_ms":50}}), Duration::ZERO, 8).await;
        let mut client = TcpStream::connect(fixture.front).await.unwrap();
        if let Some(payload) = payload {
            client.write_all(payload).await.unwrap();
        }
        until(|| fixture.recent()["records"][0]["outcome"] == outcome).await;
        let row = fixture.recent()["records"][0].clone();
        assert_eq!(row["bytes_upstream"], "0");
        assert_eq!(row["bytes_downstream"], "0");
        assert!(row["route_id"].is_null());
        fixture.manager.shutdown(Duration::ZERO).await;
    }
    origin.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned release TCP connection/telemetry diagnostic, not a capacity or SLO gate"]
async fn tcp_history_owned_connection_diagnostic() {
    assert!(
        !std::hint::black_box(cfg!(debug_assertions)),
        "run in release mode"
    );
    let (backend, origin) = echo_origin().await;
    for concurrency in [1, 64] {
        let fixture = Fixture::new(backend, json!({}), Duration::ZERO, 128).await;
        let stop = tokio_util::sync::CancellationToken::new();
        let consumer_stop = stop.clone();
        let history = fixture.metrics.tcp_history.clone();
        let consumer = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            let mut samples = 0;
            loop {
                tokio::select! {
                    _ = consumer_stop.cancelled() => return samples,
                    _ = tick.tick() => {
                        // A bounded serialization consumer runs alongside data
                        // traffic. This is not HTTP administrator auth or SSE I/O.
                        std::hint::black_box(serde_json::to_vec(&history.active(None, 128)).unwrap());
                        std::hint::black_box(serde_json::to_vec(&history.recent(None, 128)).unwrap());
                        samples += 1;
                    }
                }
            }
        });
        let started = std::time::Instant::now();
        let mut clients = tokio::task::JoinSet::new();
        for _ in 0..concurrency {
            let front = fixture.front;
            clients.spawn(async move {
                let mut latencies = Vec::with_capacity(128);
                let payload = [7u8; 1024];
                for _ in 0..128 {
                    let started = std::time::Instant::now();
                    let mut stream = TcpStream::connect(front).await.unwrap();
                    stream.write_all(&payload).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    stream.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, payload);
                    latencies.push(started.elapsed().as_nanos());
                }
                latencies
            });
        }
        let mut latencies = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(result) = clients.join_next().await {
                latencies.extend(result.unwrap());
            }
        })
        .await
        .unwrap();
        let elapsed = started.elapsed();
        stop.cancel();
        let samples = consumer.await.unwrap();
        fixture.manager.shutdown(Duration::from_secs(1)).await;
        assert_eq!(
            fixture.metrics.tcp_history.latest_event_id(),
            (concurrency * 128) as u64
        );
        let active = fixture.active_rows();
        assert_eq!(active["active_tracked"], 0);
        assert_eq!(active["omitted_total"], "0");
        let recent = fixture.recent();
        for row in recent["records"].as_array().unwrap() {
            assert_eq!(row["bytes_upstream"], "1024");
            assert_eq!(row["bytes_downstream"], "1024");
            assert_eq!(row["outcome"], "eof");
        }
        latencies.sort_unstable();
        let percentile = |percent: usize| {
            latencies[(latencies.len() * percent).div_ceil(100).saturating_sub(1)] as f64 / 1000.0
        };
        println!(
            "tcp_history_connection_diagnostic concurrency={concurrency} connections={} elapsed_ms={:.3} connections_per_second={:.0} p50_us={:.1} p95_us={:.1} p99_us={:.1} telemetry_samples={samples}",
            latencies.len(),
            elapsed.as_secs_f64() * 1000.0,
            latencies.len() as f64 / elapsed.as_secs_f64(),
            percentile(50),
            percentile(95),
            percentile(99)
        );
    }
    origin.abort();
}
