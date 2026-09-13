use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

fn named_config(a: &str, b: &str, b_id: &str, reversed: bool) -> Config {
    let a = serde_json::json!({
        "id":"a", "address":a, "weight":if reversed { 3 } else { 1 },
        "desired_state":"serving"
    });
    let b = serde_json::json!({
        "id":b_id, "address":b, "weight":if reversed { 2 } else { 1 },
        "desired_state":"serving"
    });
    let backends = if reversed { vec![b, a] } else { vec![a, b] };
    serde_json::from_value(serde_json::json!({
        "http":[{"id":"pool", "backends":backends, "balance":{
            "mode":"round_robin",
            "active_health":{
                "path":"/ready", "interval_ms":300000, "timeout_ms":60000,
                "healthy_statuses":[200], "unhealthy_statuses":[503],
                "healthy_successes":1, "unhealthy_http_failures":1,
                "unhealthy_tcp_failures":1, "unhealthy_timeouts":1
            },
            "passive_health":{
                "healthy_statuses":[200], "unhealthy_statuses":[503],
                "unhealthy_http_failures":1, "unhealthy_tcp_failures":1,
                "unhealthy_timeouts":1
            }
        }}]
    }))
    .expect("named backend shape is accepted")
}

fn named_tcp_config(a: &str, b: &str, b_id: &str, reversed: bool) -> Config {
    let a = serde_json::json!({
        "id":"a", "address":a, "weight":if reversed { 3 } else { 1 },
        "desired_state":"serving"
    });
    let b = serde_json::json!({
        "id":b_id, "address":b, "weight":if reversed { 2 } else { 1 },
        "desired_state":"serving"
    });
    let backends = if reversed { vec![b, a] } else { vec![a, b] };
    serde_json::from_value(serde_json::json!({
        "tcp":[{"id":"stream", "listen":"127.0.0.1:19092",
            "backends":backends,
            "health":{"interval_ms":1000, "timeout_ms":500,
                "healthy_successes":1, "unhealthy_failures":1}
        }]
    }))
    .expect("named TCP backend shape is accepted")
}

#[test]
fn tcp_reorder_keeps_probe_state_by_id_but_rename_and_endpoint_change_start_fresh() {
    let a = "127.0.0.1:18080";
    let b = "127.0.0.1:18081";
    let initial = Snapshot::new(named_tcp_config(a, b, "b", false)).unwrap();
    let old = initial.tcp_health["stream"].clone();
    old.record_failure(1);
    assert!(!old.available(1));

    let reordered = Snapshot::replace(named_tcp_config(a, b, "b", true), &initial).unwrap();
    let current = reordered.tcp_health["stream"].clone();
    assert!(
        !Arc::ptr_eq(&old, &current),
        "index view changes on reorder"
    );
    assert!(
        !current.available(0),
        "B's failed probe follows B to index 0"
    );
    assert!(current.available(1), "A stays eligible at index 1");

    let renamed = Snapshot::replace(named_tcp_config(a, b, "b-new", true), &reordered).unwrap();
    assert!(renamed.tcp_health["stream"].available(0));

    let endpoint_changed = Snapshot::replace(
        named_tcp_config(a, "127.0.0.1:18082", "b", true),
        &reordered,
    )
    .unwrap();
    assert!(
        endpoint_changed.tcp_health["stream"].available(0),
        "same ID with a new endpoint cannot inherit B's old failure"
    );
}

#[tokio::test]
async fn reorder_and_weight_change_preserve_held_stream_and_passive_health_by_id() {
    let origin_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address_a = origin_a.local_addr().unwrap();
    let origin_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address_b = origin_b.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin_a.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut chunk = [0_u8; 512];
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() <= 4096);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nabc")
            .await
            .unwrap();
        release_rx.await.unwrap();
        stream.write_all(b"def").await.unwrap();
    });
    let a = format!("http://{address_a}");
    let b = format!("http://{address_b}");
    let config = named_config(&a, &b, "b", false);
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_address = front.local_addr().unwrap();
    let front_task = tokio::spawn(async move {
        let (stream, peer) = front.accept().await.unwrap();
        let service = service_fn(move |request: Request<Incoming>| {
            let proxy = proxy.clone();
            async move { proxy.handle(request, peer).await }
        });
        http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let reply = client
        .request(
            Request::builder()
                .uri(format!("http://{front_address}/held"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    let old = active.load().http[0].balancer.clone();
    assert_eq!(old.backend_state(0).unwrap().active_requests, Some(1));

    // A passive observation on B is deliberately separate from A's held
    // request. Reordering must move both states with their stable identities.
    let b_lease = old.acquire(1).unwrap();
    b_lease.record_http_status(503);
    drop(b_lease);
    assert!(!old.available(1));
    let reordered = Snapshot::replace(named_config(&a, &b, "b", true), &active.load_full())
        .expect("reordered named members prepare");
    let current = reordered.http[0].balancer.clone();
    assert!(
        !Arc::ptr_eq(&old, &current),
        "ordering builds a new index view"
    );
    assert!(
        !current.available(0),
        "B retains passive quarantine at index 0"
    );
    assert_eq!(current.backend_state(1).unwrap().active_requests, Some(1));
    active.store(Arc::new(reordered));

    // Renaming B at the same address creates a fresh identity. A remains
    // shared, including its held request, across this second publication.
    let renamed = Snapshot::replace(named_config(&a, &b, "b-new", true), &active.load_full())
        .expect("renamed member prepares");
    let after_rename = renamed.http[0].balancer.clone();
    assert!(
        after_rename.available(0),
        "new ID does not inherit old quarantine"
    );
    assert_eq!(
        after_rename.backend_state(1).unwrap().active_requests,
        Some(1)
    );
    active.store(Arc::new(renamed));

    release_tx.send(()).unwrap();
    let body = reply.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"abcdef"));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if after_rename.backend_state(1).unwrap().active_requests == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shared A lease releases exactly once after body completion");
    assert_eq!(old.backend_state(0).unwrap().active_requests, Some(0));

    origin_task.await.unwrap();
    front_task.abort();
    drop(origin_b);
    policy.shutdown().await;
}
