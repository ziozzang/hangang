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
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
};

#[tokio::test]
async fn ordinary_round_robin_counts_a_held_stream_until_its_body_finishes() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
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

    let config: Config = serde_json::from_value(serde_json::json!({
        "http": [{"id": "rr", "backends": [format!("http://{origin_address}")]}]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
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
    let balancer = active.load().http[0].balancer.clone();
    assert_eq!(
        balancer.backend_state(0).unwrap().active_requests,
        Some(1),
        "the streamed response owns a real backend lease on ordinary RR"
    );
    let mut unrelated = config;
    unrelated.http.push(
        serde_json::from_value(serde_json::json!({
            "id":"other", "host":"other.example.test",
            "backends":[format!("http://{origin_address}")]
        }))
        .unwrap(),
    );
    let replacement = Snapshot::replace(unrelated, &active.load_full()).unwrap();
    let surviving = replacement
        .http
        .iter()
        .find(|runtime| runtime.route.id == "rr")
        .unwrap()
        .balancer
        .clone();
    assert!(Arc::ptr_eq(&balancer, &surviving));
    active.store(Arc::new(replacement));
    assert_eq!(surviving.backend_state(0).unwrap().active_requests, Some(1));
    release_tx.send(()).unwrap();
    let body = reply.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"abcdef"));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if balancer.backend_state(0).unwrap().active_requests == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed response releases its backend lease");
    assert_eq!(surviving.backend_state(0).unwrap().active_requests, Some(0));

    origin_task.await.unwrap();
    front_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn abandoned_response_body_releases_ordinary_round_robin_lease() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
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
        let _ = stream.write_all(b"def").await;
    });

    let config: Config = serde_json::from_value(serde_json::json!({
        "http": [{"id": "rr", "backends": [format!("http://{origin_address}")]}]
    }))
    .unwrap();
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
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let mut client = tokio::net::TcpStream::connect(front_address).await.unwrap();
    client
        .write_all(b"GET /abandon HTTP/1.1\r\nHost: test.example\r\n\r\n")
        .await
        .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !received.windows(3).any(|part| part == b"abc") {
            let mut chunk = [0_u8; 512];
            let count = client.read(&mut chunk).await.unwrap();
            assert!(count > 0, "stream closed before first body chunk");
            received.extend_from_slice(&chunk[..count]);
            assert!(received.len() <= 4096);
        }
    })
    .await
    .expect("the held origin delivered response headers and first bytes");
    assert!(received.starts_with(b"HTTP/1.1 200"));
    let balancer = active.load().http[0].balancer.clone();
    assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(1));

    // Closing the downstream while the origin still withholds its remaining
    // body bytes must drop the request-body lease, not wait for origin EOF.
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if balancer.backend_state(0).unwrap().active_requests == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("abandoned response releases its backend lease");
    release_tx.send(()).unwrap();
    origin_task.await.unwrap();
    front_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn websocket_tunnel_owns_one_backend_lease_until_close() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (stream, _) = origin.accept().await.unwrap();
        let service = service_fn(|mut request: Request<Incoming>| async move {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut message = [0_u8; 4];
                    while upgraded.read_exact(&mut message).await.is_ok() {
                        if upgraded.write_all(&message).await.is_err() {
                            break;
                        }
                    }
                }
            });
            Ok::<_, Infallible>(
                hyper::Response::builder()
                    .status(101)
                    .header("connection", "upgrade")
                    .header("upgrade", "websocket")
                    .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    });

    let config: Config = serde_json::from_value(serde_json::json!({
        "http": [{"id": "rr", "backends": [format!("http://{origin_address}")]}]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let shutdown_proxy = proxy.clone();
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_address = front.local_addr().unwrap();
    let front_task = tokio::spawn(async move {
        let (stream, peer) = front.accept().await.unwrap();
        let service = service_fn(move |request: Request<Incoming>| {
            let proxy = proxy.clone();
            async move { proxy.handle(request, peer).await }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
    });

    let mut client = tokio::net::TcpStream::connect(front_address).await.unwrap();
    client
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {front_address}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" // gitleaks:allow -- WebSocket protocol fixture
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8];
            client.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            assert!(headers.len() <= 4096);
        }
    })
    .await
    .expect("WebSocket upgrade finishes");
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    client.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    let balancer = active.load().http[0].balancer.clone();
    assert_eq!(
        balancer.backend_state(0).unwrap().active_requests,
        Some(1),
        "response head and tunnel clones share one lease"
    );
    drop(client);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if balancer.backend_state(0).unwrap().active_requests == Some(0) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("closed tunnel releases its backend lease");
    shutdown_proxy.shutdown(Duration::from_millis(200)).await;
    front_task.abort();
    origin_task.abort();
    policy.shutdown().await;
}
