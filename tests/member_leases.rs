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
    let balancer = active.load().http[0].balancer.clone();
    assert_eq!(
        balancer.backend_state(0).unwrap().active_requests,
        Some(1),
        "the streamed response owns a real backend lease on ordinary RR"
    );
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

    origin_task.await.unwrap();
    front_task.abort();
    policy.shutdown().await;
}
