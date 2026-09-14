#![cfg(unix)]

use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
    tcp::TcpManager,
};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{convert::Infallible, net::SocketAddr, os::fd::OwnedFd, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

fn config(listen: SocketAddr, backend: SocketAddr) -> Config {
    serde_json::from_value(serde_json::json!({
        "revision": 1,
        "public_http": [{"id": "edge", "listen": listen}],
        "http": [{"id": "edge-route", "path_prefix": "/edge", "listener_ids": ["edge"], "backends": [format!("http://{backend}")] }]
    })).unwrap()
}

async fn origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_request: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, task)
}

struct Running {
    manager: TcpManager,
    active: Arc<ArcSwap<Snapshot>>,
    proxy: Arc<Proxy>,
    policy: Arc<PolicyPool>,
    listen: SocketAddr,
}
impl Running {
    async fn publish(&self, config: Config) {
        let old = self.active.load_full();
        let candidate = Arc::new(Snapshot::replace(config.clone(), &old).unwrap());
        let prepared = self.manager.prepare(&config).await.unwrap();
        self.manager
            .commit_with_publication(prepared, || {
                candidate.activated();
                self.active.store(candidate);
            })
            .await
            .unwrap();
    }
    async fn shutdown(self) {
        self.manager.shutdown(Duration::ZERO).await;
        self.proxy.shutdown(Duration::ZERO).await;
        self.policy.shutdown().await;
    }
}
async fn start(config: Config, bound: TcpListener) -> Running {
    let listen = bound.local_addr().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Arc::new(Proxy::new(active.clone(), policy.clone(), metrics.clone()));
    let manager = TcpManager::new(active.clone(), metrics, 32).with_gate_closed();
    manager.set_workload_http(proxy.clone(), 32 * 1024).unwrap();
    let inherited: OwnedFd = bound.into_std().unwrap().into();
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, inherited)])
        .await
        .unwrap();
    manager.commit(prepared).await;
    manager.open_gate();
    Running {
        manager,
        active,
        proxy,
        policy,
        listen,
    }
}
async fn request(stream: &mut TcpStream) -> String {
    stream
        .write_all(b"GET /edge HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut buf = [0u8; 4096];
            let len = stream.read(&mut buf).await.unwrap();
            assert!(len > 0, "connection closed before response");
            response.extend_from_slice(&buf[..len]);
            if response.windows(2).any(|bytes| bytes == b"ok") {
                break;
            }
        }
    })
    .await
    .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test]
async fn unrelated_publication_reuses_active_socket_and_keepalive() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let running = start(config(listen, backend), bound).await;
    let mut client = TcpStream::connect(running.listen).await.unwrap();
    assert!(request(&mut client).await.starts_with("HTTP/1.1 200"));
    let mut next = config(listen, backend);
    next.revision = 2;
    running.publish(next).await;
    assert!(request(&mut client).await.starts_with("HTTP/1.1 200"));
    running.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn conflicting_public_listener_prepare_rolls_back_new_socket() {
    let (backend, origin_task) = origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend), bound).await;
    let free = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_address = occupied.local_addr().unwrap();
    let mut next = config(listen, backend);
    next.public_http
        .push(serde_json::from_value(serde_json::json!({"id":"new", "listen":free})).unwrap());
    next.public_http.push(
        serde_json::from_value(serde_json::json!({"id":"occupied", "listen":occupied_address}))
            .unwrap(),
    );
    assert!(running.manager.prepare(&next).await.is_err());
    let rebound = TcpListener::bind(free)
        .await
        .expect("prepared socket must be released");
    drop(rebound);
    let mut client = TcpStream::connect(listen).await.unwrap();
    assert!(request(&mut client).await.starts_with("HTTP/1.1 200"));
    running.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn disable_and_reenable_revokes_old_plaintext_connection() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let running = start(config(listen, backend), bound).await;
    let mut old = TcpStream::connect(listen).await.unwrap();
    assert!(request(&mut old).await.starts_with("HTTP/1.1 200"));
    let mut disabled = config(listen, backend);
    disabled.revision = 2;
    disabled.public_http[0].enabled = false;
    running.publish(disabled).await;
    let mut enabled = config(listen, backend);
    enabled.revision = 3;
    running.publish(enabled).await;
    let mut byte = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), old.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "old keepalive unexpectedly survived"
    );
    let mut fresh = TcpStream::connect(listen).await.unwrap();
    assert!(request(&mut fresh).await.starts_with("HTTP/1.1 200"));
    running.shutdown().await;
    origin_task.abort();
}
