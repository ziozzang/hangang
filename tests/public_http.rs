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
use sha2::{Digest, Sha256};
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

async fn status_for(listen: SocketAddr, path: &str) -> String {
    status_with(listen, path, "").await
}

async fn status_with(listen: SocketAddr, path: &str, headers: &str) -> String {
    let mut stream = TcpStream::connect(listen).await.unwrap();
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !response.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let mut bytes = [0u8; 1024];
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0, "connection closed before response headers");
            response.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .unwrap();
    String::from_utf8(response)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned()
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

#[tokio::test]
async fn public_listener_cannot_reach_unscoped_default_route() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let mut candidate = config(listen, backend);
    candidate.http.push(
        serde_json::from_value(serde_json::json!({
            "id": "default", "path_prefix": "/default", "backends": [format!("http://{backend}")]
        }))
        .unwrap(),
    );
    let running = start(candidate, bound).await;
    assert!(
        status_for(listen, "/edge")
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        status_for(listen, "/default")
            .await
            .starts_with("HTTP/1.1 404")
    );
    assert!(
        status_with(listen, "/default", "X-Hangang-Listener: default\r\n")
            .await
            .starts_with("HTTP/1.1 404")
    );
    running.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn named_https_listener_serves_scoped_route() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let material = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_file = material.path().join("server.pem");
    let key_file = material.path().join("server.key");
    std::fs::write(&cert_file, certificate.cert.pem()).unwrap();
    std::fs::write(&key_file, certificate.signing_key.serialize_pem()).unwrap();
    let mut candidate = config(listen, backend);
    candidate.public_http[0].certificates.push(
        serde_json::from_value(serde_json::json!({
        "id": "localhost", "hosts": [], "default": true,
            "cert_file": cert_file, "key_file": key_file
        }))
        .unwrap(),
    );
    let running = start(candidate, bound).await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(listen).await.unwrap();
    let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, stream).await.unwrap();
    tls.write_all(b"GET /edge HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), tls.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        String::from_utf8(response)
            .unwrap()
            .starts_with("HTTP/1.1 200")
    );
    running.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn forwarded_headers_require_listener_specific_proxy_trust() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let mut candidate = config(listen, backend);
    // This global setting is deliberately broad; named listeners must use
    // their own explicit trust policy rather than inheriting it.
    candidate.settings.trusted_proxy_cidrs = Some(vec!["127.0.0.0/8".parse().unwrap()]);
    candidate.settings.https_redirect_code = Some(426);
    candidate.http[0].require_tls = true;
    candidate.http.push(
        serde_json::from_value(serde_json::json!({
            "id": "client-filter", "path_prefix": "/filtered", "listener_ids": ["edge"],
            "deny_cidrs": ["8.8.8.0/24"], "backends": [format!("http://{backend}")]
        }))
        .unwrap(),
    );
    let running = start(candidate.clone(), bound).await;
    let spoof = "X-Forwarded-Proto: https\r\nX-Forwarded-For: 8.8.8.8\r\n";
    assert!(
        status_with(listen, "/edge", spoof)
            .await
            .starts_with("HTTP/1.1 426")
    );
    assert!(
        status_with(listen, "/filtered", spoof)
            .await
            .starts_with("HTTP/1.1 200")
    );

    // Updating this listener's policy creates a new evidence generation.
    candidate.revision = 2;
    candidate.public_http[0]
        .trusted_proxy_cidrs
        .push("127.0.0.0/8".parse().unwrap());
    running.publish(candidate).await;
    assert!(
        status_with(listen, "/edge", spoof)
            .await
            .starts_with("HTTP/1.1 200")
    );
    assert!(
        status_with(listen, "/filtered", spoof)
            .await
            .starts_with("HTTP/1.1 403")
    );
    running.shutdown().await;
    origin_task.abort();
}

fn protected_route(
    id: &str,
    path: &str,
    backend: SocketAddr,
    listener_ids: &[&str],
    priority: i32,
) -> serde_json::Value {
    let salt = b"0123456789abcdef";
    let mut digest = Sha256::new();
    digest.update(salt);
    digest.update(b"secret");
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    serde_json::json!({
        "id": id, "access_mode": "protected", "priority": priority,
        "path_prefix": path, "path_match": "segment_prefix", "listener_ids": listener_ids,
        "backends": [format!("http://{backend}")],
        "basic_auth": {"credentials": [format!("alice:{}:{}", hex(salt), hex(&digest.finalize()))],
            "hide_credentials": true, "identity_header": "x-verified-user"},
        "resource_policy": {"resource_id": id, "principal": {"source":"basic"},
            "allow": [{"subjects": ["alice"], "methods": ["GET"]}]}
    })
}

#[tokio::test]
async fn resource_guard_isolated_by_named_listener_scope() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let (backend, origin_task) = origin().await;
    let mut candidate = config(listen, backend);
    // CLI/default namespace owns /collision, but this socket has its own
    // public route at the same host and path.
    candidate.http.push(
        serde_json::from_value(protected_route(
            "default-protected",
            "/collision",
            backend,
            &[],
            20,
        ))
        .unwrap(),
    );
    candidate.http.push(
        serde_json::from_value(serde_json::json!({
            "id": "named-public", "path_prefix": "/collision", "listener_ids": ["edge"],
            "priority": 10, "backends": [format!("http://{backend}")]
        }))
        .unwrap(),
    );
    // Within the same listener, a higher-priority public route cannot bypass
    // the protected resource namespace.
    candidate.http.push(
        serde_json::from_value(protected_route(
            "named-protected",
            "/protected",
            backend,
            &["edge"],
            20,
        ))
        .unwrap(),
    );
    candidate.http.push(
        serde_json::from_value(serde_json::json!({
            "id": "named-shadow", "path_prefix": "/protected", "listener_ids": ["edge"],
        "priority": 30, "backends": [format!("http://{backend}")]
        }))
        .unwrap(),
    );
    let running = start(candidate, bound).await;
    assert!(
        status_for(listen, "/collision")
            .await
            .starts_with("HTTP/1.1 200")
    );
    let protected_status = status_for(listen, "/protected").await;
    assert!(
        protected_status.starts_with("HTTP/1.1 403"),
        "{protected_status}"
    );
    running.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn idle_sse_survives_route_publication_but_closes_on_listener_withdrawal() {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut stream, _) = origin.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let byte = stream.read_u8().await.unwrap();
            request.push(byte);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
            assert!(request.len() < 8192);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n8\r\ndata:x\n\n\r\n").await.unwrap();
        std::future::pending::<()>().await;
    });
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend), bound).await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"GET /edge HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await
        .unwrap();
    let mut received = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !received.windows(8).any(|part| part == b"data:x\n\n") {
            received.push(client.read_u8().await.unwrap());
            assert!(received.len() < 8192);
        }
    })
    .await
    .unwrap();
    assert!(received.starts_with(b"HTTP/1.1 200"));
    let mut updated = config(listen, backend);
    updated.revision = 2;
    running.publish(updated.clone()).await;
    let mut buffer = [0; 1024];
    // Drain chunk framing; a quiet stream must remain open over timer ticks.
    loop {
        match tokio::time::timeout(Duration::from_millis(600), client.read(&mut buffer)).await {
            Err(_) => break,
            Ok(Ok(n)) if n > 0 => continue,
            other => panic!("unchanged listener lost SSE: {other:?}"),
        }
    }
    updated.revision = 3;
    updated.public_http[0].enabled = false;
    running.publish(updated).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buffer))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "withdrawn listener retained SSE"
    );
    running.shutdown().await;
    origin_task.abort();
}

async fn websocket_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|mut request: Request<Incoming>| async move {
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut bytes = [0_u8; 4];
                    while upgraded.read_exact(&mut bytes).await.is_ok() {
                        if upgraded.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                }
            });
            Ok::<_, Infallible>(
                Response::builder()
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
    (address, task)
}

#[tokio::test]
async fn upgraded_websocket_closes_when_listener_trust_changes() {
    let (backend, backend_task) = websocket_origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend), bound).await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"GET /edge HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap(); // gitleaks:allow -- WebSocket protocol fixture
    let mut headers = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(client.read_u8().await.unwrap());
            assert!(headers.len() < 8192);
        }
    })
    .await
    .unwrap();
    assert!(headers.starts_with(b"HTTP/1.1 101"));
    let mut updated = config(listen, backend);
    updated.revision = 2;
    running.publish(updated.clone()).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    client.write_all(b"ping").await.unwrap();
    let mut echoed = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"ping");
    updated.revision = 3;
    updated.public_http[0].trusted_proxy_cidrs = vec!["127.0.0.1/32".parse().unwrap()];
    running.publish(updated).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut echoed))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "old upgraded stream survived trust change"
    );
    running.shutdown().await;
    backend_task.abort();
}
