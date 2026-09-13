#![cfg(unix)]

//! Dedicated HTTP mTLS listener integration with owned certificates and sockets.
use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
    tcp::TcpManager,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::{
    convert::Infallible,
    io::Cursor,
    net::SocketAddr,
    os::{fd::OwnedFd, unix::fs::PermissionsExt},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

const GOOD_ID: &str = "spiffe://example.org/ns/test/sa/allowed";
const OTHER_ID: &str = "spiffe://example.org/ns/test/sa/other";

struct Material {
    _dir: tempfile::TempDir,
    server_cert: PathBuf,
    server_key: PathBuf,
    ca_file: PathBuf,
    ca_der: rustls::pki_types::CertificateDer<'static>,
    good: (String, String),
    other: (String, String),
    wrong_ca: (String, String),
}

fn issuer() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn client(issuer: &CertifiedIssuer<'_, KeyPair>, uri: &str) -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn material() -> Material {
    let dir = tempfile::tempdir().unwrap();
    let trusted = issuer();
    let untrusted = issuer();
    let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_keypair = KeyPair::generate().unwrap();
    let server = server_params.signed_by(&server_keypair, &trusted).unwrap();
    let server_cert = dir.path().join("server.pem");
    let server_key = dir.path().join("server.key");
    let ca_file = dir.path().join("clients-ca.pem");
    std::fs::write(&server_cert, server.pem()).unwrap();
    std::fs::write(&server_key, server_keypair.serialize_pem()).unwrap();
    std::fs::set_permissions(&server_key, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&ca_file, trusted.pem()).unwrap();
    Material {
        _dir: dir,
        server_cert,
        server_key,
        ca_file,
        ca_der: trusted.der().clone(),
        good: client(&trusted, GOOD_ID),
        other: client(&trusted, OTHER_ID),
        wrong_ca: client(&untrusted, GOOD_ID),
    }
}

fn connector(
    material: &Material,
    identity: Option<&(String, String)>,
) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(material.ca_der.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    let config = if let Some((cert, key)) = identity {
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut Cursor::new(key))
            .unwrap()
            .unwrap();
        builder.with_client_auth_cert(certs, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn config(listen: SocketAddr, backend: SocketAddr, material: &Material) -> Config {
    serde_json::from_value(serde_json::json!({
        "revision": 1,
        "settings": {"trusted_proxy_cidrs": ["127.0.0.0/8"]},
        "workload_http": [{
            "id": "private-edge", "listen": listen,
            "tls": {
                "cert_file": material.server_cert,
                "key_file": material.server_key,
                "client_ca_file": material.ca_file,
                "allowed_uri_sans": [GOOD_ID, OTHER_ID],
                "handshake_timeout_ms": 1000
            }
        }],
        "http": [{
            "id": "protected", "path_prefix": "/private",
            "backends": [format!("http://{backend}")],
            "access_mode": "protected", "require_tls": true,
            "workload_auth": {
                "listener_ids": ["private-edge"],
                "allowed_uri_sans": [GOOD_ID],
                "identity_header": "x-workload-subject"
            },
            "resource_policy": {
                "resource_id": "private-api", "principal": {"source":"workload"},
                "allow": [{"subjects": [GOOD_ID], "methods": ["GET"]}]
            }
        }]
    }))
    .unwrap()
}

struct Running {
    manager: TcpManager,
    proxy: Arc<Proxy>,
    policy: Arc<PolicyPool>,
    active: Arc<ArcSwap<Snapshot>>,
    metrics: Arc<Metrics>,
    watch_cancel: CancellationToken,
    watcher: JoinHandle<()>,
}

impl Running {
    async fn shutdown(self) {
        self.manager.shutdown(Duration::ZERO).await;
        self.watch_cancel.cancel();
        self.watcher.await.unwrap();
        self.proxy.shutdown(Duration::ZERO).await;
        self.policy.shutdown().await;
    }
}

async fn wait_material(
    active: &Arc<ArcSwap<Snapshot>>,
    ready: bool,
) -> Option<Arc<hangang::workload_tls::Prepared>> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let current = active.load().http_workload_tls["private-edge"].load();
            if current.is_some() == ready {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("HTTP workload material did not reach the requested state")
}

async fn start(config: Config, bound: TcpListener) -> Running {
    start_with_limit_and_idle(config, bound, 32, Duration::ZERO).await
}

async fn start_with_limit(config: Config, bound: TcpListener, max_connections: usize) -> Running {
    start_with_limit_and_idle(config, bound, max_connections, Duration::from_secs(60)).await
}

async fn start_with_limit_and_idle(
    config: Config,
    bound: TcpListener,
    max_connections: usize,
    idle_timeout: Duration,
) -> Running {
    let listen = bound.local_addr().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let watch_cancel = CancellationToken::new();
    let watcher = tokio::spawn(hangang::workload_material::watch(
        active.clone(),
        watch_cancel.clone(),
    ));
    let metrics = Arc::new(Metrics::default());
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Arc::new(Proxy::new(active.clone(), policy.clone(), metrics.clone()));
    let manager = TcpManager::with_idle_timeout(
        active.clone(),
        metrics.clone(),
        max_connections,
        idle_timeout,
    )
    .with_gate_closed();
    manager.set_workload_http(proxy.clone(), 32 * 1024).unwrap();
    let inherited: OwnedFd = bound.into_std().unwrap().into();
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, inherited)])
        .await
        .unwrap();
    manager.commit(prepared).await;
    manager.open_gate();
    wait_material(&active, true).await;
    Running {
        manager,
        proxy,
        policy,
        active,
        metrics,
        watch_cancel,
        watcher,
    }
}

async fn origin() -> (
    SocketAddr,
    Arc<Mutex<Vec<hyper::HeaderMap>>>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let task_seen = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = task_seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(request.headers().clone());
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, seen, task)
}

async fn payload_origin(payload: Bytes) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let payload = payload.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    let payload = payload.clone();
                    async move { Ok::<_, Infallible>(Response::new(Full::new(payload))) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, task)
}

async fn streaming_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut incoming = [0; 2048];
        let _ = stream.read(&mut incoming).await.unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n7\r\ndata:x\n\r\n").await.unwrap();
        std::future::pending::<()>().await;
    });
    (address, task)
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

async fn publish(running: &Running, config: Config) {
    let old = running.active.load_full();
    let candidate = Arc::new(Snapshot::replace(config.clone(), &old).unwrap());
    let prepared = running.manager.prepare(&config).await.unwrap();
    running
        .manager
        .commit_with_publication(prepared, || {
            candidate.activated();
            running.active.store(candidate);
        })
        .await
        .unwrap();
    wait_material(&running.active, true).await;
}

async fn request_h1(
    connector: &tokio_rustls::TlsConnector,
    address: SocketAddr,
    extra_headers: &str,
) -> Option<(u16, String)> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = TcpStream::connect(address).await.ok()?;
        let mut tls = connector.connect("localhost".try_into().unwrap(), socket).await.ok()?;
        let request = format!("GET /private HTTP/1.1\r\nHost: private.test\r\nConnection: close\r\n{extra_headers}\r\n");
        tls.write_all(request.as_bytes()).await.ok()?;
        let mut reply = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            match tls.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(count) => reply.extend_from_slice(&chunk[..count]),
            }
            if reply.len() > 64 * 1024 {
                return None;
            }
        }
        let reply = String::from_utf8(reply).ok()?;
        let status = reply.split_whitespace().nth(1)?.parse().ok()?;
        Some((status, reply))
    })
    .await
    .ok()
    .flatten()
}

async fn plain_request(proxy: Arc<Proxy>, header: &str) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let service = service_fn(move |request| {
            let proxy = proxy.clone();
            async move { proxy.handle(request, peer).await }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(format!("GET /private HTTP/1.1\r\nHost: private.test\r\nConnection: close\r\nX-Workload-Subject: {header}\r\n\r\n").as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    stream.read_to_end(&mut reply).await.unwrap();
    task.await.unwrap();
    String::from_utf8(reply)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn http1_requires_verified_workload_and_ignores_spoofed_forwarding_identity() {
    let material = material();
    let (backend, seen, backend_task) = origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend, &material), bound).await;
    let good = connector(&material, Some(&material.good));
    let no_cert = connector(&material, None);
    let other = connector(&material, Some(&material.other));
    let wrong_ca = connector(&material, Some(&material.wrong_ca));

    let (status, _) = request_h1(
        &good,
        listen,
        "X-Forwarded-For: 198.51.100.77\r\nX-Workload-Subject: forged\r\n",
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    {
        let headers = seen.lock().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0]["x-workload-subject"], GOOD_ID);
        assert_eq!(headers[0]["x-forwarded-for"], "127.0.0.1");
    }

    assert!(request_h1(&no_cert, listen, "").await.is_none());
    assert!(request_h1(&wrong_ca, listen, "").await.is_none());
    assert_eq!(request_h1(&other, listen, "").await.unwrap().0, 403);
    assert_eq!(plain_request(running.proxy.clone(), GOOD_ID).await, 403);
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "unauthorized requests reached the origin"
    );
    assert!(
        running
            .metrics
            .http_mtls_rejections
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 2
    );
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn http2_uses_the_same_verified_workload_resource_policy() {
    let material = material();
    let (backend, seen, backend_task) = origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend, &material), bound).await;
    let connector = connector(&material, Some(&material.good));
    let socket = TcpStream::connect(listen).await.unwrap();
    let tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://private.test/private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
    let denied = sender
        .send_request(
            Request::builder()
                .method("POST")
                .uri("https://private.test/private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(seen.lock().unwrap().len(), 1);
    connection_task.abort();
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn automatic_ca_damage_withdraws_http_identity_without_config_revision() {
    let material = material();
    let original_ca = std::fs::read(&material.ca_file).unwrap();
    let (backend, seen, backend_task) = origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend, &material), bound).await;
    let snapshot_before = running.active.load_full();
    let prepared_before = wait_material(&running.active, true).await.unwrap();
    let connector = connector(&material, Some(&material.good));
    let socket = TcpStream::connect(listen).await.unwrap();
    let tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://private.test/private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );

    std::fs::write(&material.ca_file, b"malformed CA PEM").unwrap();
    wait_material(&running.active, false).await;
    assert!(
        Arc::ptr_eq(&snapshot_before, &running.active.load_full()),
        "material change unexpectedly published config"
    );
    tokio::time::timeout(Duration::from_secs(3), connection_task)
        .await
        .expect("HTTP/2 mTLS connection survived invalid material")
        .unwrap();
    assert!(
        request_h1(&connector, listen, "").await.is_none(),
        "invalid material admitted a new HTTP request"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);

    std::fs::write(&material.ca_file, original_ca).unwrap();
    let restored = wait_material(&running.active, true).await.unwrap();
    assert!(
        !Arc::ptr_eq(&prepared_before, &restored),
        "restored CA reused a withdrawn verifier"
    );
    assert_eq!(request_h1(&connector, listen, "").await.unwrap().0, 200);
    assert_eq!(seen.lock().unwrap().len(), 2);
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn held_sse_stream_closes_when_listener_identity_generation_is_withdrawn() {
    let material = material();
    let (backend, backend_task) = streaming_origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let initial = config(listen, backend, &material);
    let running = start(initial.clone(), bound).await;
    let connector = connector(&material, Some(&material.good));
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    tls.write_all(b"GET /private HTTP/1.1\r\nHost: private.test\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        let mut chunk = [0; 1024];
        while !response
            .windows(b"data:x\n".len())
            .any(|window| window == b"data:x\n")
        {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0, "SSE closed before first event");
            response.extend_from_slice(&chunk[..count]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
    })
    .await
    .unwrap();

    let mut next = initial;
    next.revision += 1;
    next.workload_http[0].tls.allowed_uri_sans = vec![OTHER_ID.into()];
    publish(&running, next).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut byte = [0];
        loop {
            match tls.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("withdrawn mTLS SSE stream remained open");
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn upgraded_websocket_keeps_connection_admission_and_closes_on_route_policy_change() {
    let material = material();
    let (backend, backend_task) = websocket_origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let initial = config(listen, backend, &material);
    let running = start_with_limit(initial.clone(), bound, 1).await;
    let connector = connector(&material, Some(&material.good));
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    tls.write_all(b"GET /private HTTP/1.1\r\nHost: private.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").await.unwrap(); // gitleaks:allow -- WebSocket protocol fixture
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    tokio::time::timeout(Duration::from_secs(3), async {
        while !headers.ends_with(b"\r\n\r\n") {
            tls.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
        }
    })
    .await
    .unwrap();
    assert!(
        headers.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&headers)
    );
    tls.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    tls.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    assert_eq!(
        running
            .metrics
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let second = TcpStream::connect(listen).await.unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect("localhost".try_into().unwrap(), second)
        )
        .await
        .unwrap()
        .is_err(),
        "upgraded tunnel released the listener connection permit"
    );

    let mut next = initial;
    next.revision += 1;
    next.http[0].resource_policy.as_mut().unwrap().allow[0].subjects = vec![OTHER_ID.into()];
    publish(&running, next).await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match tls.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .expect("withdrawn route policy left the WebSocket tunnel open");
    assert!(
        running
            .metrics
            .workload_route_terminations
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn http2_stream_retirement_does_not_close_an_unrelated_workload_route() {
    let material = material();
    let (stream_backend, stream_task) = streaming_origin().await;
    let (other_backend, seen, other_task) = origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let mut initial = config(listen, stream_backend, &material);
    let mut other_route = initial.http[0].clone();
    other_route.id = "other".into();
    other_route.path_prefix = Some("/other".into());
    other_route.backends = vec![format!("http://{other_backend}").into()];
    other_route.resource_policy.as_mut().unwrap().resource_id = "other-api".into();
    initial.http.push(other_route);
    let running = start(initial.clone(), bound).await;
    let connector = connector(&material, Some(&material.good));
    let socket = TcpStream::connect(listen).await.unwrap();
    let tls = connector
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://private.test/private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(3), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        first
            .into_data()
            .unwrap()
            .windows(b"data:x\n".len())
            .any(|window| window == b"data:x\n")
    );

    let mut next = initial;
    next.revision += 1;
    next.http[0].resource_policy.as_mut().unwrap().allow[0].subjects = vec![OTHER_ID.into()];
    publish(&running, next).await;
    tokio::time::timeout(Duration::from_secs(2), body.frame())
        .await
        .expect("changed route's held HTTP/2 stream was not retired");
    let response = sender
        .send_request(
            Request::builder()
                .uri("https://private.test/other")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect("unrelated route's HTTP/2 connection was closed");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "ok"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    connection_task.abort();
    running.shutdown().await;
    stream_task.abort();
    other_task.abort();
}

/// Diagnostic only: localhost origin, one mTLS listener, 8 keep-alive clients,
/// 8 requests each, 1 MiB response per request. TLS handshakes are timed;
/// certificate generation and server startup are not. This is not a claim
/// about production or competing proxies' throughput.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run explicitly in release mode to measure loopback mTLS throughput"]
async fn release_workload_http_mtls_throughput_diagnostic() {
    const CLIENTS: usize = 8;
    const REQUESTS_PER_CLIENT: usize = 8;
    const PAYLOAD_BYTES: usize = 1024 * 1024;
    let payload = Bytes::from(
        (0..PAYLOAD_BYTES)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let material = material();
    let (backend, backend_task) = payload_origin(payload.clone()).await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let running = start(config(listen, backend, &material), bound).await;
    let connector = connector(&material, Some(&material.good));

    let started = tokio::time::Instant::now();
    let clients = (0..CLIENTS)
        .map(|_| {
            let connector = connector.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let socket = TcpStream::connect(listen).await.unwrap();
                socket.set_nodelay(true).unwrap();
                let tls = connector
                    .connect("localhost".try_into().unwrap(), socket)
                    .await
                    .unwrap();
                let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
                    .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
                    .await
                    .unwrap();
                let connection_task = tokio::spawn(async move { connection.await.unwrap() });
                for _ in 0..REQUESTS_PER_CLIENT {
                    let response = sender
                        .send_request(
                            Request::builder()
                                .uri("https://private.test/private")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), 200);
                    let body = response.into_body().collect().await.unwrap().to_bytes();
                    assert_eq!(body.len(), PAYLOAD_BYTES);
                    assert_eq!(body, payload, "mTLS response payload was corrupted");
                }
                drop(sender);
                connection_task.await.unwrap();
            })
        })
        .collect::<Vec<_>>();
    tokio::time::timeout(Duration::from_secs(60), async {
        for client in clients {
            client.await.unwrap();
        }
    })
    .await
    .expect("mTLS throughput diagnostic exceeded 60 seconds");
    let elapsed = started.elapsed();
    let mebibytes = (CLIENTS * REQUESTS_PER_CLIENT * PAYLOAD_BYTES) as f64 / 1_048_576.0;
    eprintln!(
        "workload HTTP mTLS loopback diagnostic: {mebibytes:.0} MiB verified in {:.3} s = {:.1} MiB/s payload; {CLIENTS} concurrent keep-alive clients, {} requests, 4 Tokio workers, client TCP_NODELAY, TLS handshakes included, setup excluded",
        elapsed.as_secs_f64(),
        mebibytes / elapsed.as_secs_f64(),
        CLIENTS * REQUESTS_PER_CLIENT
    );
    running.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn jwt_expiry_retires_sse_even_while_workload_identity_is_current() {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};
    let material = material();
    let (backend, backend_task) = streaming_origin().await;
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let key = SigningKey::from_bytes(&[63; 32]);
    let mut document = serde_json::to_value(config(listen, backend, &material)).unwrap();
    document["http"][0]["jwt_auth"] = json!({
        "verification":{"issuer":"https://issuer.example.test/", "audiences":["workload-api"],
            "profile":"rfc9068", "algorithms":["EdDSA"], "leeway_seconds":0},
        "keys":{"source":"local", "jwks":{"keys":[{"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA",
            "use":"sig", "kid":"lease-fixture", "x":URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes())}]}}
    });
    let running = start(serde_json::from_value(document).unwrap(), bound).await;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"typ":"at+jwt","alg":"EdDSA","kid":"lease-fixture"})).unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(
            &json!({"iss":"https://issuer.example.test/","aud":"workload-api",
        "sub":"alice","client_id":"owned","iat":now,"exp":now+4,"jti":"owned-lease"}),
        )
        .unwrap(),
    );
    let input = format!("{header}.{claims}");
    let token = format!(
        "{input}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(input.as_bytes()).to_bytes())
    );
    let good = connector(&material, Some(&material.good));
    assert_eq!(request_h1(&good, listen, "").await.unwrap().0, 401);
    let without_certificate = connector(&material, None);
    assert!(
        request_h1(
            &without_certificate,
            listen,
            &format!("Authorization: Bearer {token}\r\n")
        )
        .await
        .is_none()
    );
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut tls = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    tls.write_all(
        format!(
            "GET /private HTTP/1.1\r\nHost: private.test\r\nAuthorization: Bearer {token}\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut response = Vec::new();
        let mut chunk = [0; 1024];
        while !response.windows(7).any(|bytes| bytes == b"data:x\n") {
            let count = tls.read(&mut chunk).await.unwrap();
            assert!(count > 0, "combined auth stream ended before admission");
            response.extend_from_slice(&chunk[..count]);
        }
        assert!(response.starts_with(b"HTTP/1.1 200"));
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(7), async {
        let mut chunk = [0; 1024];
        while let Ok(count) = tls.read(&mut chunk).await {
            if count == 0 {
                break;
            }
        }
    })
    .await
    .expect("JWT expiry did not retire the workload-authenticated SSE stream");
    assert!(
        running.active.load().http_workload_tls["private-edge"]
            .load()
            .is_some()
    );
    assert!(
        running
            .metrics
            .jwt_lease_terminations
            .load(std::sync::atomic::Ordering::Relaxed)
            > 0
    );
    assert_eq!(
        running
            .metrics
            .workload_route_terminations
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    running.shutdown().await;
    backend_task.abort();
}
