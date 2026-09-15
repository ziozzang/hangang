use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, HttpRoute, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::{Body, Proxy, response},
    traffic::TrafficHistory,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use std::{
    collections::BTreeMap,
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

#[derive(Clone, Debug)]
struct Seen {
    headers: hyper::HeaderMap,
    body: Bytes,
}

#[tokio::test]
async fn traffic_history_records_real_peer_and_trusted_client_without_query_or_headers() {
    let (origin, _seen, origin_task) = upstream("ok").await;
    let settings = hangang::config::Settings {
        trusted_proxy_cidrs: Some(vec!["127.0.0.0/8".parse().unwrap()]),
        ..Default::default()
    };
    let ((proxy, policy), _) =
        proxy_with_settings(vec![route(vec![format!("http://{origin}")])], settings);
    let traffic = Arc::new(TrafficHistory::default());
    let (front, front_task, _) = frontend(proxy.with_traffic_history(traffic.clone())).await;
    let reply = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/items?token=never-store-this"))
                .header("x-forwarded-for", "198.51.100.7")
                .header("authorization", "Bearer never-store-this")
                .header("cookie", "session=never-store-this")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    reply.into_body().collect().await.unwrap();
    let batch = traffic.snapshot_since(None, 128);
    assert_eq!(batch.records.len(), 1);
    let record = &batch.records[0];
    assert_eq!(record.peer_ip, "127.0.0.1");
    assert_eq!(record.client_ip, "198.51.100.7");
    assert_eq!(record.method, "GET");
    assert_eq!(record.path, "/items");
    assert_eq!(record.route_id.as_deref(), Some("route"));
    assert_eq!(
        serde_json::to_value(&record.listener).unwrap(),
        serde_json::json!({"kind":"unknown","id":null})
    );
    assert_eq!(record.status, 200);
    assert_eq!(record.protocol, "h1");
    assert!(!record.tls);
    assert!(
        !serde_json::to_string(&batch)
            .unwrap()
            .contains("never-store-this")
    );
    front_task.abort();
    origin_task.abort();
    policy.shutdown().await;
}

/// HTTP/2 origins can reject a request that carries both :authority and a
/// regular Host field. hyper-util adds Host from the URI on HTTP/1 itself.
#[tokio::test]
async fn outbound_preserve_host_uses_one_authority_on_h2_and_host_on_h1() {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.cert.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into()),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let h2_seen = Arc::new(Mutex::new(None));
    let origin = tokio::spawn({
        let h2_seen = h2_seen.clone();
        async move {
            let (socket, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(socket).await.unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let h2_seen = h2_seen.clone();
                async move {
                    let has_host = request.headers().contains_key(hyper::header::HOST);
                    let authority = request
                        .uri()
                        .authority()
                        .map(|authority| authority.as_str().to_owned());
                    *h2_seen.lock().unwrap() = Some((request.version(), has_host, authority));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(if has_host { 400 } else { 200 })
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        }
    });
    let mut secure = route(vec![format!("https://{address}")]);
    secure.host = Some("dsm.home.jioh.net".into());
    secure.preserve_host = true;
    secure.upstream.tls = Some(hangang::upstream::UpstreamTls {
        insecure_skip_verify: true,
        ..Default::default()
    });
    let (secure_proxy, policy) = proxy(vec![secure]);
    let (front, front_task, _) = frontend(secure_proxy).await;
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("Host", "dsm.home.jioh.net")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        *h2_seen.lock().unwrap(),
        Some((
            hyper::Version::HTTP_2,
            false,
            Some("dsm.home.jioh.net".to_owned())
        ))
    );
    front_task.abort();
    origin.abort();
    policy.shutdown().await;

    let (address, seen, origin) = upstream("h1").await;
    let mut plain = route(vec![format!("http://{address}")]);
    plain.host = Some("dsm.home.jioh.net".into());
    plain.preserve_host = true;
    let (plain_proxy, policy) = proxy(vec![plain]);
    let (front, front_task, _) = frontend(plain_proxy).await;
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("Host", "dsm.home.jioh.net")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(seen.lock().unwrap()[0].headers["host"], "dsm.home.jioh.net");
    front_task.abort();
    origin.abort();
    policy.shutdown().await;
}

async fn upstream(label: &'static str) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let records = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let records = records.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let records = records.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        records.lock().unwrap().push(Seen {
                            headers: parts.headers,
                            body,
                        });
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            label.as_bytes(),
                        ))))
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

async fn frontend(proxy: Proxy) -> (SocketAddr, JoinHandle<()>, Arc<Metrics>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let metrics = Arc::new(Metrics::default());
    let task_metrics = metrics.clone();
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            let permit = permits.clone().acquire_owned().await.unwrap();
            let lease = Arc::new(hangang::metrics::ConnectionLease::new(
                permit,
                task_metrics.clone(),
            ));
            tokio::spawn(async move {
                let connection_lease = lease.clone();
                let service = service_fn(move |mut request: Request<Incoming>| {
                    request.extensions_mut().insert(lease.clone());
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
                drop(connection_lease);
            });
        }
    });
    (address, task, metrics)
}

fn route(backends: Vec<String>) -> HttpRoute {
    HttpRoute {
        listener_ids: Vec::new(),
        access_mode: Default::default(),
        resource_policy: None,
        language_policy: None,
        country_policy: None,
        jwt_auth: None,
        workload_auth: None,
        enabled: true,
        upstream: Default::default(),
        priority: 0,
        host_regex: None,
        upstream_host: None,
        preserve_host: false,
        id: "route".into(),
        host: None,
        hosts: Vec::new(),
        canonical_domain: None,
        path_prefix: None,
        path_match: Default::default(),
        max_requests: None,
        upstream_timeout_ms: None,
        retries: 0,
        require_tls: false,
        https_redirect_code: None,
        cache: None,
        headers: BTreeMap::new(),
        json: BTreeMap::new(),
        backends: backends.into_iter().map(Into::into).collect(),
        deny_cidrs: Vec::new(),
        lua: None,
        request_transform: None,
        response_transform: None,
        auth: None,
        basic_auth: None,
        balance: Default::default(),
        response_set_headers: std::collections::BTreeMap::new(),
        response_remove_headers: Vec::new(),
    }
}

#[tokio::test]
async fn http2_canonical_domain_redirect_preserves_encoded_uri_without_origin_access() {
    let (backend, seen, backend_task) = upstream("must-not-run").await;
    let mut alias = route(vec![format!("http://{backend}")]);
    alias.hosts = vec!["www.example.test".into(), "example.test".into()];
    alias.require_tls = true;
    alias.canonical_domain = Some(hangang::config::CanonicalDomain {
        enabled: true,
        host: "example.test".into(),
        scheme: hangang::config::CanonicalScheme::Https,
        status: 308,
        path_prefixes: vec!["/wp-login.php".into()],
        exclude_path_prefixes: vec![],
        methods: vec!["GET".into(), "HEAD".into()],
    });
    let (proxy, policy) = proxy(vec![alias]);
    let (front, front_task) = frontend_h2(proxy).await;
    let mut client = h2_client(front).await;
    let response = client.send_request(Request::builder()
        .uri(format!("http://{front}/wp-login.php/%2Fkeep?redirect_to=https%3A%2F%2Fevil.test&x=1&x=2"))
        .header("host", "www.example.test")
        .body(UnknownLengthBody(Default::default())).unwrap()).await.unwrap();
    assert_eq!(response.status(), 308);
    assert_eq!(
        response.headers()["location"],
        "https://example.test/wp-login.php/%2Fkeep?redirect_to=https%3A%2F%2Fevil.test&x=1&x=2"
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-hangang-canonical-redirect"], "true");
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

fn proxy(routes: Vec<HttpRoute>) -> (Proxy, Arc<PolicyPool>) {
    proxy_with_settings(routes, Default::default()).0
}

/// A proxy plus its live snapshot handle, so a test can publish a new
/// document (for example with different `settings`) without restarting.
fn proxy_with_settings(
    routes: Vec<HttpRoute>,
    settings: hangang::config::Settings,
) -> ((Proxy, Arc<PolicyPool>), Arc<ArcSwap<Snapshot>>) {
    let config = Config {
        geoip_database: None,
        certificates: vec![],
        cache: None,
        revision: 1,
        http: routes,
        tcp: Vec::new(),
        workload_http: Vec::new(),
        public_http: Vec::new(),
        settings,
        cache_generation_floor: 0,
    };
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    (
        (
            Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default())),
            policy,
        ),
        active,
    )
}

fn client() -> Client<HttpConnector, Full<Bytes>> {
    Client::builder(TokioExecutor::new()).build(HttpConnector::new())
}

#[cfg(unix)]
#[tokio::test]
async fn route_lua_capacity_is_503_and_recovers_without_hiding_execution_errors() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let worker = temp.path().join("held-policy-worker.py");
    let ready = temp.path().join("request-started");
    let release = temp.path().join("release-request");
    let ready_json = serde_json::to_string(&ready.display().to_string()).unwrap();
    let release_json = serde_json::to_string(&release.display().to_string()).unwrap();
    let source = format!(
        r#"#!/usr/bin/python3
import json, os, struct, sys, time
ready = {ready_json}
release = {release_json}
first = True
while True:
    size = sys.stdin.buffer.read(4)
    if not size:
        break
    length = struct.unpack(">I", size)[0]
    request = json.loads(sys.stdin.buffer.read(length))
    if request["op"] == "shutdown":
        response = {{"status": "validated"}}
    else:
        if first:
            first = False
            open(ready, "wb").close()
            while not os.path.exists(release):
                time.sleep(0.001)
        if request["data"]["path"] == "/error":
            response = {{"status": "error", "data": {{"message": "fixture execution error"}}}}
        else:
            response = {{"status": "decision", "data": {{"backend": None, "headers": {{}}, "reject": None}}}}
    payload = json.dumps(response).encode()
    sys.stdout.buffer.write(struct.pack(">I", len(payload)) + payload)
    sys.stdout.buffer.flush()
    if request["op"] == "shutdown":
        break
"#
    );
    std::fs::write(&worker, source).unwrap();
    std::fs::set_permissions(&worker, std::fs::Permissions::from_mode(0o700)).unwrap();

    let (origin, seen, origin_task) = upstream("ok").await;
    let mut lua_route = route(vec![format!("http://{origin}")]);
    lua_route.lua = Some("return nil".into());
    let mut config = Config::default();
    config.http.push(lua_route);
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let metrics = Arc::new(Metrics::default());
    let policy = Arc::new(PolicyPool::new(worker, 1));
    let proxy = Proxy::new(active, policy.clone(), metrics.clone());
    let (front, front_task, _) = frontend(proxy).await;

    let occupied = tokio::spawn(async move {
        let response = client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/occupied"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        response.status()
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("first HTTP request reached the worker");

    let busy = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/busy"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(busy.status(), 503);
    assert_eq!(
        busy.into_body().collect().await.unwrap().to_bytes(),
        "policy worker capacity exhausted"
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "busy request reached origin"
    );
    assert_eq!(
        metrics
            .policy_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        metrics
            .policy_capacity_rejections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    std::fs::write(&release, b"").unwrap();
    assert_eq!(occupied.await.unwrap(), 200);
    let recovered = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/recovered"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(recovered.status(), 200);

    let failed = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/error"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(failed.status(), 503);
    assert_eq!(
        failed.into_body().collect().await.unwrap().to_bytes(),
        "policy evaluation failed"
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(
        metrics
            .policy_errors
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );
    assert_eq!(
        metrics
            .policy_capacity_rejections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    front_task.abort();
    origin_task.abort();
    policy.shutdown().await;
}

struct SlowBody {
    state: u8,
    delay: Pin<Box<tokio::time::Sleep>>,
}
impl hyper::body::Body for SlowBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        match self.state {
            0 => {
                self.state = 1;
                Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                    b"one\n\n",
                )))))
            }
            1 => match self.delay.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    self.state = 2;
                    Poll::Ready(Some(Ok(hyper::body::Frame::data(Bytes::from_static(
                        b"two\n\n",
                    )))))
                }
            },
            _ => Poll::Ready(None),
        }
    }
}

async fn sse_upstream() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|_: Request<Incoming>| async {
            let body = SlowBody {
                state: 0,
                delay: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
            };
            Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "text/event-stream")
                    .body(body)
                    .unwrap(),
            )
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    (address, task)
}

async fn websocket_upstream() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(|mut request: Request<Incoming>| async move {
            assert_eq!(request.headers()["connection"], "upgrade");
            assert_eq!(request.headers()["upgrade"], "websocket");
            let upgrade = hyper::upgrade::on(&mut request);
            tokio::spawn(async move {
                if let Ok(upgraded) = upgrade.await {
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut bytes = [0_u8; 4];
                    if upgraded.read_exact(&mut bytes).await.is_ok() {
                        let _ = upgraded.write_all(&bytes).await;
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

/// WebSocket upstream that echoes 4-byte messages until the tunnel closes.
async fn websocket_echo_upstream() -> (SocketAddr, JoinHandle<()>) {
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

/// Frontend serving HTTP/2 (prior knowledge) so wire-level HTTP/2 request
/// shapes can be sent to the proxy.
async fn frontend_h2(proxy: Proxy) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, task)
}

/// A request body of unknown length (no size hint, never reports end of
/// stream up front), so the HTTP/2 client sends HEADERS without END_STREAM
/// and the proxy sees an unknown-length body.
struct UnknownLengthBody(std::collections::VecDeque<Bytes>);
impl hyper::body::Body for UnknownLengthBody {
    type Data = Bytes;
    type Error = Infallible;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Bytes>, Infallible>>> {
        Poll::Ready(
            self.0
                .pop_front()
                .map(|chunk| Ok(hyper::body::Frame::data(chunk))),
        )
    }
}

async fn h2_client(
    address: SocketAddr,
) -> hyper::client::conn::http2::SendRequest<UnknownLengthBody> {
    let stream = TcpStream::connect(address).await.unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
}

/// Upstream that records the raw request bytes it receives (head plus body,
/// framed by Content-Length or chunked) and answers a fixed 200.
async fn raw_upstream() -> (SocketAddr, Arc<Mutex<Vec<Vec<u8>>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let records = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let records = records.clone();
            tokio::spawn(async move {
                let mut received = Vec::new();
                let mut buf = [0_u8; 1024];
                loop {
                    let n = match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    received.extend_from_slice(&buf[..n]);
                    let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8_lossy(&received[..end]).to_ascii_lowercase();
                    let chunked = head
                        .lines()
                        .any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
                    let length = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let done = if chunked {
                        received.ends_with(b"0\r\n\r\n")
                    } else {
                        received.len() - (end + 4) >= length
                    };
                    if done {
                        break;
                    }
                }
                records.lock().unwrap().push(received);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, seen, task)
}

/// Backend that accepts the connection, reads the whole request head (so the
/// request was transmitted and may have executed), then drops the connection
/// without answering.
async fn accept_then_drop_backend() -> (
    SocketAddr,
    Arc<std::sync::atomic::AtomicUsize>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let mut received = Vec::new();
            let mut buf = [0_u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        received.extend_from_slice(&buf[..n]);
                        if received.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
            drop(stream);
        }
    });
    (address, hits, task)
}

fn basic_credential(username: &str, password: &str) -> String {
    use sha2::{Digest, Sha256};
    let salt = b"0123456789abcdef";
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    format!("{username}:{}:{}", hex(salt), hex(&hasher.finalize()))
}

async fn raw_request(address: SocketAddr, request: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[tokio::test]
async fn response_uses_requested_status_and_plain_text() {
    let response = response(418, "teapot");
    assert_eq!(response.status(), 418);
    assert_eq!(
        response.headers()[hyper::header::CONTENT_TYPE],
        "text/plain; charset=utf-8"
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "teapot"
    );
}

#[tokio::test]
async fn host_globs_are_label_local_and_equal_priority_keeps_route_order() {
    let (wildcard, _, wildcard_task) = upstream("wildcard").await;
    let (exact, exact_seen, exact_task) = upstream("exact").await;
    let (question, _, question_task) = upstream("question").await;
    let mut wildcard_route = route(vec![format!("http://{wildcard}")]);
    wildcard_route.id = "wildcard".into();
    wildcard_route.host = Some("*.foo.com".into());
    let mut exact_route = route(vec![format!("http://{exact}")]);
    exact_route.id = "exact".into();
    exact_route.host = Some("special.foo.com".into());
    let mut question_route = route(vec![format!("http://{question}")]);
    question_route.id = "question".into();
    question_route.host = Some("f??.bar.com".into());
    let (proxy, policy) = proxy(vec![wildcard_route, exact_route, question_route]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    for (host, status, body) in [
        ("A.FOO.COM", 200, "wildcard"),
        ("special.foo.com", 200, "wildcard"),
        ("foo.com", 404, "no matching route"),
        ("a.b.foo.com", 404, "no matching route"),
        ("foo.bar.com", 200, "question"),
        ("fooo.bar.com", 404, "no matching route"),
    ] {
        let request = Request::builder()
            .uri(format!("http://{front}/"))
            .header("host", host)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(response.status(), status, "{host}");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            body,
            "{host}"
        );
    }
    assert!(
        exact_seen.lock().unwrap().is_empty(),
        "the later exact route must not overtake an earlier equal-priority glob"
    );
    policy.shutdown().await;
    front_task.abort();
    wildcard_task.abort();
    exact_task.abort();
    question_task.abort();
}

#[tokio::test]
async fn host_alias_group_shares_one_route_and_priority_still_controls_overlap() {
    let (group, _, group_task) = upstream("group").await;
    let (wildcard, _, wildcard_task) = upstream("wildcard").await;
    let mut group_route = route(vec![format!("http://{group}")]);
    group_route.id = "group".into();
    group_route.hosts = vec![
        "foo.com".into(),
        "www.foo.com".into(),
        "*.alias.test".into(),
    ];
    group_route.priority = 5;
    let mut wildcard_route = route(vec![format!("http://{wildcard}")]);
    wildcard_route.id = "wildcard".into();
    wildcard_route.host = Some("*.foo.com".into());
    wildcard_route.priority = 10;
    let (proxy, policy) = proxy(vec![group_route, wildcard_route]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();
    for (host, expected_status, expected_body) in [
        ("foo.com", 200, "group"),
        ("WWW.FOO.COM", 200, "wildcard"),
        ("x.alias.test", 200, "group"),
        ("a.b.alias.test", 404, "no matching route"),
        ("unrelated.test", 404, "no matching route"),
    ] {
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("host", host)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status, "{host}");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected_body,
            "{host}"
        );
    }
    policy.shutdown().await;
    front_task.abort();
    group_task.abort();
    wildcard_task.abort();
}

#[tokio::test]
async fn host_regex_is_anchored_and_higher_priority_runs_first() {
    let (fallback, _, fallback_task) = upstream("fallback").await;
    let (regex, _, regex_task) = upstream("regex").await;
    let mut fallback_route = route(vec![format!("http://{fallback}")]);
    fallback_route.id = "fallback".into();
    let mut regex_route = route(vec![format!("http://{regex}")]);
    regex_route.id = "regex".into();
    regex_route.priority = 10;
    regex_route.host_regex = Some(r"api-[0-9]+\.example\.com".into());
    let (proxy, policy) = proxy(vec![fallback_route, regex_route]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    for (host, expected) in [
        ("API-42.EXAMPLE.COM", "regex"),
        ("xapi-42.example.com", "fallback"),
        ("api-x.example.com", "fallback"),
    ] {
        let request = Request::builder()
            .uri(format!("http://{front}/"))
            .header("host", host)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = client.request(request).await.unwrap();
        assert_eq!(response.status(), 200, "{host}");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected,
            "{host}"
        );
    }
    policy.shutdown().await;
    front_task.abort();
    fallback_task.abort();
    regex_task.abort();
}

#[tokio::test]
async fn matches_json_restores_body_and_rebuilds_forwarding_headers() {
    let (upstream, seen, upstream_task) = upstream("matched").await;
    let mut configured = route(vec![format!("http://{upstream}")]);
    configured.host = Some("example.test".into());
    configured.path_prefix = Some("/api".into());
    configured.headers.insert("x-mode".into(), "blue".into());
    configured
        .json
        .insert("/user/id".into(), serde_json::json!(7));
    let (proxy, policy) = proxy(vec![configured]);
    let (front, front_task, _) = frontend(proxy).await;
    let body = Bytes::from_static(br#"{"user":{"id":7}}"#);
    let request = Request::builder()
        .method("POST")
        .uri(format!("http://{front}/api/check"))
        .header("host", "example.test")
        .header("content-type", "application/json")
        .header("x-mode", "blue")
        .header("connection", "x-remove")
        .header("x-remove", "secret")
        .header("forwarded", "for=attacker")
        .header("x-forwarded-for", "attacker")
        .body(Full::new(body.clone()))
        .unwrap();
    let response = client().request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "matched"
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].body, body);
        assert_eq!(seen[0].headers["x-forwarded-for"], "127.0.0.1");
        assert!(!seen[0].headers.contains_key("forwarded"));
        assert!(!seen[0].headers.contains_key("x-remove"));
    }
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn round_robins_without_retries() {
    let (first, _, first_task) = upstream("a").await;
    let (second, _, second_task) = upstream("b").await;
    let (proxy, policy) = proxy(vec![route(vec![
        format!("http://{first}"),
        format!("http://{second}"),
    ])]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();
    let mut values = Vec::new();
    for _ in 0..3 {
        let request = Request::builder()
            .uri(format!("http://{front}/"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        values.push(
            client
                .request(request)
                .await
                .unwrap()
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes(),
        );
    }
    assert_eq!(
        values,
        [
            Bytes::from_static(b"a"),
            Bytes::from_static(b"b"),
            Bytes::from_static(b"a")
        ]
    );
    policy.shutdown().await;
    front_task.abort();
    first_task.abort();
    second_task.abort();
}

#[tokio::test]
async fn streams_sse_frames_without_buffering_the_response() {
    let (upstream, upstream_task) = sse_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    let (front, front_task, _) = frontend(proxy).await;
    let request = Request::builder()
        .uri(format!("http://{front}/events"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let mut body = client().request(request).await.unwrap().into_body();
    assert_eq!(
        body.frame().await.unwrap().unwrap().into_data().unwrap(),
        "one\n\n"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), body.frame())
            .await
            .is_err()
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(200), body.frame())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "two\n\n"
    );
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn websocket_upgrade_tunnels_bytes() {
    let (upstream, upstream_task) = websocket_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    let shutdown_proxy = proxy.clone();
    let (front, front_task, connection_metrics) = frontend(proxy).await;
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {front}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" // gitleaks:allow -- protocol/test fixture
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        headers.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 101"));
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0_u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    assert_eq!(
        connection_metrics
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    drop(stream);
    shutdown_proxy.shutdown(Duration::from_millis(200)).await;
    tokio::time::timeout(Duration::from_millis(200), async {
        while connection_metrics
            .active_connections
            .load(std::sync::atomic::Ordering::Relaxed)
            != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

fn _streaming_body_type(_: Response<Body>) {}

#[tokio::test]
async fn draining_proxy_refuses_new_upgrade_tunnels() {
    let (upstream, upstream_task) = websocket_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    proxy.shutdown(Duration::ZERO).await;
    let tracker = proxy.tunnels.clone();
    let (front, front_task, _) = frontend(proxy).await;
    let request = Request::builder()
        .uri(format!("http://{front}/"))
        .header("connection", "upgrade")
        .header("upgrade", "websocket")
        .header("sec-websocket-version", "13")
        .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==") // gitleaks:allow -- protocol/test fixture
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = client().request(request).await.unwrap();
    assert_eq!(response.status(), 503);
    assert!(tracker.is_empty());
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn streaming_response_holds_request_admission_until_complete() {
    let (upstream, upstream_task) = sse_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    let (front, front_task, _) = frontend(proxy.with_request_limit(1)).await;
    let request = || {
        Request::builder()
            .uri(format!("http://{front}/events"))
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    let first_client = client();
    let mut stream = first_client.request(request()).await.unwrap().into_body();
    assert_eq!(
        stream.frame().await.unwrap().unwrap().into_data().unwrap(),
        "one\n\n"
    );
    let refused = client().request(request()).await.unwrap();
    assert_eq!(refused.status(), 503);
    stream.collect().await.unwrap();
    let accepted = client().request(request()).await.unwrap();
    assert_eq!(accepted.status(), 200);
    accepted.into_body().collect().await.unwrap();
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn default_listener_and_request_capacity_are_server_attributed() {
    let (upstream, upstream_task) = sse_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    let traffic = Arc::new(TrafficHistory::default());
    let (front, front_task) = frontend_with_peer_transport(
        proxy
            .with_traffic_history(traffic.clone())
            .with_request_limit(1),
        "127.0.0.1:34567".parse().unwrap(),
        true,
    )
    .await;
    let request = || {
        Request::builder()
            .uri(format!("http://{front}/events?secret=hidden"))
            .header("x-hangang-listener", "forged")
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    let mut stream = client().request(request()).await.unwrap().into_body();
    assert_eq!(
        stream.frame().await.unwrap().unwrap().into_data().unwrap(),
        "one\n\n"
    );
    assert_eq!(client().request(request()).await.unwrap().status(), 503);
    let records = traffic.snapshot_since(None, 128).records;
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].status, 503);
    for row in records {
        assert_eq!(
            serde_json::to_value(row.listener).unwrap(),
            serde_json::json!({"kind":"default","id":"default"})
        );
        assert_eq!(row.path, "/events");
    }
    stream.collect().await.unwrap();
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn external_authorization_is_bounded_fail_closed_and_replaces_spoofed_identity() {
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    assert_eq!(request.headers()["x-original-method"], "GET");
                    assert_eq!(request.headers()["x-original-client-ip"], "127.0.0.1");
                    assert!(!request.headers().contains_key("cookie"));
                    let status = match request
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                    {
                        Some("allow") => 200,
                        Some("deny") => 403,
                        Some("unauthorized") => 401,
                        Some("redirect") => 302,
                        Some("slow") => std::future::pending::<u16>().await,
                        _ => 500,
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header("x-user", "verified")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, seen, backend_task) = upstream("allowed").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/check"),
        request_headers: vec!["authorization".into()],
        response_headers: vec!["x-user".into()],
        timeout_ms: 500,
        forward_response: false,
        terminal_response: false,
    });
    let (proxy, policy) = proxy(vec![secured]);
    let (front, front_task, _) = frontend(proxy).await;
    for (authorization, expected) in [
        ("allow", 200),
        ("deny", 403),
        ("unauthorized", 401),
        ("redirect", 503),
        ("slow", 503),
        ("error", 503),
    ] {
        let request = Request::builder()
            .uri(format!("http://{front}/private"))
            .header("authorization", authorization)
            .header("x-user", "spoofed")
            .header("cookie", "secret")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(3), client().request(request))
            .await
            .expect("authorization must have a finite deadline")
            .unwrap();
        assert_eq!(response.status(), expected);
        response.into_body().collect().await.unwrap();
    }
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("authorization", "allow")
                .header("authorization", "different-backend-meaning")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        400,
        "a scalar authorization decision must not inspect a different repeated value than the backend"
    );
    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers["x-user"], "verified");
    }
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
}

#[tokio::test]
async fn authorization_service_receives_edge_resolved_forward_auth_context() {
    // The auth service records the request context it received.
    let seen_context = Arc::new(Mutex::new(Vec::<(String, String)>::new()));
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let recorder = seen_context.clone();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            let recorder = recorder.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let recorder = recorder.clone();
                    async move {
                        let mut context = recorder.lock().unwrap();
                        context.clear();
                        for (name, value) in request.headers() {
                            context.push((
                                name.as_str().to_owned(),
                                value.to_str().unwrap_or("<binary>").to_owned(),
                            ));
                        }
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(200)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, _seen, backend_task) = upstream("allowed").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/check"),
        // Generated names cannot be configured as inputs (validation rejects
        // them); a client pre-filling them is ignored either way.
        request_headers: vec!["authorization".into()],
        response_headers: Vec::new(),
        timeout_ms: 500,
        forward_response: false,
        terminal_response: false,
    });
    let (proxy, policy) = proxy(vec![secured]);
    let proxy = proxy.with_trusted_proxies(vec!["127.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]);
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let (front, front_task) = frontend_with_peer(proxy, peer).await;
    let response = client()
        .request(
            Request::builder()
                .method("PUT")
                .uri(format!("http://{front}/private/item?x=1"))
                .header("host", "app.example")
                .header("x-forwarded-for", "203.0.113.9")
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-host", "public.example")
                .header("x-forwarded-port", "8443")
                .header("x-original-url", "http://evil.example/")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let context: std::collections::HashMap<String, Vec<String>> = seen_context
        .lock()
        .unwrap()
        .iter()
        .fold(Default::default(), |mut map, (name, value)| {
            map.entry(name.clone()).or_default().push(value.clone());
            map
        });
    let one = |name: &str| -> String {
        let values = &context[name];
        assert_eq!(values.len(), 1, "{name} must appear exactly once");
        values[0].clone()
    };
    assert_eq!(one("x-forwarded-method"), "PUT");
    assert_eq!(one("x-original-method"), "PUT");
    assert_eq!(one("x-forwarded-uri"), "/private/item?x=1");
    assert_eq!(one("x-original-uri"), "/private/item?x=1");
    assert_eq!(one("x-forwarded-for"), "203.0.113.9");
    assert_eq!(one("x-real-ip"), "203.0.113.9");
    assert_eq!(one("x-original-client-ip"), "203.0.113.9");
    assert_eq!(one("x-forwarded-proto"), "https");
    assert_eq!(one("x-forwarded-port"), "8443");
    assert_eq!(one("x-forwarded-host"), "public.example");
    assert_eq!(
        one("x-original-url"),
        "https://public.example:8443/private/item?x=1"
    );
    // A Host that is not an authority would let the client choose the URL
    // structure the authorization service judges: rejected before auth.
    for (name, value) in [
        ("host", "app.test/public#"),
        ("host", "user@app.test"),
        ("host", "app.test:abc"),
        ("host", "app.test:"),
        ("host", "[not-an-ip]"),
        ("x-forwarded-host", "evil.test/admin?"),
        ("x-forwarded-port", "+443"),
        ("x-forwarded-port", "0"),
        ("x-forwarded-port", "65536"),
    ] {
        let response = client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/private"))
                    .header(name, value)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "{name}: {value}");
    }
    assert!(
        seen_context
            .lock()
            .unwrap()
            .iter()
            .any(|(name, value)| name == "x-forwarded-uri" && value == "/private/item?x=1"),
        "the authorization service must not be consulted for a malformed host"
    );
    // Two Host fields, or a Host nominated as hop-by-hop, are rejected as well.
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("host", "app.example")
                .header("host", "other.example")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    // A trusted edge commonly appends its authoritative forwarding value to a
    // client-supplied field. Accepting the first duplicate would let the
    // client choose redirect and authorization URL context.
    for (name, client_value, edge_value) in [
        ("x-forwarded-host", "attacker.example", "public.example"),
        ("x-forwarded-port", "80", "443"),
    ] {
        let response = client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/private"))
                    .header("host", "app.example")
                    .header(name, client_value)
                    .header(name, edge_value)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400, "duplicate {name} must fail closed");
    }
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("connection", "host")
                .header("host", "app.test/public#")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
}

#[tokio::test]
async fn sso_identity_under_forwarded_prefix_reaches_the_upstream_unspoofed() {
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    // The client's spoofed identity never reaches the auth service.
                    assert!(!request.headers().contains_key("x-forwarded-user"));
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("x-forwarded-user", "alice")
                            .header("x-forwarded-groups", "admins,dev")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, seen, backend_task) = upstream("allowed").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/check"),
        request_headers: vec![],
        response_headers: vec!["x-forwarded-user".into(), "x-forwarded-groups".into()],
        timeout_ms: 500,
        forward_response: false,
        terminal_response: false,
    });
    // Identity names are accepted as response headers but never as inputs.
    let mut rejected = secured.clone();
    rejected.auth.as_mut().unwrap().request_headers = vec!["x-forwarded-user".into()];
    assert!(
        hangang::config::Config {
            http: vec![rejected],
            ..Default::default()
        }
        .validate()
        .is_err()
    );
    let (proxy, policy) = proxy(vec![secured]);
    let (front, front_task, _) = frontend(proxy).await;
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("x-forwarded-user", "root")
                .header("x-forwarded-for", "203.0.113.9")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].headers["x-forwarded-user"], "alice");
        assert_eq!(requests[0].headers["x-forwarded-groups"], "admins,dev");
        assert_eq!(
            requests[0]
                .headers
                .get_all("x-forwarded-user")
                .iter()
                .count(),
            1
        );
        // An untrusted client's forwarding headers are replaced by the edge's.
        assert_eq!(requests[0].headers["x-forwarded-for"], "127.0.0.1");
    }
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
}

#[tokio::test]
async fn document_settings_override_process_defaults_and_apply_on_reload() {
    use hangang::config::Settings;
    let (backend, seen, backend_task) = upstream("app").await;
    let settings = Settings {
        trusted_proxy_cidrs: Some(vec!["127.0.0.0/8".parse::<ipnet::IpNet>().unwrap()]),
        remove_response_headers: Some(vec!["x-powered-by".into()]),
        https_redirect_code: Some(301),
        upstream_timeout_ms: Some(120_000),
        allow_dot_segments: Some(true),
        health_path: Some("/-/fleet-ready".into()),
        ..Settings::default()
    };
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.require_tls = true;
    let mut open = route(vec![format!("http://{backend}")]);
    open.id = "open".into();
    open.path_prefix = Some("/open".into());
    open.priority = 10;
    let ((proxy, policy), active) =
        proxy_with_settings(vec![secured.clone(), open.clone()], settings);
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let (front, front_task) = frontend_with_peer(proxy, peer).await;
    let client = client();

    // Health path from the document, without --health-path.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/-/fleet-ready"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    // Trusted proxy from the document: the forwarded proto satisfies require_tls.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/open/x"))
                .header("x-forwarded-proto", "https")
                .header("x-forwarded-for", "203.0.113.7")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    {
        let requests = seen.lock().unwrap();
        assert_eq!(
            requests.last().unwrap().headers["x-forwarded-for"],
            "203.0.113.7"
        );
        assert!(
            !requests
                .last()
                .unwrap()
                .headers
                .contains_key("x-powered-by")
        );
    }
    // Redirect code from the document.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/plain"))
                .header("host", "app.example")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 301);
    // Dot segments allowed by the document.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/open/../open/y"))
                .header("x-forwarded-proto", "https")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_ne!(response.status(), 400);

    // A new document without settings restores the process defaults at once.
    let plain = Config {
        geoip_database: None,
        certificates: vec![],
        cache: None,
        revision: 2,
        http: vec![secured, open],
        tcp: Vec::new(),
        workload_http: Vec::new(),
        public_http: Vec::new(),
        settings: Default::default(),
        cache_generation_floor: 0,
    };
    plain.validate().unwrap();
    let previous = active.load_full();
    active.store(Arc::new(Snapshot::replace(plain, &previous).unwrap()));
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/-/fleet-ready"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        308,
        "no health path and no trusted proxy: the process default redirect applies"
    );
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/open/../open/y"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);

    // Validation rejects out-of-range settings.
    let mut bad = Config::default();
    bad.settings.https_redirect_code = Some(200);
    assert!(bad.validate().is_err());
    bad.settings.https_redirect_code = None;
    bad.settings.remove_response_headers = Some(vec!["content-length".into()]);
    assert!(bad.validate().is_err());
    bad.settings.remove_response_headers = None;
    bad.settings.health_path = Some("ready".into());
    assert!(bad.validate().is_err());
    // Serialisation omits an empty settings block, keeping older documents stable.
    assert!(
        !serde_json::to_string(&Config::default())
            .unwrap()
            .contains("settings")
    );

    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn weighted_routes_distribute_requests_and_failed_backends_are_not_retried() {
    let (first, _, first_task) = upstream("a").await;
    let (second, _, second_task) = upstream("b").await;
    let mut weighted = route(vec![format!("http://{first}"), format!("http://{second}")]);
    weighted.balance.weights = vec![3, 1];
    let (weighted_proxy, policy) = proxy(vec![weighted]);
    let (front, front_task, _) = frontend(weighted_proxy).await;
    let client = client();
    let mut counts = [0; 2];
    for _ in 0..40 {
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        counts[if body == "a" { 0 } else { 1 }] += 1;
    }
    assert_eq!(counts, [30, 10]);
    policy.shutdown().await;
    front_task.abort();
    first_task.abort();
    second_task.abort();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let failed = listener.local_addr().unwrap();
    drop(listener);
    let (good, seen, good_task) = upstream("healthy").await;
    let mut health = route(vec![format!("http://{failed}"), format!("http://{good}")]);
    health.balance.health = Some(hangang::balance::HealthPolicy {
        failure_threshold: 1,
        cooldown_ms: 10_000,
    });
    let (health_proxy, policy) = proxy(vec![health]);
    let (front, front_task, _) = frontend(health_proxy).await;
    for expected in [502, 200, 200] {
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        response.into_body().collect().await.unwrap();
    }
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "failed request must not be replayed"
    );
    policy.shutdown().await;
    front_task.abort();
    good_task.abort();
}

#[tokio::test]
async fn one_streaming_route_cannot_consume_another_routes_capacity() {
    let (events, events_task) = sse_upstream().await;
    let (fast, _, fast_task) = upstream("independent").await;
    let mut first = route(vec![format!("http://{events}")]);
    first.id = "events".into();
    first.path_prefix = Some("/events".into());
    first.max_requests = Some(1);
    let mut second = route(vec![format!("http://{fast}")]);
    second.id = "fast".into();
    second.max_requests = Some(1);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            geoip_database: None,
            certificates: vec![],
            cache: None,
            revision: 0,
            http: vec![first, second],
            tcp: Vec::new(),
            workload_http: Vec::new(),
            public_http: Vec::new(),
            settings: Default::default(),
            cache_generation_floor: 0,
        })
        .unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy.with_request_limit(2)).await;
    let request = |path: &str| {
        Request::builder()
            .uri(format!("http://{front}{path}"))
            .body(Full::new(Bytes::new()))
            .unwrap()
    };
    let mut held = client()
        .request(request("/events"))
        .await
        .unwrap()
        .into_body();
    held.frame().await.unwrap().unwrap();
    // A revision change must not reset the occupied route's counter.
    let old = active.load_full();
    let mut config = old.config.clone();
    config.revision += 1;
    active.store(Arc::new(Snapshot::replace(config, &old).unwrap()));
    let refused = client().request(request("/events")).await.unwrap();
    assert_eq!(refused.status(), 503);
    refused.into_body().collect().await.unwrap();
    let independent = client().request(request("/other")).await.unwrap();
    assert_eq!(independent.status(), 200);
    assert_eq!(
        independent.into_body().collect().await.unwrap().to_bytes(),
        "independent"
    );
    held.collect().await.unwrap();
    policy.shutdown().await;
    front_task.abort();
    events_task.abort();
    fast_task.abort();
}

#[tokio::test]
async fn slow_json_inspection_has_its_own_budget_and_leaves_native_routes_available() {
    let (backend, _, backend_task) = upstream("ok").await;
    let mut json_route = route(vec![format!("http://{backend}")]);
    json_route.id = "json".into();
    json_route.path_prefix = Some("/json".into());
    json_route.json.insert("/k".into(), serde_json::json!(1));
    let mut native = route(vec![format!("http://{backend}")]);
    native.id = "native".into();
    native.path_prefix = Some("/native".into());
    let (proxy, policy) = proxy(vec![json_route, native]);
    let (front, task, _) = frontend(proxy.with_inspection_limit(1)).await;
    let mut a = TcpStream::connect(front).await.unwrap();
    let mut b = TcpStream::connect(front).await.unwrap();
    let headers = b"POST /json HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{";
    a.write_all(headers).await.unwrap();
    b.write_all(headers).await.unwrap();
    let mut first = [0; 256];
    let mut second = [0; 256];
    let reply = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::select! {
            n = a.read(&mut first) => first[..n.unwrap()].to_vec(),
            n = b.read(&mut second) => second[..n.unwrap()].to_vec(),
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 503"));
    let client = client();
    let response = client
        .get(format!("http://{front}/native").parse().unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    drop(a);
    drop(b);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let request = Request::post(format!("http://{front}/json"))
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from_static(br#"{"k":1}"#)))
            .unwrap();
        let response = client.request(request).await.unwrap();
        let status = response.status();
        response.into_body().collect().await.unwrap();
        if status == 200 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "inspection permit was not released after disconnect"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

// A frontend that forces a fixed peer address, so the dual-stack
// IPv4-mapped-IPv6 canonicalization can be tested deterministically without
// depending on the host's IPv6 socket behavior.
async fn frontend_with_peer(proxy: Proxy, forced_peer: SocketAddr) -> (SocketAddr, JoinHandle<()>) {
    frontend_with_peer_transport(proxy, forced_peer, false).await
}

async fn frontend_with_peer_transport(
    proxy: Proxy,
    forced_peer: SocketAddr,
    transport_tls: bool,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let metrics = Arc::new(Metrics::default());
    let permits = Arc::new(tokio::sync::Semaphore::new(8));
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _real_peer)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            let permit = permits.clone().acquire_owned().await.unwrap();
            let lease = Arc::new(hangang::metrics::ConnectionLease::new(
                permit,
                metrics.clone(),
            ));
            tokio::spawn(async move {
                let connection_lease = lease.clone();
                let service = service_fn(move |mut request: Request<Incoming>| {
                    request.extensions_mut().insert(lease.clone());
                    if transport_tls {
                        request
                            .extensions_mut()
                            .insert(hangang::tls::TransportInfo {
                                tls: true,
                                local_port: 443,
                            });
                    }
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, forced_peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
                drop(connection_lease);
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn deny_cidrs_and_forwarded_ip_canonicalize_ipv4_mapped_but_preserve_ipv6() {
    use ipnet::IpNet;

    // Case 1: IPv4 client on a dual-stack [::] listener arrives as
    // ::ffff:127.0.0.1. An IPv4 deny CIDR MUST match it (regression: it did
    // not before canonicalization).
    {
        let (backend, _seen, backend_task) = upstream("deny").await;
        let mut r = route(vec![format!("http://{backend}")]);
        r.deny_cidrs = vec!["127.0.0.0/8".parse::<IpNet>().unwrap()];
        let (proxy, policy) = proxy(vec![r]);
        let peer: SocketAddr = "[::ffff:127.0.0.1]:40000".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            403,
            "IPv4-mapped peer must be denied by an IPv4 CIDR"
        );
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // Case 2: same mapped peer, no deny -> allowed, and the forwarded client IP
    // is the canonical IPv4, not the ::ffff: form.
    {
        let (backend, seen, backend_task) = upstream("map").await;
        let r = route(vec![format!("http://{backend}")]);
        let (proxy, policy) = proxy(vec![r]);
        let peer: SocketAddr = "[::ffff:203.0.113.7]:40001".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.into_body().collect().await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].headers["x-forwarded-for"], "203.0.113.7");
            assert_eq!(seen[0].headers["x-real-ip"], "203.0.113.7");
        }
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // Case 3: a genuine IPv6 client is unaffected: matched by an IPv6 CIDR and
    // forwarded as its real IPv6 address (dual-stack IPv6 support preserved).
    {
        let (backend, _seen, backend_task) = upstream("v6deny").await;
        let mut r = route(vec![format!("http://{backend}")]);
        r.deny_cidrs = vec!["2001:db8::/32".parse::<IpNet>().unwrap()];
        let (proxy, policy) = proxy(vec![r]);
        let peer: SocketAddr = "[2001:db8::1]:40002".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403, "IPv6 peer must match an IPv6 CIDR");
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // Case 4: genuine IPv6 client, no deny -> allowed and forwarded as IPv6.
    {
        let (backend, seen, backend_task) = upstream("v6ok").await;
        let r = route(vec![format!("http://{backend}")]);
        let (proxy, policy) = proxy(vec![r]);
        let peer: SocketAddr = "[2001:db8::2]:40003".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.into_body().collect().await.unwrap();
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen[0].headers["x-forwarded-for"], "2001:db8::2");
        }
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }
}

#[tokio::test]
async fn health_path_is_unauthenticated_and_reflects_readiness_and_draining() {
    use std::sync::atomic::{AtomicBool, Ordering};

    async fn get_status(client: &Client<HttpConnector, Full<Bytes>>, url: String) -> (u16, Bytes) {
        let response = client
            .request(
                Request::builder()
                    .uri(url)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, body)
    }

    // Ready instance: GET/HEAD -> 200, POST -> 405, unrelated path still routes.
    {
        let (proxy, policy) = proxy(vec![route(vec!["http://127.0.0.1:1".into()])]);
        let proxy = proxy.with_health_path(Some("/healthz".into()));
        let (front, front_task, _) = frontend(proxy).await;
        let client = client();
        let (status, body) = get_status(&client, format!("http://{front}/healthz")).await;
        assert_eq!(status, 200);
        assert_eq!(body, "ok");
        let post = client
            .request(
                Request::post(format!("http://{front}/healthz"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post.status(), 405);
        // A non-health path is not shadowed by the probe (backend is down -> 502).
        let (other, _) = get_status(&client, format!("http://{front}/other")).await;
        assert_eq!(other, 502);
        front_task.abort();
        policy.shutdown().await;
    }

    // Not-ready instance (e.g. controller before first reconcile): 503 until ready.
    {
        let ready = Arc::new(AtomicBool::new(false));
        let (proxy, policy) = proxy(vec![route(vec!["http://127.0.0.1:1".into()])]);
        let proxy = proxy
            .with_health_path(Some("/healthz".into()))
            .with_readiness(ready.clone());
        let (front, front_task, _) = frontend(proxy).await;
        let client = client();
        let (status, body) = get_status(&client, format!("http://{front}/healthz")).await;
        assert_eq!(status, 503);
        assert_eq!(body, "draining");
        ready.store(true, Ordering::Relaxed);
        let (status, _) = get_status(&client, format!("http://{front}/healthz")).await;
        assert_eq!(status, 200);
        front_task.abort();
        policy.shutdown().await;
    }

    // Draining instance: 503 so a balancer deregisters it.
    {
        let (proxy, policy) = proxy(vec![route(vec!["http://127.0.0.1:1".into()])]);
        let proxy = proxy.with_health_path(Some("/healthz".into()));
        let draining = proxy.shutdown.clone();
        let (front, front_task, _) = frontend(proxy).await;
        let client = client();
        draining.cancel();
        let (status, _) = get_status(&client, format!("http://{front}/healthz")).await;
        assert_eq!(status, 503);
        front_task.abort();
        policy.shutdown().await;
    }
}

#[tokio::test]
async fn client_connection_token_cannot_erase_auth_injected_header() {
    // Regression for M-1: an injected identity header must survive a client
    // `Connection: x-user` (which previously caused the final hop-by-hop strip
    // to delete the auth-injected header before it reached the backend).
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_: Request<Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(200)
                            .header("x-user", "verified")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, seen, backend_task) = upstream("allowed").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/check"),
        request_headers: vec!["authorization".into()],
        response_headers: vec!["x-user".into()],
        timeout_ms: 500,
        forward_response: false,
        terminal_response: false,
    });
    let (proxy, policy) = proxy(vec![secured]);
    let (front, front_task, _) = frontend(proxy).await;
    let request = Request::builder()
        .uri(format!("http://{front}/private"))
        .header("authorization", "allow")
        // Attempt to strip the injected identity header via the Connection list.
        .header("connection", "x-user")
        .header("x-user", "spoofed")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = client().request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers["x-user"], "verified",
            "auth-injected identity header must survive a client Connection: x-user"
        );
        // The client's Connection header itself must not be forwarded.
        assert!(!requests[0].headers.contains_key("connection"));
    }
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
}

#[tokio::test]
async fn connection_nominated_header_cannot_select_a_route() {
    let (protected, _, protected_task) = upstream("protected").await;
    let (fallback, _, fallback_task) = upstream("fallback").await;
    let mut header_route = route(vec![format!("http://{protected}")]);
    header_route.id = "header-route".into();
    header_route
        .headers
        .insert("x-route".into(), "private".into());
    let mut fallback_route = route(vec![format!("http://{fallback}")]);
    fallback_route.id = "fallback".into();
    let (proxy, policy) = proxy(vec![header_route, fallback_route]);
    let (front, front_task, _) = frontend(proxy).await;
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("connection", "x-route")
                .header("x-route", "private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "fallback",
        "a hop-by-hop request header must not participate in route selection"
    );
    policy.shutdown().await;
    front_task.abort();
    protected_task.abort();
    fallback_task.abort();
}

#[tokio::test]
async fn dot_segment_paths_are_rejected_before_routing_unless_allowed() {
    // Regression for M-2: a raw `/public/../admin` must not be routed as
    // `/public` (a normalizing backend would then serve `/admin`). The HTTP
    // client normalizes dot segments, so a raw socket is used.
    async fn raw_status(addr: SocketAddr, line: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                format!("GET {line} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n").as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf).into_owned();
        let status = text
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        (status, text)
    }

    // Default: reject dot segments with 400.
    {
        let (backend, seen, backend_task) = upstream("b").await;
        let mut public = route(vec![format!("http://{backend}")]);
        public.id = "public".into();
        public.path_prefix = Some("/public".into());
        let (proxy, policy) = proxy(vec![public]);
        let (front, front_task, _) = frontend(proxy).await;
        for target in ["/public/../admin", "/public/%2e%2e/admin", "/public/%2E./x"] {
            let (status, _) = raw_status(front, target).await;
            assert_eq!(status, 400, "{target} must be rejected");
        }
        // A clean path under the prefix still routes.
        let (status, _) = raw_status(front, "/public/ok").await;
        assert_eq!(status, 200);
        assert!(seen.lock().unwrap().iter().all(|s| !s.headers.is_empty()));
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // Opt-in: forward raw dot segments verbatim.
    {
        let (backend, seen, backend_task) = upstream("b").await;
        let mut public = route(vec![format!("http://{backend}")]);
        public.id = "public".into();
        public.path_prefix = Some("/public".into());
        let (proxy, policy) = proxy(vec![public]);
        let proxy = proxy.with_dot_segments_allowed(true);
        let (front, front_task, _) = frontend(proxy).await;
        let (status, _) = raw_status(front, "/public/../admin").await;
        assert_eq!(status, 200);
        {
            let seen = seen.lock().unwrap();
            assert_eq!(seen.len(), 1);
        }
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }
}

#[tokio::test]
async fn per_route_upstream_timeout_overrides_the_default() {
    // Regression for HIGH-2: a route can raise or lower the time budget for the
    // upstream to return response headers (which also bounds slow uploads).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow = listener.local_addr().unwrap();
    let slow_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_: Request<Incoming>| async {
                    // Delay before returning response headers.
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"slow"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let mut tight = route(vec![format!("http://{slow}")]);
    tight.id = "tight".into();
    tight.host = Some("tight.test".into());
    tight.upstream_timeout_ms = Some(100);
    let mut generous = route(vec![format!("http://{slow}")]);
    generous.id = "generous".into();
    generous.host = Some("generous.test".into());
    generous.upstream_timeout_ms = Some(2000);
    let (proxy, policy) = proxy(vec![tight, generous]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    // Tight budget (100ms) < upstream delay (400ms) -> 504.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("host", "tight.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 504);
    response.into_body().collect().await.unwrap();

    // Generous budget (2000ms) > upstream delay -> 200.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("host", "generous.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "slow"
    );

    front_task.abort();
    slow_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn trusted_proxy_derives_client_from_forwarded_headers_only_when_trusted() {
    use ipnet::IpNet;

    fn xff_headers(seen: &Seen) -> (String, String, String, String, String) {
        let get = |n: &str| {
            seen.headers
                .get(n)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        (
            get("x-forwarded-for"),
            get("x-real-ip"),
            get("x-forwarded-proto"),
            get("x-forwarded-host"),
            get("x-forwarded-port"),
        )
    }

    // Trusted peer: the incoming X-Forwarded-* are honored.
    {
        let (backend, seen, backend_task) = upstream("b").await;
        let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
        // Both the fronting proxy (127/8) and an intermediate (10/8) are
        // trusted, so the recursive walk skips them and lands on 8.8.8.8.
        let proxy = proxy.with_trusted_proxies(vec![
            "127.0.0.0/8".parse::<IpNet>().unwrap(),
            "10.0.0.0/8".parse::<IpNet>().unwrap(),
        ]);
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("x-forwarded-for", "8.8.8.8, 10.0.0.1")
                    .header("x-forwarded-proto", "https")
                    .header("x-forwarded-host", "real.example")
                    .header("x-forwarded-port", "8443")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.into_body().collect().await.unwrap();
        let (xff, xri, proto, host, port) = xff_headers(&seen.lock().unwrap()[0]);
        assert_eq!(xff, "8.8.8.8");
        assert_eq!(xri, "8.8.8.8");
        assert_eq!(proto, "https");
        assert_eq!(host, "real.example");
        assert_eq!(port, "8443");
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // Untrusted peer (no trusted CIDRs): inbound forwarding headers are ignored.
    {
        let (backend, seen, backend_task) = upstream("b").await;
        let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("x-forwarded-for", "::ffff:8.8.8.8")
                    .header("x-forwarded-proto", "https")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        response.into_body().collect().await.unwrap();
        let (xff, _, proto, _, _) = xff_headers(&seen.lock().unwrap()[0]);
        assert_eq!(
            xff, "127.0.0.1",
            "spoofed XFF must be ignored from an untrusted peer"
        );
        assert_eq!(proto, "http");
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }

    // deny_cidrs applies to the effective client IP behind a trusted proxy.
    {
        let (backend, _seen, backend_task) = upstream("b").await;
        let mut denied = route(vec![format!("http://{backend}")]);
        denied.deny_cidrs = vec!["8.8.8.0/24".parse::<IpNet>().unwrap()];
        let (proxy, policy) = proxy(vec![denied]);
        let proxy = proxy.with_trusted_proxies(vec!["127.0.0.0/8".parse::<IpNet>().unwrap()]);
        let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let (front, front_task) = frontend_with_peer(proxy, peer).await;
        let client = client();
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("x-forwarded-for", "8.8.8.8")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("x-forwarded-for", "8.8.8.8, malformed")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            400,
            "malformed XFF from a trusted peer must fail closed"
        );
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("connection", "x-forwarded-for")
                    .header("x-forwarded-for", "8.8.8.8")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            400,
            "nominated XFF must not fall back to the trusted proxy address"
        );
        front_task.abort();
        backend_task.abort();
        policy.shutdown().await;
    }
}

#[tokio::test]
async fn ambiguous_forwarded_proto_cannot_bypass_required_tls() {
    use ipnet::IpNet;

    let (backend, _, backend_task) = upstream("secure").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.require_tls = true;
    let (proxy, policy) = proxy(vec![secured]);
    let proxy = proxy.with_trusted_proxies(vec!["127.0.0.0/8".parse::<IpNet>().unwrap()]);
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let (front, front_task) = frontend_with_peer_transport(proxy, peer, true).await;
    let client = client();

    let ambiguous = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("host", "secure.test")
                .header("x-forwarded-proto", "https, http")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ambiguous.status(), 308);
    assert_eq!(
        ambiguous.headers()["location"],
        "https://secure.test/private"
    );

    let exact = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("host", "secure.test")
                .header("x-forwarded-proto", "https")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(exact.status(), 200);

    let nominated = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("host", "secure.test")
                .header("connection", "x-forwarded-proto")
                .header("x-forwarded-proto", "http")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        nominated.status(),
        400,
        "nominated XFP must not fall back to the TLS proxy hop"
    );

    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn response_header_rules_are_streaming_safe() {
    // Upstream that advertises Server and a custom header on a streamed body.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("server", "upstream/1.0")
                            .header("x-drop", "secret")
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"hello world")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let mut r = route(vec![format!("http://{backend}")]);
    r.response_set_headers = BTreeMap::from([("x-added".to_owned(), "yes".to_owned())]);
    r.response_remove_headers = vec!["x-drop".to_owned()];
    let (proxy, policy) = proxy(vec![r]);
    let proxy = proxy.with_removed_response_headers(vec!["server".parse().unwrap()]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let headers = response.headers().clone();
    assert!(
        !headers.contains_key("server"),
        "global remove must drop Server"
    );
    assert!(
        !headers.contains_key("x-drop"),
        "per-route remove must drop x-drop"
    );
    assert_eq!(headers["x-added"], "yes");
    // Body still streams intact (rules are header-only, no buffering).
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "hello world"
    );
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn idempotent_requests_retry_to_a_healthy_backend_but_bodyful_ones_do_not() {
    let (healthy, seen, healthy_task) = upstream("ok").await;
    // First backend refuses connections; second is healthy. Round-robin selects
    // the dead one first, so a retry is required to succeed.
    let mut r = route(vec![
        "http://127.0.0.1:1".to_owned(),
        format!("http://{healthy}"),
    ]);
    r.retries = 1;
    let (proxy, policy) = proxy(vec![r]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    // Idempotent bodyless GET retries past the dead backend to the healthy one.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
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
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "healthy backend served the retry"
    );

    // A request with a body is never replayed; hitting the dead backend fails.
    let response = client
        .request(
            Request::post(format!("http://{front}/"))
                .body(Full::new(Bytes::from_static(b"payload")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        502,
        "bodyful requests must not be retried"
    );

    front_task.abort();
    healthy_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn policy_selected_backend_is_never_replaced_by_a_retry() {
    policy_selected_backend_is_never_replaced_by_a_retry_case(false).await;
}

#[tokio::test]
async fn policy_selected_backend_is_never_replaced_by_a_retry_by_member_id() {
    policy_selected_backend_is_never_replaced_by_a_retry_case(true).await;
}

async fn policy_selected_backend_is_never_replaced_by_a_retry_case(named: bool) {
    let (healthy, seen, healthy_task) = upstream("unexpected").await;
    let selected = "http://127.0.0.1:1".to_owned();
    let mut r = route(vec![selected.clone(), format!("http://{healthy}")]);
    r.retries = 1;
    r.lua = Some(format!("hangang.select_backend({selected:?})"));
    if named {
        r.backends = r
            .backends
            .into_iter()
            .enumerate()
            .map(|(i, backend)| {
                hangang::pool_member::Backend::Member(hangang::pool_member::PoolMember {
                    id: format!("member-{i}"),
                    address: backend.address().to_owned(),
                    weight: 1,
                    desired_state: Default::default(),
                })
            })
            .collect();
        r.lua = Some("hangang.select_member(\"member-0\")".into());
    }
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            revision: 1,
            http: vec![r],
            ..Config::default()
        })
        .unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;

    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert!(
        seen.lock().unwrap().is_empty(),
        "a connect failure must not send the request to a backend the policy did not select"
    );

    front_task.abort();
    healthy_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn checking_health_cannot_be_bypassed_by_lua_backend_selection() {
    checking_health_cannot_be_bypassed_by_lua_backend_selection_case(false).await;
}

#[tokio::test]
async fn checking_health_cannot_be_bypassed_by_lua_backend_selection_by_member_id() {
    checking_health_cannot_be_bypassed_by_lua_backend_selection_case(true).await;
}

async fn checking_health_cannot_be_bypassed_by_lua_backend_selection_case(named: bool) {
    let (first, _first_seen, first_task) = upstream("first").await;
    let (second, _second_seen, second_task) = upstream("second").await;
    let selected = format!("http://{second}");
    let mut route = route(vec![format!("http://{first}"), selected.clone()]);
    route.lua = Some(format!("hangang.select_backend({selected:?})"));
    if named {
        route.backends = route
            .backends
            .into_iter()
            .enumerate()
            .map(|(i, backend)| {
                hangang::pool_member::Backend::Member(hangang::pool_member::PoolMember {
                    id: format!("member-{i}"),
                    address: backend.address().to_owned(),
                    weight: 1,
                    desired_state: Default::default(),
                })
            })
            .collect();
        route.lua = Some("hangang.select_member(\"member-1\")".into());
    }
    route.balance.active_health = Some(hangang::balance::ActiveHealthPolicy {
        path: "/ready".into(),
        host: None,
        interval_ms: 3000,
        timeout_ms: 2000,
        // The fixture origins return 200 to real /ready probes. Only the
        // explicit 204 reports below qualify a backend, so probe scheduling
        // cannot race this gate test.
        healthy_statuses: vec![204],
        unhealthy_statuses: vec![503],
        healthy_successes: 1,
        unhealthy_http_failures: 1,
        unhealthy_tcp_failures: 1,
        unhealthy_timeouts: 1,
        initial_state: hangang::balance::InitialHealthState::Checking,
    });
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            revision: 1,
            http: vec![route],
            ..Config::default()
        })
        .unwrap(),
    ));
    let balancer = active.load().http[0].balancer.clone();
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;
    let get = || async {
        client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap()
    };

    let response = get().await;
    assert_eq!(
        response.status(),
        503,
        "nothing qualified for Lua selection"
    );
    balancer.record_active_status(0, 204);
    assert!(!balancer.available(1));
    let response = get().await;
    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        status, 503,
        "Lua chose the still-checking backend; body={body:?}"
    );
    assert_eq!(body, "selected backend is unavailable");
    balancer.record_active_status(1, 204);
    let response = get().await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "second"
    );

    front_task.abort();
    first_task.abort();
    second_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn native_basic_auth_challenges_verifies_and_hides_credentials() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let salt = b"0123456789abcdef";
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"s3cret");
    let credential = format!("alice:{}:{}", hex(salt), hex(&hasher.finalize()));

    let (backend, seen, backend_task) = upstream("ok").await;
    let mut r = route(vec![format!("http://{backend}")]);
    r.basic_auth = Some(hangang::config::BasicAuth {
        realm: "restricted".into(),
        credentials: vec![credential],
        hide_credentials: true,
        accept_proxy_authorization: false,
        identity_header: Some("x-user".into()),
    });
    let (proxy, policy) = proxy(vec![r]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    // Missing credentials -> 401 with a Basic challenge.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert!(
        response.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic realm=\"restricted\""),
        "must send a Basic challenge"
    );

    // Wrong password -> 401.
    let wrong = base64::engine::general_purpose::STANDARD.encode("alice:nope");
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("authorization", format!("Basic {wrong}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    // Correct credentials -> 200; Authorization hidden, identity header set.
    let good = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("authorization", format!("Basic {good}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(
            !seen[0].headers.contains_key("authorization"),
            "hide_credentials must strip Authorization"
        );
        assert_eq!(seen[0].headers["x-user"], "alice");
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn protected_only_if_cached_checks_basic_and_lua_before_returning_no_content() {
    use base64::Engine;
    let (backend, seen, backend_task) = upstream("must-not-run").await;
    let basic = hangang::config::BasicAuth {
        realm: "restricted".into(),
        credentials: vec![basic_credential("alice", "secret")],
        hide_credentials: true,
        accept_proxy_authorization: false,
        identity_header: None,
    };
    let mut protected = route(vec![format!("http://{backend}")]);
    protected.id = "protected".into();
    protected.path_prefix = Some("/protected".into());
    protected.access_mode = hangang::config::AccessMode::Protected;
    protected.basic_auth = Some(basic.clone());
    let mut policy_route = protected.clone();
    policy_route.id = "policy".into();
    policy_route.path_prefix = Some("/policy".into());
    policy_route.lua = Some("hangang.reject(403)".into());
    let mut legacy = protected.clone();
    legacy.id = "legacy".into();
    legacy.path_prefix = Some("/legacy".into());
    legacy.access_mode = hangang::config::AccessMode::Legacy;
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            revision: 1,
            http: vec![protected, policy_route, legacy],
            ..Config::default()
        })
        .unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let (front, front_task, _) = frontend(Proxy::new(
        active,
        policy.clone(),
        Arc::new(Metrics::default()),
    ))
    .await;
    let encoded = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    for (path, auth, expected) in [
        ("/protected", None, 401),
        ("/protected", Some(encoded.as_str()), 504),
        ("/policy", Some(encoded.as_str()), 403),
        ("/legacy", None, 504),
    ] {
        let mut builder = Request::builder()
            .uri(format!("http://{front}{path}"))
            .header("cache-control", "only-if-cached");
        if let Some(encoded) = auth {
            builder = builder.header("authorization", format!("Basic {encoded}"));
        }
        let reply = client()
            .request(builder.body(Full::new(Bytes::new())).unwrap())
            .await
            .unwrap();
        assert_eq!(reply.status(), expected, "{path}");
        reply.into_body().collect().await.unwrap();
    }
    assert!(seen.lock().unwrap().is_empty());
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn migrated_basic_credential_clears_spoofed_consumer_identity() {
    use base64::Engine;
    let encode = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    let identity = serde_json::json!({
        "X-Consumer-ID":"consumer-uuid",
        "X-Consumer-Username":"original",
        "X-Credential-Identifier":"compat",
        "X-Anonymous-Consumer":null
    });
    let mut sha = sha1_smol::Sha1::new();
    sha.update(b"secretconsumer-uuid");
    let entry = format!(
        "v1:sha1-suffix:{}:{}:{}:{}",
        encode(b"compat"),
        encode(b"consumer-uuid"),
        sha.digest(),
        encode(identity.to_string().as_bytes())
    );
    let (backend, seen, backend_task) = upstream("ok").await;
    let mut route = route(vec![format!("http://{backend}")]);
    route.basic_auth = Some(hangang::config::BasicAuth {
        realm: "compat".into(),
        credentials: vec![entry],
        hide_credentials: false,
        accept_proxy_authorization: true,
        identity_header: None,
    });
    let (proxy, policy) = proxy(vec![route]);
    let (front, front_task, _) = frontend(proxy).await;
    let auth = |value: &str| {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(value)
        )
    };
    let client = client();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("x-consumer-id", "attacker")
                .header("x-anonymous-consumer", "true")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("authorization", auth("compat:secret"))
                .header("proxy-authorization", auth("compat:wrong"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        401,
        "known proxy credential cannot fall back to Authorization"
    );
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("authorization", auth("compat:secret"))
                .header("proxy-authorization", auth("unknown:wrong"))
                .header("x-consumer-id", "attacker")
                .header("x-consumer-username", "malicious")
                .header("x-anonymous-consumer", "true")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].headers["x-consumer-id"], "consumer-uuid");
        assert_eq!(seen[0].headers["x-consumer-username"], "original");
        assert_eq!(seen[0].headers["x-credential-identifier"], "compat");
        assert!(!seen[0].headers.contains_key("x-anonymous-consumer"));
        assert!(
            seen[0].headers.contains_key("authorization"),
            "live plugin forwards credentials"
        );
        assert!(
            !seen[0].headers.contains_key("proxy-authorization"),
            "proxy hop credential is not forwarded"
        );
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn terminal_auth_2xx_never_contacts_upstream_or_leaks_marker() {
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        loop {
            let (stream, _) = auth_listener.accept().await.unwrap();
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let path = request
                        .headers()
                        .get("x-original-uri")
                        .unwrap()
                        .to_str()
                        .unwrap();
                    let mut response = Response::builder()
                        .status(200)
                        .body(Full::new(Bytes::from_static(b"local only")))
                        .unwrap();
                    if path == "/terminal" {
                        response
                            .headers_mut()
                            .insert("x-hangang-auth-terminal", "1".parse().unwrap());
                        response
                            .headers_mut()
                            .insert("content-type", "text/plain".parse().unwrap());
                    } else if path == "/duplicate" {
                        response
                            .headers_mut()
                            .append("x-hangang-auth-terminal", "1".parse().unwrap());
                        response
                            .headers_mut()
                            .append("x-hangang-auth-terminal", "1".parse().unwrap());
                    } else if path == "/nominated" {
                        response
                            .headers_mut()
                            .insert("connection", "x-hangang-auth-terminal".parse().unwrap());
                        response
                            .headers_mut()
                            .insert("x-hangang-auth-terminal", "1".parse().unwrap());
                    }
                    Ok::<_, Infallible>(response)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, seen, backend_task) = upstream("upstream").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/authorize"),
        request_headers: vec![],
        response_headers: vec![],
        timeout_ms: 500,
        forward_response: true,
        terminal_response: true,
    });
    let (proxy, policy) = proxy(vec![secured]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();
    let terminal = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/terminal"))
                .header("x-hangang-auth-terminal", "forged")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(terminal.status(), 200);
    assert_eq!(terminal.headers()["content-type"], "text/plain");
    assert!(!terminal.headers().contains_key("x-hangang-auth-terminal"));
    assert_eq!(
        terminal.into_body().collect().await.unwrap().to_bytes(),
        "local only"
    );
    assert!(seen.lock().unwrap().is_empty());
    for path in ["/duplicate", "/nominated"] {
        let denied = client
            .request(
                Request::builder()
                    .uri(format!("http://{front}{path}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), 503);
    }
    let allowed = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/regular"))
                .header("x-hangang-auth-terminal", "forged")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
    allowed.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(!seen[0].headers.contains_key("x-hangang-auth-terminal"));
    }
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_policy_cannot_override_native_basic_identity() {
    use base64::Engine;
    use sha2::{Digest, Sha256};

    let salt = b"0123456789abcdef";
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"secret");
    let credential = format!("alice:{}:{}", hex(salt), hex(&hasher.finalize()));
    let (backend, seen, backend_task) = upstream("must-not-run").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.basic_auth = Some(hangang::config::BasicAuth {
        realm: "restricted".into(),
        credentials: vec![credential],
        hide_credentials: true,
        accept_proxy_authorization: false,
        identity_header: Some("x-user".into()),
    });
    secured.lua = Some("hangang.set_header('x-user', 'mallory')".into());
    let config = Config {
        revision: 1,
        http: vec![secured],
        ..Config::default()
    };
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;
    let encoded = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("authorization", format!("Basic {encoded}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert!(seen.lock().unwrap().is_empty());
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn lua_cannot_fill_a_null_compatibility_identity_but_can_set_application_headers() {
    use base64::Engine;
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let mut sha = sha1_smol::Sha1::new();
    sha.update(b"secret");
    sha.update(b"suffix");
    let identity = serde_json::json!({
        "x-anonymous-consumer": null,
        "x-consumer-id": "verified-consumer"
    });
    let credential = format!(
        "v1:sha1-suffix:{}:{}:{}:{}",
        encode(b"alice"),
        encode(b"suffix"),
        sha.digest(),
        encode(identity.to_string().as_bytes())
    );
    let basic = hangang::config::BasicAuth {
        realm: "restricted".into(),
        credentials: vec![credential],
        hide_credentials: true,
        accept_proxy_authorization: false,
        identity_header: None,
    };
    let (backend, seen, backend_task) = upstream("ok").await;
    let mut rejected = route(vec![format!("http://{backend}")]);
    rejected.id = "rejected".into();
    rejected.path_prefix = Some("/rejected".into());
    rejected.basic_auth = Some(basic.clone());
    rejected.lua = Some("hangang.set_header('x-anonymous-consumer', 'forged')".into());
    let mut allowed = route(vec![format!("http://{backend}")]);
    allowed.id = "allowed".into();
    allowed.path_prefix = Some("/allowed".into());
    allowed.basic_auth = Some(basic);
    allowed.lua = Some("hangang.set_header('x-application-tag', 'ok')".into());
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            revision: 1,
            http: vec![rejected, allowed],
            ..Config::default()
        })
        .unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let (front, front_task, _) = frontend(Proxy::new(
        active,
        policy.clone(),
        Arc::new(Metrics::default()),
    ))
    .await;
    let submitted = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    for (path, expected_status) in [("/rejected", 503), ("/allowed", 200)] {
        let reply = client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}{path}"))
                    .header("authorization", format!("Basic {submitted}"))
                    .header("x-anonymous-consumer", "client-forged")
                    .header("x-consumer-id", "client-forged")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(reply.status(), expected_status, "{path}");
        reply.into_body().collect().await.unwrap();
    }
    {
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            1,
            "only the allowed policy may reach the origin"
        );
        assert!(!seen[0].headers.contains_key("x-anonymous-consumer"));
        assert_eq!(seen[0].headers["x-consumer-id"], "verified-consumer");
        assert_eq!(seen[0].headers["x-application-tag"], "ok");
    }
    policy.shutdown().await;
    front_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn external_auth_forward_response_drives_sso_redirect_and_cookie() {
    // Auth service redirects unauthenticated requests to a login URL with a cookie.
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let original_uri = request
                        .headers()
                        .get("x-original-uri")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("");
                    if original_uri.starts_with("/hop") {
                        return Ok::<_, Infallible>(
                            Response::builder()
                                .status(302)
                                .header("connection", "set-cookie")
                                .header("set-cookie", "must-not-pass=1")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        );
                    }
                    if original_uri.starts_with("/large") {
                        return Ok(Response::builder()
                            .status(302)
                            .header("set-cookie", "x".repeat(17 * 1024))
                            .body(Full::new(Bytes::new()))
                            .unwrap());
                    }
                    let allowed = request
                        .headers()
                        .get("cookie")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(|c| c.contains("session=ok"));
                    if allowed {
                        // A 2xx may refresh the session cookie.
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(200)
                                .header("set-cookie", "session=refreshed; Path=/; HttpOnly")
                                .header("set-cookie", "trace=1; Path=/")
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        )
                    } else {
                        Ok(Response::builder()
                            .status(302)
                            .header("location", "https://login.example/authorize")
                            .header("set-cookie", "flow=abc; Path=/; HttpOnly")
                            .body(Full::new(Bytes::from_static(b"redirecting")))
                            .unwrap())
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (backend, _seen, backend_task) = upstream("app").await;
    let mut secured = route(vec![format!("http://{backend}")]);
    secured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth_address}/check"),
        request_headers: vec!["cookie".into()],
        response_headers: vec![],
        timeout_ms: 500,
        forward_response: true,
        terminal_response: false,
    });
    let (proxy, policy) = proxy(vec![secured]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    // Unauthenticated: the auth redirect and cookie reach the client verbatim.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()["location"],
        "https://login.example/authorize"
    );
    assert_eq!(
        response.headers()["set-cookie"],
        "flow=abc; Path=/; HttpOnly"
    );
    response.into_body().collect().await.unwrap();

    // Connection-nominated auth response fields are hop-by-hop and must not
    // reach the client, even when they are in the SSO forwarding allowlist.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/hop"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 302);
    assert!(!response.headers().contains_key("set-cookie"));

    // The allowlisted forwarded header aggregate has the same explicit bound
    // as configured identity headers.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/large"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 503);

    // With a valid session cookie the request is allowed through to the app.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/private"))
                .header("cookie", "session=ok")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let refreshed: Vec<_> = response
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        refreshed,
        ["session=refreshed; Path=/; HttpOnly", "trace=1; Path=/"],
        "cookies issued by the auth service on 2xx reach the client"
    );
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "app"
    );

    front_task.abort();
    backend_task.abort();
    auth_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn require_tls_redirects_plaintext_requests_to_https() {
    let (backend, _seen, backend_task) = upstream("secure").await;
    let mut r = route(vec![format!("http://{backend}")]);
    r.host = Some("secure.test".into());
    r.require_tls = true;
    let (proxy, policy) = proxy(vec![r]);
    let (front, front_task, _) = frontend(proxy).await;
    // The test frontend does not set TransportInfo, so the request is plaintext.
    let client = client();
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/dashboard?a=1"))
                .header("host", "secure.test")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 308);
    assert_eq!(
        response.headers()["location"],
        "https://secure.test/dashboard?a=1"
    );
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn http2_conflicting_content_lengths_are_rejected_before_forwarding() {
    // HTTP/2 validates only the first Content-Length; hyper represents a
    // disagreement as an unknown body length while keeping every field. Left
    // alone, the HTTP/1 upstream would receive both invalid fields plus
    // chunked framing. The raw upstream must never be contacted for those.
    let (backend, seen, backend_task) = raw_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
    let (front, front_task) = frontend_h2(proxy).await;
    let mut sender = h2_client(front).await;
    let body = || {
        UnknownLengthBody(std::collections::VecDeque::from([Bytes::from_static(
            b"data",
        )]))
    };

    for (first, second) in [("4", "1"), ("4", "abc"), ("4", "4, 4")] {
        let request = Request::post(format!("http://{front}/echo"))
            .header("content-length", first)
            .header("content-length", second)
            .body(body())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), 400, "{first:?}/{second:?}");
        let text = response.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&text).contains("Content-Length"),
            "rejection must come from the gateway, not the upstream: {text:?}"
        );
    }
    assert!(
        seen.lock().unwrap().is_empty(),
        "conflicting framing must never reach the upstream"
    );

    // Identical duplicates are canonicalized to one field and the body is
    // forwarded intact under that single length.
    let request = Request::post(format!("http://{front}/echo"))
        .header("content-length", "4")
        .header("content-length", "4")
        .body(body())
        .unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        let raw = String::from_utf8_lossy(&seen[0]).to_ascii_lowercase();
        assert_eq!(
            raw.lines()
                .filter(|l| l.starts_with("content-length:"))
                .count(),
            1,
            "exactly one Content-Length must be forwarded: {raw}"
        );
        assert!(raw.contains("content-length: 4"), "{raw}");
        assert!(!raw.contains("transfer-encoding"), "{raw}");
        assert!(raw.ends_with("\r\n\r\ndata"), "{raw}");
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn encoded_separator_traversal_is_rejected_before_routing() {
    // `/public/%2e%2e%2fadmin` used to pass the dot-segment filter (it split
    // only on a literal `/`), match the `/public` route and be forwarded; a
    // backend decoding `%2f` before resolving `..` would then serve `/admin`.
    let (backend, seen, backend_task) = upstream("b").await;
    let mut public = route(vec![format!("http://{backend}")]);
    public.id = "public".into();
    public.path_prefix = Some("/public".into());
    let (proxy, policy) = proxy(vec![public]);
    let (front, front_task, _) = frontend(proxy).await;
    for target in [
        "/public/%2e%2e%2fadmin",
        "/public/%2E%2E%2Fadmin",
        "/public%2f..%2fadmin",
        "/public/%2f..%2fadmin",
        "/public%5c..%5cadmin",
        "/public/%5C..%5Cadmin",
        "/public/..%5cadmin",
        "/public/..%2Fadmin",
    ] {
        let (status, _) = raw_request(
            front,
            &format!("GET {target} HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n"),
        )
        .await;
        assert_eq!(status, 400, "{target} must be rejected");
    }
    assert!(seen.lock().unwrap().is_empty());
    // An encoded separator without a dot segment is still ordinary data.
    let (status, _) = raw_request(
        front,
        "GET /public/a%2fb HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(seen.lock().unwrap().len(), 1);
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn requests_are_not_retried_after_a_backend_accepted_the_connection() {
    // A retry is only safe when the request provably never left the gateway.
    // A backend that accepts the connection, reads the request and then drops
    // it may already have executed a DELETE; that must not be replayed.
    let (dropping, hits, dropping_task) = accept_then_drop_backend().await;
    let (healthy, seen, healthy_task) = upstream("ok").await;
    let mut r = route(vec![
        format!("http://{dropping}"),
        format!("http://{healthy}"),
    ]);
    r.retries = 1;
    let (proxy, policy) = proxy(vec![r]);
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();
    // Round-robin selects the dropping backend first.
    let response = client
        .request(
            Request::delete(format!("http://{front}/item/1"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        502,
        "a request that reached a backend must fail, not be replayed"
    );
    assert_eq!(hits.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert!(
        seen.lock().unwrap().is_empty(),
        "the DELETE must not be replayed to another backend"
    );
    front_task.abort();
    dropping_task.abort();
    healthy_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn chunked_get_body_is_forwarded_not_silently_dropped() {
    // With the incoming Transfer-Encoding stripped and no Content-Length, the
    // HTTP/1 client encoder assumes a GET body is empty and drops it, so the
    // upstream used to see a bodyless GET instead of the client's request.
    let (backend, seen, backend_task) = upstream("ok").await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
    let (front, front_task, _) = frontend(proxy).await;
    let (status, _) = raw_request(
        front,
        "GET /search HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0].body, "data",
            "the chunked GET body must reach the upstream"
        );
        assert!(!seen[0].headers.contains_key("content-length"));
    }
    // A plain bodyless GET is still sent without any body framing.
    let (status, _) = raw_request(
        front,
        "GET /plain HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 200);
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].body.is_empty());
        assert!(!seen[1].headers.contains_key("transfer-encoding"));
        assert!(!seen[1].headers.contains_key("content-length"));
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn websocket_tunnel_is_closed_when_idle_but_survives_while_active() {
    // The listener's transport idle watchdog ends when hyper hands the socket
    // to the tunnel; the tunnel must keep its own so a silent WebSocket cannot
    // hold admission forever.
    let (upstream, upstream_task) = websocket_echo_upstream().await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{upstream}")])]);
    let proxy = proxy.with_tunnel_idle_timeout(Duration::from_millis(300));
    let tracker = proxy.tunnels.clone();
    let (front, front_task, connection_metrics) = frontend(proxy).await;
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /socket HTTP/1.1\r\nHost: {front}\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n" // gitleaks:allow -- protocol/test fixture
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        headers.push(byte[0]);
    }
    assert!(String::from_utf8_lossy(&headers).starts_with("HTTP/1.1 101"));
    // Active for well over the idle window: every exchange keeps it alive.
    let started = std::time::Instant::now();
    let mut last_exchange = started;
    while started.elapsed() < Duration::from_millis(900) {
        stream.write_all(b"ping").await.unwrap();
        let mut echoed = [0_u8; 4];
        tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut echoed))
            .await
            .expect("active tunnel must not be closed")
            .unwrap();
        assert_eq!(&echoed, b"ping");
        last_exchange = std::time::Instant::now();
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!tracker.is_empty(), "the tunnel is still tracked");
    // Silent: the tunnel is closed once the idle window elapses after the
    // last byte, and the client sees EOF.
    let mut buf = [0_u8; 4];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf))
        .await
        .expect("idle tunnel must be closed within the idle window");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    assert!(last_exchange.elapsed() >= Duration::from_millis(280));
    tokio::time::timeout(Duration::from_secs(2), async {
        while !tracker.is_empty()
            || connection_metrics
                .active_connections
                .load(std::sync::atomic::Ordering::Relaxed)
                != 0
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("tunnel task and connection lease must be released");
    policy.shutdown().await;
    front_task.abort();
    upstream_task.abort();
}

#[tokio::test]
async fn request_transform_cannot_overwrite_basic_identity_at_runtime() {
    use base64::Engine;
    let credential = basic_credential("alice", "s3cret");
    let basic = hangang::config::BasicAuth {
        realm: "restricted".into(),
        credentials: vec![credential],
        hide_credentials: true,
        accept_proxy_authorization: false,
        identity_header: Some("x-user".into()),
    };
    let (backend, seen, backend_task) = upstream("ok").await;
    let mut r = route(vec![format!("http://{backend}")]);
    r.basic_auth = Some(basic.clone());
    let mut transform = hangang::transform::BodyTransform::default();
    transform
        .set_headers
        .insert("X-User".to_owned(), "admin".to_owned());

    // Configuration validation rejects the composition outright ...
    let mut rejected = r.clone();
    rejected.request_transform = Some(transform.clone());
    let invalid = Config {
        revision: 1,
        http: vec![rejected.clone()],
        ..Config::default()
    };
    assert!(invalid.validate().is_err());

    // ... so build the runtime by hand to exercise the runtime guard that
    // re-asserts the authenticated identity after the transform.
    let valid = Snapshot::new(Config {
        revision: 1,
        http: vec![r.clone()],
        ..Config::default()
    })
    .unwrap();
    let runtime = hangang::config::HttpRuntime {
        language_policy: None,
        country_policy: None,
        auth_reserved: Vec::new(),
        jwt_auth: None,
        workload_auth: None,
        host_regex: None,
        admission: valid.admissions["route"].clone(),
        balancer: std::sync::Arc::new(hangang::balance::Balancer::new(Default::default(), 1)),
        cache_fingerprint: String::new(),
        request_transform: Some(Arc::new(transform)),
        response_transform: None,
        basic_auth: Some(hangang::basic_auth::prepare(&basic).unwrap()),
        route: rejected,
    };
    let mut snapshot = valid;
    snapshot.http = vec![Arc::new(runtime)];
    let active = Arc::new(ArcSwap::from_pointee(snapshot));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;
    let good = base64::engine::general_purpose::STANDARD.encode("alice:s3cret");
    let response = client()
        .request(
            Request::post(format!("http://{front}/"))
                .header("authorization", format!("Basic {good}"))
                .header("x-user", "mallory")
                .body(Full::new(Bytes::from_static(b"hello")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].headers.get_all("x-user").iter().count(), 1);
        assert_eq!(
            seen[0].headers["x-user"], "alice",
            "the transform must not replace the authenticated identity"
        );
        assert_eq!(seen[0].body, "hello");
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn global_response_removal_never_strips_protected_representation_headers() {
    // `--remove-response-headers content-encoding` would strip the encoding
    // while streaming the still-compressed bytes. Protected names are refused
    // by the CLI and ignored by the builder; ordinary names still apply.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = listener.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_: Request<Incoming>| async {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .header("server", "upstream/1.0")
                            .header("content-encoding", "gzip")
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(b"\x1f\x8b-not-really")))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    assert!(hangang::config::is_protected_response_header(
        "content-encoding"
    ));
    assert!(!hangang::config::is_protected_response_header("server"));
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
    let proxy = proxy.with_removed_response_headers(vec![
        "content-encoding".parse().unwrap(),
        "Content-Length".parse().unwrap(),
        "server".parse().unwrap(),
    ]);
    let (front, front_task, _) = frontend(proxy).await;
    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-encoding"],
        "gzip",
        "content-encoding must survive a global removal"
    );
    assert!(response.headers().contains_key("content-length"));
    assert!(!response.headers().contains_key("server"));
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        &b"\x1f\x8b-not-really"[..]
    );
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn malformed_host_cannot_shape_the_https_redirect() {
    // Routing falls back to the request-target authority when Host does not
    // parse, so `secure.test` is selected; the redirect must not then splice
    // the raw `Host: evil.test/#` into Location.
    let (backend, seen, backend_task) = upstream("secure").await;
    let mut r = route(vec![format!("http://{backend}")]);
    r.host = Some("secure.test".into());
    r.require_tls = true;
    let (proxy, policy) = proxy(vec![r]);
    let (front, front_task, _) = frontend(proxy).await;
    let (status, text) = raw_request(
        front,
        "GET http://secure.test/private HTTP/1.1\r\nHost: evil.test/#\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 400, "{text}");
    assert!(
        !text.to_ascii_lowercase().contains("location:"),
        "no redirect may be built from a malformed Host: {text}"
    );
    assert!(!text.contains("evil.test"));
    // A well-formed Host still redirects, with any port dropped.
    let (status, text) = raw_request(
        front,
        "GET /private HTTP/1.1\r\nHost: secure.test:8080\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert_eq!(status, 308, "{text}");
    assert!(
        text.contains("location: https://secure.test/private"),
        "{text}"
    );
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn duplicate_route_match_header_cannot_select_a_different_backend_view() {
    let (guarded_backend, guarded_seen, guarded_task) = upstream("guarded").await;
    let (fallback_backend, fallback_seen, fallback_task) = upstream("fallback").await;
    let mut guarded = route(vec![format!("http://{guarded_backend}")]);
    guarded.id = "guarded".into();
    guarded.headers.insert("x-scope".into(), "private".into());
    let mut fallback = route(vec![format!("http://{fallback_backend}")]);
    fallback.id = "fallback".into();
    let (proxy, policy) = proxy(vec![guarded, fallback]);
    let (front, front_task, _) = frontend(proxy).await;

    let response = client()
        .request(
            Request::builder()
                .uri(format!("http://{front}/"))
                .header("x-scope", "public")
                .header("x-scope", "private")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(guarded_seen.lock().unwrap().is_empty());
    assert!(fallback_seen.lock().unwrap().is_empty());

    for (scope, expected) in [("private", "guarded"), ("public", "fallback")] {
        let response = client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .header("x-scope", scope)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            expected
        );
    }

    front_task.abort();
    guarded_task.abort();
    fallback_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_route_rejects_ambiguous_duplicate_headers_but_plain_routes_forward_them() {
    // The policy API returns one value per name while the upstream receives
    // every field: `X-Scope: private` + `X-Scope: public` could satisfy a
    // policy on the last value while the upstream acts on the first.
    let (backend, seen, backend_task) = upstream("ok").await;
    let mut guarded = route(vec![format!("http://{backend}")]);
    guarded.id = "guarded".into();
    guarded.path_prefix = Some("/guarded".into());
    guarded.lua =
        Some("if hangang.header('x-scope') ~= 'public' then hangang.reject(403) end".into());
    let mut plain = route(vec![format!("http://{backend}")]);
    plain.id = "plain".into();
    plain.path_prefix = Some("/plain".into());
    let mut cookies = route(vec![format!("http://{backend}")]);
    cookies.id = "cookies".into();
    cookies.path_prefix = Some("/cookies".into());
    cookies.lua =
        Some("if hangang.header('cookie') ~= 'a=1; b=2' then hangang.reject(403) end".into());
    let config = Config {
        revision: 1,
        http: vec![guarded, plain, cookies],
        ..Config::default()
    };
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;
    let client = client();

    // Duplicate application header on a Lua route: refused before the policy runs.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/guarded"))
                .header("x-scope", "private")
                .header("x-scope", "public")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(seen.lock().unwrap().is_empty());

    // A single value still flows through the policy to the upstream.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/guarded"))
                .header("x-scope", "public")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 1);

    // The same duplicate request on a route without Lua is forwarded unchanged.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/plain"))
                .header("x-scope", "private")
                .header("x-scope", "public")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        let values: Vec<_> = seen[1].headers.get_all("x-scope").iter().collect();
        assert_eq!(values, ["private", "public"]);
    }

    // Repeated cookie fields (as HTTP/2 clients send them) are joined into the
    // single value the policy checked, and that same value reaches the upstream.
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front}/cookies"))
                .header("cookie", "a=1")
                .header("cookie", "b=2")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[2].headers.get_all("cookie").iter().count(), 1);
        assert_eq!(seen[2].headers["cookie"], "a=1; b=2");
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn http2_cookie_join_precedes_route_matching_and_external_auth() {
    let (backend, seen, backend_task) = upstream("app").await;
    let (auth, auth_seen, auth_task) = upstream("allowed").await;
    let mut configured = route(vec![format!("http://{backend}")]);
    configured
        .headers
        .insert("cookie".into(), "a=1; session=ok".into());
    configured.auth = Some(hangang::config::ExternalAuth {
        url: format!("http://{auth}/check"),
        request_headers: vec!["cookie".into()],
        response_headers: vec![],
        timeout_ms: 500,
        forward_response: false,
        terminal_response: false,
    });
    let (proxy, policy) = proxy(vec![configured]);
    let (front, front_task) = frontend_h2(proxy).await;
    let mut client = h2_client(front).await;
    let request = Request::builder()
        .uri(format!("http://{front}/account"))
        .header("cookie", "a=1")
        .header("cookie", "session=ok")
        .body(UnknownLengthBody(Default::default()))
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    for records in [&auth_seen, &seen] {
        let records = records.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].headers.get_all("cookie").iter().count(), 1);
        assert_eq!(records[0].headers["cookie"], "a=1; session=ok");
    }
    front_task.abort();
    backend_task.abort();
    auth_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn http2_split_cookies_are_joined_before_plain_http1_upstream() {
    let (backend, seen, backend_task) = upstream("ok").await;
    let (proxy, policy) = proxy(vec![route(vec![format!("http://{backend}")])]);
    let (front, front_task) = frontend_h2(proxy).await;
    let mut client = h2_client(front).await;
    let request = Request::builder()
        .uri(format!("http://{front}/wp-login.php"))
        .header("cookie", "wordpress_test_cookie=WP%20Cookie%20check")
        .header("cookie", "wordpress_logged_in=fake")
        .body(UnknownLengthBody(Default::default()))
        .unwrap();
    let response = client.send_request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    response.into_body().collect().await.unwrap();
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].headers.get_all("cookie").iter().count(), 1);
        assert_eq!(
            seen[0].headers["cookie"],
            "wordpress_test_cookie=WP%20Cookie%20check; wordpress_logged_in=fake"
        );
    }
    front_task.abort();
    backend_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn disabled_domain_group_never_selects_its_upstream_and_can_reactivate() {
    let (origin, _, origin_task) = upstream("enabled-again").await;
    for enabled in [false, true] {
        let mut group = route(vec![format!("http://{origin}")]);
        group.hosts = vec!["foo.example.test".into(), "www.foo.example.test".into()];
        group.enabled = enabled;
        let (proxy, policy) = proxy(vec![group]);
        let (front, front_task, _) = frontend(proxy).await;
        for host in ["foo.example.test", "www.foo.example.test"] {
            let response = client()
                .request(
                    Request::builder()
                        .uri(format!("http://{front}/"))
                        .header("host", host)
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), if enabled { 200 } else { 404 });
            let body = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(
                body,
                if enabled {
                    "enabled-again"
                } else {
                    "no matching route"
                }
            );
        }
        policy.shutdown().await;
        front_task.abort();
    }
    origin_task.abort();
}

#[tokio::test]
async fn lua_member_selection_is_route_scoped_and_survives_reorder() {
    let (first, first_seen, first_task) = upstream("first").await;
    let (second, second_seen, second_task) = upstream("second").await;
    let mut r = route(vec![format!("http://{first}"), format!("http://{second}")]);
    r.backends = r
        .backends
        .into_iter()
        .zip(["Blue", "green"])
        .map(|(backend, id)| {
            hangang::pool_member::Backend::Member(hangang::pool_member::PoolMember {
                id: id.into(),
                address: backend.address().to_owned(),
                weight: 1,
                desired_state: Default::default(),
            })
        })
        .collect();
    r.lua = Some("hangang.select_member('green')".into());
    let mut other = r.clone();
    other.id = "other-route".into();
    other.host = Some("other.example.test".into());
    other.backends = vec![hangang::pool_member::Backend::Member(
        hangang::pool_member::PoolMember {
            id: "green".into(),
            address: format!("http://{first}"),
            weight: 1,
            desired_state: Default::default(),
        },
    )];
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config {
            revision: 1,
            http: vec![other, r],
            ..Config::default()
        })
        .unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task, _) = frontend(proxy).await;
    let get = || async {
        client()
            .request(
                Request::builder()
                    .uri(format!("http://{front}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap()
    };
    for reversed in [false, true] {
        if reversed {
            let old = active.load_full();
            let mut config = old.config.clone();
            config.revision += 1;
            config.http[1].backends.reverse();
            active.store(Arc::new(Snapshot::replace(config, &old).unwrap()));
        }
        let response = get().await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "second"
        );
    }
    assert!(first_seen.lock().unwrap().is_empty());
    assert_eq!(second_seen.lock().unwrap().len(), 2);
    for (id, legacy) in [("missing", false), ("blue", false), ("green", true)] {
        let old = active.load_full();
        let mut config = old.config.clone();
        config.revision += 1;
        config.http[1].lua = Some(format!("hangang.select_member({id:?})"));
        if legacy {
            config.http[1].backends = config.http[1]
                .backends
                .iter()
                .map(|backend| backend.address().to_owned().into())
                .collect();
        }
        active.store(Arc::new(Snapshot::replace(config, &old).unwrap()));
        assert_eq!(get().await.status(), 503);
    }
    assert!(
        first_seen.lock().unwrap().is_empty(),
        "unknown member must never fall back"
    );
    assert_eq!(second_seen.lock().unwrap().len(), 2);
    front_task.abort();
    first_task.abort();
    second_task.abort();
    policy.shutdown().await;
}
