use arc_swap::ArcSwap;
use hangang::{
    admin::{Admin, Manager},
    certificates::CertificateFiles,
    config::{Config, Snapshot},
    config_store::FileConfigStore,
    metrics::Metrics,
    policy::PolicyPool,
    tcp::TcpManager,
};
use hyper::{Request, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};

const TOKEN: &str = "0123456789abcdef";
static NEXT_DOCKER_FIXTURE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

struct EventFixture {
    traffic: Arc<hangang::traffic::TrafficHistory>,
    limit: usize,
}

async fn server() -> (std::net::SocketAddr, Arc<Manager>, tempfile::TempDir) {
    server_with_source(false).await
}
async fn server_with_source(
    externally_managed: bool,
) -> (std::net::SocketAddr, Arc<Manager>, tempfile::TempDir) {
    server_with_limits(externally_managed, 64, Admin::PUBLIC_REQUEST_LIMIT).await
}
/// The fixture speaks HTTP/1 and prior-knowledge HTTP/2 like the real admin
/// listener, so tests can hold flow-controlled response bodies open.
async fn server_with_limits(
    externally_managed: bool,
    request_limit: usize,
    public_limit: usize,
) -> (std::net::SocketAddr, Arc<Manager>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");
    let config = Config::default();
    hangang::store::save(state_path.clone(), config.clone())
        .await
        .unwrap();
    let (address, manager) = server_on(
        state_path,
        config,
        None,
        externally_managed,
        request_limit,
        public_limit,
    )
    .await;
    (address, manager, dir)
}

/// One admin server whose manager starts from `config`; with a shared store
/// the instance behaves like a fleet member (unready until its first poll).
async fn server_on(
    state_path: std::path::PathBuf,
    config: Config,
    config_store: Option<Arc<dyn hangang::config_store::ConfigStore>>,
    externally_managed: bool,
    request_limit: usize,
    public_limit: usize,
) -> (std::net::SocketAddr, Arc<Manager>) {
    server_on_with_traffic(
        state_path,
        config,
        config_store,
        externally_managed,
        request_limit,
        public_limit,
        EventFixture {
            traffic: Arc::new(hangang::traffic::TrafficHistory::default()),
            limit: Admin::EVENT_STREAM_LIMIT,
        },
    )
    .await
}

async fn server_on_with_traffic(
    state_path: std::path::PathBuf,
    config: Config,
    config_store: Option<Arc<dyn hangang::config_store::ConfigStore>>,
    externally_managed: bool,
    request_limit: usize,
    public_limit: usize,
    event_fixture: EventFixture,
) -> (std::net::SocketAddr, Arc<Manager>) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        state_path.parent().unwrap(),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let shared = config_store.is_some();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let metrics = Arc::new(Metrics::default());
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path,
        config_store,
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(
            !externally_managed && !shared,
        )),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(None),
        store_health: Default::default(),
    });
    let admin = Arc::new(Admin {
        acme_status: None,
        file_tls_enabled: false,
        manager: manager.clone(),
        token: Arc::new(TOKEN.into()),
        traffic: event_fixture.traffic,
        users: Arc::new(
            hangang::admin_users::Store::open(
                manager.state_path.with_extension("admin-users.sqlite3"),
            )
            .unwrap(),
        ),
        docker: Some(Arc::new(
            hangang::docker_connections::DockerConnections::open(
                manager.state_path.with_extension(format!(
                    "docker-connection-{}.json",
                    NEXT_DOCKER_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                )),
                None,
            )
            .unwrap(),
        )),
        lifecycle: None,
        update_status_path: None,
        requests: Arc::new(tokio::sync::Semaphore::new(request_limit)),
        public_requests: Arc::new(tokio::sync::Semaphore::new(public_limit)),
        auth_requests: Arc::new(tokio::sync::Semaphore::new(Admin::AUTH_REQUEST_LIMIT)),
        events: Arc::new(tokio::sync::Semaphore::new(event_fixture.limit)),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let admin = admin.clone();
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |request: Request<Incoming>| {
                            let admin = admin.clone();
                            async move { admin.handle(request).await as Result<_, Infallible> }
                        }),
                    )
                    .await;
            });
        }
    });
    (address, manager)
}

async fn request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    revision: Option<u64>,
) -> (u16, hyper::HeaderMap, Vec<u8>) {
    request_with_token(address, method, path, body, revision, Some(TOKEN)).await
}

async fn request_with_token(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
    revision: Option<u64>,
    token: Option<&str>,
) -> (u16, hyper::HeaderMap, Vec<u8>) {
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder().method(method).uri(path);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    if let Some(revision) = revision {
        builder = builder.header("if-match", format!("\"{revision}\""));
    }
    let response = sender
        .send_request(
            builder
                .body(Full::new(Bytes::from(body.unwrap_or("").to_owned())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, bytes)
}

fn json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap()
}

async fn read_raw_response_headers(stream: &mut tokio::net::TcpStream) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut headers = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !headers.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            headers.push(byte[0]);
            assert!(headers.len() < 8192);
        }
    })
    .await
    .expect("administrator response headers stalled");
    headers
}

async fn admitted_user_mutation_waiting_for_body(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    let interim = read_raw_response_headers(&mut stream).await;
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "body was not polled after account authorization: {interim:?}"
    );
    stream
}

async fn finish_user_mutation(stream: &mut tokio::net::TcpStream, body: &str) -> u16 {
    use tokio::io::AsyncWriteExt;
    stream.write_all(body.as_bytes()).await.unwrap();
    let headers = read_raw_response_headers(stream).await;
    let line = String::from_utf8_lossy(&headers);
    line.lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

async fn account_admin_token(address: std::net::SocketAddr) -> String {
    let credentials = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(credentials),
            None
        )
        .await
        .0,
        201
    );
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(credentials),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    json(&body)["token"].as_str().unwrap().to_owned()
}

async fn admitted_config_mutation_waiting_for_body(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> tokio::net::TcpStream {
    use tokio::io::AsyncWriteExt;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let headers = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nIf-Match: \"0\"\r\nContent-Length: {}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    let interim = read_raw_response_headers(&mut stream).await;
    assert!(
        interim.starts_with(b"HTTP/1.1 100 Continue"),
        "configuration body was not polled: {interim:?}"
    );
    stream
}

async fn revoke_account_session(address: std::net::SocketAddr, token: &str) {
    assert_eq!(
        request_with_token(address, "POST", "/v1/auth/logout", None, None, Some(token))
            .await
            .0,
        204
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/auth/me", None, None, Some(token))
            .await
            .0,
        401
    );
}

async fn config_operation_records(address: std::net::SocketAddr) -> Vec<serde_json::Value> {
    let (status, _, body) = request(address, "GET", "/v1/config/operations", None, None).await;
    assert_eq!(status, 200);
    let page = json(&body);
    assert_eq!(page["scope"], "instance");
    page["records"].as_array().unwrap().clone()
}

struct HeldCasStore {
    inner: FileConfigStore,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl hangang::config_store::ConfigStore for HeldCasStore {
    async fn load_latest(
        &self,
    ) -> hangang::config_store::StoreResult<Option<hangang::config_store::Stored>> {
        hangang::config_store::ConfigStore::load_latest(&self.inner).await
    }

    async fn bootstrap(
        &self,
        initial: Config,
    ) -> hangang::config_store::StoreResult<hangang::config_store::Stored> {
        hangang::config_store::ConfigStore::bootstrap(&self.inner, initial).await
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        next: Config,
    ) -> hangang::config_store::StoreResult<hangang::config_store::CasResult> {
        self.entered.notify_one();
        self.release.notified().await;
        hangang::config_store::ConfigStore::compare_and_swap(&self.inner, epoch, expected, next)
            .await
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: std::time::Duration,
    ) -> hangang::config_store::StoreResult<()> {
        hangang::config_store::ConfigStore::publish_challenge(
            &self.inner,
            token,
            key_authorization,
            ttl,
        )
        .await
    }

    async fn lookup_challenge(
        &self,
        token: &str,
    ) -> hangang::config_store::StoreResult<Option<String>> {
        hangang::config_store::ConfigStore::lookup_challenge(&self.inner, token).await
    }

    async fn withdraw_challenge(&self, token: &str) -> hangang::config_store::StoreResult<()> {
        hangang::config_store::ConfigStore::withdraw_challenge(&self.inner, token).await
    }
}

async fn event_fixture(
    event_limit: usize,
) -> (
    std::net::SocketAddr,
    Arc<hangang::traffic::TrafficHistory>,
    tempfile::TempDir,
) {
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("state.json");
    let config = Config::default();
    hangang::store::save(state_path.clone(), config.clone())
        .await
        .unwrap();
    let traffic = Arc::new(hangang::traffic::TrafficHistory::default());
    let (address, _) = server_on_with_traffic(
        state_path,
        config,
        None,
        false,
        1,
        1,
        EventFixture {
            traffic: traffic.clone(),
            limit: event_limit,
        },
    )
    .await;
    (address, traffic, directory)
}

async fn next_event(response: &mut reqwest::Response, pending: &mut Vec<u8>) -> String {
    loop {
        if let Some(position) = pending.windows(2).position(|bytes| bytes == b"\n\n") {
            let frame: Vec<u8> = pending.drain(..position + 2).collect();
            return String::from_utf8(frame).unwrap();
        }
        let chunk = tokio::time::timeout(std::time::Duration::from_secs(3), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .expect("event stream closed before next event");
        pending.extend_from_slice(&chunk);
        assert!(pending.len() < 256 * 1024, "event frame exceeded bound");
    }
}

fn event_json(frame: &str) -> serde_json::Value {
    let data = frame
        .lines()
        .find_map(|line| line.strip_prefix("data: "))
        .unwrap();
    serde_json::from_str(data).unwrap()
}

#[tokio::test]
async fn events_and_recent_traffic_respect_roles_and_session_revocation() {
    use hangang::traffic::TrafficInput;
    let (address, traffic, _directory) = event_fixture(2).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let origin = format!("http://{address}");
    let root = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(root), None)
            .await
            .0,
        201
    );
    let (_, _, body) =
        request_with_token(address, "POST", "/v1/auth/login", Some(root), None, None).await;
    let admin_token = json(&body)["token"].as_str().unwrap().to_owned();
    let viewer = r#"{"username":"observer","password":"viewer password 123","role":"viewer"}"#;
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/users",
            Some(viewer),
            None,
            Some(&admin_token)
        )
        .await
        .0,
        201
    );
    let (_, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"observer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    let viewer_token = json(&body)["token"].as_str().unwrap().to_owned();
    traffic.record(TrafficInput {
        peer_ip: "192.0.2.10".parse().unwrap(),
        peer_port: 45678,
        client_ip: "198.51.100.20".parse().unwrap(),
        method: "GET",
        path: "/public?authorization=private",
        route_id: Some("public"),
        status: 200,
        response_head_ms: 3,
        protocol: "h1",
        tls: false,
    });
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/traffic",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        403
    );
    let (status, _, body) = request_with_token(
        address,
        "GET",
        "/v1/traffic?limit=1",
        None,
        None,
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, 200);
    let batch = json(&body);
    assert_eq!(batch["records"][0]["path"], "/public");
    assert_eq!(batch["records"][0]["client_ip"], "198.51.100.20");
    assert_eq!(batch["next_after"], 1);
    assert!(!String::from_utf8_lossy(&body).contains("private"));
    for path in [
        "/v1/traffic?after=nope",
        "/v1/traffic?limit=129",
        "/v1/traffic?token=secret",
    ] {
        assert_eq!(
            request_with_token(address, "GET", path, None, None, Some(&admin_token))
                .await
                .0,
            400
        );
    }

    let mut viewer_events = client
        .get(format!("{origin}/v1/events"))
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap();
    let mut admin_events = client
        .get(format!("{origin}/v1/events"))
        .bearer_auth(&admin_token)
        .send()
        .await
        .unwrap();
    assert_eq!(viewer_events.status(), 200);
    assert_eq!(admin_events.status(), 200);
    assert!(
        admin_events.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/event-stream")
    );
    assert_eq!(admin_events.headers()["cache-control"], "no-store");
    let mut viewer_pending = Vec::new();
    let mut admin_pending = Vec::new();
    let first_viewer = next_event(&mut viewer_events, &mut viewer_pending).await;
    let first_admin = next_event(&mut admin_events, &mut admin_pending).await;
    assert!(first_viewer.starts_with("event: status\n"));
    assert!(first_admin.starts_with("event: status\n"));
    assert_eq!(
        event_json(&first_viewer)["revision"],
        event_json(&first_admin)["revision"]
    );
    traffic.record(TrafficInput {
        peer_ip: "192.0.2.11".parse().unwrap(),
        peer_port: 45679,
        client_ip: "198.51.100.21".parse().unwrap(),
        method: "POST",
        path: "/new?token=private",
        route_id: Some("new"),
        status: 201,
        response_head_ms: 5,
        protocol: "h2",
        tls: true,
    });
    let next_admin = next_event(&mut admin_events, &mut admin_pending).await;
    assert!(next_admin.starts_with("event: status\n"));
    let traffic_event = next_event(&mut admin_events, &mut admin_pending).await;
    assert!(traffic_event.starts_with("event: traffic\n"));
    assert_eq!(event_json(&traffic_event)["records"][0]["path"], "/new");
    let next_viewer = next_event(&mut viewer_events, &mut viewer_pending).await;
    assert!(next_viewer.starts_with("event: status\n"));
    assert!(!next_viewer.contains("traffic"));

    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/logout",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        204
    );
    let mut expired = false;
    for _ in 0..3 {
        if next_event(&mut viewer_events, &mut viewer_pending)
            .await
            .starts_with("event: auth_expired\n")
        {
            expired = true;
            break;
        }
    }
    assert!(
        expired,
        "revoked viewer session must close its stream promptly"
    );
}

#[tokio::test]
async fn docker_connection_is_admin_only_revisioned_and_persistent() {
    let (address, manager, _dir) = server().await;
    let (status, headers, body) =
        request(address, "GET", "/v1/docker/connection", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("etag").unwrap(), "\"0\"");
    assert_eq!(json(&body)["source"], "disabled");
    let socket = manager.state_path.parent().unwrap().join("docker.sock");
    let candidate = serde_json::json!({"transport":"unix","socket_path":socket}).to_string();
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/docker/connection",
            Some(&candidate),
            None
        )
        .await
        .0,
        428
    );
    let (status, headers, body) = request(
        address,
        "PUT",
        "/v1/docker/connection",
        Some(&candidate),
        Some(0),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers.get("etag").unwrap(), "\"1\"");
    assert_eq!(json(&body)["source"], "managed");
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/docker/connection",
            Some(&candidate),
            Some(0)
        )
        .await
        .0,
        409
    );
    let (status, _, body) = request(
        address,
        "PUT",
        "/v1/docker/connection",
        Some(r#"{"transport":"disabled"}"#),
        Some(1),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["enabled"], false);
    let (_, _, persisted) = request(address, "GET", "/v1/docker/connection", None, None).await;
    assert_eq!(json(&persisted)["revision"], 2);
    assert_eq!(json(&persisted)["config"]["transport"], "disabled");
    let (status, _, body) =
        request(address, "DELETE", "/v1/docker/connection", None, Some(2)).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["revision"], 3);
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/docker/connection/test",
            Some(&candidate),
            None
        )
        .await
        .0,
        422
    );

    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(r#"{"username":"operator","password":"correct horse battery"}"#),
            None
        )
        .await
        .0,
        201
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/users",
            Some(r#"{"username":"viewer","password":"viewer password 123","role":"viewer"}"#),
            None
        )
        .await
        .0,
        201
    );
    let (_, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"viewer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    let viewer = json(&body)["token"].as_str().unwrap().to_owned();
    for (method, path, body, revision) in [
        ("GET", "/v1/docker/connection", None, None),
        (
            "PUT",
            "/v1/docker/connection",
            Some(candidate.as_str()),
            Some(3),
        ),
        ("DELETE", "/v1/docker/connection", None, Some(3)),
        (
            "POST",
            "/v1/docker/connection/test",
            Some(candidate.as_str()),
            None,
        ),
    ] {
        assert_eq!(
            request_with_token(address, method, path, body, revision, Some(&viewer))
                .await
                .0,
            403
        );
    }
}

#[tokio::test]
async fn certificate_inventory_is_admin_only_bounded_and_does_not_claim_unconfigured_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (address, manager) = server_on(
        dir.path().join("state.json"),
        Config::default(),
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    assert_eq!(
        request_with_token(address, "GET", "/v1/certificates", None, None, None)
            .await
            .0,
        401
    );
    let (status, _, body) = request(address, "GET", "/v1/certificates", None, None).await;
    assert_eq!(status, 200);
    let result = json(&body);
    assert_eq!(result["mode"], "other_or_none");
    assert_eq!(result["total"], 0);
    assert_eq!(result["certificates"].as_array().unwrap().len(), 0);
    assert!(result["server_time_unix_ms"].as_u64().unwrap() > 0);
    assert!(result["in_process_acme"].is_null());
    let pair = rcgen::generate_simple_self_signed(vec!["inventory.example.test".into()]).unwrap();
    let cert_file = dir.path().join("inventory.cert.pem");
    let key_file = dir.path().join("inventory.key.pem");
    std::fs::write(&cert_file, pair.cert.pem()).unwrap();
    std::fs::write(&key_file, pair.signing_key.serialize_pem()).unwrap();
    let mut config = Config::default();
    config.certificates.push(CertificateFiles {
        id: "inventory".into(),
        hosts: vec!["inventory.example.test".into()],
        default: false,
        enabled: true,
        cert_file,
        key_file,
        issuer_status_file: None,
    });
    manager.apply(config, 0).await.unwrap();
    let (status, _, body) = request(address, "GET", "/v1/certificates?limit=1", None, None).await;
    assert_eq!(status, 200);
    let result = json(&body);
    assert_eq!(result["total"], 1);
    assert_eq!(result["mode"], "configured_files");
    let certificate = &result["certificates"][0];
    assert_eq!(certificate["source"], "configured_file");
    assert_eq!(certificate["read_state"], "ok");
    assert_eq!(certificate["tls_binding"], "unknown");
    assert_eq!(certificate["san_dns"][0], "inventory.example.test");
    assert!(
        certificate["not_after_unix_ms"].as_u64().unwrap()
            > result["server_time_unix_ms"].as_u64().unwrap()
    );
    assert!(certificate["fingerprint_sha256"].as_str().unwrap().len() == 64);
    assert!(result.to_string().find("inventory.key.pem").is_none());
    let (_, _, body) = request(
        address,
        "GET",
        "/v1/certificates?offset=1&limit=1",
        None,
        None,
    )
    .await;
    assert!(json(&body)["certificates"].as_array().unwrap().is_empty());
    for path in [
        "/v1/certificates?limit=65",
        "/v1/certificates?offset=-1",
        "/v1/certificates?limit=1&limit=2",
        "/v1/certificates?token=secret",
    ] {
        assert_eq!(request(address, "GET", path, None, None).await.0, 400);
    }
    assert_eq!(
        request(address, "POST", "/v1/certificates", None, None)
            .await
            .0,
        405
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(r#"{"username":"operator","password":"correct horse battery"}"#),
            None,
        )
        .await
        .0,
        201
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/users",
            Some(r#"{"username":"viewer","password":"viewer password 123","role":"viewer"}"#),
            None,
        )
        .await
        .0,
        201
    );
    let (_, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"viewer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    let viewer = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/certificates",
            None,
            None,
            Some(&viewer)
        )
        .await
        .0,
        403
    );
}

#[tokio::test]
async fn operations_are_admin_only_paginated_and_reflect_backend_state() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "http": [{
            "id": "api", "hosts": ["example.test", "www.example.test"],
            "backends": ["http://127.0.0.1:9001", "http://127.0.0.1:9002"],
            "balance": {
                "mode": "least_connections", "weights": [2, 1],
                "active_health": {
                    "path": "/health", "interval_ms": 1000, "timeout_ms": 500,
                    "initial_state": "checking",
                    "healthy_statuses": [200], "unhealthy_statuses": [503],
                    "healthy_successes": 1, "unhealthy_http_failures": 1,
                    "unhealthy_tcp_failures": 1, "unhealthy_timeouts": 1
                }
            }
        }],
        "tcp": [{"id": "socket", "listen": "127.0.0.1:18099", "backends": ["127.0.0.1:9010"]}]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (address, manager) = server_on(
        dir.path().join("state.json"),
        config,
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let account = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(account), None)
            .await
            .0,
        201
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/users",
            Some(r#"{"username":"viewer","password":"viewer password 123","role":"viewer"}"#),
            None
        )
        .await
        .0,
        201
    );
    let (_, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"viewer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    let viewer = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(address, "GET", "/v1/operations", None, None, Some(&viewer))
            .await
            .0,
        403
    );
    assert_eq!(
        request(address, "GET", "/v1/operations", None, None)
            .await
            .0,
        200
    );
    let (status, _, body) = request(
        address,
        "GET",
        "/v1/operations?offset=1&limit=1",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let result = json(&body);
    assert_eq!(result["total"], 3);
    assert_eq!(result["offset"], 1);
    assert_eq!(result["limit"], 1);
    assert_eq!(result["rows"].as_array().unwrap().len(), 1);
    assert_eq!(result["rows"][0]["address"], "http://127.0.0.1:9002");
    assert_eq!(
        result["rows"][0]["match_host"],
        "group:example.test, www.example.test"
    );
    assert_eq!(result["rows"][0]["weight"], 1);
    assert_eq!(result["rows"][0]["health_mode"], "active");
    assert_eq!(result["rows"][0]["probe_observed"], false);
    assert_eq!(result["rows"][0]["initial_check_pending"], true);
    assert_eq!(result["rows"][0]["available"], false);
    assert_eq!(result["rows"][0]["active_requests"], 0);
    assert_eq!(result["capabilities"]["configuration_source"], "file");
    assert_eq!(result["capabilities"]["signed_updates_enabled"], false);

    let balancer = manager.active.load().http[0].balancer.clone();
    balancer.record_active_status(1, 503);
    let (_, _, body) = request(
        address,
        "GET",
        "/v1/operations?offset=1&limit=1",
        None,
        None,
    )
    .await;
    let row = &json(&body)["rows"][0];
    assert_eq!(row["probe_observed"], true);
    assert_eq!(row["initial_check_pending"], true);
    assert_eq!(row["available"], false);
    balancer.record_active_status(1, 200);
    let (_, _, body) = request(
        address,
        "GET",
        "/v1/operations?offset=1&limit=1",
        None,
        None,
    )
    .await;
    assert_eq!(json(&body)["rows"][0]["available"], true);
    assert_eq!(json(&body)["rows"][0]["initial_check_pending"], false);
    let (_, _, body) = request(
        address,
        "GET",
        "/v1/operations?offset=2&limit=1",
        None,
        None,
    )
    .await;
    let tcp = &json(&body)["rows"][0];
    assert_eq!(tcp["protocol"], "tcp");
    assert_eq!(tcp["listen"], "127.0.0.1:18099");
    assert!(tcp["active_requests"].is_null());
    assert_eq!(
        tcp.get("member_active_streams"),
        Some(&serde_json::Value::Null)
    );
    assert!(tcp["initial_check_pending"].is_null());
    assert_eq!(tcp["route_active_connections"], 0);
    for path in [
        "/v1/operations?limit=129",
        "/v1/operations?offset=-1",
        "/v1/operations?offset=0&offset=1",
        "/v1/operations?token=secret",
    ] {
        assert_eq!(request(address, "GET", path, None, None).await.0, 400);
    }
}

#[tokio::test]
async fn event_stream_admission_is_bounded_and_does_not_pin_ordinary_admin_capacity() {
    let (address, _traffic, _directory) = event_fixture(1).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let origin = format!("http://{address}");
    assert_eq!(
        client
            .get(format!("{origin}/v1/events"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        request(address, "GET", "/v1/events?token=secret", None, None)
            .await
            .0,
        400
    );
    let mut first = client
        .get(format!("{origin}/v1/events"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    assert!(
        next_event(&mut first, &mut Vec::new())
            .await
            .starts_with("event: status\n")
    );
    assert_eq!(
        client
            .get(format!("{origin}/v1/events"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    assert_eq!(
        request(address, "GET", "/v1/status", None, None).await.0,
        200
    );
    drop(first);
    let reopened = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let response = client
                .get(format!("{origin}/v1/events"))
                .bearer_auth(TOKEN)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                break response;
            }
            assert_eq!(response.status(), 503);
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(reopened.status(), 200);
}

#[tokio::test]
async fn first_run_bootstrap_login_role_limits_and_logout() {
    let (address, _manager, _directory) = server().await;
    let (status, _, body) =
        request_with_token(address, "GET", "/v1/auth/setup", None, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["bootstrap_required"], true);
    let root = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(root),
            None,
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(root),
            None,
            Some("wrong")
        )
        .await
        .0,
        401
    );
    let (status, _, body) = request(address, "POST", "/v1/auth/bootstrap", Some(root), None).await;
    assert_eq!(status, 201);
    assert_eq!(json(&body)["user"]["role"], "admin");
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(root), None)
            .await
            .0,
        409
    );
    let (status, _, body) =
        request_with_token(address, "GET", "/v1/auth/setup", None, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["bootstrap_required"], false);
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"operator","password":"incorrect"}"#),
            None,
            None
        )
        .await
        .0,
        401
    );
    let (status, headers, body) =
        request_with_token(address, "POST", "/v1/auth/login", Some(root), None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let token = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(token.len(), 43);
    let (status, _, body) =
        request_with_token(address, "GET", "/v1/auth/me", None, None, Some(&token)).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["user"]["username"], "operator");
    let viewer = r#"{"username":"observer","password":"viewer password 123","role":"viewer"}"#;
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/users",
        Some(viewer),
        None,
        Some(&token),
    )
    .await;
    assert_eq!(status, 201);
    let viewer_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"observer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let viewer_token = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/status",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        200
    );
    for (method, path) in [
        ("GET", "/v1/config"),
        ("GET", "/v1/config/operation-proof"),
        (
            "GET",
            "/v1/config/commit-receipt?authority_id=11111111111111111111111111111111&operation_id=22222222222222222222222222222222",
        ),
        ("GET", "/v1/routes/http"),
        ("GET", "/v1/users"),
        ("POST", "/v1/cache/purge"),
    ] {
        assert_eq!(
            request_with_token(address, method, path, None, None, Some(&viewer_token))
                .await
                .0,
            403,
            "{path}"
        );
    }
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/logout",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        204
    );
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/status",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request_with_token(
            address,
            "PUT",
            &format!("/v1/users/{viewer_id}"),
            Some(r#"{"enabled":false}"#),
            None,
            Some(&token)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/users", None, None, Some(&token))
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn login_admission_is_independent_of_public_asset_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config::default();
    let state_path = directory.path().join("state.json");
    hangang::store::save(state_path.clone(), config.clone())
        .await
        .unwrap();
    let (address, _manager) = server_on(state_path, config, None, false, 64, 0).await;
    assert_eq!(
        request_with_token(address, "GET", "/ui/", None, None, None)
            .await
            .0,
        503
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/auth/setup", None, None, None)
            .await
            .0,
        200
    );
    let body = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(body), None)
            .await
            .0,
        201
    );
    assert_eq!(
        request_with_token(address, "POST", "/v1/auth/login", Some(body), None, None)
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn last_admin_and_password_change_are_enforced_through_api() {
    let (address, _manager, _directory) = server().await;
    let root = r#"{"username":"firstadmin","password":"correct horse battery"}"#;
    let (status, _, body) = request(address, "POST", "/v1/auth/bootstrap", Some(root), None).await;
    assert_eq!(status, 201);
    let id = json(&body)["user"]["id"].as_i64().unwrap();
    assert_eq!(
        request(address, "DELETE", &format!("/v1/users/{id}"), None, None)
            .await
            .0,
        409
    );
    assert_eq!(
        request(
            address,
            "PUT",
            &format!("/v1/users/{id}"),
            Some(r#"{"role":"viewer"}"#),
            None
        )
        .await
        .0,
        409
    );
    let (status, _, body) =
        request_with_token(address, "POST", "/v1/auth/login", Some(root), None, None).await;
    assert_eq!(status, 200);
    let token = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request(
            address,
            "PUT",
            &format!("/v1/users/{id}"),
            Some(r#"{"password":"new secure password"}"#),
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/auth/me", None, None, Some(&token))
            .await
            .0,
        401
    );
    assert_eq!(
        request_with_token(address, "POST", "/v1/auth/login", Some(root), None, None)
            .await
            .0,
        401
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"firstadmin","password":"new secure password"}"#),
            None,
            None
        )
        .await
        .0,
        200
    );
}

#[tokio::test]
async fn revoked_account_cannot_finish_user_creation_after_body_admission() {
    let (address, _manager, _directory) = server().await;
    let credentials = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(credentials),
            None
        )
        .await
        .0,
        201
    );
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(credentials),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let token = json(&body)["token"].as_str().unwrap().to_owned();
    let create = r#"{"username":"lateviewer","password":"viewer password 123","role":"viewer"}"#;
    let mut pending =
        admitted_user_mutation_waiting_for_body(address, "POST", "/v1/users", &token, create).await;
    // The 100 Continue response is a protocol barrier: read_json has polled
    // the body, which occurs only after handle_inner authenticated the actor.
    assert_eq!(
        request_with_token(address, "POST", "/v1/auth/logout", None, None, Some(&token))
            .await
            .0,
        204
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/auth/me", None, None, Some(&token))
            .await
            .0,
        401
    );
    assert_eq!(finish_user_mutation(&mut pending, create).await, 403);
    let (status, _, body) = request(address, "GET", "/v1/users", None, None).await;
    assert_eq!(status, 200);
    assert!(
        json(&body)["users"]
            .as_array()
            .unwrap()
            .iter()
            .all(|user| user["username"] != "lateviewer"),
        "revoked account created a user after its session was removed"
    );
}

#[tokio::test]
async fn demoted_account_cannot_finish_password_update_after_body_admission() {
    let (address, _manager, _directory) = server().await;
    let credentials = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(credentials),
            None
        )
        .await
        .0,
        201
    );
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/users",
        Some(r#"{"username":"secondadmin","password":"second password 123","role":"admin"}"#),
        None,
    )
    .await;
    assert_eq!(status, 201);
    let actor_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/users",
        Some(r#"{"username":"targetviewer","password":"viewer password 123","role":"viewer"}"#),
        None,
    )
    .await;
    assert_eq!(status, 201);
    let target_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"secondadmin","password":"second password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let actor_token = json(&body)["token"].as_str().unwrap().to_owned();
    let update = r#"{"password":"replacement password 123"}"#;
    let mut pending = admitted_user_mutation_waiting_for_body(
        address,
        "PUT",
        &format!("/v1/users/{target_id}"),
        &actor_token,
        update,
    )
    .await;
    assert_eq!(
        request(
            address,
            "PUT",
            &format!("/v1/users/{actor_id}"),
            Some(r#"{"role":"viewer"}"#),
            None,
        )
        .await
        .0,
        200
    );
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/auth/me",
            None,
            None,
            Some(&actor_token),
        )
        .await
        .0,
        401
    );
    assert_eq!(finish_user_mutation(&mut pending, update).await, 403);
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"targetviewer","password":"replacement password 123"}"#),
            None,
            None,
        )
        .await
        .0,
        401,
        "a demoted actor changed another user's password"
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"targetviewer","password":"viewer password 123"}"#),
            None,
            None,
        )
        .await
        .0,
        200
    );
}

#[tokio::test]
async fn status_and_openapi_have_stable_contracts() {
    let (address, manager, _dir) = server().await;
    manager
        .metrics
        .requests
        .store(7, std::sync::atomic::Ordering::Relaxed);
    manager
        .metrics
        .policy_errors
        .store(3, std::sync::atomic::Ordering::Relaxed);
    manager
        .metrics
        .policy_capacity_rejections
        .store(2, std::sync::atomic::Ordering::Relaxed);
    let (status, _, body) = request(address, "GET", "/v1/status", None, None).await;
    assert_eq!(status, 200);
    let value = json(&body);
    assert_eq!(value["revision"], 0);
    assert_eq!(value["http_routes"], 0);
    assert_eq!(value["metrics"]["requests_total"], 7);
    assert_eq!(value["metrics"]["rejected_requests_total"], 0);
    assert_eq!(value["metrics"]["policy_errors_total"], 3);
    assert_eq!(value["metrics"]["policy_capacity_rejections_total"], 2);
    let (status, _, body) = request(address, "GET", "/metrics", None, None).await;
    assert_eq!(status, 200);
    let metrics_text = String::from_utf8(body).unwrap();
    assert!(metrics_text.contains("hangang_policy_errors_total 3\n"));
    assert!(metrics_text.contains("hangang_policy_capacity_rejections_total 2\n"));
    assert_eq!(value["state"]["supervised"], false);
    assert!(value["process_id"].is_u64());
    assert_eq!(value["version"], env!("CARGO_PKG_VERSION"));
    assert!(value["uptime_seconds"].is_u64());
    let (status, _, body) =
        request_with_token(address, "GET", "/openapi.json", None, None, None).await;
    assert_eq!(status, 200);
    let spec = json(&body);
    assert_eq!(spec["openapi"], "3.1.0");
    for (path, method, status) in [
        ("/v1/users", "post", "201"),
        ("/v1/users/{id}", "put", "200"),
    ] {
        assert_eq!(
            spec["paths"][path][method]["responses"][status]["content"]["application/json"]["schema"]
                ["$ref"],
            "#/components/schemas/AuthUserResponse",
            "{method} {path} must document the actual {{user: ...}} envelope"
        );
    }
    let (status, headers, body) =
        request_with_token(address, "GET", "/v1/status", None, None, None).await;
    assert_eq!(status, 401);
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(json(&body)["title"], "Unauthorized");
}

#[tokio::test]
async fn validates_without_committing_and_rejects_unknown_fields() {
    let (address, manager, _dir) = server().await;
    let valid =
        r#"{"revision":99,"http":[{"id":"test","backends":["http://127.0.0.1:9"]}],"tcp":[]}"#;
    assert_eq!(
        request(address, "POST", "/v1/config/validate", Some(valid), None)
            .await
            .0,
        200
    );
    assert_eq!(manager.active.load().config.revision, 0);
    let invalid = r#"{"revision":0,"http":[],"tcp":[],"surprise":true}"#;
    let (status, headers, body) =
        request(address, "POST", "/v1/config/validate", Some(invalid), None).await;
    assert_eq!(status, 400);
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(json(&body)["status"], 400);
}

#[tokio::test]
async fn http_route_crud_enforces_revisions_and_not_found() {
    let (address, manager, _dir) = server().await;
    let route = r#"{"id":"web","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let unknown = r#"{"id":"bad","backends":["http://127.0.0.1:9"],"unknown":true}"#;
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(unknown), Some(0))
            .await
            .0,
        400
    );
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(route), None)
            .await
            .0,
        428
    );
    let (status, headers, body) =
        request(address, "POST", "/v1/routes/http", Some(route), Some(0)).await;
    assert_eq!(status, 201);
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(json(&body)["id"], "web");
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(route), Some(0))
            .await
            .0,
        409
    );
    assert_eq!(
        request(address, "GET", "/v1/routes/http/missing", None, None)
            .await
            .0,
        404
    );
    let changed = r#"{"id":"web","host":"example.test","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/web",
            Some(changed),
            Some(1)
        )
        .await
        .0,
        200
    );
    assert_eq!(
        manager.active.load().config.http[0].host.as_deref(),
        Some("example.test")
    );
    assert_eq!(
        request(address, "DELETE", "/v1/routes/http/web", None, Some(2))
            .await
            .0,
        204
    );
    assert_eq!(
        request(address, "GET", "/v1/routes/http/web", None, None)
            .await
            .0,
        404
    );
}

#[tokio::test]
async fn revoked_account_cannot_publish_route_after_body_admission() {
    let (address, manager, _directory) = server().await;
    let token = account_admin_token(address).await;
    let body = r#"{"id":"late-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let mut pending =
        admitted_config_mutation_waiting_for_body(address, "POST", "/v1/routes/http", &token, body)
            .await;
    revoke_account_session(address, &token).await;
    assert_eq!(finish_user_mutation(&mut pending, body).await, 403);
    assert_eq!(manager.active.load().config.revision, 0);
    assert!(manager.active.load().config.http.is_empty());
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 0);
    assert!(persisted.http.is_empty());
    assert!(config_operation_records(address).await.is_empty());

    // Static break-glass authority remains a valid, explicit system writer.
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(body), Some(0))
            .await
            .0,
        201
    );
    assert_eq!(manager.active.load().config.revision, 1);
    let operations = config_operation_records(address).await;
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["actor_kind"], "system");
    assert_eq!(operations[0]["state"], "candidate_activated");
}

#[tokio::test]
async fn revoked_account_cannot_publish_whole_config_after_body_admission() {
    let (address, manager, _directory) = server().await;
    let token = account_admin_token(address).await;
    let body = serde_json::to_string(&Config::default()).unwrap();
    let mut pending =
        admitted_config_mutation_waiting_for_body(address, "PUT", "/v1/config", &token, &body)
            .await;
    revoke_account_session(address, &token).await;
    assert_eq!(finish_user_mutation(&mut pending, &body).await, 403);
    assert_eq!(manager.active.load().config.revision, 0);
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 0);
    assert!(config_operation_records(address).await.is_empty());
}

#[tokio::test]
async fn revoked_account_cannot_publish_after_writer_queue_wait() {
    let (address, manager, _directory) = server().await;
    let token = account_admin_token(address).await;
    let body = r#"{"id":"queued-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let writer = manager.writes.lock().await;
    let request = tokio::spawn({
        let token = token.clone();
        async move {
            request_with_token(
                address,
                "POST",
                "/v1/routes/http",
                Some(body),
                Some(0),
                Some(&token),
            )
            .await
            .0
        }
    });
    // Acquiring the detached transaction permit proves the request has passed
    // header/body admission and is queued on the held configuration writer.
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while manager.transactions.available_permits() == 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("configuration mutation did not reach writer queue");
    revoke_account_session(address, &token).await;
    drop(writer);
    assert_eq!(request.await.unwrap(), 403);
    assert_eq!(manager.active.load().config.revision, 0);
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 0);
    assert!(persisted.http.is_empty());
    assert!(config_operation_records(address).await.is_empty());
}

#[tokio::test]
async fn accepted_configuration_intent_can_finish_after_session_logout() {
    use hangang::config_store::ConfigStore;

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("shared.json");
    let initial = Config::default();
    let inner = FileConfigStore::new(state_path.clone());
    inner.bootstrap(initial.clone()).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(HeldCasStore {
        inner,
        entered: entered.clone(),
        release: release.clone(),
    });
    let (address, manager) = server_on(state_path, initial, Some(store), false, 64, 16).await;
    manager.reload_file().await.unwrap();
    let token = account_admin_token(address).await;
    let body = r#"{"id":"accepted-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let mutation = tokio::spawn({
        let token = token.clone();
        async move {
            request_with_token(
                address,
                "POST",
                "/v1/routes/http",
                Some(body),
                Some(0),
                Some(&token),
            )
            .await
            .0
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
        .await
        .expect("accepted mutation did not reach configuration CAS");
    let accepted = config_operation_records(address).await;
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0]["actor_kind"], "account");
    assert_eq!(accepted[0]["state"], "accepted");
    revoke_account_session(address, &token).await;
    release.notify_one();
    assert_eq!(mutation.await.unwrap(), 201);
    assert_eq!(manager.active.load().config.revision, 1);
    let completed = config_operation_records(address).await;
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0]["operation_id"], accepted[0]["operation_id"]);
    assert_eq!(completed[0]["state"], "candidate_activated");
}

#[tokio::test]
async fn failed_intent_insert_prevents_configuration_persistence() {
    let (address, manager, _directory) = server().await;
    let db = manager.state_path.with_extension("admin-users.sqlite3");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_config_accept BEFORE INSERT ON admin_config_operations \
             BEGIN SELECT RAISE(ABORT, 'fixture rejects acceptance'); END;",
        )
        .unwrap();
    let body = r#"{"id":"blocked-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(body), Some(0))
            .await
            .0,
        503
    );
    assert_eq!(manager.active.load().config.revision, 0);
    assert!(manager.active.load().config.http.is_empty());
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 0);
    assert!(persisted.http.is_empty());
    assert!(config_operation_records(address).await.is_empty());
}

#[tokio::test]
async fn failed_intent_completion_reports_unknown_outcome_without_erasing_acceptance() {
    let (address, manager, _directory) = server().await;
    let db = manager.state_path.with_extension("admin-users.sqlite3");
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER reject_config_finish BEFORE UPDATE ON admin_config_operations \
             WHEN NEW.state!='accepted' \
             BEGIN SELECT RAISE(ABORT, 'fixture rejects completion'); END;",
        )
        .unwrap();
    let body = r#"{"id":"applied-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(body), Some(0))
            .await
            .0,
        503
    );
    assert_eq!(manager.active.load().config.revision, 1);
    assert!(
        manager
            .active
            .load()
            .config
            .http
            .iter()
            .any(|route| route.id == "applied-route")
    );
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 1);
    let operations = config_operation_records(address).await;
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["state"], "accepted");
}

#[tokio::test]
async fn config_operation_history_is_admin_only_strict_paginated_and_redacted() {
    let (address, _manager, _directory) = server().await;
    let credentials = r#"{"username":"historyoperator","password":"history secure password 123"}"#;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/auth/bootstrap",
            Some(credentials),
            None
        )
        .await
        .0,
        201
    );
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(credentials),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let admin_token = json(&body)["token"].as_str().unwrap().to_owned();
    let account_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/users",
        Some(r#"{"username":"historyviewer","password":"viewer secure password 123","role":"viewer"}"#),
        None,
    )
    .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"historyviewer","password":"viewer secure password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let viewer_token = json(&body)["token"].as_str().unwrap().to_owned();

    let path = "/v1/config/operations?after=0&limit=1";
    let (status, headers, body) = request_with_token(address, "GET", path, None, None, None).await;
    assert_eq!(status, 401);
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["status"], 401);
    let (status, headers, body) =
        request_with_token(address, "GET", path, None, None, Some(&viewer_token)).await;
    assert_eq!(status, 403);
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["status"], 403);

    let first_route =
        r#"{"id":"history-first","path_prefix":"/first","backends":["http://127.0.0.1:9"]}"#;
    let second_route =
        r#"{"id":"history-second","path_prefix":"/second","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/routes/http",
            Some(first_route),
            Some(0),
            Some(&admin_token),
        )
        .await
        .0,
        201
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/routes/http",
            Some(second_route),
            Some(1),
        )
        .await
        .0,
        201
    );

    let (status, headers, body) =
        request_with_token(address, "GET", path, None, None, Some(&admin_token)).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(headers["content-type"], "application/json");
    let page = json(&body);
    assert_eq!(page["scope"], "instance");
    assert_eq!(
        page["coverage"],
        serde_json::json!(["acceptance", "local_outcome"])
    );
    assert_eq!(page["records"].as_array().unwrap().len(), 1);
    assert_eq!(page["records"][0]["id"], 1);
    assert_eq!(page["records"][0]["actor_kind"], "account");
    assert_eq!(page["records"][0]["actor_user_id"], account_id);
    assert_eq!(page["records"][0]["expected_revision"], 0);
    assert_eq!(page["records"][0]["state"], "candidate_activated");
    assert_eq!(page["oldest_id"], 1);
    assert_eq!(page["latest_id"], 2);
    assert_eq!(page["stored_records"], 2);
    assert_eq!(page["capacity"], 10_000);
    assert_eq!(page["next_after"], 1);
    assert_eq!(page["has_more"], true);
    assert_eq!(page["writes_available"], true);
    let authority_id = page["authority_id"].clone();
    assert!(authority_id.as_str().is_some_and(|id| id.len() == 32));
    let serialized = String::from_utf8(body).unwrap();
    for sensitive in [
        "historyoperator",
        "historyviewer",
        "history secure password 123",
        "viewer secure password 123",
        admin_token.as_str(),
        viewer_token.as_str(),
    ] {
        assert!(
            !serialized.contains(sensitive),
            "operation history exposed private data"
        );
    }

    let (status, _, body) = request_with_token(
        address,
        "GET",
        "/v1/config/operations?after=1&limit=1",
        None,
        None,
        Some(&admin_token),
    )
    .await;
    assert_eq!(status, 200);
    let second = json(&body);
    assert_eq!(second["authority_id"], authority_id);
    assert_eq!(second["records"].as_array().unwrap().len(), 1);
    assert_eq!(second["records"][0]["id"], 2);
    assert_eq!(second["records"][0]["actor_kind"], "system");
    assert!(second["records"][0]["actor_user_id"].is_null());
    assert_eq!(second["records"][0]["expected_revision"], 1);
    assert_eq!(second["next_after"], 2);
    assert_eq!(second["has_more"], false);

    for query in [
        "after=-1",
        "after=9007199254740992",
        "after=0&after=1",
        "limit=0",
        "limit=101",
        "limit=1&limit=2",
        "unknown=1",
    ] {
        let (status, headers, body) = request_with_token(
            address,
            "GET",
            &format!("/v1/config/operations?{query}"),
            None,
            None,
            Some(&admin_token),
        )
        .await;
        assert_eq!(status, 400, "query {query}");
        assert_eq!(headers["content-type"], "application/problem+json");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(json(&body)["status"], 400);
    }
}

async fn post_named_route(address: std::net::SocketAddr, id: &str, revision: u64) -> u16 {
    let body =
        format!(r#"{{"id":"{id}","path_prefix":"/{id}","backends":["http://127.0.0.1:9"]}}"#);
    request(
        address,
        "POST",
        "/v1/routes/http",
        Some(&body),
        Some(revision),
    )
    .await
    .0
}

async fn config_operation_page(address: std::net::SocketAddr) -> serde_json::Value {
    let (status, headers, body) = request(
        address,
        "GET",
        "/v1/config/operations?after=0&limit=100",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    json(&body)
}

fn config_prune_body(page: &serde_json::Value, through_id: i64) -> String {
    serde_json::json!({
        "through_id": through_id,
        "expected_latest_id": page["latest_id"],
        "expected_history_revision": page["history_revision"],
    })
    .to_string()
}

#[tokio::test]
async fn config_operation_prune_keeps_unresolved_records_and_never_reuses_ids() {
    let (address, manager, _directory) = server().await;
    assert_eq!(post_named_route(address, "retention-one", 0).await, 201);

    // A failed terminal journal write leaves a real Accepted operation even
    // though the separately stored configuration was activated.
    let db = manager.state_path.with_extension("admin-users.sqlite3");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_finish_for_retention BEFORE UPDATE ON admin_config_operations \
             WHEN NEW.state!='accepted' BEGIN SELECT RAISE(ABORT, 'fixture completion failure'); END;",
        )
        .unwrap();
    assert_eq!(post_named_route(address, "retention-two", 1).await, 503);
    connection
        .execute_batch("DROP TRIGGER reject_finish_for_retention")
        .unwrap();

    // A failed local persistence attempt is conservatively Indeterminate.
    let backup = manager.state_path.with_extension("saved-state.json");
    std::fs::rename(&manager.state_path, &backup).unwrap();
    std::fs::create_dir(&manager.state_path).unwrap();
    let failed_status = post_named_route(address, "retention-three", 2).await;
    std::fs::remove_dir(&manager.state_path).unwrap();
    std::fs::rename(&backup, &manager.state_path).unwrap();
    assert_ne!(failed_status, 201);
    assert_eq!(manager.active.load().config.revision, 2);
    assert_eq!(post_named_route(address, "retention-four", 2).await, 201);
    assert_eq!(post_named_route(address, "retention-five", 3).await, 201);

    let before = config_operation_page(address).await;
    assert_eq!(before["records"].as_array().unwrap().len(), 5);
    assert_eq!(before["records"][0]["state"], "candidate_activated");
    assert_eq!(before["records"][1]["state"], "accepted");
    assert_eq!(before["records"][2]["state"], "indeterminate");
    assert_eq!(before["records"][3]["state"], "candidate_activated");
    assert_eq!(before["records"][4]["state"], "candidate_activated");
    assert_eq!(before["latest_id"], 5);
    assert_eq!(before["pruned_through"], 0);
    assert_eq!(before["truncated"], false);

    let stale = config_prune_body(&before, 5);
    let operation_id = before["records"][1]["operation_id"].as_str().unwrap();
    let reopened = hangang::admin_users::Store::open(db).unwrap();
    reopened
        .finish_config(
            operation_id,
            hangang::admin_users::ConfigOperationState::Indeterminate,
        )
        .await
        .unwrap();
    let changed = config_operation_page(address).await;
    assert_eq!(changed["latest_id"], before["latest_id"]);
    assert!(
        changed["history_revision"].as_u64().unwrap()
            > before["history_revision"].as_u64().unwrap()
    );
    let (status, headers, body) = request(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&stale),
        None,
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["status"], 409);
    let after_stale = config_operation_page(address).await;
    assert_eq!(after_stale["history_revision"], changed["history_revision"]);
    assert_eq!(after_stale["stored_records"], 5);

    let valid = config_prune_body(&changed, 5);
    let (status, headers, body) = request(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&valid),
        None,
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["cache-control"], "no-store");
    let pruned = json(&body);
    assert_eq!(pruned["pruned_records"], 3);
    assert_eq!(pruned["retained_unresolved"], 2);
    assert_eq!(pruned["record"]["action"], "config_operations_prune");
    assert_eq!(pruned["record"]["actor_kind"], "system");
    assert_eq!(pruned["record"]["affected_count"], 3);
    assert_eq!(pruned["record"]["through_id"], 5);
    assert!(
        pruned["record"]["through_id"].as_i64().unwrap() > pruned["record"]["id"].as_i64().unwrap(),
        "cross-journal boundary may exceed account audit sequence"
    );
    let after = config_operation_page(address).await;
    assert_eq!(after["records"].as_array().unwrap().len(), 2);
    assert_eq!(after["records"][0]["id"], 2);
    assert_eq!(after["records"][1]["id"], 3);
    assert_eq!(after["records"][0]["state"], "indeterminate");
    assert_eq!(after["records"][1]["state"], "indeterminate");
    assert_eq!(after["stored_records"], 2);
    assert_eq!(after["oldest_id"], 2);
    assert_eq!(after["latest_id"], 5);
    assert_eq!(after["pruned_through"], 5);
    assert_eq!(after["truncated"], true);
    assert!(
        after["history_revision"].as_u64().unwrap() > changed["history_revision"].as_u64().unwrap()
    );
    let (_, _, audit_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    let audit = json(&audit_body);
    assert!(
        audit["coverage"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item == "config_operations_prune")
    );
    assert_eq!(audit["records"].as_array().unwrap().len(), 2);
    assert_eq!(audit["records"][1]["action"], "config_operations_prune");

    assert_eq!(post_named_route(address, "retention-six", 4).await, 201);
    let newest = config_operation_page(address).await;
    assert_eq!(newest["latest_id"], 6);
    assert_eq!(newest["records"].as_array().unwrap().len(), 3);
    assert_eq!(newest["records"][2]["id"], 6);
    assert_eq!(newest["stored_records"], 3);
}

#[tokio::test]
async fn config_operation_prune_checks_role_bounds_and_rolls_back_on_audit_failure() {
    let (address, manager, _directory) = server().await;
    assert_eq!(post_named_route(address, "prune-one", 0).await, 201);
    assert_eq!(post_named_route(address, "prune-two", 1).await, 201);
    let before = config_operation_page(address).await;
    let valid = config_prune_body(&before, 2);

    let (status, headers, body) = request_with_token(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&valid),
        None,
        None,
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["status"], 401);
    let root_credentials = r#"{"username":"pruneroot","password":"first secure password 123"}"#;
    let (status, _, root_body) = request(
        address,
        "POST",
        "/v1/auth/bootstrap",
        Some(root_credentials),
        None,
    )
    .await;
    assert_eq!(status, 201);
    let root_id = json(&root_body)["user"]["id"].as_i64().unwrap();
    let (status, _, login_body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(root_credentials),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let root_token = json(&login_body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/users",
            Some(r#"{"username":"pruneviewer","password":"viewer secure password 123","role":"viewer"}"#),
            None,
        )
        .await
        .0,
        201
    );
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"pruneviewer","password":"viewer secure password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let viewer = json(&body)["token"].as_str().unwrap().to_owned();
    let (status, headers, body) = request_with_token(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&valid),
        None,
        Some(&viewer),
    )
    .await;
    assert_eq!(status, 403);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["status"], 403);

    let latest = before["latest_id"].as_i64().unwrap();
    let history = before["history_revision"].as_u64().unwrap();
    for invalid in [
        serde_json::json!({"through_id":0,"expected_latest_id":latest,"expected_history_revision":history}),
        serde_json::json!({"through_id":-1,"expected_latest_id":latest,"expected_history_revision":history}),
        serde_json::json!({"through_id":9_007_199_254_740_992_u64,"expected_latest_id":latest,"expected_history_revision":history}),
        serde_json::json!({"through_id":1,"expected_latest_id":latest,"expected_history_revision":9_007_199_254_740_992_u64}),
        serde_json::json!({"through_id":1,"expected_latest_id":latest}),
        serde_json::json!({"through_id":1,"expected_latest_id":latest,"expected_history_revision":history,"unknown":true}),
    ] {
        let (status, headers, body) = request(
            address,
            "POST",
            "/v1/config/operations/prune",
            Some(&invalid.to_string()),
            None,
        )
        .await;
        assert_eq!(status, 400, "body {invalid}");
        assert_eq!(headers["cache-control"], "no-store");
        assert_eq!(json(&body)["status"], 400);
    }
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/config/operations/prune?unused=1",
            Some(&valid),
            None,
        )
        .await
        .0,
        400
    );

    let db = manager.state_path.with_extension("admin-users.sqlite3");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_config_prune_receipt BEFORE INSERT ON admin_audit \
             BEGIN SELECT RAISE(ABORT, 'fixture audit append failure'); END;",
        )
        .unwrap();
    let (status, headers, _) = request(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&valid),
        None,
    )
    .await;
    assert_eq!(status, 503);
    assert_eq!(headers["cache-control"], "no-store");
    let unchanged = config_operation_page(address).await;
    assert_eq!(unchanged["history_revision"], before["history_revision"]);
    assert_eq!(unchanged["stored_records"], 2);
    assert_eq!(unchanged["pruned_through"], 0);
    assert_eq!(unchanged["records"].as_array().unwrap().len(), 2);
    connection
        .execute_batch("DROP TRIGGER reject_config_prune_receipt")
        .unwrap();
    let (_, _, audit_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    assert!(
        json(&audit_body)["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["action"] != "config_operations_prune")
    );

    let (status, headers, body) = request_with_token(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&valid),
        None,
        Some(&root_token),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let result = json(&body);
    assert_eq!(result["pruned_records"], 2);
    assert_eq!(result["record"]["action"], "config_operations_prune");
    assert_eq!(result["record"]["actor_kind"], "account");
    assert_eq!(result["record"]["actor_user_id"], root_id);
    assert_eq!(config_operation_page(address).await["stored_records"], 0);
}

#[tokio::test]
async fn config_operation_prune_can_revisit_a_boundary_after_late_completion() {
    let (address, manager, _directory) = server().await;
    let db = manager.state_path.with_extension("admin-users.sqlite3");
    let connection = rusqlite::Connection::open(&db).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER hold_config_completion BEFORE UPDATE ON admin_config_operations \
             WHEN NEW.state!='accepted' BEGIN SELECT RAISE(ABORT, 'fixture delayed completion'); END;",
        )
        .unwrap();
    assert_eq!(post_named_route(address, "late-first", 0).await, 503);
    connection
        .execute_batch("DROP TRIGGER hold_config_completion")
        .unwrap();
    assert_eq!(post_named_route(address, "late-second", 1).await, 201);
    let before = config_operation_page(address).await;
    let first_id = before["records"][0]["operation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(before["records"][0]["state"], "accepted");
    let first_prune = config_prune_body(&before, 2);
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&first_prune),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["pruned_records"], 1);
    assert_eq!(json(&body)["retained_unresolved"], 1);
    let retained = config_operation_page(address).await;
    assert_eq!(retained["records"].as_array().unwrap().len(), 1);
    assert_eq!(retained["records"][0]["id"], 1);
    assert_eq!(retained["pruned_through"], 2);

    let reopened = hangang::admin_users::Store::open(db).unwrap();
    reopened
        .finish_config(
            &first_id,
            hangang::admin_users::ConfigOperationState::CandidateActivated,
        )
        .await
        .unwrap();
    let completed = config_operation_page(address).await;
    assert_eq!(completed["records"][0]["state"], "candidate_activated");
    assert!(
        completed["history_revision"].as_u64().unwrap()
            > retained["history_revision"].as_u64().unwrap()
    );
    let second_prune = config_prune_body(&completed, 2);
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/config/operations/prune",
        Some(&second_prune),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["pruned_records"], 1);
    assert_eq!(json(&body)["retained_unresolved"], 0);
    let empty = config_operation_page(address).await;
    assert!(empty["records"].as_array().unwrap().is_empty());
    assert_eq!(empty["latest_id"], 2);
    assert_eq!(empty["pruned_through"], 2);
}

#[tokio::test]
async fn protected_route_api_rejects_missing_or_removed_auth_without_advancing_revision() {
    let (address, manager, _dir) = server().await;
    let unauthenticated = r#"{"id":"guarded","access_mode":"protected","lua":"hangang.reject(403)","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/routes/http",
            Some(unauthenticated),
            Some(0)
        )
        .await
        .0,
        422
    );
    let disabled = r#"{"id":"guarded","enabled":false,"access_mode":"protected","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(disabled), Some(0))
            .await
            .0,
        422
    );
    assert_eq!(manager.active.load().config.revision, 0);

    let credential = format!("alice:{}:{}", "00".repeat(16), "00".repeat(32));
    let valid = serde_json::json!({
        "id":"guarded", "access_mode":"protected", "backends":["http://127.0.0.1:9"],
        "basic_auth":{"credentials":[credential],"hide_credentials":true}
    })
    .to_string();
    let (status, headers, body) =
        request(address, "POST", "/v1/routes/http", Some(&valid), Some(0)).await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(json(&body)["access_mode"], "protected");

    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/guarded",
            Some(unauthenticated),
            Some(1)
        )
        .await
        .0,
        422
    );
    assert_eq!(manager.active.load().config.revision, 1);
    let (status, _, body) = request(address, "GET", "/v1/routes/http/guarded", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["access_mode"], "protected");
    assert!(json(&body)["basic_auth"].is_object());

    // An old editor may send a complete replacement without the new mode or
    // authentication fields. This must not silently turn a protected route
    // into an anonymous legacy route.
    let old_editor = r#"{"id":"guarded","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/guarded",
            Some(old_editor),
            Some(1)
        )
        .await
        .0,
        422
    );
    let mut full = serde_json::to_value(&manager.active.load().config).unwrap();
    let route = full["http"][0].as_object_mut().unwrap();
    route.remove("access_mode");
    route.remove("basic_auth");
    let full = full.to_string();
    assert_eq!(
        request(address, "POST", "/v1/config/validate", Some(&full), None)
            .await
            .0,
        422
    );
    assert_eq!(
        request(address, "PUT", "/v1/config", Some(&full), Some(1))
            .await
            .0,
        422
    );
    assert_eq!(manager.active.load().config.revision, 1);

    let plain = r#"{"id":"guarded","access_mode":"public","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/guarded",
            Some(plain),
            Some(0)
        )
        .await
        .0,
        409
    );
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/guarded",
            Some(plain),
            Some(1)
        )
        .await
        .0,
        200
    );
    assert_eq!(manager.active.load().config.revision, 2);
}

#[tokio::test]
async fn resource_policy_scope_requires_explicit_release_before_api_removal() {
    let (address, manager, _dir) = server().await;
    let route = serde_json::json!({
        "id": "guarded-resource",
        "access_mode": "protected",
        "host": "app.test",
        "path_prefix": "/admin",
        "path_match": "segment_prefix",
        "backends": ["http://127.0.0.1:9"],
        "auth": {
            "url": "http://127.0.0.1:9/check",
            "response_headers": ["x-subject"]
        },
        "resource_policy": {
            "resource_id": "admin",
            "principal": {"source": "external", "subject_header": "x-subject"},
            "allow": [{"subjects": ["alice"], "methods": ["GET"]}]
        }
    });
    let (status, headers, body) = request(
        address,
        "POST",
        "/v1/routes/http",
        Some(&route.to_string()),
        Some(0),
    )
    .await;
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(json(&body)["resource_policy"]["resource_id"], "admin");

    let active = serde_json::to_value(&manager.active.load().config).unwrap();
    let persisted = std::fs::read(&manager.state_path).unwrap();
    let assert_unchanged = || {
        assert_eq!(manager.active.load().config.revision, 1);
        assert_eq!(
            serde_json::to_value(&manager.active.load().config).unwrap(),
            active
        );
        assert_eq!(std::fs::read(&manager.state_path).unwrap(), persisted);
    };

    let (status, _, _) = request(
        address,
        "DELETE",
        "/v1/routes/http/guarded-resource",
        None,
        Some(1),
    )
    .await;
    assert_eq!(status, 422, "protected namespace deletion must be rejected");
    assert_unchanged();

    // An older route editor may retain Protected/auth but omit the new policy.
    let mut without_policy = route.clone();
    without_policy
        .as_object_mut()
        .unwrap()
        .remove("resource_policy");
    let (status, _, _) = request(
        address,
        "PUT",
        "/v1/routes/http/guarded-resource",
        Some(&without_policy.to_string()),
        Some(1),
    )
    .await;
    assert_eq!(
        status, 422,
        "omitted resource policy must not release scope"
    );
    assert_unchanged();

    // A host/path move under the same resource ID must not expose the old URL.
    for (name, value) in [
        ("host", serde_json::json!("elsewhere.test")),
        ("path_prefix", serde_json::json!("/elsewhere")),
    ] {
        let mut moved = route.clone();
        moved[name] = value;
        let (status, _, _) = request(
            address,
            "PUT",
            "/v1/routes/http/guarded-resource",
            Some(&moved.to_string()),
            Some(1),
        )
        .await;
        assert_eq!(status, 422, "{name} move must not release old scope");
        assert_unchanged();
    }

    // Full-document preview and commit have the same transition guard.
    let mut dropped = active.clone();
    dropped["http"] = serde_json::json!([]);
    let dropped = dropped.to_string();
    assert_eq!(
        request(address, "POST", "/v1/config/validate", Some(&dropped), None)
            .await
            .0,
        422
    );
    assert_eq!(
        request(address, "PUT", "/v1/config", Some(&dropped), Some(1))
            .await
            .0,
        422
    );
    assert_unchanged();

    // A separate, reviewable revision explicitly releases this exact scope.
    let mut released = route;
    released["resource_policy"]["enforce"] = serde_json::json!(false);
    let (status, headers, body) = request(
        address,
        "PUT",
        "/v1/routes/http/guarded-resource",
        Some(&released.to_string()),
        Some(1),
    )
    .await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(headers["etag"], "\"2\"");
    assert_eq!(json(&body)["resource_policy"]["enforce"], false);
    assert_eq!(
        serde_json::to_value(&manager.active.load().config).unwrap()["http"][0]["resource_policy"]
            ["enforce"],
        false
    );
    assert_eq!(
        serde_json::to_value(hangang::store::load(&manager.state_path).unwrap()).unwrap()["http"]
            [0]["resource_policy"]["enforce"],
        false
    );

    let (status, headers, _) = request(
        address,
        "DELETE",
        "/v1/routes/http/guarded-resource",
        None,
        Some(2),
    )
    .await;
    assert_eq!(status, 204);
    assert_eq!(headers["etag"], "\"3\"");
    assert!(manager.active.load().config.http.is_empty());
    assert!(
        hangang::store::load(&manager.state_path)
            .unwrap()
            .http
            .is_empty()
    );
}

#[tokio::test]
async fn tcp_route_collection_and_body_limits_are_strict() {
    let (address, _manager, _dir) = server().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = listener.local_addr().unwrap();
    drop(listener);
    let route =
        serde_json::json!({"id":"stream","listen":listen,"backends":["127.0.0.1:9"]}).to_string();
    assert_eq!(
        request(address, "POST", "/v1/routes/tcp", Some(&route), Some(0))
            .await
            .0,
        201
    );
    let (_, _, body) = request(address, "GET", "/v1/routes/tcp", None, None).await;
    assert_eq!(json(&body)["routes"].as_array().unwrap().len(), 1);
    let oversized = format!(
        r#"{{"id":"big","backends":["http://127.0.0.1:9"],"lua":"{}"}}"#,
        "x".repeat(1024 * 1024)
    );
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/routes/http",
            Some(&oversized),
            Some(1)
        )
        .await
        .0,
        413
    );
}

#[tokio::test]
async fn lifecycle_and_updater_require_auth_and_explicit_runtime_configuration() {
    let (address, manager, _dir) = server().await;
    for (method, path) in [
        ("POST", "/v1/lifecycle/restart"),
        ("POST", "/v1/update/check"),
        ("GET", "/v1/update/status"),
    ] {
        let response = request_with_token(address, method, path, None, None, None).await;
        assert_eq!(response.0, 401);
        assert_eq!(response.1["content-type"], "application/problem+json");
    }
    assert_eq!(
        request(address, "POST", "/v1/lifecycle/restart", None, None)
            .await
            .0,
        503
    );
    assert_eq!(
        request(address, "POST", "/v1/update/check", None, None)
            .await
            .0,
        503
    );
    let (code, _, body) = request(address, "GET", "/v1/update/status", None, None).await;
    assert_eq!(code, 200);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["enabled"],
        false
    );
    assert_eq!(
        request(address, "GET", "/v1/lifecycle/restart", None, None)
            .await
            .0,
        405
    );
    assert_eq!(
        request(address, "POST", "/v1/update/status", None, None)
            .await
            .0,
        405
    );
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn cancelled_mutations_retain_bounded_transaction_admission() {
    let (address, manager, _directory) = server().await;
    let all = manager
        .transactions
        .clone()
        .acquire_many_owned(32)
        .await
        .unwrap();
    assert_eq!(
        request(address, "PUT", "/v1/config", Some("{}"), Some(0))
            .await
            .0,
        503
    );
    drop(all);
    let writer = manager.writes.lock().await;
    let task = tokio::spawn({
        let manager = manager.clone();
        async move { manager.apply(Config::default(), 0).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while manager.transactions.available_permits() == 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(
        manager.transactions.available_permits(),
        31,
        "detached commit retains its admission"
    );
    drop(writer);
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while manager.transactions.available_permits() != 32 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(manager.active.load().config.revision, 1);
}

#[tokio::test]
async fn controller_configuration_has_one_authoritative_writer() {
    let (address, manager, _directory) = server_with_source(true).await;
    assert_eq!(
        request(address, "PUT", "/v1/config", Some("{}"), Some(0))
            .await
            .0,
        409
    );
    assert!(manager.reload_file().await.is_err());
    assert_eq!(
        manager
            .apply_external(Config::default())
            .await
            .unwrap()
            .revision,
        0
    );
    assert!(
        manager.ready.load(std::sync::atomic::Ordering::Acquire),
        "an unchanged initial controller snapshot establishes readiness"
    );
    let config: Config = serde_json::from_value(
        serde_json::json!({"http":[{"id":"controller","backends":["http://127.0.0.1:9"]}]}),
    )
    .unwrap();
    let next = manager.apply_external(config.clone()).await.unwrap();
    assert_eq!(next.revision, 1);
    assert_eq!(
        manager.apply_external(config).await.unwrap().revision,
        1,
        "unchanged reconciles do not churn revisions"
    );
    assert_eq!(
        hangang::store::load(&manager.state_path).unwrap().revision,
        0,
        "controller snapshots do not write the seed file"
    );
}

#[tokio::test]
async fn transformation_scripts_validate_atomically_and_round_trip() {
    let (address, manager, _dir) = server().await;
    let mut config = serde_json::json!({"http":[{"id":"body","backends":["http://127.0.0.1:9"],"response_transform":{"mode":"ndjson","lua":"return hangang.body()","max_buffer_bytes":16384,"max_output_bytes":16384}}]});
    let good = config.to_string();
    assert_eq!(
        request(address, "POST", "/v1/config/validate", Some(&good), None)
            .await
            .0,
        200
    );
    assert_eq!(manager.active.load().config.revision, 0);
    assert_eq!(
        request(address, "PUT", "/v1/config", Some(&good), Some(0))
            .await
            .0,
        200
    );
    let (_, _, body) = request(address, "GET", "/v1/config", None, None).await;
    let saved: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        saved["http"][0]["response_transform"]["lua"],
        "return hangang.body()"
    );
    config["http"][0]["response_transform"]["lua"] = serde_json::json!("this is not lua (");
    let bad = config.to_string();
    assert_eq!(
        request(address, "POST", "/v1/config/validate", Some(&bad), None)
            .await
            .0,
        422
    );
    assert_eq!(
        request(address, "PUT", "/v1/config", Some(&bad), Some(1))
            .await
            .0,
        422
    );
    assert!(
        manager.ready.load(std::sync::atomic::Ordering::Acquire),
        "an invalid API proposal must not change instance readiness"
    );
    assert_eq!(manager.active.load().config.revision, 1);
    std::fs::write(&manager.state_path, bad).unwrap();
    assert!(manager.reload_file().await.is_err());
    assert_eq!(manager.active.load().config.revision, 1);
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn shared_store_divergence_fails_readiness_and_exact_or_newer_state_recovers() {
    use std::sync::atomic::Ordering;

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("shared.json");
    let active_config = Config {
        revision: 5,
        ..Config::default()
    };
    hangang::store::save(state_path.clone(), active_config.clone())
        .await
        .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(active_config.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path: state_path.clone(),
        config_store: Some(Arc::new(FileConfigStore::new(state_path.clone()))),
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed: false,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(None),
        store_health: Default::default(),
    });

    std::fs::remove_file(&state_path).unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));

    hangang::store::save(state_path.clone(), active_config.clone())
        .await
        .unwrap();
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));

    let mut older = active_config.clone();
    older.revision = 4;
    hangang::store::save(state_path.clone(), older)
        .await
        .unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));

    let mut replaced = active_config.clone();
    replaced.certificates.push(CertificateFiles {
        id: "different".into(),
        hosts: vec!["different.example".into()],
        default: false,
        enabled: true,
        cert_file: "/nonexistent/hangang-cert.pem".into(),
        key_file: "/nonexistent/hangang-key.pem".into(),
        issuer_status_file: None,
    });
    hangang::store::save(state_path.clone(), replaced.clone())
        .await
        .unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));

    replaced.revision = 6;
    hangang::store::save(state_path.clone(), replaced)
        .await
        .unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.active.load().config, active_config);

    let mut recovered = active_config;
    recovered.revision = 6;
    hangang::store::save(state_path, recovered.clone())
        .await
        .unwrap();
    assert!(manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.active.load().config, recovered);

    manager.stop_updates().await;
    manager.resume_updates();
    assert!(
        !manager.ready.load(Ordering::Acquire),
        "a resumed shared-store worker must revalidate its authority"
    );
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn cache_policy_hot_reload_validation_and_authenticated_purge() {
    let (address, manager, _dir) = server().await;
    for (method, path) in [("GET", "/v1/cache"), ("POST", "/v1/cache/purge")] {
        assert_eq!(
            request_with_token(address, method, path, None, None, None)
                .await
                .0,
            401
        );
    }
    let (_, _, body) = request(address, "GET", "/v1/cache", None, None).await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["enabled"],
        false
    );
    let mut config = serde_json::to_value(Config::default()).unwrap();
    config["cache"] =
        serde_json::json!({"memory":{"max_bytes":65536,"max_entries":8,"eviction":"fifo"}});
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/config",
            Some(&config.to_string()),
            Some(manager.active.load().config.revision)
        )
        .await
        .0,
        200
    );
    let original = manager.active.load().cache.clone().unwrap();
    config["cache"]["memory"]["max_bytes"] = serde_json::json!(32768);
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/config",
            Some(&config.to_string()),
            Some(manager.active.load().config.revision)
        )
        .await
        .0,
        200
    );
    assert!(!Arc::ptr_eq(
        &original,
        manager.active.load().cache.as_ref().unwrap()
    ));
    config["cache"]["memory"]["max_bytes"] = serde_json::json!(0);
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/config",
            Some(&config.to_string()),
            Some(manager.active.load().config.revision)
        )
        .await
        .0,
        422
    );
    let (_, _, body) = request(address, "GET", "/v1/cache", None, None).await;
    let status: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(status["config"]["memory"]["max_bytes"], 32768);
    assert_eq!(status["config"]["memory"]["eviction"], "fifo");
    assert_eq!(
        request(address, "POST", "/v1/cache/purge", None, None)
            .await
            .0,
        200
    );
}

#[tokio::test]
async fn controller_routes_and_tls_publish_as_one_snapshot() {
    let (_address, manager, _dir) = server_with_source(true).await;
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = tokio::spawn({
        let active = manager.active.clone();
        let stop = stop.clone();
        async move {
            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                let snapshot = active.load_full();
                if let Some(route) = snapshot.config.http.first() {
                    let tls = snapshot
                        .certificates
                        .as_ref()
                        .expect("route and TLS must publish together")
                        .load_full();
                    assert_eq!(tls.alpn_protocols[0], route.id.as_bytes());
                }
                tokio::task::yield_now().await;
            }
        }
    });
    for generation in 0..32 {
        let id = format!("generation-{generation}");
        let config: Config = serde_json::from_value(
            serde_json::json!({"http":[{"id":id,"backends":["http://127.0.0.1:9"]}]}),
        )
        .unwrap();
        let mut tls = hangang::tls::sni_server_config(vec![]).unwrap();
        tls.alpn_protocols = vec![id.into_bytes()];
        manager
            .apply_external_with_tls(config, Arc::new(tls))
            .await
            .unwrap();
    }
    let before = manager.active.load_full();
    let invalid: Config =
        serde_json::from_value(serde_json::json!({"http":[{"id":"broken","backends":[]}]}))
            .unwrap();
    assert!(
        manager
            .apply_external_with_tls(
                invalid,
                Arc::new(hangang::tls::sni_server_config(vec![]).unwrap())
            )
            .await
            .is_err()
    );
    assert!(Arc::ptr_eq(&before, &manager.active.load_full()));
    stop.store(true, std::sync::atomic::Ordering::Release);
    reader.await.unwrap();
}

/// Unauthenticated peers may only ever pin the small public-asset budget.
/// Holding every public permit with unread HTTP/2 bodies (zero receive
/// window) must leave authenticated administration fully available.
#[tokio::test]
async fn unread_public_assets_cannot_exhaust_authenticated_admission() {
    use http_body_util::Empty;
    use hyper::body::Bytes;
    let (address, _manager, _dir) = server_with_limits(false, 4, 4).await;

    let stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .initial_stream_window_size(0)
        .handshake::<_, Empty<Bytes>>(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut held = Vec::new();
    for _ in 0..4 {
        let response = sender
            .send_request(
                Request::builder()
                    .uri("/ui/app.js")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        // The body stays unread: the server cannot send DATA into a zero window.
        held.push(response);
    }

    // The public budget is exhausted for further anonymous asset loads...
    let (status, _, _) =
        request_with_token(address, "GET", "/openapi.json", None, None, None).await;
    assert_eq!(status, 503);
    // ...but authenticated administration and its 401 path are unaffected.
    let (status, _, body) = request(address, "GET", "/v1/status", None, None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let (status, _, _) = request_with_token(address, "GET", "/v1/status", None, None, None).await;
    assert_eq!(status, 401);
    let (status, _, _) = request(address, "PUT", "/v1/config", Some("{}"), Some(0)).await;
    assert_eq!(status, 200);

    // Releasing the held bodies returns the public budget.
    drop(held);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (status, _, body) =
                request_with_token(address, "GET", "/openapi.json", None, None, None).await;
            if status == 200 {
                assert_eq!(json(&body)["openapi"], "3.1.0");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
}

/// A compact document under the request limit whose persisted (pretty) form
/// would exceed the file read limit is a validation failure, not a commit.
#[tokio::test]
async fn configuration_that_cannot_be_reloaded_is_rejected_before_persisting() {
    let (address, manager, _dir) = server().await;
    let before = std::fs::read(&manager.state_path).unwrap();
    let wide = serde_json::json!({
        "http":[{"id":"wide","backends":["http://127.0.0.1:9"],
                 "json":{"/values": vec![0_u8; 200_000]}}]
    })
    .to_string();
    assert!(wide.len() < 1024 * 1024);
    let (status, _, body) = request(address, "PUT", "/v1/config", Some(&wide), Some(0)).await;
    assert_eq!(status, 422, "{}", String::from_utf8_lossy(&body));
    assert_eq!(manager.active.load().config.revision, 0);
    assert_eq!(std::fs::read(&manager.state_path).unwrap(), before);
    assert_eq!(
        hangang::store::load(&manager.state_path).unwrap().revision,
        0
    );

    let route = serde_json::json!({"id":"wide","backends":["http://127.0.0.1:9"],
                                   "json":{"/values": vec![0_u8; 200_000]}})
    .to_string();
    let (status, headers, _) =
        request(address, "POST", "/v1/routes/http", Some(&route), Some(0)).await;
    assert_eq!(status, 422);
    assert_eq!(headers["content-type"], "application/problem+json");
    assert_eq!(manager.active.load().config.revision, 0);
    assert_eq!(std::fs::read(&manager.state_path).unwrap(), before);
}

/// A shared-store instance starts unready (as a replacement generation now
/// does) and may only report readiness once the store confirms its snapshot.
#[tokio::test]
async fn shared_store_instance_stays_unready_until_the_store_confirms_its_snapshot() {
    use std::{sync::atomic::Ordering, time::Duration};
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("shared.json");
    let inherited = Config {
        revision: 5,
        ..Config::default()
    };
    // The predecessor followed this authority; the handoff carries its epoch.
    let store = FileConfigStore::new(state_path.clone());
    let epoch = {
        use hangang::config_store::ConfigStore;
        store.bootstrap(inherited.clone()).await.unwrap().epoch
    };
    std::fs::remove_file(&state_path).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(inherited.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path: state_path.clone(),
        config_store: Some(Arc::new(store)),
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed: false,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(Some(epoch)),
        store_health: Default::default(),
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    let watcher = tokio::spawn(hangang::admin::watch_config(
        manager.clone(),
        cancel.clone(),
    ));

    // The store lost the inherited revision: no readiness.
    assert!(!hangang::admin::await_readiness(&manager.ready, Duration::from_millis(700)).await);
    assert!(!manager.ready.load(Ordering::Acquire));

    // An older authoritative revision is not agreement either.
    let mut older = inherited.clone();
    older.revision = 4;
    hangang::store::save(state_path.clone(), older)
        .await
        .unwrap();
    assert!(!hangang::admin::await_readiness(&manager.ready, Duration::from_millis(700)).await);

    // Exact agreement with the store establishes readiness.
    hangang::store::save(state_path.clone(), inherited.clone())
        .await
        .unwrap();
    assert!(hangang::admin::await_readiness(&manager.ready, Duration::from_secs(5)).await);
    assert_eq!(manager.active.load().config, inherited);

    cancel.cancel();
    watcher.await.unwrap();
    manager.policy.shutdown().await;

    // Without an inherited epoch (an older exporter) the first poll attaches
    // to whatever the store holds, like a fresh start: revisions of an unknown
    // history are not compared, so an "older" document is adopted.
    let older_path = directory.path().join("legacy.json");
    let mut older = inherited.clone();
    older.revision = 4;
    hangang::store::save(older_path.clone(), older.clone())
        .await
        .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(inherited.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let legacy = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path: older_path.clone(),
        config_store: Some(Arc::new(FileConfigStore::new(older_path))),
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed: false,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(None),
        store_health: Default::default(),
    });
    assert!(legacy.reload_file().await.unwrap());
    assert!(legacy.ready.load(Ordering::Acquire));
    assert_eq!(legacy.active.load().config, older);
    assert!(legacy.recorded_epoch().is_some());
    legacy.policy.shutdown().await;
}

/// A store that was wiped and seeded again carries a new authority epoch.
/// An instance that followed the old history must not adopt the new one just
/// because its revision numbers are higher, and must not write into it with
/// a stale revision either.
#[tokio::test]
async fn shared_store_authority_change_withdraws_readiness_instead_of_adopting_it() {
    use hangang::config_store::ConfigStore;
    use std::sync::atomic::Ordering;

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("shared.json");
    let store = Arc::new(FileConfigStore::new(state_path.clone()));
    let seeded = store
        .bootstrap(Config {
            revision: 5,
            ..Config::default()
        })
        .await
        .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(seeded.config.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path: state_path.clone(),
        config_store: Some(store.clone()),
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(32)),
        externally_managed: false,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(None),
        store_health: Default::default(),
    });

    // The first poll records the epoch it follows.
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    assert_eq!(
        manager.authority_epoch.lock().unwrap().as_deref(),
        Some(seeded.epoch.as_str())
    );

    // Wipe and re-seed: a different history whose revisions overlap ours.
    std::fs::remove_file(&state_path).unwrap();
    std::fs::remove_file(format!("{}.epoch", state_path.display())).unwrap();
    let mut other_history = Config {
        revision: 9,
        ..Config::default()
    };
    other_history.certificates.push(CertificateFiles {
        id: "other".into(),
        hosts: vec!["other.example".into()],
        default: false,
        enabled: true,
        cert_file: "/nonexistent/hangang-cert.pem".into(),
        key_file: "/nonexistent/hangang-key.pem".into(),
        issuer_status_file: None,
    });
    let reseeded = FileConfigStore::new(state_path.clone())
        .bootstrap(other_history)
        .await
        .unwrap();
    assert_ne!(reseeded.epoch, seeded.epoch);

    let error = manager.reload_file().await.unwrap_err();
    assert!(error.to_string().contains("authority changed"), "{error:#}");
    assert!(!manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.active.load().config.revision, 5);
    assert_eq!(
        manager.authority_epoch.lock().unwrap().as_deref(),
        Some(seeded.epoch.as_str()),
        "the followed authority is not replaced silently"
    );

    // A write with our (stale) revision must not land in the new history.
    let error = manager
        .apply(Config::default(), 5)
        .await
        .expect_err("a stale writer must not overwrite another history");
    assert!(error.to_string().contains("authority changed"), "{error:#}");
    assert!(!manager.ready.load(Ordering::Acquire));
    let durable = store.load_latest().await.unwrap().unwrap();
    assert_eq!(durable, reseeded, "the new history is untouched");
    assert_eq!(manager.active.load().config.revision, 5);
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn shared_store_transport_failures_are_tolerated_for_the_grace_window() {
    use hangang::admin::StoreHealth;
    use std::sync::atomic::Ordering;

    async fn member(state_path: &std::path::Path, grace: std::time::Duration) -> Arc<Manager> {
        let config = hangang::store::load(state_path).unwrap();
        let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
        let metrics = Arc::new(Metrics::default());
        Arc::new(Manager {
            active: active.clone(),
            tcp: Arc::new(TcpManager::new(active, metrics.clone(), 8)),
            policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
            metrics,
            state_path: state_path.to_path_buf(),
            config_store: Some(Arc::new(FileConfigStore::new(state_path.to_path_buf()))),
            writes: Mutex::new(()),
            transactions: Arc::new(tokio::sync::Semaphore::new(32)),
            externally_managed: false,
            ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stopping: std::sync::atomic::AtomicBool::new(false),
            withdrawing: std::sync::atomic::AtomicBool::new(false),
            authority_epoch: std::sync::Mutex::new(None),
            store_health: StoreHealth::new(grace),
        })
    }

    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("shared.json");
    let config = Config {
        revision: 5,
        ..Config::default()
    };
    hangang::store::save(state_path.clone(), config.clone())
        .await
        .unwrap();
    let bytes = std::fs::read(&state_path).unwrap();
    let manager = member(&state_path, std::time::Duration::from_millis(700)).await;

    // Never confirmed: a failure withdraws at once (startup semantics).
    std::fs::remove_file(&state_path).unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.store_health.report().reason, Some("missing"));

    // Confirmed, then the store disappears: tolerated inside the grace window.
    std::fs::write(&state_path, &bytes).unwrap();
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    std::fs::remove_file(&state_path).unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(
        manager.ready.load(Ordering::Acquire),
        "a store blip must not withdraw a confirmed instance"
    );
    let report = manager.store_health.report();
    assert!(report.degraded);
    assert_eq!(report.reason, Some("missing"));
    // The missing-store grace expires without a confirmation.
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    std::fs::write(&state_path, &bytes).unwrap();
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    // A directory is readable metadata proving this is not a config file,
    // not a transient inability to contact the authority.
    std::fs::remove_file(&state_path).unwrap();
    std::fs::create_dir(&state_path).unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.store_health.report().reason, Some("invalid"));
    assert!(!manager.store_health.report().degraded);
    // Recovery on the first confirming poll.
    std::fs::remove_dir(&state_path).unwrap();
    std::fs::write(&state_path, &bytes).unwrap();
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));
    let report = manager.store_health.report();
    assert!(!report.degraded);
    assert_eq!(report.reason, None);
    assert_eq!(report.last_confirmed_seconds_ago, Some(0));

    // A reachable store containing a document this binary cannot decode is
    // an authority disagreement, not a transient transport failure. Keeping
    // readiness for the grace window would advertise stale routes during a
    // mixed-version schema rollout.
    std::fs::write(
        &state_path,
        br#"{"revision":6,"http":[{"id":"unsupported","backends":[42]}]}"#,
    )
    .unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    let report = manager.store_health.report();
    assert_eq!(report.reason, Some("invalid"));
    assert!(!report.degraded);
    std::fs::write(&state_path, &bytes).unwrap();
    assert!(!manager.reload_file().await.unwrap());
    assert!(manager.ready.load(Ordering::Acquire));

    // Authority disagreements ignore the grace window.
    let mut older = config.clone();
    older.revision = 4;
    hangang::store::save(state_path.clone(), older)
        .await
        .unwrap();
    assert!(manager.reload_file().await.is_err());
    assert!(!manager.ready.load(Ordering::Acquire));
    assert_eq!(manager.store_health.report().reason, Some("rollback"));

    // Zero grace: strict mode withdraws on the first failed poll.
    std::fs::write(&state_path, &bytes).unwrap();
    let strict = member(&state_path, std::time::Duration::ZERO).await;
    assert!(!strict.reload_file().await.unwrap());
    assert!(strict.ready.load(Ordering::Acquire));
    std::fs::remove_file(&state_path).unwrap();
    assert!(strict.reload_file().await.is_err());
    assert!(!strict.ready.load(Ordering::Acquire));

    manager.policy.shutdown().await;
    strict.policy.shutdown().await;
}

#[tokio::test]
async fn shared_store_writes_are_arbitrated_by_the_store_across_members() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};
    use std::sync::atomic::Ordering;

    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("shared.db");
    let seed_path = directory.path().join("seed.json");
    let seed = Config::default();
    hangang::store::save(seed_path.clone(), seed.clone())
        .await
        .unwrap();
    let store_a: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let store_b: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    store_a.bootstrap(seed.clone()).await.unwrap();
    let (address_a, a) =
        server_on(seed_path.clone(), seed.clone(), Some(store_a), false, 8, 8).await;
    let (address_b, b) = server_on(seed_path, seed, Some(store_b), false, 8, 8).await;
    assert!(!a.reload_file().await.unwrap());
    assert!(!b.reload_file().await.unwrap());
    assert!(a.ready.load(Ordering::Acquire) && b.ready.load(Ordering::Acquire));

    // A commits revision 1; B has not polled yet.
    let route = r#"{"id":"web","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let (status, headers, _) =
        request(address_a, "POST", "/v1/routes/http", Some(route), Some(0)).await;
    assert_eq!(status, 201);
    assert_eq!(headers["etag"], "\"1\"");
    assert_eq!(b.active.load().config.revision, 0);

    // Read-your-writes through a load balancer: the client carries the
    // revision it saw on A to B, which catches up instead of answering 409.
    let second = r#"{"id":"api","path_prefix":"/api","backends":["http://127.0.0.1:9"]}"#;
    let (status, headers, _) =
        request(address_b, "POST", "/v1/routes/http", Some(second), Some(1)).await;
    assert_eq!(
        status, 201,
        "B must let the store arbitrate a precondition ahead of it"
    );
    assert_eq!(headers["etag"], "\"2\"");
    assert_eq!(b.active.load().config.revision, 2);
    assert_eq!(b.active.load().config.http.len(), 2);

    // A is now behind (local 1, store 2). A stale precondition is a real
    // conflict, and losing it brings A up to date.
    let third = r#"{"id":"third","path_prefix":"/third","backends":["http://127.0.0.1:9"]}"#;
    let (status, _, _) = request(address_a, "POST", "/v1/routes/http", Some(third), Some(1)).await;
    assert_eq!(status, 409);
    assert_eq!(
        a.active.load().config.revision,
        2,
        "a conflict reconciles the loser"
    );
    // A precondition behind the local revision is refused without a store round trip.
    let (status, _, _) = request(address_a, "POST", "/v1/routes/http", Some(third), Some(0)).await;
    assert_eq!(status, 409);
    // The status reports fleet diagnostics.
    let (status, _, body) = request(address_a, "GET", "/v1/status", None, None).await;
    assert_eq!(status, 200);
    let status = json(&body);
    assert_eq!(status["store"]["revision"], 2);
    assert_eq!(status["store"]["ready"], true);
    assert_eq!(status["store"]["reason"], serde_json::Value::Null);
    assert!(status["store"]["epoch"].as_str().unwrap().len() == 32);
    assert_eq!(status["instance"]["id"].as_str().unwrap().len(), 16);
    assert_eq!(
        status["instance"]["config_digest"].as_str().unwrap().len(),
        16
    );
    let (_, _, body_b) = request(address_b, "GET", "/v1/status", None, None).await;
    assert_eq!(
        json(&body_b)["instance"]["config_digest"],
        status["instance"]["config_digest"],
        "members at one revision agree on the digest"
    );
    a.policy.shutdown().await;
    b.policy.shutdown().await;
}

#[tokio::test]
async fn cache_purge_is_a_configuration_change_in_shared_store_mode() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};

    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("shared.db");
    let seed_path = directory.path().join("seed.json");
    let seed = Config {
        cache: Some(hangang::cache_store::CacheConfig::default()),
        ..Config::default()
    };
    hangang::store::save(seed_path.clone(), seed.clone())
        .await
        .unwrap();
    let store: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    store.bootstrap(seed.clone()).await.unwrap();
    let (address, manager) = server_on(seed_path, seed, Some(store.clone()), false, 8, 8).await;
    assert!(!manager.reload_file().await.unwrap());

    let (status, headers, body) = request(address, "POST", "/v1/cache/purge", None, None).await;
    assert_eq!(status, 200);
    let body = json(&body);
    assert_eq!(body["scope"], "fleet");
    assert_eq!(body["generation"], 1);
    assert_eq!(body["revision"], 1);
    assert_eq!(headers["etag"], "\"1\"");
    let stored = store.load_latest().await.unwrap().unwrap();
    assert_eq!(stored.config.cache.as_ref().unwrap().generation, 1);
    let (_, _, body) = request(address, "GET", "/v1/cache", None, None).await;
    let body = json(&body);
    assert_eq!(body["generation"], 1);
    assert_eq!(body["config"]["generation"], 1);
    let (_, _, body) = request(address, "POST", "/v1/cache/purge", None, None).await;
    assert_eq!(json(&body)["generation"], 2);

    // The floor travels with the document: disabling the cache and enabling
    // it again with generation 0 keeps 2, so an instance that skipped the
    // disabled revision (still holding generation-2 entries) cannot have a
    // later purge ignored.
    let mut disabled = manager.active.load().config.clone();
    disabled.cache = None;
    let (status, _, _) = request(
        address,
        "PUT",
        "/v1/config",
        Some(&serde_json::to_string(&disabled).unwrap()),
        Some(disabled.revision),
    )
    .await;
    assert_eq!(status, 200);
    let stored = store.load_latest().await.unwrap().unwrap();
    assert!(stored.config.cache.is_none());
    assert_eq!(stored.config.cache_generation_floor, 2);
    let mut enabled = manager.active.load().config.clone();
    enabled.cache = Some(hangang::cache_store::CacheConfig::default());
    assert_eq!(enabled.cache.as_ref().unwrap().generation, 0);
    let (status, _, _) = request(
        address,
        "PUT",
        "/v1/config",
        Some(&serde_json::to_string(&enabled).unwrap()),
        Some(enabled.revision),
    )
    .await;
    assert_eq!(status, 200);
    let stored = store.load_latest().await.unwrap().unwrap();
    assert_eq!(stored.config.cache.as_ref().unwrap().generation, 2);
    let (_, _, body) = request(address, "POST", "/v1/cache/purge", None, None).await;
    assert_eq!(json(&body)["generation"], 3);
    assert_eq!(
        manager.active.load().cache.as_ref().unwrap().generation(),
        3
    );
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn hash_password_utility_returns_a_usable_basic_auth_credential() {
    let (address, _manager, _dir) = server().await;
    let (status, _, body) = request(
        address,
        "POST",
        "/v1/util/hash-password",
        Some(r#"{"username":"alice","password":"s3cret"}"#),
        None,
    )
    .await;
    assert_eq!(status, 200);
    let credential = json(&body)["credential"].as_str().unwrap().to_owned();
    let (username, salt, digest) = hangang::basic_auth::parse_credential(&credential).unwrap();
    assert_eq!(username, "alice");
    assert_eq!(salt.len(), 16);
    assert_eq!(digest.len(), 32);
    // Two calls never share a salt.
    let (_, _, again) = request(
        address,
        "POST",
        "/v1/util/hash-password",
        Some(r#"{"username":"alice","password":"s3cret"}"#),
        None,
    )
    .await;
    assert_ne!(json(&again)["credential"], credential);
    // The credential is accepted by a route definition.
    let route = format!(
        r#"{{"id":"web","backends":["http://127.0.0.1:9"],"basic_auth":{{"credentials":["{credential}"]}}}}"#
    );
    let (status, _, _) = request(address, "POST", "/v1/routes/http", Some(&route), Some(0)).await;
    assert_eq!(status, 201);
    // Invalid input is rejected, and the endpoint needs the admin token.
    let (status, _, _) = request(
        address,
        "POST",
        "/v1/util/hash-password",
        Some(r#"{"username":"a:b","password":"x"}"#),
        None,
    )
    .await;
    assert_eq!(status, 422);
    let (status, _, _) = request(
        address,
        "POST",
        "/v1/util/hash-password",
        Some(r#"{"username":"alice","password":""}"#),
        None,
    )
    .await;
    assert_eq!(status, 422);
    let (status, _, _) = request_with_token(
        address,
        "POST",
        "/v1/util/hash-password",
        Some(r#"{"username":"alice","password":"x"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 401);
}

#[tokio::test]
async fn frozen_generation_keeps_checking_the_authority_and_fails_closed_when_it_moves() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};
    use std::sync::atomic::Ordering;

    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("shared.db");
    let seed_path = directory.path().join("seed.json");
    let seed = Config::default();
    hangang::store::save(seed_path.clone(), seed.clone())
        .await
        .unwrap();
    let store_a: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let store_b: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let stored = store_a.bootstrap(seed.clone()).await.unwrap();
    let (_address_a, a) =
        server_on(seed_path.clone(), seed.clone(), Some(store_a), false, 8, 8).await;
    let (address_b, b) =
        server_on(seed_path, seed.clone(), Some(store_b.clone()), false, 8, 8).await;
    assert!(!a.reload_file().await.unwrap());
    assert!(!b.reload_file().await.unwrap());

    // A is frozen for a handoff; agreement is still confirmed while nothing changes.
    a.freeze_updates().await;
    assert!(!a.reload_file().await.unwrap());
    assert!(a.ready.load(Ordering::Acquire));
    // B commits a change: the frozen generation cannot activate it and must
    // not keep advertising readiness (a revoked route would stay served).
    let route = r#"{"id":"web","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let (status, _, _) = request(address_b, "POST", "/v1/routes/http", Some(route), Some(0)).await;
    assert_eq!(status, 201);
    assert!(a.reload_file().await.is_err());
    assert!(
        !a.ready.load(Ordering::Acquire),
        "frozen and stale: withdrawn"
    );
    assert_eq!(a.store_health.report().reason, Some("stale"));
    assert_eq!(a.active.load().config.revision, 0);
    // Resumed (the handoff was abandoned): the next poll activates and recovers.
    a.resume_updates();
    assert!(a.reload_file().await.unwrap());
    assert!(a.ready.load(Ordering::Acquire));
    assert_eq!(a.active.load().config.revision, 1);

    // Failed catch-up is reported as the store failure it is, not as 409.
    let (status, _, _) = request(
        address_b,
        "POST",
        "/v1/routes/http",
        Some(r#"{"id":"api","path_prefix":"/api","backends":["http://127.0.0.1:9"]}"#),
        Some(1),
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(a.active.load().config.revision, 1);
    let moved = directory.path().join("shared.moved");
    std::fs::rename(&db, &moved).unwrap();
    std::fs::create_dir(&db).unwrap();
    let (status, _, body) = request(
        _address_a,
        "POST",
        "/v1/routes/http",
        Some(r#"{"id":"third","path_prefix":"/third","backends":["http://127.0.0.1:9"]}"#),
        Some(2),
    )
    .await;
    assert_eq!(status, 503, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["title"], "Store Unavailable");
    std::fs::remove_dir(&db).unwrap();
    std::fs::rename(&moved, &db).unwrap();
    let (status, _, _) = request(
        _address_a,
        "POST",
        "/v1/routes/http",
        Some(r#"{"id":"third","path_prefix":"/third","backends":["http://127.0.0.1:9"]}"#),
        Some(2),
    )
    .await;
    assert_eq!(status, 201);
    let _ = stored;
    a.policy.shutdown().await;
    b.policy.shutdown().await;
}

#[tokio::test]
async fn failed_fleet_purge_does_not_touch_the_live_cache_generation() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};

    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("shared.db");
    let seed_path = directory.path().join("seed.json");
    let seed = Config {
        cache: Some(hangang::cache_store::CacheConfig::default()),
        ..Config::default()
    };
    hangang::store::save(seed_path.clone(), seed.clone())
        .await
        .unwrap();
    let store_a: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let store_b: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    store_a.bootstrap(seed.clone()).await.unwrap();
    let (address_a, a) =
        server_on(seed_path.clone(), seed.clone(), Some(store_a), false, 8, 8).await;
    let (address_b, b) = server_on(seed_path, seed, Some(store_b), false, 8, 8).await;
    assert!(!a.reload_file().await.unwrap());
    assert!(!b.reload_file().await.unwrap());
    let runtime = a.active.load().cache.clone().unwrap();
    assert_eq!(runtime.generation(), 0);

    // B moves the authority; A's purge is prepared on revision 0 and its CAS
    // must fail. Preparation must leave the live runtime untouched.
    let route = r#"{"id":"web","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let (status, _, _) = request(address_b, "POST", "/v1/routes/http", Some(route), Some(0)).await;
    assert_eq!(status, 201);
    let (status, _, body) = request(address_a, "POST", "/v1/cache/purge", None, None).await;
    assert_eq!(status, 409, "{}", String::from_utf8_lossy(&body));
    assert_eq!(
        runtime.generation(),
        0,
        "a failed purge must not adopt a generation the document never carried"
    );
    // The conflict brought A up to date; the retried purge is the real one.
    assert_eq!(a.active.load().config.revision, 1);
    let (status, _, body) = request(address_a, "POST", "/v1/cache/purge", None, None).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["generation"], 1);
    assert_eq!(runtime.generation(), 1);
    assert!(Arc::ptr_eq(
        &runtime,
        a.active.load().cache.as_ref().unwrap()
    ));
    // A document that carries a lower generation never reopens the old namespace.
    assert!(
        !b.reload_file().await.unwrap()
            || b.active.load().cache.as_ref().unwrap().generation() == 1
    );
    let mut rollback = a.active.load().config.clone();
    rollback.cache.as_mut().unwrap().generation = 0;
    let (status, _, _) = request(
        address_a,
        "PUT",
        "/v1/config",
        Some(&serde_json::to_string(&rollback).unwrap()),
        Some(rollback.revision),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(runtime.generation(), 1, "adoption is monotonic");
    assert_eq!(
        a.active.load().config.cache.as_ref().unwrap().generation,
        1,
        "the authority preserves the generation through a document rollback"
    );
    a.policy.shutdown().await;
    b.policy.shutdown().await;
}

#[tokio::test]
async fn file_reload_is_stable_once_the_active_document_carries_a_generation_floor() {
    let (_address, manager, dir) = server().await;
    let path = dir.path().join("state.json");
    // The file names a generation but no floor (a hand-written document).
    let mut config = hangang::store::load(&path).unwrap();
    config.cache = Some(hangang::cache_store::CacheConfig {
        generation: 1,
        ..Default::default()
    });
    hangang::store::save(path.clone(), config).await.unwrap();
    assert!(manager.reload_file().await.unwrap());
    let revision = manager.active.load().config.revision;
    assert_eq!(manager.active.load().config.cache_generation_floor, 1);
    // The unchanged file must not be reloaded again and again.
    for _ in 0..3 {
        assert!(!manager.reload_file().await.unwrap());
        assert_eq!(manager.active.load().config.revision, revision);
    }
    // The floor is bounded even while caching is disabled.
    let mut bad = Config {
        cache_generation_floor: u64::from(u32::MAX) + 1,
        ..Config::default()
    };
    assert!(bad.validate().is_err());
    bad.cache_generation_floor = u64::from(u32::MAX);
    assert!(bad.validate().is_ok());
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn controller_resume_does_not_restore_unconfirmed_readiness() {
    use std::sync::atomic::Ordering;
    let (address, manager, _directory) = server_with_source(true).await;
    manager.freeze_updates().await;
    manager.resume_updates();
    assert!(
        !manager.ready.load(Ordering::Acquire),
        "resuming a controller must not invent confirmation of its authority"
    );
    let response = reqwest::Client::new()
        .get(format!("http://{address}/healthz"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    manager.apply_external(Config::default()).await.unwrap();
    assert!(manager.ready.load(Ordering::Acquire));
    manager.freeze_updates().await;
    manager.resume_updates();
    assert!(
        manager.ready.load(Ordering::Acquire),
        "a healthy frozen controller keeps its last confirmation"
    );
}

#[tokio::test]
async fn frozen_controller_tracks_authority_but_withdrawn_endpoint_cannot_revive() {
    use std::sync::atomic::Ordering;
    let (_address, manager, _directory) = server_with_source(true).await;
    manager.report_controller_authority(true);
    manager.freeze_updates().await;
    manager.report_controller_authority(false);
    assert!(!manager.ready.load(Ordering::Acquire));
    manager.resume_updates();
    assert!(!manager.ready.load(Ordering::Acquire));
    manager.freeze_updates().await;
    manager.report_controller_authority(true);
    assert!(
        manager.ready.load(Ordering::Acquire),
        "authority can recover during a write freeze"
    );
    manager.resume_updates();
    assert!(manager.ready.load(Ordering::Acquire));
    manager.withdraw_now();
    manager.report_controller_authority(true);
    assert!(
        !manager.ready.load(Ordering::Acquire),
        "confirmation must not undo endpoint withdrawal"
    );
}

#[tokio::test]
async fn operations_tcp_member_streams_remain_distinct_from_http_requests() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "http": [{"id":"http", "backends":["http://127.0.0.1:18001"]}],
        "tcp": [{"id":"tcp", "enabled":false, "listen":"127.0.0.1:19001",
                 "backends":[{"id":"blue", "address":"127.0.0.1:18002"}]}]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (address, manager) = server_on(
        dir.path().join("state.json"),
        config,
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let counter = manager.active.load().tcp_member_activity["tcp"]
        .node(0)
        .unwrap();
    let lease = counter.acquire().unwrap();
    let (status, _, body) = request(address, "GET", "/v1/operations", None, None).await;
    assert_eq!(status, 200);
    let data = json(&body);
    let rows = data["rows"].as_array().unwrap();
    let http = rows.iter().find(|row| row["protocol"] == "http").unwrap();
    assert_eq!(
        http.get("member_active_streams"),
        Some(&serde_json::Value::Null)
    );
    assert_eq!(http["active_requests"], 0);
    let tcp = rows.iter().find(|row| row["protocol"] == "tcp").unwrap();
    assert_eq!(tcp["member_active_streams"], 1);
    assert_eq!(tcp["member_id"], "blue");
    assert_eq!(tcp["enabled"], false);
    assert!(tcp["active_requests"].is_null());
    drop(lease);
    let (_, _, body) = request(address, "GET", "/v1/operations", None, None).await;
    let data = json(&body);
    assert_eq!(
        data["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["protocol"] == "tcp")
            .unwrap()["member_active_streams"],
        0
    );
}

#[tokio::test]
async fn failed_save_keeps_member_gates_open_and_successful_removal_retires_them() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "http":[{"id":"http", "backends":[{"id":"a", "address":"http://127.0.0.1:18001"}]}],
        "tcp":[{"id":"tcp", "listen":"127.0.0.1:19001", "backends":[{"id":"a", "address":"127.0.0.1:18002"}]}]
    })).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let (address, manager) = server_on(
        path.clone(),
        config,
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let old = manager.active.load_full();
    let http = old.http[0].balancer.clone();
    let http_owner = http.acquire(0).unwrap();
    let tcp = old.tcp_member_admissions["tcp"][0].clone();
    let tcp_owner = tcp.lease().unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(manager.apply(Config::default(), 0).await.is_err());
    assert_eq!(manager.active.load().config.revision, 0);
    assert!(http.available(0));
    assert!(tcp.is_open());
    assert_eq!(tcp.active(), 1);
    let (status, _, body) = request(address, "GET", "/v1/retired-members", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(
        json(&body)["total"],
        0,
        "failed save publishes no retirement"
    );
    std::fs::remove_dir(&path).unwrap();
    assert_eq!(
        manager.apply(Config::default(), 0).await.unwrap().revision,
        1
    );
    assert!(!http.available(0));
    assert!(http.acquire(0).is_none());
    assert!(!tcp.is_open());
    assert!(tcp.lease().is_none());
    assert_eq!(tcp.active(), 1, "retirement must preserve old ownership");
    assert_eq!(http.backend_state(0).unwrap().active_requests, Some(1));
    let mut rows = Vec::new();
    for offset in 0..2 {
        let (status, headers, body) = request(
            address,
            "GET",
            &format!("/v1/retired-members?offset={offset}&limit=1"),
            None,
            None,
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(headers["cache-control"], "no-store");
        let page = json(&body);
        assert_eq!(page["total"], 2);
        assert_eq!(page["offset"], offset);
        assert_eq!(page["limit"], 1);
        assert_eq!(page["capacity"], 4096);
        assert_eq!(page["rows"].as_array().unwrap().len(), 1);
        rows.push(page["rows"][0].clone());
    }
    rows.sort_by(|a, b| a["protocol"].as_str().cmp(&b["protocol"].as_str()));
    assert_eq!(rows[0]["protocol"], "http");
    assert_eq!(rows[0]["route_id"], "http");
    assert_eq!(rows[0]["member_id"], "a");
    assert_eq!(rows[0]["address"], "http://127.0.0.1:18001");
    assert_eq!(rows[0]["active_admissions"], 1);
    assert_eq!(rows[1]["protocol"], "tcp");
    assert_eq!(rows[1]["route_id"], "tcp");
    assert_eq!(rows[1]["member_id"], "a");
    assert_eq!(rows[1]["address"], "127.0.0.1:18002");
    assert_eq!(rows[1]["active_admissions"], 1);
    assert_ne!(rows[0]["retirement_id"], rows[1]["retirement_id"]);
    drop(http_owner);
    drop(tcp_owner);
    assert_eq!(tcp.active(), 0);
    assert_eq!(http.backend_state(0).unwrap().active_requests, Some(0));
    let (status, _, body) = request(address, "GET", "/v1/retired-members", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["total"], 0, "completed owners are pruned");
    manager.tcp.shutdown(std::time::Duration::ZERO).await;
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn retired_member_inventory_requires_admin_and_rejects_unbounded_queries() {
    let (address, manager, _directory) = server().await;
    assert_eq!(
        request_with_token(address, "GET", "/v1/retired-members", None, None, None)
            .await
            .0,
        401
    );
    let root = r#"{"username":"operator","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(root), None)
            .await
            .0,
        201
    );
    let viewer = r#"{"username":"observer","password":"viewer password 123","role":"viewer"}"#;
    assert_eq!(
        request(address, "POST", "/v1/users", Some(viewer), None)
            .await
            .0,
        201
    );
    let (_, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"observer","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    let viewer_token = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/retired-members",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request(address, "POST", "/v1/retired-members", None, None)
            .await
            .0,
        405
    );
    for path in [
        "/v1/retired-members?limit=0",
        "/v1/retired-members?limit=129",
        "/v1/retired-members?offset=-1",
        "/v1/retired-members?offset=1&offset=2",
        "/v1/retired-members?unknown=1",
    ] {
        assert_eq!(
            request(address, "GET", path, None, None).await.0,
            400,
            "{path}"
        );
    }
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn desired_member_state_publishes_only_after_save_and_reports_current_gate() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "http":[{"id":"pool", "backends":[{"id":"blue", "address":"http://127.0.0.1:18001"}]}]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.json");
    let (address, manager) = server_on(
        path.clone(),
        config.clone(),
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let old = manager.active.load_full();
    let owner = old.http[0].balancer.acquire(0).unwrap();
    let mut next = config.clone();
    let hangang::pool_member::Backend::Member(member) = &mut next.http[0].backends[0] else {
        unreachable!()
    };
    member.desired_state = hangang::pool_member::DesiredState::Maintenance;
    std::fs::create_dir(&path).unwrap();
    assert!(manager.apply(next.clone(), 0).await.is_err());
    assert!(old.http[0].balancer.available(0));
    assert!(old.retired_members.snapshot().is_empty());
    let (_, _, body) = request(address, "GET", "/v1/operations", None, None).await;
    let row = &json(&body)["rows"][0];
    assert_eq!(row["desired_state"], "serving");
    assert_eq!(row["active_admissions"], 1);
    assert_eq!(row["admission_open"], true);
    std::fs::remove_dir(&path).unwrap();
    manager.apply(next, 0).await.unwrap();
    assert!(old.http[0].balancer.acquire(0).is_none());
    assert_eq!(old.retired_members.snapshot()[0].active_admissions, 1);
    let (_, _, body) = request(address, "GET", "/v1/operations", None, None).await;
    let row = &json(&body)["rows"][0];
    assert_eq!(row["desired_state"], "maintenance");
    assert_eq!(row["admission_open"], false);
    assert_eq!(row["available"], false);
    assert_eq!(
        row["active_admissions"], 0,
        "old work remains in the retired inventory"
    );
    manager.apply(config, 1).await.unwrap();
    assert!(manager.active.load().http[0].balancer.acquire(0).is_some());
    assert!(
        old.http[0].balancer.acquire(0).is_none(),
        "reactivation cannot reopen old nodes"
    );
    drop(owner);
    assert!(old.retired_members.snapshot().is_empty());
    manager.tcp.shutdown(std::time::Duration::ZERO).await;
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn operations_do_not_reuse_old_http_probe_evidence_when_docker_resolution_is_missing() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "http":[{"id":"dynamic", "backends":["docker://app/edge/8080"],
        "balance":{"active_health":{"initial_state":"checking", "path":"/ready",
            "interval_ms":1000, "timeout_ms":100, "healthy_statuses":[200],
            "unhealthy_statuses":[503], "healthy_successes":1,
            "unhealthy_http_failures":1, "unhealthy_tcp_failures":1, "unhealthy_timeouts":1}}}]
    }))
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (address, manager) = server_on(
        dir.path().join("state.json"),
        config,
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let old = manager.active.load_full();
    old.http[0].balancer.observe_epoch(0, 7);
    old.http[0].balancer.record_active_status_for(0, 7, 200);
    assert!(old.http[0].balancer.available_for(0, 7));
    let (status, _, body) = request(address, "GET", "/v1/operations", None, None).await;
    assert_eq!(status, 200);
    let data = json(&body);
    let row = &data["rows"][0];
    assert_eq!(row["available"], false);
    assert_eq!(row["probe_observed"], false);
    assert_eq!(row["initial_check_pending"], true);
    assert_eq!(
        row["admission_open"], true,
        "configured member gate is distinct from discovery"
    );
    assert_eq!(row["active_admissions"], 0);
    assert!(
        old.http[0].balancer.available_for(0, 7),
        "observation must not mutate old health"
    );
    manager.tcp.shutdown(std::time::Duration::ZERO).await;
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn jwt_revocation_publication_is_revisioned_validated_and_persistent() {
    let (address, manager, _dir) = server().await;
    let example: serde_json::Value =
        serde_json::from_str(include_str!("../examples/jwt-auth.json")).unwrap();
    let mut route = example["http"][0].clone();
    route["jwt_auth"]["verification"]["revocation"] = serde_json::Value::Null;
    assert_eq!(
        request(
            address,
            "POST",
            "/v1/routes/http",
            Some(&route.to_string()),
            Some(0)
        )
        .await
        .0,
        201
    );
    let initial = manager.active.load_full();
    route["jwt_auth"]["verification"]["revocation"] = serde_json::json!({"issued_before": 1700000000u64, "token_ids": ["withdrawn", "withdrawn"]});
    let (status, _, body) = request(
        address,
        "PUT",
        "/v1/routes/http/orders-api",
        Some(&route.to_string()),
        Some(1),
    )
    .await;
    assert_eq!(status, 422);
    assert!(!String::from_utf8_lossy(&body).contains("withdrawn"));
    assert!(Arc::ptr_eq(&initial, &manager.active.load_full()));
    route["jwt_auth"]["verification"]["revocation"]["token_ids"] = serde_json::json!(["withdrawn"]);
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/orders-api",
            Some(&route.to_string()),
            Some(0)
        )
        .await
        .0,
        409
    );
    assert!(Arc::ptr_eq(&initial, &manager.active.load_full()));
    assert_eq!(
        request(
            address,
            "PUT",
            "/v1/routes/http/orders-api",
            Some(&route.to_string()),
            Some(1)
        )
        .await
        .0,
        200
    );
    assert_eq!(manager.active.load().config.revision, 2);
    assert!(!Arc::ptr_eq(
        initial.jwt_routes.get("orders-api").unwrap(),
        manager.active.load().jwt_routes.get("orders-api").unwrap()
    ));
    let persisted: Config =
        serde_json::from_slice(&std::fs::read(&manager.state_path).unwrap()).unwrap();
    assert_eq!(persisted.revision, 2);
    assert_eq!(
        serde_json::to_value(&persisted.http[0]).unwrap()["jwt_auth"]["verification"]["revocation"],
        route["jwt_auth"]["verification"]["revocation"]
    );
    // A new process prepares the durable revoked policy, not admission defaults.
    Snapshot::new(persisted).unwrap();
    let (status, _, body) = request(address, "GET", "/v1/routes/http/orders-api", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(
        json(&body)["jwt_auth"]["verification"]["revocation"],
        route["jwt_auth"]["verification"]["revocation"]
    );
}

#[tokio::test]
async fn user_audit_records_actor_target_and_durable_order_without_secrets() {
    let (address, _manager, directory) = server().await;
    let root = r#"{"username":"auditoperator","password":"correct horse battery"}"#;
    let initial = request(address, "GET", "/v1/audit/users", None, None).await;
    assert_eq!(initial.0, 200);
    let initial_latest = json(&initial.2)["latest_id"].as_i64().unwrap_or(0);
    let (status, _, body) = request(address, "POST", "/v1/auth/bootstrap", Some(root), None).await;
    assert_eq!(status, 201);
    let actor_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) =
        request_with_token(address, "POST", "/v1/auth/login", Some(root), None, None).await;
    assert_eq!(status, 200);
    let actor_token = json(&body)["token"].as_str().unwrap().to_owned();

    let target = r#"{"username":"audit-target","password":"viewer password 123","role":"viewer"}"#;
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/users",
        Some(target),
        None,
        Some(&actor_token),
    )
    .await;
    assert_eq!(status, 201);
    let first_target_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request_with_token(
        address,
        "PUT",
        &format!("/v1/users/{first_target_id}"),
        Some(r#"{"password":"replacement password 123"}"#),
        None,
        Some(&actor_token),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["user"]["id"], first_target_id);
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"audit-target","password":"replacement password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let viewer_token = json(&body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/audit/users",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/audit/users", None, None, None)
            .await
            .0,
        401
    );
    assert_eq!(
        request_with_token(
            address,
            "DELETE",
            &format!("/v1/users/{first_target_id}"),
            None,
            None,
            Some(&actor_token)
        )
        .await
        .0,
        204
    );
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/users",
        Some(r#"{"username":"audit-next","password":"viewer password 123","role":"viewer"}"#),
        None,
        Some(&actor_token),
    )
    .await;
    assert_eq!(status, 201);
    let second_target_id = json(&body)["user"]["id"].as_i64().unwrap();
    assert!(
        second_target_id > first_target_id,
        "deleted user ID was reused"
    );

    let path = format!("/v1/audit/users?after={initial_latest}&limit=100");
    let (status, _, body) = request(address, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    let raw = String::from_utf8(body.clone()).unwrap();
    for sensitive in [
        "correct horse battery",
        "viewer password 123",
        "replacement password 123",
        actor_token.as_str(),
        viewer_token.as_str(),
        "audit-target",
        "audit-next",
    ] {
        assert!(
            !raw.contains(sensitive),
            "audit response retained a credential or username"
        );
    }
    let page = json(&body);
    let records = page["records"].as_array().unwrap();
    assert_eq!(records.len(), 5);
    assert_eq!(
        records
            .iter()
            .map(|item| item["action"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["bootstrap", "create", "update", "delete", "create"]
    );
    assert!(
        records
            .windows(2)
            .all(|pair| pair[0]["id"].as_i64().unwrap() < pair[1]["id"].as_i64().unwrap())
    );
    assert_eq!(records[0]["target_user_id"], actor_id);
    for record in &records[1..] {
        assert_eq!(record["actor_kind"], "account");
        assert_eq!(record["actor_user_id"], actor_id);
    }
    assert_eq!(records[1]["target_user_id"], first_target_id);
    assert_eq!(records[2]["target_user_id"], first_target_id);
    assert_eq!(records[3]["target_user_id"], first_target_id);
    assert_eq!(records[4]["target_user_id"], second_target_id);
    assert_eq!(records[1]["after"]["role"], "viewer");
    assert_eq!(records[2]["before"]["role"], "viewer");
    assert_eq!(records[2]["after"]["role"], "viewer");
    assert_eq!(records[2]["password_changed"], true);
    assert_eq!(records[3]["after"], serde_json::Value::Null);
    assert!(page["writes_available"].as_bool().unwrap());
    assert!(page["server_time_unix_ms"].is_u64());
    assert!(page["started_at_unix_ms"].is_u64());

    let (reopened, _) = server_on(
        directory.path().join("state.json"),
        Config::default(),
        None,
        false,
        64,
        Admin::PUBLIC_REQUEST_LIMIT,
    )
    .await;
    let (status, _, reopened_body) = request(reopened, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&reopened_body)["records"], page["records"]);
    assert_eq!(json(&reopened_body)["latest_id"], page["latest_id"]);
}

#[tokio::test]
async fn user_audit_pages_validate_queries_and_prune_with_revision_fence() {
    let (address, _manager, _directory) = server().await;
    let bootstrap = r#"{"username":"auditroot","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(bootstrap), None)
            .await
            .0,
        201
    );
    for name in ["one", "two", "three"] {
        let body = format!(
            r#"{{"username":"audit-{name}","password":"viewer password 123","role":"viewer"}}"#
        );
        assert_eq!(
            request(address, "POST", "/v1/users", Some(&body), None)
                .await
                .0,
            201
        );
    }
    let (status, _, first_body) = request(
        address,
        "GET",
        "/v1/audit/users?after=0&limit=2",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let first = json(&first_body);
    let first_records = first["records"].as_array().unwrap();
    assert_eq!(first_records.len(), 2);
    assert_eq!(first["has_more"], true);
    assert_eq!(first["next_after"], first_records[1]["id"]);
    assert_eq!(first["capacity"], 100000);
    assert_eq!(first["stored_records"], 5);
    let latest = first["latest_id"].as_i64().unwrap();
    let after = first["next_after"].as_i64().unwrap();
    let (status, _, login_body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"audit-one","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let viewer_token = json(&login_body)["token"].as_str().unwrap().to_owned();
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/audit/users",
            None,
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request_with_token(address, "GET", "/v1/audit/users", None, None, None)
            .await
            .0,
        401
    );
    let (status, _, next_body) = request(
        address,
        "GET",
        &format!("/v1/audit/users?after={after}&limit=2"),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let next = json(&next_body);
    assert_eq!(next["records"].as_array().unwrap().len(), 2);
    assert!(next["records"][0]["id"].as_i64().unwrap() > after);
    for invalid in [
        "after=-1",
        "after=1&after=2",
        "limit=0",
        "limit=101",
        "limit=1&limit=2",
        "unknown=1",
        "after=+1",
        "after=18446744073709551616",
    ] {
        assert_eq!(
            request(
                address,
                "GET",
                &format!("/v1/audit/users?{invalid}"),
                None,
                None
            )
            .await
            .0,
            400,
            "query {invalid}"
        );
    }

    let through_id = first_records[0]["id"].as_i64().unwrap();
    let stale = format!(
        r#"{{"through_id":{through_id},"expected_latest_id":{}}}"#,
        latest - 1
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/audit/users/prune",
            Some(&stale),
            None,
            Some(&viewer_token)
        )
        .await
        .0,
        403
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/audit/users/prune",
            Some(&stale),
            None,
            None
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request(address, "POST", "/v1/audit/users/prune", Some(&stale), None)
            .await
            .0,
        409
    );
    let (status, _, unchanged_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&unchanged_body)["latest_id"], latest);
    assert_eq!(json(&unchanged_body)["pruned_through"], 0);

    let valid = format!(r#"{{"through_id":{through_id},"expected_latest_id":{latest}}}"#);
    let (status, _, prune_body) =
        request(address, "POST", "/v1/audit/users/prune", Some(&valid), None).await;
    assert_eq!(status, 200);
    let prune = json(&prune_body);
    assert!(prune["pruned_records"].as_u64().unwrap() >= 1);
    assert_eq!(prune["record"]["action"], "prune");
    assert_eq!(prune["record"]["through_id"], through_id);
    assert_eq!(prune["record"]["actor_kind"], "system");
    let (status, _, after_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    assert_eq!(status, 200);
    let after = json(&after_body);
    assert!(after["truncated"].as_bool().unwrap());
    assert_eq!(after["pruned_through"], through_id);
    assert!(after["oldest_id"].as_i64().unwrap() > through_id);
    assert!(after["latest_id"].as_i64().unwrap() > latest);
    assert_eq!(
        after["records"].as_array().unwrap().last().unwrap()["action"],
        "prune"
    );
}

#[tokio::test]
async fn audit_append_failure_rolls_back_user_password_and_session_mutations() {
    let (address, _manager, directory) = server().await;
    let bootstrap = r#"{"username":"auditroot","password":"correct horse battery"}"#;
    assert_eq!(
        request(address, "POST", "/v1/auth/bootstrap", Some(bootstrap), None)
            .await
            .0,
        201
    );
    let target = r#"{"username":"auditvictim","password":"viewer password 123","role":"viewer"}"#;
    let (status, _, body) = request(address, "POST", "/v1/users", Some(target), None).await;
    assert_eq!(status, 201);
    let target_id = json(&body)["user"]["id"].as_i64().unwrap();
    let (status, _, body) = request_with_token(
        address,
        "POST",
        "/v1/auth/login",
        Some(r#"{"username":"auditvictim","password":"viewer password 123"}"#),
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let victim_token = json(&body)["token"].as_str().unwrap().to_owned();
    let (_, _, before_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    let before = json(&before_body);
    let database = directory.path().join("state.admin-users.sqlite3");
    let connection = rusqlite::Connection::open(database).unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER reject_audit_append BEFORE INSERT ON admin_audit
         BEGIN SELECT RAISE(ABORT, 'owned fixture audit failure'); END;",
        )
        .unwrap();

    let attempted =
        r#"{"username":"audit-failed","password":"viewer password 123","role":"viewer"}"#;
    assert_eq!(
        request(address, "POST", "/v1/users", Some(attempted), None)
            .await
            .0,
        503
    );
    assert_eq!(
        request(
            address,
            "PUT",
            &format!("/v1/users/{target_id}"),
            Some(r#"{"password":"replacement password 123"}"#),
            None,
        )
        .await
        .0,
        503
    );
    assert_eq!(
        request(
            address,
            "DELETE",
            &format!("/v1/users/{target_id}"),
            None,
            None
        )
        .await
        .0,
        503
    );
    connection
        .execute_batch("DROP TRIGGER reject_audit_append")
        .unwrap();

    let (status, _, users_body) = request(address, "GET", "/v1/users", None, None).await;
    assert_eq!(status, 200);
    let users = json(&users_body);
    assert!(
        users["users"]
            .as_array()
            .unwrap()
            .iter()
            .all(|user| user["username"] != "audit-failed")
    );
    assert!(
        users["users"]
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["id"] == target_id)
    );
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/status",
            None,
            None,
            Some(&victim_token)
        )
        .await
        .0,
        200,
        "password-update rollback must retain the existing session"
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"auditvictim","password":"replacement password 123"}"#),
            None,
            None,
        )
        .await
        .0,
        401
    );
    assert_eq!(
        request_with_token(
            address,
            "POST",
            "/v1/auth/login",
            Some(r#"{"username":"auditvictim","password":"viewer password 123"}"#),
            None,
            None,
        )
        .await
        .0,
        200
    );
    let (status, _, after_body) = request(address, "GET", "/v1/audit/users", None, None).await;
    assert_eq!(status, 200);
    let after = json(&after_body);
    assert_eq!(after["latest_id"], before["latest_id"]);
    assert_eq!(after["records"], before["records"]);
}

struct HeldProofStore {
    inner: FileConfigStore,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl hangang::config_store::ConfigStore for HeldProofStore {
    fn supports_sequenced_operation_cas(&self) -> bool {
        true
    }
    async fn lookup_commit_receipt_v2(
        &self,
        _authority_id: &str,
        acceptance_seq: u64,
    ) -> hangang::config_store::StoreResult<hangang::config_store::SequencedReceiptObservation>
    {
        if acceptance_seq == 9_007_199_254_740_991 {
            return Err(hangang::config_store::StoreError::Unavailable(
                anyhow::anyhow!("private-v2-receipt-database-detail"),
            ));
        }
        self.entered.notify_one();
        self.release.notified().await;
        Ok(hangang::config_store::SequencedReceiptObservation {
            receipt: None,
            high_water: 0,
            stored_records: 0,
            capacity: 100000,
            registered_authorities: 0,
            authority_capacity: 4096,
            writes_available: true,
        })
    }
    fn supports_commit_receipts(&self) -> bool {
        true
    }
    async fn lookup_commit_receipt(
        &self,
        _authority_id: &str,
        operation_id: &str,
    ) -> hangang::config_store::StoreResult<hangang::config_store::CommitReceiptObservation> {
        if operation_id == "ffffffffffffffffffffffffffffffff" {
            return Err(hangang::config_store::StoreError::Unavailable(
                anyhow::anyhow!("private-receipt-database-detail"),
            ));
        }
        self.entered.notify_one();
        self.release.notified().await;
        Ok(hangang::config_store::CommitReceiptObservation {
            receipt: None,
            stored_records: 0,
            capacity: 100000,
            writes_available: true,
        })
    }
    fn supports_operation_cas(&self) -> bool {
        true
    }
    async fn load_current_operation_proof(
        &self,
    ) -> hangang::config_store::StoreResult<Option<hangang::config_store::OperationProof>> {
        self.entered.notify_one();
        self.release.notified().await;
        Ok(None)
    }
    async fn load_latest(
        &self,
    ) -> hangang::config_store::StoreResult<Option<hangang::config_store::Stored>> {
        hangang::config_store::ConfigStore::load_latest(&self.inner).await
    }

    async fn bootstrap(
        &self,
        initial: Config,
    ) -> hangang::config_store::StoreResult<hangang::config_store::Stored> {
        hangang::config_store::ConfigStore::bootstrap(&self.inner, initial).await
    }

    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        next: Config,
    ) -> hangang::config_store::StoreResult<hangang::config_store::CasResult> {
        hangang::config_store::ConfigStore::compare_and_swap(&self.inner, epoch, expected, next)
            .await
    }

    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: std::time::Duration,
    ) -> hangang::config_store::StoreResult<()> {
        hangang::config_store::ConfigStore::publish_challenge(
            &self.inner,
            token,
            key_authorization,
            ttl,
        )
        .await
    }

    async fn lookup_challenge(
        &self,
        token: &str,
    ) -> hangang::config_store::StoreResult<Option<String>> {
        hangang::config_store::ConfigStore::lookup_challenge(&self.inner, token).await
    }

    async fn withdraw_challenge(&self, token: &str) -> hangang::config_store::StoreResult<()> {
        hangang::config_store::ConfigStore::withdraw_challenge(&self.inner, token).await
    }
}

#[tokio::test]
async fn current_operation_proof_matches_sql_write_and_survives_reopen() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("authority.db");
    let store = Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let initial = Config::default();
    store.bootstrap(initial.clone()).await.unwrap();
    let (address, manager) = server_on(
        directory.path().join("seed.json"),
        initial,
        Some(store.clone()),
        false,
        64,
        16,
    )
    .await;
    manager.reload_file().await.unwrap();
    let (status, headers, body) =
        request(address, "GET", "/v1/config/operation-proof", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(json(&body)["supported"], true);
    assert!(json(&body)["proof"].is_null());
    let route = r#"{"id":"proof-route","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    assert_eq!(
        request(address, "POST", "/v1/routes/http", Some(route), Some(0))
            .await
            .0,
        201
    );
    let records = config_operation_records(address).await;
    assert_eq!(records.len(), 1);
    let (status, _, body) = request(address, "GET", "/v1/config/operation-proof", None, None).await;
    assert_eq!(status, 200);
    let response = json(&body);
    assert_eq!(response["scope"], "configuration_authority");
    assert_eq!(response["proof"]["revision"], 1);
    for key in ["authority_id", "operation_id", "candidate_sha256"] {
        assert_eq!(response["proof"]["stamp"][key], records[0][key]);
    }
    let reopened = SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap();
    assert_eq!(
        serde_json::to_value(reopened.load_current_operation_proof().await.unwrap()).unwrap(),
        response["proof"]
    );
    // Ungoverned legacy writes cannot retain the previous operation's claim.
    let current = store.load_latest().await.unwrap().unwrap();
    store
        .compare_and_swap(&current.epoch, 1, current.config)
        .await
        .unwrap();
    assert!(
        store
            .load_current_operation_proof()
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(config_operation_records(address).await.len(), 1);
}

#[tokio::test]
async fn current_operation_proof_reports_unsupported_and_rejects_invalid_requests() {
    let (address, _, _directory) = server().await;
    let (status, _, body) = request(address, "GET", "/v1/config/operation-proof", None, None).await;
    assert_eq!(status, 200);
    assert_eq!(json(&body)["supported"], false);
    assert!(json(&body)["proof"].is_null());
    assert_eq!(
        request(address, "GET", "/v1/config/operation-proof?x=1", None, None)
            .await
            .0,
        400
    );
    assert_eq!(
        request(address, "POST", "/v1/config/operation-proof", None, None)
            .await
            .0,
        405
    );
    assert_eq!(
        request_with_token(
            address,
            "GET",
            "/v1/config/operation-proof",
            None,
            None,
            None
        )
        .await
        .0,
        401
    );
}

#[tokio::test]
async fn current_operation_proof_rechecks_authority_after_remote_wait() {
    use hangang::config_store::ConfigStore;
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("held.json");
    let initial = Config::default();
    let inner = FileConfigStore::new(state_path.clone());
    inner.bootstrap(initial.clone()).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(HeldProofStore {
        inner,
        entered: entered.clone(),
        release: release.clone(),
    });
    let (address, _) = server_on(state_path, initial, Some(store), false, 64, 16).await;
    let token = account_admin_token(address).await;
    let read = tokio::spawn({
        let token = token.clone();
        async move {
            request_with_token(
                address,
                "GET",
                "/v1/config/operation-proof",
                None,
                None,
                Some(&token),
            )
            .await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    revoke_account_session(address, &token).await;
    release.notify_one();
    let (status, _, body) = read.await.unwrap();
    assert_eq!(status, 403);
    assert!(json(&body).get("proof").is_none());
}

#[tokio::test]
async fn operation_aware_cas_failure_never_falls_back_to_legacy_write() {
    use hangang::config_store::ConfigStore;
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("no-fallback.json");
    let initial = Config::default();
    let inner = FileConfigStore::new(state_path.clone());
    inner.bootstrap(initial.clone()).await.unwrap();
    // This fixture advertises operation-aware support but its operation CAS
    // rejects writes. Its ordinary CAS would succeed if incorrectly called.
    let store = Arc::new(HeldProofStore {
        inner,
        entered: Arc::new(tokio::sync::Notify::new()),
        release: Arc::new(tokio::sync::Notify::new()),
    });
    let (address, manager) =
        server_on(state_path, initial, Some(store.clone()), false, 64, 16).await;
    manager.reload_file().await.unwrap();
    let route = r#"{"id":"must-not-write","path_prefix":"/","backends":["http://127.0.0.1:9"]}"#;
    let (status, _, _) = request(address, "POST", "/v1/routes/http", Some(route), Some(0)).await;
    assert!(
        status >= 400,
        "failed operation CAS must not become success"
    );
    assert_eq!(manager.active.load().config.revision, 0);
    assert_eq!(
        store.load_latest().await.unwrap().unwrap().config.revision,
        0
    );
    let records = config_operation_records(address).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["state"], "indeterminate");
}

#[tokio::test]
async fn sequenced_commit_receipt_is_historical_after_later_http_write() {
    use hangang::config_store::{ConfigStore, SqliteConfigStore};
    let directory = tempfile::tempdir().unwrap();
    let db = directory.path().join("receipts.db");
    let store = Arc::new(SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap());
    let initial = Config::default();
    store.bootstrap(initial.clone()).await.unwrap();
    let (address, manager) = server_on(
        directory.path().join("seed.json"),
        initial,
        Some(store),
        false,
        64,
        16,
    )
    .await;
    manager.reload_file().await.unwrap();
    for (revision, id) in [(0, "first"), (1, "second")] {
        let route =
            format!(r#"{{"id":"{id}","path_prefix":"/{id}","backends":["http://127.0.0.1:9"]}}"#);
        assert_eq!(
            request(
                address,
                "POST",
                "/v1/routes/http",
                Some(&route),
                Some(revision)
            )
            .await
            .0,
            201
        );
    }
    let records = config_operation_records(address).await;
    let first = &records[0];
    let authority = first["authority_id"].as_str().unwrap();
    let seq = first["id"].as_u64().unwrap();
    assert_eq!(first["receipt_version"], 2);
    assert_eq!(
        first["operation_id"],
        hangang::config_store::canonical_operation_id(authority, seq).unwrap()
    );
    let path =
        format!("/v1/config/commit-receipt-v2?authority_id={authority}&acceptance_seq={seq}");
    let (status, headers, body) = request(address, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let observation = json(&body);
    assert_eq!(observation["supported"], true);
    assert_eq!(observation["scope"], "configuration_authority");
    assert_eq!(observation["stored_records"], 2);
    assert_eq!(observation["capacity"], 100000);
    assert_eq!(observation["writes_available"], true);
    assert_eq!(observation["high_water"], 2);
    assert_eq!(observation["registered_authorities"], 1);
    assert_eq!(observation["authority_capacity"], 4096);
    assert_eq!(observation["receipt"]["stamp"]["acceptance_seq"], seq);
    assert_eq!(observation["receipt"]["revision"], 1);
    for key in ["authority_id", "operation_id", "candidate_sha256"] {
        assert_eq!(observation["receipt"]["stamp"][key], first[key]);
    }
    let reopened = SqliteConfigStore::open(db.to_str().unwrap()).await.unwrap();
    assert_eq!(
        serde_json::to_value(
            reopened
                .lookup_commit_receipt_v2(authority, seq)
                .await
                .unwrap()
                .receipt
        )
        .unwrap(),
        observation["receipt"]
    );
    assert_eq!(manager.active.load().config.revision, 2);
    assert_eq!(
        reopened
            .load_latest()
            .await
            .unwrap()
            .unwrap()
            .config
            .revision,
        2
    );
    let path = format!("/v1/config/commit-receipt-v2?authority_id={authority}&acceptance_seq=999");
    let (status, _, body) = request(address, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    assert!(json(&body)["receipt"].is_null());
    assert_eq!(json(&body)["stored_records"], 2);
}

#[tokio::test]
async fn retained_commit_receipt_validates_query_and_reports_unsupported() {
    let (address, _, _directory) = server().await;
    let query = "authority_id=11111111111111111111111111111111&operation_id=22222222222222222222222222222222";
    let path = format!("/v1/config/commit-receipt?{query}");
    let (status, headers, body) = request(address, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let observation = json(&body);
    assert_eq!(observation["supported"], false);
    for field in ["receipt", "stored_records", "capacity", "writes_available"] {
        assert!(observation[field].is_null());
    }
    assert_eq!(
        request_with_token(address, "GET", &path, None, None, None)
            .await
            .0,
        401
    );
    assert_eq!(request(address, "POST", &path, None, None).await.0, 405);
    for invalid in [
        String::new(),
        "?".into(),
        "?authority_id=11111111111111111111111111111111".into(),
        format!("?{query}&extra=0"),
        format!("?{query}&operation_id=22222222222222222222222222222222"),
        format!("?{}", query.replace('1', "A")),
        format!("?{}", query.replace("operation_id=", "operation_id=x")),
    ] {
        assert_eq!(
            request(
                address,
                "GET",
                &format!("/v1/config/commit-receipt{invalid}"),
                None,
                None
            )
            .await
            .0,
            400,
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn retained_commit_receipt_rechecks_after_wait_and_redacts_read_failures() {
    use hangang::config_store::ConfigStore;
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("held-receipt.json");
    let initial = Config::default();
    let inner = FileConfigStore::new(state_path.clone());
    inner.bootstrap(initial.clone()).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(HeldProofStore {
        inner,
        entered: entered.clone(),
        release: release.clone(),
    });
    let (address, _) = server_on(state_path, initial, Some(store), false, 64, 16).await;
    let token = account_admin_token(address).await;
    let read = tokio::spawn({
        let token = token.clone();
        async move {
            request_with_token(address, "GET", "/v1/config/commit-receipt?authority_id=11111111111111111111111111111111&operation_id=22222222222222222222222222222222", None, None, Some(&token)).await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    revoke_account_session(address, &token).await;
    release.notify_one();
    let (status, _, body) = read.await.unwrap();
    assert_eq!(status, 403);
    assert!(json(&body).get("receipt").is_none());
    let (status, headers, body) = request(address, "GET", "/v1/config/commit-receipt?authority_id=11111111111111111111111111111111&operation_id=ffffffffffffffffffffffffffffffff", None, None).await;
    assert_eq!(status, 503);
    assert_eq!(headers["cache-control"], "no-store");
    assert!(
        !String::from_utf8(body)
            .unwrap()
            .contains("private-receipt-database-detail")
    );
}

#[tokio::test]
async fn sequenced_commit_receipt_validates_query_and_reports_unsupported() {
    let (address, _, _directory) = server().await;
    let query = "authority_id=11111111111111111111111111111111&acceptance_seq=1";
    let path = format!("/v1/config/commit-receipt-v2?{query}");
    let (status, headers, body) = request(address, "GET", &path, None, None).await;
    assert_eq!(status, 200);
    assert_eq!(headers["cache-control"], "no-store");
    let observation = json(&body);
    assert_eq!(observation["supported"], false);
    for field in [
        "receipt",
        "stored_records",
        "capacity",
        "writes_available",
        "high_water",
        "registered_authorities",
        "authority_capacity",
    ] {
        assert!(observation[field].is_null());
    }
    assert_eq!(
        request_with_token(address, "GET", &path, None, None, None)
            .await
            .0,
        401
    );
    assert_eq!(request(address, "POST", &path, None, None).await.0, 405);
    for invalid in [
        String::new(),
        "?".into(),
        "?authority_id=11111111111111111111111111111111".into(),
        format!("?{query}&extra=0"),
        format!("?{}", query.replace("acceptance_seq=1", "acceptance_seq=0")),
        format!(
            "?{}",
            query.replace("acceptance_seq=1", "acceptance_seq=01")
        ),
        format!(
            "?{}",
            query.replace("acceptance_seq=1", "acceptance_seq=9007199254740992")
        ),
        format!(
            "?{}",
            query.replace("acceptance_seq=1", "acceptance_seq=%2b1")
        ),
        format!("?{query}&acceptance_seq=1"),
        format!("?{}", query.replace('1', "A")),
        format!("?{}", query.replace("acceptance_seq=", "acceptance_seq=x")),
    ] {
        assert_eq!(
            request(
                address,
                "GET",
                &format!("/v1/config/commit-receipt-v2{invalid}"),
                None,
                None
            )
            .await
            .0,
            400,
            "{invalid}"
        );
    }
}

#[tokio::test]
async fn sequenced_commit_receipt_rechecks_after_wait_and_redacts_read_failures() {
    use hangang::config_store::ConfigStore;
    let directory = tempfile::tempdir().unwrap();
    let state_path = directory.path().join("held-receipt.json");
    let initial = Config::default();
    let inner = FileConfigStore::new(state_path.clone());
    inner.bootstrap(initial.clone()).await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let store = Arc::new(HeldProofStore {
        inner,
        entered: entered.clone(),
        release: release.clone(),
    });
    let (address, _) = server_on(state_path, initial, Some(store), false, 64, 16).await;
    let token = account_admin_token(address).await;
    let read = tokio::spawn({
        let token = token.clone();
        async move {
            request_with_token(address, "GET", "/v1/config/commit-receipt-v2?authority_id=11111111111111111111111111111111&acceptance_seq=1", None, None, Some(&token)).await
        }
    });
    tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
        .await
        .unwrap();
    revoke_account_session(address, &token).await;
    release.notify_one();
    let (status, _, body) = read.await.unwrap();
    assert_eq!(status, 403);
    assert!(json(&body).get("receipt").is_none());
    let (status, headers, body) = request(address, "GET", "/v1/config/commit-receipt-v2?authority_id=11111111111111111111111111111111&acceptance_seq=9007199254740991", None, None).await;
    assert_eq!(status, 503);
    assert_eq!(headers["cache-control"], "no-store");
    assert!(
        !String::from_utf8(body)
            .unwrap()
            .contains("private-v2-receipt-database-detail")
    );
}
