//! Console decision APIs through the administration broker and a real
//! exporter process core: administrator-only access, forward lookup by
//! subject without forwarding the raw ID, filtering, pagination and request
//! detail.

use arc_swap::ArcSwap;
use hangang::{
    admin::{Admin, Manager},
    config::{Config, Snapshot},
    decision,
    metrics::Metrics,
    policy::PolicyPool,
    tcp::TcpManager,
};
use hyper::{Request, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex};

const TOKEN: &str = "decision-admin-test-token";

fn runtime() -> Arc<hangang::config::HttpRuntime> {
    let config: Config = serde_json::from_value(serde_json::json!({
        "revision": 5,
        "http": [{"id": "reports", "hosts": ["app.example.test"], "path_prefix": "/api/",
                  "backends": ["http://127.0.0.1:9"]}]
    }))
    .unwrap();
    Snapshot::new(config).unwrap().http[0].clone()
}

async fn serve(dir: &tempfile::TempDir, decisions: Option<Arc<decision::Emitter>>) -> String {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let state_path = dir.path().join("admin-state.json");
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = Arc::new(Manager {
        active: active.clone(),
        tcp: Arc::new(TcpManager::new(active, metrics.clone(), 4)),
        policy: Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1)),
        metrics,
        state_path: state_path.clone(),
        config_store: None,
        writes: Mutex::new(()),
        transactions: Arc::new(tokio::sync::Semaphore::new(8)),
        externally_managed: false,
        ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        stopping: std::sync::atomic::AtomicBool::new(false),
        withdrawing: std::sync::atomic::AtomicBool::new(false),
        authority_epoch: std::sync::Mutex::new(None),
        store_health: Default::default(),
    });
    let admin = Arc::new(Admin {
        decisions,
        plugins: None,
        fleet_observer: None,
        fleet_collector: None,
        acme_status: None,
        file_tls_enabled: false,
        manager,
        token: Arc::new(TOKEN.to_owned()),
        users: Arc::new(
            hangang::admin_users::Store::open(state_path.with_extension("users.sqlite3")).unwrap(),
        ),
        traffic: Arc::new(hangang::traffic::TrafficHistory::default()),
        docker: None,
        lifecycle: None,
        update_status_path: None,
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
        viewer_requests: Arc::new(tokio::sync::Semaphore::new(Admin::VIEWER_REQUEST_LIMIT)),
        public_requests: Arc::new(tokio::sync::Semaphore::new(Admin::PUBLIC_REQUEST_LIMIT)),
        auth_requests: Arc::new(tokio::sync::Semaphore::new(Admin::AUTH_REQUEST_LIMIT)),
        observer_requests: Arc::new(tokio::sync::Semaphore::new(Admin::OBSERVER_REQUEST_LIMIT)),
        events: Arc::new(tokio::sync::Semaphore::new(Admin::EVENT_STREAM_LIMIT)),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
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
    format!("http://{address}")
}

async fn call(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: String,
    token: impl Into<Option<String>>,
    body: Option<&str>,
) -> (u16, serde_json::Value) {
    let token: Option<String> = token.into();
    let mut request = client.request(method, url);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request
            .header("content-type", "application/json")
            .body(body.to_owned());
    }
    let response = request.send().await.unwrap();
    let status = response.status().as_u16();
    let text = response.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

async fn viewer_token(client: &reqwest::Client, base: &str) -> String {
    let operator = r#"{"username":"operator","password":"correct horse battery"}"#;
    let (status, _) = call(
        client,
        reqwest::Method::POST,
        format!("{base}/v1/auth/bootstrap"),
        Some(TOKEN.to_owned()),
        Some(operator),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _) = call(
        client,
        reqwest::Method::POST,
        format!("{base}/v1/users"),
        Some(TOKEN.to_owned()),
        Some(r#"{"username":"viewer","password":"viewer password 123","role":"viewer"}"#),
    )
    .await;
    assert_eq!(status, 201);
    let (status, body) = call(
        client,
        reqwest::Method::POST,
        format!("{base}/v1/auth/login"),
        None::<String>,
        Some(r#"{"username":"viewer","password":"viewer password 123"}"#),
    )
    .await;
    assert_eq!(status, 200);
    body["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn decision_apis_are_admin_only_filtered_paginated_and_pseudonymous() {
    let dir = tempfile::tempdir().unwrap();
    let exporter = hangang_decision_exporter::Config {
        ingest_socket: dir.path().join("ingest.sock"),
        query_socket: dir.path().join("query.sock"),
        store: dir.path().join("decisions.db"),
        limits: Default::default(),
        max_connections: 2,
        socket_mode: 0o600,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let exporter_task = tokio::spawn(hangang_decision_exporter::run(exporter.clone(), async {
        let _ = stopped.await;
    }));
    for _ in 0..200 {
        if exporter.query_socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let config: decision::Config = serde_json::from_value(serde_json::json!({
        "profile": "strict",
        "exporter_socket": exporter.ingest_socket,
        "query_socket": exporter.query_socket,
        "key_file": dir.path().join("keys.json"),
        "manage_keys": true,
        "rings": {"shards": 1},
    }))
    .unwrap();
    let emitter = decision::Emitter::new(config).unwrap().unwrap();
    let rng = ring::rand::SystemRandom::new();
    decision::drain::KeyKeeper::new().tick(&emitter, &rng, true);
    let route = runtime();
    for (index, subject) in ["u_alice", "u_bob", "u_alice", "u_alice", "u_bob"]
        .iter()
        .enumerate()
    {
        let mut capture = emitter.capture(&hyper::Method::GET, 5);
        capture.route(&route);
        capture.client(format!("198.51.{index}.7").parse().unwrap());
        capture.identity(decision::Identity {
            authority: decision::IdentityAuthority::Hopae,
            verdict: decision::IdentityVerdict::Authenticated,
            principal: decision::Principal::Human,
            aal: Some(1),
            factor: decision::FactorKind::Federated,
            subject: Some(decision::Subject::new(subject.as_bytes())),
            latency_us: 12,
            transport: decision::Transport::Hop1,
        });
        capture.authorization(
            decision::Authorization::ClassDenied,
            Some(77),
            None,
            decision::Transport::Grpc,
        );
        capture.refuse(
            decision::Stage::Authorization,
            decision::Reason::Pumgye(decision::Authorization::ClassDenied),
        );
        emitter.finish(capture, 403);
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    let keys = emitter.keys.load_full();
    let cx = decision::drain::Context {
        keys: &keys,
        profile: emitter.profile(),
        instance: "gw-a",
        build: "test",
        rng: &rng,
    };
    let mut connection = decision::drain::ConnectionState::new();
    decision::drain::drain_once(&emitter, &cx, &mut connection).await;
    assert_eq!(
        emitter
            .counters
            .exported
            .load(std::sync::atomic::Ordering::Relaxed),
        5
    );

    let base = serve(&dir, Some(emitter.clone())).await;
    let client = reqwest::Client::new();
    let get = |path: &str, token: Option<&str>| {
        call(
            &client,
            reqwest::Method::GET,
            format!("{base}{path}"),
            token.map(str::to_owned),
            None,
        )
    };
    // Wait for the exporter writer.
    let mut rows = 0;
    for _ in 0..200 {
        let (status, body) = get("/v1/observability/status", Some(TOKEN)).await;
        assert_eq!(status, 200);
        rows = body["store"]["rows"].as_u64().unwrap_or(0);
        if rows == 5 {
            assert_eq!(body["state"], "enabled");
            assert_eq!(body["profile"], "strict");
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(rows, 5);

    // Authentication and administrator role are required.
    let viewer = viewer_token(&client, &base).await;
    for path in [
        "/v1/observability/decisions",
        "/v1/observability/decisions/facets",
        "/v1/observability/requests/hg-0000000000000001",
        "/v1/observability/status",
    ] {
        assert_eq!(get(path, None).await.0, 401, "{path}");
        assert_eq!(get(path, Some(&viewer)).await.0, 403, "{path}");
    }
    let (status, _) = call(
        &client,
        reqwest::Method::POST,
        format!("{base}/v1/observability/decisions"),
        Some(TOKEN.to_owned()),
        Some("{}"),
    )
    .await;
    assert_eq!(status, 405);

    // Forward lookup: the raw subject never reaches the exporter or the reply.
    let (status, alice) = get(
        "/v1/observability/decisions?subject=u_alice&outcome=deny&reason=pumgye.class_denied",
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    let items = alice["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    assert!(!alice.to_string().contains("u_alice"));
    assert_eq!(alice["profile"], "strict");
    for item in items {
        assert_eq!(item["stages"][2]["decision"], "ClassDenied");
        assert_eq!(item["revisions"]["pumgye"], 77);
        assert_eq!(item["privacy"]["profile"], "strict");
        assert_eq!(item["stages"][1]["subject_sealed"], false);
    }

    // Pagination visits all five rows exactly once.
    let mut seen = std::collections::BTreeSet::new();
    let mut cursor: Option<String> = None;
    loop {
        let path = match &cursor {
            Some(c) => format!("/v1/observability/decisions?limit=2&cursor={c}"),
            None => "/v1/observability/decisions?limit=2".to_owned(),
        };
        let (status, page) = get(&path, Some(TOKEN)).await;
        assert_eq!(status, 200);
        let items = page["items"].as_array().unwrap();
        assert!(items.len() <= 2);
        for item in items {
            assert!(seen.insert(item["event_id"].as_str().unwrap().to_owned()));
        }
        match page["next_cursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len(), 5);

    // Request detail and facets.
    let request_id = alice["items"][0]["request_id"].as_str().unwrap().to_owned();
    let (status, detail) = get(
        &format!("/v1/observability/requests/{request_id}"),
        Some(TOKEN),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(detail["events"].as_array().unwrap().len(), 1);
    let (status, facets) = get("/v1/observability/decisions/facets", Some(TOKEN)).await;
    assert_eq!(status, 200);
    assert_eq!(
        facets["facets"]["reason"][0]["value"],
        "pumgye.class_denied"
    );
    assert_eq!(facets["facets"]["reason"][0]["events"], 5);

    // Bounds are enforced by the exporter and surfaced as client errors.
    for bad in [
        "limit=500",
        "from=0&to=9999999999999",
        "headers=1",
        "ip=nope",
    ] {
        let (status, _) = get(&format!("/v1/observability/decisions?{bad}"), Some(TOKEN)).await;
        assert_eq!(status, 400, "{bad}");
    }
    let (status, _) = get("/v1/observability/requests/..%2Fetc", Some(TOKEN)).await;
    assert_eq!(status, 400);

    let _ = stop.send(());
    exporter_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn decision_log_is_reported_disabled_not_empty_when_off() {
    let dir = tempfile::tempdir().unwrap();
    let base = serve(&dir, None).await;
    let client = reqwest::Client::new();
    let (status, body) = call(
        &client,
        reqwest::Method::GET,
        format!("{base}/v1/observability/decisions"),
        Some(TOKEN.to_owned()),
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["state"], "disabled");
    let mut metrics = client
        .get(format!("{base}/metrics"))
        .bearer_auth(TOKEN)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!metrics.contains("hangang_decision_events"));
    metrics.clear();
}
