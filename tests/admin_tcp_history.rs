//! Real admin HTTP and SSE authorization around the instance-local TCP history.

use arc_swap::ArcSwap;
use hangang::{
    admin::{Admin, Manager},
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    tcp::TcpManager,
    tcp_history::{History, Outcome, Phase},
};
use hyper::{Request, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex};

const SYSTEM_TOKEN: &str = "tcp-history-fixture-system-token";

async fn fixture() -> (
    String,
    reqwest::Client,
    Arc<Manager>,
    tempfile::TempDir,
    tokio::task::JoinHandle<()>,
) {
    let directory = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state_path = directory.path().join("state.json");
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics {
        tcp_history: Arc::new(History::with_limits(Duration::from_secs(60), 1, 16)),
        ..Metrics::default()
    });
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
        acme_status: None,
        file_tls_enabled: false,
        manager: manager.clone(),
        token: Arc::new(SYSTEM_TOKEN.to_owned()),
        users: Arc::new(
            hangang::admin_users::Store::open(state_path.with_extension("users.sqlite3")).unwrap(),
        ),
        traffic: Arc::new(hangang::traffic::TrafficHistory::default()),
        docker: None,
        lifecycle: None,
        update_status_path: None,
        requests: Arc::new(tokio::sync::Semaphore::new(8)),
        public_requests: Arc::new(tokio::sync::Semaphore::new(Admin::PUBLIC_REQUEST_LIMIT)),
        auth_requests: Arc::new(tokio::sync::Semaphore::new(Admin::AUTH_REQUEST_LIMIT)),
        events: Arc::new(tokio::sync::Semaphore::new(Admin::EVENT_STREAM_LIMIT)),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
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
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    (
        format!("http://{address}"),
        client,
        manager,
        directory,
        server,
    )
}

async fn call(
    client: &reqwest::Client,
    base: &str,
    method: reqwest::Method,
    path: &str,
    token: Option<&str>,
    body: Option<serde_json::Value>,
) -> reqwest::Response {
    let mut request = client.request(method, format!("{base}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(&body);
    }
    request.send().await.unwrap()
}

async fn frame(response: &mut reqwest::Response, pending: &mut Vec<u8>) -> String {
    loop {
        if let Some(end) = pending.windows(2).position(|bytes| bytes == b"\n\n") {
            return String::from_utf8(pending.drain(..end + 2).collect()).unwrap();
        }
        let chunk = tokio::time::timeout(Duration::from_secs(4), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .expect("SSE stream closed unexpectedly");
        pending.extend_from_slice(&chunk);
        assert!(pending.len() < 256 * 1024);
    }
}

fn data(frame: &str) -> serde_json::Value {
    serde_json::from_str(
        frame
            .lines()
            .find_map(|line| line.strip_prefix("data: "))
            .unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn drop_only_tcp_recent_policy_keeps_api_cursor_private_and_sse_counter_visible() {
    let (base, client, manager, _directory, server) = fixture().await;
    let credentials = serde_json::json!({"username":"operator","password":"correct horse battery"});
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/auth/bootstrap",
            Some(SYSTEM_TOKEN),
            Some(credentials.clone())
        )
        .await
        .status(),
        201
    );
    let login = call(
        &client,
        &base,
        reqwest::Method::POST,
        "/v1/auth/login",
        None,
        Some(credentials),
    )
    .await;
    let token = login.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut stream = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/events",
        Some(&token),
        None,
    )
    .await;
    let mut pending = Vec::new();
    assert!(
        frame(&mut stream, &mut pending)
            .await
            .starts_with("event: status\n")
    );
    let config: Config = serde_json::from_value(serde_json::json!({
        "revision":1,"settings":{"tcp_recent_recording":{"default_action":"drop","rules":[]}}
    }))
    .unwrap();
    manager
        .active
        .store(Arc::new(Snapshot::new(config).unwrap()));
    let history = manager.metrics.tcp_history.clone();
    let guard = history.begin_with_policy(
        "127.0.0.1:41000".parse().unwrap(),
        "127.0.0.1:11235".parse().unwrap(),
        manager.active.clone(),
    );
    drop(guard);
    let recent = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/connections/tcp/recent?after=0",
        Some(&token),
        None,
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap();
    assert!(recent["records"].as_array().unwrap().is_empty());
    assert_eq!(recent["latest_event_id"], "0");
    assert_eq!(recent["next_after"], "0");
    assert_eq!(recent["filtered_total"], "1");
    assert_eq!(recent["omitted_total"], "0");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let next = frame(&mut stream, &mut pending).await;
            if next.starts_with("event: tcp_connections\n") {
                let batch = data(&next);
                if batch["recent"]["filtered_total"] == "1" {
                    assert!(batch["recent"]["records"].as_array().unwrap().is_empty());
                    assert_eq!(batch["recent"]["next_after"], "0");
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "revision":2,"settings":{"tcp_recent_recording":{"default_action":"record","rules":[]}}
    }))
    .unwrap();
    manager
        .active
        .store(Arc::new(Snapshot::new(config).unwrap()));
    drop(history.begin_with_policy(
        "127.0.0.1:41001".parse().unwrap(),
        "127.0.0.1:11235".parse().unwrap(),
        manager.active.clone(),
    ));
    let recorded = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/connections/tcp/recent?after=0",
        Some(&token),
        None,
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap();
    assert_eq!(recorded["records"][0]["event_id"], "1");
    assert_eq!(recorded["records"][0]["policy_revision"], "2");
    assert_eq!(recorded["filtered_total"], "1");
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::GET,
            "/v1/connections/tcp/recent",
            None,
            None
        )
        .await
        .status(),
        401
    );
    server.abort();
}

#[tokio::test]
async fn tcp_history_is_admin_only_lossless_and_session_fenced() {
    let (base, client, manager, _directory, server) = fixture().await;
    let active_path = "/v1/connections/tcp/active";
    let recent_path = "/v1/connections/tcp/recent";
    for path in [active_path, recent_path] {
        let response = call(&client, &base, reqwest::Method::GET, path, None, None).await;
        assert_eq!(response.status(), 401);
        assert_eq!(response.headers()["cache-control"], "no-store");
    }

    let credentials = serde_json::json!({"username":"operator","password":"correct horse battery"});
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/auth/bootstrap",
            Some(SYSTEM_TOKEN),
            Some(credentials.clone())
        )
        .await
        .status(),
        201
    );
    let login = call(
        &client,
        &base,
        reqwest::Method::POST,
        "/v1/auth/login",
        None,
        Some(credentials.clone()),
    )
    .await;
    let admin_token = login.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let viewer =
        serde_json::json!({"username":"viewer","password":"viewer password 123","role":"viewer"});
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/users",
            Some(&admin_token),
            Some(viewer.clone())
        )
        .await
        .status(),
        201
    );
    let viewer_login = call(
        &client,
        &base,
        reqwest::Method::POST,
        "/v1/auth/login",
        None,
        Some(serde_json::json!({"username":"viewer","password":"viewer password 123"})),
    )
    .await;
    let viewer_token = viewer_login.json::<serde_json::Value>().await.unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();
    for path in [active_path, recent_path] {
        let response = call(
            &client,
            &base,
            reqwest::Method::GET,
            path,
            Some(&viewer_token),
            None,
        )
        .await;
        assert_eq!(response.status(), 403);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(
            call(
                &client,
                &base,
                reqwest::Method::POST,
                path,
                Some(&admin_token),
                None
            )
            .await
            .status(),
            405
        );
    }

    let history = manager.metrics.tcp_history.clone();
    let mut guard = history.begin(
        "192.0.2.10:44320".parse().unwrap(),
        "127.0.0.1:8443".parse().unwrap(),
    );
    guard.set_route("tcp-blue");
    guard.set_member(Some("blue"));
    guard.set_phase(Phase::Forwarding);
    if let Some(bytes) = guard.bytes() {
        bytes.add_upstream(9_007_199_254_740_993);
        bytes.add_downstream(17);
    }
    // With one active slot, a second connection is counted but has no record
    // or completion event. Its later close must still reach SSE subscribers.
    let untracked = history.begin(
        "192.0.2.11:44321".parse().unwrap(),
        "127.0.0.1:8443".parse().unwrap(),
    );
    assert!(untracked.bytes().is_none());
    let response = call(
        &client,
        &base,
        reqwest::Method::GET,
        active_path,
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let active = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(active["records"][0]["peer_ip"], "192.0.2.10");
    assert_eq!(active["records"][0]["route_id"], "tcp-blue");
    assert_eq!(active["records"][0]["member_id"], "blue");
    assert_eq!(active["records"][0]["bytes_upstream"], "9007199254740993");
    assert_eq!(active["active_untracked"], 1);
    assert!(active["records"][0]["connection_id"].is_string());
    assert!(active["process_id"].as_str().unwrap().len() == 16);
    let cursor = active["records"][0]["connection_id"].as_str().unwrap();
    let page = call(
        &client,
        &base,
        reqwest::Method::GET,
        &format!("{active_path}?after={cursor}&limit=1"),
        Some(&admin_token),
        None,
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap();
    assert!(page["records"].as_array().unwrap().is_empty());

    for path in [
        format!("{active_path}?after=01"),
        format!("{active_path}?after=-1"),
        format!("{active_path}?limit=0"),
        format!("{active_path}?limit=129"),
        format!("{active_path}?after=1&after=2"),
        format!("{recent_path}?token=secret"),
        format!("{recent_path}?limit=01"),
        format!("{recent_path}?after=18446744073709551616"),
    ] {
        assert_eq!(
            call(
                &client,
                &base,
                reqwest::Method::GET,
                &path,
                Some(&admin_token),
                None
            )
            .await
            .status(),
            400,
            "{path}"
        );
    }

    let mut admin_stream = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/events",
        Some(&admin_token),
        None,
    )
    .await;
    let mut viewer_stream = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/events",
        Some(&viewer_token),
        None,
    )
    .await;
    let mut admin_pending = Vec::new();
    let mut viewer_pending = Vec::new();
    assert!(
        frame(&mut admin_stream, &mut admin_pending)
            .await
            .starts_with("event: status\n")
    );
    let http = frame(&mut admin_stream, &mut admin_pending).await;
    assert!(http.starts_with("event: traffic\n"));
    assert!(data(&http)["records"].as_array().unwrap().is_empty());
    assert_eq!(data(&http)["filtered_total"], 0);
    let live = frame(&mut admin_stream, &mut admin_pending).await;
    assert!(live.starts_with("event: tcp_connections\n"));
    assert_eq!(data(&live)["active"]["records"][0]["route_id"], "tcp-blue");
    assert!(
        frame(&mut viewer_stream, &mut viewer_pending)
            .await
            .starts_with("event: status\n")
    );
    assert!(
        !frame(&mut viewer_stream, &mut viewer_pending)
            .await
            .contains("tcp_connections")
    );

    guard.set_outcome(Outcome::Eof);
    drop(guard);
    let response = call(
        &client,
        &base,
        reqwest::Method::GET,
        recent_path,
        Some(&admin_token),
        None,
    )
    .await;
    assert_eq!(response.status(), 200);
    let recent = response.json::<serde_json::Value>().await.unwrap();
    assert_eq!(recent["records"][0]["outcome"], "eof");
    assert_eq!(recent["records"][0]["bytes_upstream"], "9007199254740993");
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let next = frame(&mut admin_stream, &mut admin_pending).await;
            if next.starts_with("event: tcp_connections\n")
                && !data(&next)["recent"]["records"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            {
                break;
            }
        }
    })
    .await
    .expect("admin stream omitted completed connection");

    drop(untracked);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            let next = frame(&mut admin_stream, &mut admin_pending).await;
            if !next.starts_with("event: tcp_connections\n") {
                continue;
            }
            let snapshot = data(&next);
            if snapshot["active"]["records"].as_array().unwrap().is_empty()
                && snapshot["active"]["active_untracked"] == 0
                && snapshot["recent"]["records"].as_array().unwrap().is_empty()
            {
                break;
            }
        }
    })
    .await
    .expect("admin stream did not clear the final TCP connection");

    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/auth/logout",
            Some(&admin_token),
            None
        )
        .await
        .status(),
        204
    );
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::GET,
            recent_path,
            Some(&admin_token),
            None
        )
        .await
        .status(),
        401
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if frame(&mut admin_stream, &mut admin_pending)
                .await
                .starts_with("event: auth_expired\n")
            {
                break;
            }
        }
    })
    .await
    .expect("logout did not revoke TCP SSE access");
    server.abort();
    manager.policy.shutdown().await;
}

#[tokio::test]
async fn demoted_administrator_stream_expires_and_clears_ip_bearing_history() {
    let (base, client, manager, _directory, server) = fixture().await;
    let first = serde_json::json!({"username":"firstadmin","password":"correct horse battery"});
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/auth/bootstrap",
            Some(SYSTEM_TOKEN),
            Some(first.clone())
        )
        .await
        .status(),
        201,
    );
    let first_login = call(
        &client,
        &base,
        reqwest::Method::POST,
        "/v1/auth/login",
        None,
        Some(first),
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap();
    let first_id = first_login["user"]["id"].as_i64().unwrap();
    let first_token = first_login["token"].as_str().unwrap().to_owned();
    let second = serde_json::json!({"username":"secondadmin","password":"second correct horse battery","role":"admin"});
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::POST,
            "/v1/users",
            Some(&first_token),
            Some(second.clone())
        )
        .await
        .status(),
        201,
    );
    let second_token = call(
        &client,
        &base,
        reqwest::Method::POST,
        "/v1/auth/login",
        None,
        Some(
            serde_json::json!({"username":"secondadmin","password":"second correct horse battery"}),
        ),
    )
    .await
    .json::<serde_json::Value>()
    .await
    .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_owned();

    let history = manager.metrics.tcp_history.clone();
    let _guard = history.begin(
        "198.51.100.9:45678".parse().unwrap(),
        "127.0.0.1:8443".parse().unwrap(),
    );
    let mut stream = call(
        &client,
        &base,
        reqwest::Method::GET,
        "/v1/events",
        Some(&first_token),
        None,
    )
    .await;
    let mut pending = Vec::new();
    assert!(
        frame(&mut stream, &mut pending)
            .await
            .starts_with("event: status\n")
    );
    let http = frame(&mut stream, &mut pending).await;
    assert!(http.starts_with("event: traffic\n"));
    assert!(data(&http)["records"].as_array().unwrap().is_empty());
    let sensitive = frame(&mut stream, &mut pending).await;
    assert!(sensitive.starts_with("event: tcp_connections\n"));
    assert_eq!(
        data(&sensitive)["active"]["records"][0]["peer_ip"],
        "198.51.100.9"
    );

    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::PUT,
            &format!("/v1/users/{first_id}"),
            Some(&second_token),
            Some(serde_json::json!({"role":"viewer"})),
        )
        .await
        .status(),
        200,
    );
    assert_eq!(
        call(
            &client,
            &base,
            reqwest::Method::GET,
            "/v1/connections/tcp/active",
            Some(&first_token),
            None
        )
        .await
        .status(),
        401,
    );
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if frame(&mut stream, &mut pending)
                .await
                .starts_with("event: auth_expired\n")
            {
                break;
            }
        }
    })
    .await
    .expect("demoted administrator stream retained an IP-bearing session");
    assert!(pending.is_empty(), "frames followed the revoke signal");
    assert!(
        tokio::time::timeout(Duration::from_secs(2), stream.chunk())
            .await
            .expect("stream did not close after revocation")
            .unwrap()
            .is_none()
    );
    server.abort();
    manager.policy.shutdown().await;
}
