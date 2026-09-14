use arc_swap::ArcSwap;
use hangang::{
    admin::{Admin, Manager},
    config::{Config, Snapshot},
    geoip_runtime::{Published, Source, watch},
    metrics::Metrics,
    policy::PolicyPool,
    tcp::TcpManager,
};
use hyper::{Request, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::sync::CancellationToken;

const TOKEN: &str = "geoip-admin-test-token";

fn fresh_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    let marker = b"build_epoch";
    let offset = bytes
        .windows(marker.len())
        .rposition(|part| part == marker)
        .unwrap()
        + marker.len();
    assert_eq!(&bytes[offset..offset + 2], &[4, 2]);
    let now: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    bytes[offset + 2..offset + 6].copy_from_slice(&now.to_be_bytes());
    bytes
}

async fn serve(
    config: Config,
    dir: &tempfile::TempDir,
) -> (
    std::net::SocketAddr,
    Arc<Manager>,
    tokio::task::JoinHandle<()>,
) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let state_path = dir.path().join("admin-state.json");
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
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
        fleet_observer: None,
        acme_status: None,
        file_tls_enabled: false,
        manager: manager.clone(),
        token: Arc::new(TOKEN.to_owned()),
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
        observer_requests: Arc::new(tokio::sync::Semaphore::new(Admin::OBSERVER_REQUEST_LIMIT)),
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
    (address, manager, server)
}

async fn get(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    token: Option<&str>,
) -> reqwest::Response {
    let request = client.get(format!("{base}{path}"));
    let request = if let Some(token) = token {
        request.bearer_auth(token)
    } else {
        request
    };
    request.send().await.unwrap()
}

#[tokio::test]
async fn admin_geoip_status_and_lookup_are_bounded_path_free_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("private-country.mmdb");
    std::fs::write(&file, b"invalid mmdb").unwrap();
    let config = Config {
        geoip_database: Some(Source {
            file: file.clone(),
            max_file_bytes: 32 * 1024 * 1024,
            max_age_days: 14,
            reload_interval_seconds: 1,
        }),
        ..Config::default()
    };
    let (address, manager, server) = serve(config, &dir).await;
    let base = format!("http://{address}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let unauthorized = get(&client, &base, "/v1/geoip/status", None).await;
    assert_eq!(unauthorized.status().as_u16(), 401);
    assert_eq!(unauthorized.headers()["cache-control"], "no-store");
    let status = get(&client, &base, "/v1/geoip/status", Some(TOKEN)).await;
    assert_eq!(status.status().as_u16(), 200);
    assert_eq!(status.headers()["cache-control"], "no-store");
    let status: serde_json::Value = status.json().await.unwrap();
    assert_eq!(status["configured"], true);
    assert_eq!(status["ready"], false);
    assert!(!status.to_string().contains(file.to_str().unwrap()));
    let unavailable = get(
        &client,
        &base,
        "/v1/geoip/lookup?ip=81.2.69.160",
        Some(TOKEN),
    )
    .await;
    assert_eq!(unavailable.status().as_u16(), 503);
    assert!(
        !unavailable
            .text()
            .await
            .unwrap()
            .contains(file.to_str().unwrap())
    );

    let slot = manager.active.load().geoip.clone().unwrap();
    let active = manager.active.clone();
    let published: Arc<Published> = Arc::new(move |candidate| {
        active
            .load()
            .geoip
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, candidate))
    });
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(watch(slot.clone(), published, cancel.clone()));
    tokio::time::timeout(Duration::from_secs(5), async {
        while slot.status().error_code != Some("invalid_database") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let replacement = dir.path().join("fresh.mmdb");
    std::fs::write(&replacement, fresh_fixture()).unwrap();
    std::fs::rename(&replacement, &file).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !slot.status().ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let status = get(&client, &base, "/v1/geoip/status", Some(TOKEN)).await;
    let status: serde_json::Value = status.json().await.unwrap();
    assert_eq!(status["database"]["database_type"], "GeoIP2-Country");
    assert_eq!(
        status["database"]["generation_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert!(!status.to_string().contains(file.to_str().unwrap()));
    for (ip, canonical, country) in [
        ("81.2.69.160", "81.2.69.160", Some("GB")),
        ("%3A%3Affff%3A81.2.69.160", "81.2.69.160", Some("GB")),
        ("2001%3A220%3A%3A1", "2001:220::1", Some("KR")),
        ("127.0.0.1", "127.0.0.1", None),
    ] {
        let response = get(
            &client,
            &base,
            &format!("/v1/geoip/lookup?ip={ip}"),
            Some(TOKEN),
        )
        .await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.headers()["cache-control"], "no-store");
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["ip"], canonical);
        assert_eq!(body["country"].as_str(), country);
    }
    for path in [
        "/v1/geoip/lookup",
        "/v1/geoip/lookup?ip=",
        "/v1/geoip/lookup?ip=not-an-ip",
        "/v1/geoip/lookup?ip=1.1.1.1&ip=2.2.2.2",
        "/v1/geoip/lookup?ip=1.1.1.1&file=/etc/passwd",
        "/v1/geoip/status?file=/etc/passwd",
    ] {
        assert_eq!(
            get(&client, &base, path, Some(TOKEN))
                .await
                .status()
                .as_u16(),
            400,
            "{path}"
        );
    }
    assert_eq!(
        client
            .post(format!("{base}/v1/geoip/status"))
            .bearer_auth(TOKEN)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        405
    );
    cancel.cancel();
    watcher.await.unwrap();
    server.abort();
    manager.policy.shutdown().await;
}
