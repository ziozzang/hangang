#![cfg(unix)]

use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    discovery::{Discovery, Protocol},
    docker::DockerResolver,
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::Full;
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixListener},
    sync::oneshot,
};

const REFERENCE: &str = "docker://app/edge/PORT";

struct FakeDocker {
    _directory: TempDir,
    socket: PathBuf,
    ip: Arc<Mutex<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl FakeDocker {
    async fn start(ip: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let ip = Arc::new(Mutex::new(ip.to_owned()));
        let current_ip = ip.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let current_ip = current_ip.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let current_ip = current_ip.clone();
                        async move {
                            assert_eq!(request.uri().path(), "/containers/app/json");
                            let ip = current_ip.lock().unwrap().clone();
                            let body = serde_json::to_vec(&serde_json::json!({
                                "Id":"container-a",
                                "State":{"Running":true,"StartedAt":"2026-09-14T00:00:00Z"},
                                "NetworkSettings":{"Networks":{"edge":{
                                    "IPAddress":ip,"GlobalIPv6Address":""
                                }}}
                            }))
                            .unwrap();
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            _directory: directory,
            socket,
            ip,
            task,
        }
    }

    fn set_ip(&self, ip: &str) {
        *self.ip.lock().unwrap() = ip.to_owned();
    }
}

impl Drop for FakeDocker {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(port: u16) -> Config {
    let reference = REFERENCE.replace("PORT", &port.to_string());
    serde_json::from_value(serde_json::json!({"http":[{
        "id":"docker-health", "backends":[reference],
        "balance":{"active_health":{
            "path":"/ready", "interval_ms":1000, "timeout_ms":1000,
            "healthy_statuses":[200], "unhealthy_statuses":[503],
            "healthy_successes":1, "unhealthy_http_failures":1,
            "unhealthy_tcp_failures":1, "unhealthy_timeouts":1,
            "initial_state":"checking"
        }}
    }]}))
    .unwrap()
}

async fn wait_for(mut condition: impl FnMut() -> bool, label: &str) {
    tokio::time::timeout(Duration::from_secs(4), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

async fn status_origin(
    ip: &str,
    port: u16,
    status: StatusCode,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind((ip, port)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
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
    (address, hits, task)
}

fn start_probe(
    config: &Config,
    discovery: Arc<Discovery>,
) -> (Arc<ArcSwap<Snapshot>>, Arc<PolicyPool>, Proxy) {
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()))
        .with_discovery(discovery);
    (active, policy, proxy)
}

#[tokio::test]
async fn docker_reference_runs_a_real_resolved_http_probe() {
    let (origin, hits, origin_task) = status_origin("127.0.0.1", 0, StatusCode::OK).await;
    let docker = FakeDocker::start("127.0.0.1").await;
    let config = config(origin.port());
    let reference = config.http[0].backends[0].address().to_owned();
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    discovery.refresh(&config).await.unwrap();
    assert_eq!(
        discovery.resolve(&reference, Protocol::Http).unwrap(),
        format!("http://{origin}")
    );
    let (active, policy, proxy) = start_probe(&config, discovery);
    let balancer = active.load().http[0].balancer.clone();
    assert!(!balancer.available(0), "checking starts closed");
    wait_for(
        || hits.load(Ordering::SeqCst) > 0 && balancer.available(0),
        "Docker-resolved probe qualification",
    )
    .await;
    assert_eq!(
        balancer.backend_state(0).unwrap().initial_check_pending,
        Some(false)
    );
    proxy.shutdown(Duration::from_millis(100)).await;
    policy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn legacy_healthy_docker_reference_is_actually_probed() {
    let (origin, hits, origin_task) = status_origin("127.0.0.1", 0, StatusCode::OK).await;
    let docker = FakeDocker::start("127.0.0.1").await;
    let mut config = config(origin.port());
    config.http[0]
        .balance
        .active_health
        .as_mut()
        .unwrap()
        .initial_state = hangang::balance::InitialHealthState::Healthy;
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    discovery.refresh(&config).await.unwrap();
    let (_active, policy, proxy) = start_probe(&config, discovery);
    wait_for(
        || hits.load(Ordering::SeqCst) > 0,
        "legacy Docker reference HTTP probe",
    )
    .await;
    proxy.shutdown(Duration::from_millis(100)).await;
    policy.shutdown().await;
    origin_task.abort();
}

#[tokio::test]
async fn stale_a_probe_cannot_qualify_b_after_discovery_address_changes() {
    let a = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = a.local_addr().unwrap().port();
    let (_b, b_hits, b_task) =
        status_origin("127.0.0.2", port, StatusCode::SERVICE_UNAVAILABLE).await;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let a_task = tokio::spawn(async move {
        let (mut stream, _) = a.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut chunk = [0; 512];
            let n = stream.read(&mut chunk).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&chunk[..n]);
            assert!(request.len() < 4096);
        }
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let docker = FakeDocker::start("127.0.0.1").await;
    let config = config(port);
    let reference = config.http[0].backends[0].address().to_owned();
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    discovery.refresh(&config).await.unwrap();
    let first = discovery
        .resolve_with_epoch(&reference, Protocol::Http)
        .unwrap();
    let (active, policy, proxy) = start_probe(&config, discovery.clone());
    let balancer = active.load().http[0].balancer.clone();
    tokio::time::timeout(Duration::from_secs(4), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert!(!balancer.available(0));

    docker.set_ip("127.0.0.2");
    discovery.refresh(&config).await.unwrap();
    let second = discovery
        .resolve_with_epoch(&reference, Protocol::Http)
        .unwrap();
    assert_ne!(first.epoch, second.epoch);
    assert_ne!(first.endpoint, second.endpoint);
    release_tx.send(()).unwrap();
    a_task.await.unwrap();
    wait_for(|| b_hits.load(Ordering::SeqCst) >= 1, "new B probe").await;
    assert_eq!(
        balancer.backend_state(0).unwrap().initial_check_pending,
        Some(true),
        "A's late 200 must not qualify the new Docker endpoint B"
    );
    assert!(!balancer.available(0));
    proxy.shutdown(Duration::from_millis(100)).await;
    policy.shutdown().await;
    b_task.abort();
}
