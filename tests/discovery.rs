#![cfg(unix)]

use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    discovery::{Discovery, Protocol, parse_reference},
    docker::DockerResolver,
    docker_connections::{ConnectionConfig, DockerConnections},
};
use http_body_util::Full;
use hyper::{Request, Response, StatusCode, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    collections::HashMap,
    convert::Infallible,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::net::UnixListener;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

#[derive(Clone)]
struct Container {
    running: bool,
    ip: String,
}

struct FakeDocker {
    _directory: TempDir,
    socket: PathBuf,
    containers: Arc<Mutex<HashMap<String, Container>>>,
    active: Arc<AtomicUsize>,
    maximum_active: Arc<AtomicUsize>,
    delay: Arc<Mutex<Duration>>,
    _task: AbortOnDropHandle<()>,
}

impl FakeDocker {
    async fn start(delay: Duration) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let containers = Arc::new(Mutex::new(HashMap::<String, Container>::new()));
        let active = Arc::new(AtomicUsize::new(0));
        let maximum_active = Arc::new(AtomicUsize::new(0));
        let delay = Arc::new(Mutex::new(delay));
        let task_containers = containers.clone();
        let task_active = active.clone();
        let task_maximum = maximum_active.clone();
        let task_delay = delay.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let containers = task_containers.clone();
                let active = task_active.clone();
                let maximum = task_maximum.clone();
                let delay = task_delay.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                        let containers = containers.clone();
                        let active = active.clone();
                        let maximum = maximum.clone();
                        let delay = delay.clone();
                        async move {
                            let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                            maximum.fetch_max(current, Ordering::SeqCst);
                            let _guard = ActiveGuard(active);
                            let delay = *delay.lock().unwrap();
                            tokio::time::sleep(delay).await;
                            let name = request
                                .uri()
                                .path()
                                .strip_prefix("/containers/")
                                .and_then(|path| path.strip_suffix("/json"))
                                .unwrap_or_default();
                            let container = containers.lock().unwrap().get(name).cloned();
                            let (status, body) = if let Some(container) = container {
                                (
                                    StatusCode::OK,
                                    serde_json::to_vec(&serde_json::json!({
                                        "State": {"Running": container.running},
                                        "NetworkSettings": {"Networks": {
                                            "edge": {
                                                "IPAddress": container.ip,
                                                "GlobalIPv6Address": ""
                                            }
                                        }}
                                    }))
                                    .unwrap(),
                                )
                            } else {
                                (StatusCode::NOT_FOUND, b"missing".to_vec())
                            };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(status)
                                    .body(Full::new(Bytes::from(body)))
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
        Self {
            _directory: directory,
            socket,
            containers,
            active,
            maximum_active,
            delay,
            _task: AbortOnDropHandle::new(task),
        }
    }

    fn set(&self, name: &str, running: bool, ip: &str) {
        self.containers.lock().unwrap().insert(
            name.to_owned(),
            Container {
                running,
                ip: ip.to_owned(),
            },
        );
    }

    fn set_delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn config(http: Vec<String>, tcp: Vec<String>) -> Config {
    serde_json::from_value(serde_json::json!({
        "http": if http.is_empty() { Vec::<serde_json::Value>::new() } else { vec![serde_json::json!({"id":"web","backends":http})] },
        "tcp": if tcp.is_empty() { Vec::<serde_json::Value>::new() } else { vec![serde_json::json!({"id":"stream","listen":"127.0.0.1:19001","backends":tcp})] }
    }))
    .unwrap()
}

#[test]
fn parses_only_canonical_docker_references() {
    let reference = parse_reference("docker://api-1/edge_net/8080")
        .unwrap()
        .unwrap();
    assert_eq!(reference.container, "api-1");
    assert_eq!(reference.network, "edge_net");
    assert_eq!(reference.port, 8080);
    assert!(parse_reference("https://example.test").unwrap().is_none());
    for invalid in [
        "docker://",
        "docker://api",
        "docker://api/edge",
        "docker://api/edge/0",
        "docker://api/edge/080",
        "docker://api/edge/65536",
        "docker://api/edge/-1",
        "docker://api/bad network/80",
        "docker://bad@name/edge/80",
        "docker://api/edge/80/extra",
        "docker://api/edge/80?query",
        "docker://api/edge/80#fragment",
    ] {
        assert!(parse_reference(invalid).is_err(), "accepted {invalid}");
    }
}

#[test]
fn native_backends_pass_through_without_a_docker_socket() {
    let discovery = Discovery::new(None);
    assert_eq!(
        discovery.resolve("https://127.0.0.1:8443", Protocol::Http),
        Some("https://127.0.0.1:8443".into())
    );
    assert_eq!(
        discovery.resolve("127.0.0.1:9000", Protocol::Tcp),
        Some("127.0.0.1:9000".into())
    );
    assert_eq!(
        discovery.resolve("docker://api/edge/80", Protocol::Http),
        None
    );
}

#[tokio::test]
async fn managed_connection_swap_and_disable_invalidate_cached_addresses_immediately() {
    let first = FakeDocker::start(Duration::ZERO).await;
    first.set("api", true, "172.20.0.2");
    let second = FakeDocker::start(Duration::ZERO).await;
    second.set("api", true, "172.20.0.9");
    let directory = tempfile::tempdir().unwrap();
    let connections = Arc::new(
        DockerConnections::open(
            directory.path().join("connection.json"),
            Some(first.socket.clone()),
        )
        .unwrap(),
    );
    let discovery = Discovery::managed(connections.clone());
    let reference = "docker://api/edge/8080";
    let configured = config(vec![reference.into()], Vec::new());
    discovery.refresh(&configured).await.unwrap();
    assert_eq!(
        discovery.resolve(reference, Protocol::Http).as_deref(),
        Some("http://172.20.0.2:8080")
    );
    connections
        .put(
            0,
            ConnectionConfig::Unix {
                socket_path: second.socket.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert_eq!(discovery.resolve(reference, Protocol::Http), None);
    discovery.refresh(&configured).await.unwrap();
    assert_eq!(
        discovery.resolve(reference, Protocol::Http).as_deref(),
        Some("http://172.20.0.9:8080")
    );
    connections
        .put(1, ConnectionConfig::Disabled)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(discovery.resolve(reference, Protocol::Http), None);
    assert!(discovery.refresh(&configured).await.is_err());
    assert_eq!(discovery.resolve(reference, Protocol::Http), None);
}

#[tokio::test]
async fn in_flight_old_daemon_refresh_cannot_publish_after_swap() {
    let first = FakeDocker::start(Duration::from_millis(150)).await;
    first.set("api", true, "172.20.0.2");
    let second = FakeDocker::start(Duration::ZERO).await;
    second.set("api", true, "172.20.0.9");
    let directory = tempfile::tempdir().unwrap();
    let connections = Arc::new(
        DockerConnections::open(
            directory.path().join("connection.json"),
            Some(first.socket.clone()),
        )
        .unwrap(),
    );
    let discovery = Discovery::managed(connections.clone());
    let reference = "docker://api/edge/8080";
    let configured = config(vec![reference.into()], Vec::new());
    let refreshing = {
        let discovery = discovery.clone();
        let configured = configured.clone();
        tokio::spawn(async move { discovery.refresh(&configured).await })
    };
    tokio::time::sleep(Duration::from_millis(25)).await;
    connections
        .put(
            0,
            ConnectionConfig::Unix {
                socket_path: second.socket.clone(),
            },
        )
        .await
        .unwrap()
        .unwrap();
    assert!(refreshing.await.unwrap().is_err());
    assert_eq!(discovery.resolve(reference, Protocol::Http), None);
    discovery.refresh(&configured).await.unwrap();
    assert_eq!(
        discovery.resolve(reference, Protocol::Http).as_deref(),
        Some("http://172.20.0.9:8080")
    );
}

#[tokio::test]
async fn refresh_tracks_ip_changes_and_removes_stopped_or_unconfigured_containers() {
    let docker = FakeDocker::start(Duration::ZERO).await;
    docker.set("api", true, "172.20.0.2");
    let discovery = Discovery::new(Some(Arc::new(DockerResolver::new(docker.socket.clone()))));
    let reference = "docker://api/edge/8080";
    let configured = config(vec![reference.into()], vec![reference.into()]);

    discovery.refresh(&configured).await.unwrap();
    assert_eq!(
        discovery.resolve(reference, Protocol::Http).unwrap(),
        "http://172.20.0.2:8080"
    );
    assert_eq!(
        discovery.resolve(reference, Protocol::Tcp).unwrap(),
        "172.20.0.2:8080"
    );

    docker.set("api", true, "172.20.0.9");
    discovery.refresh(&configured).await.unwrap();
    assert_eq!(
        discovery.resolve(reference, Protocol::Http).unwrap(),
        "http://172.20.0.9:8080"
    );

    docker.set("api", false, "172.20.0.9");
    assert!(discovery.refresh(&configured).await.is_err());
    assert_eq!(discovery.resolve(reference, Protocol::Http), None);

    docker.set("api", true, "172.20.0.10");
    discovery.refresh(&configured).await.unwrap();
    discovery.refresh(&Config::default()).await.unwrap();
    assert_eq!(discovery.resolve(reference, Protocol::Tcp), None);
}

#[tokio::test]
async fn missing_container_and_disabled_discovery_fail_closed() {
    let docker = FakeDocker::start(Duration::ZERO).await;
    let configured = config(vec!["docker://missing/edge/80".into()], Vec::new());
    let discovery = Discovery::new(Some(Arc::new(DockerResolver::new(docker.socket.clone()))));
    assert!(discovery.refresh(&configured).await.is_err());
    assert_eq!(
        discovery.resolve("docker://missing/edge/80", Protocol::Http),
        None
    );

    let disabled = Discovery::new(None);
    assert!(disabled.refresh(&configured).await.is_err());
    assert_eq!(
        disabled.resolve("docker://missing/edge/80", Protocol::Http),
        None
    );
}

#[tokio::test]
async fn refresh_never_runs_more_than_eight_inspections_at_once() {
    let docker = FakeDocker::start(Duration::from_millis(30)).await;
    let mut references = Vec::new();
    for index in 0..20 {
        let name = format!("api-{index}");
        docker.set(&name, true, &format!("172.20.1.{}", index + 1));
        references.push(format!("docker://{name}/edge/80"));
    }
    let discovery = Discovery::new(Some(Arc::new(DockerResolver::new(docker.socket.clone()))));
    discovery
        .refresh(&config(references, Vec::new()))
        .await
        .unwrap();
    assert!(docker.maximum_active.load(Ordering::SeqCst) <= 8);
    assert!(docker.maximum_active.load(Ordering::SeqCst) > 1);
    assert_eq!(docker.active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn watcher_refreshes_without_changing_the_config_revision() {
    let docker = FakeDocker::start(Duration::ZERO).await;
    docker.set("watch", true, "172.21.0.4");
    let configured = config(vec!["docker://watch/edge/80".into()], Vec::new());
    let revision = configured.revision;
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(configured).unwrap()));
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(discovery.clone().watch(active.clone(), cancel.clone()));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if discovery
                .resolve("docker://watch/edge/80", Protocol::Http)
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(active.load().config.revision, revision);
    cancel.cancel();
    watcher.await.unwrap();
}

#[tokio::test]
async fn whole_refresh_has_one_deadline_and_clears_stale_results() {
    let docker = FakeDocker::start(Duration::ZERO).await;
    docker.set("slow", true, "172.22.0.4");
    let configured = config(vec!["docker://slow/edge/80".into()], Vec::new());
    let discovery = Discovery::new(Some(Arc::new(DockerResolver::new(docker.socket.clone()))));
    discovery.refresh(&configured).await.unwrap();
    assert!(
        discovery
            .resolve("docker://slow/edge/80", Protocol::Http)
            .is_some()
    );

    let mut references = vec!["docker://slow/edge/80".to_owned()];
    for index in 0..16 {
        let name = format!("queued-{index}");
        docker.set(&name, true, &format!("172.22.1.{}", index + 1));
        references.push(format!("docker://{name}/edge/80"));
    }
    // Seventeen two-second inspections require three batches at the
    // eight-request concurrency cap, so the batch deadline must win even
    // though no individual resolver reaches its own three-second timeout.
    let delayed = config(references, Vec::new());
    docker.set_delay(Duration::from_secs(2));
    let started = tokio::time::Instant::now();
    let error = discovery.refresh(&delayed).await.unwrap_err();
    assert!(error.to_string().contains("exceeded 5 seconds"));
    assert!(started.elapsed() < Duration::from_secs(7));
    assert_eq!(
        discovery.resolve("docker://slow/edge/80", Protocol::Http),
        None
    );
}

#[tokio::test]
async fn watcher_cancellation_interrupts_a_stalled_refresh() {
    let docker = FakeDocker::start(Duration::from_secs(30)).await;
    docker.set("slow", true, "172.23.0.4");
    let configured = config(vec!["docker://slow/edge/80".into()], Vec::new());
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(configured).unwrap()));
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(discovery.watch(active, cancel.clone()));
    tokio::time::timeout(Duration::from_secs(1), async {
        while docker.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    cancel.cancel();
    tokio::time::timeout(Duration::from_millis(250), watcher)
        .await
        .expect("watcher ignored cancellation")
        .unwrap();
}

#[tokio::test]
async fn changed_docker_epoch_during_socks_dial_closes_without_payload_and_records_reason() {
    use hangang::{metrics::Metrics, tcp::TcpManager};
    use std::{net::TcpListener as StdTcpListener, os::fd::OwnedFd};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
    };

    let docker = FakeDocker::start(Duration::ZERO).await;
    docker.set("api", true, "127.0.0.1");
    let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
        docker.socket.clone(),
    )))));
    let reference = "docker://api/edge/8080";
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_address = socks.local_addr().unwrap();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let socks_task = tokio::spawn(async move {
        let (mut socket, _) = socks.accept().await.unwrap();
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        socket.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0; 10];
        socket.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect[..8], &[5, 1, 0, 1, 127, 0, 0, 1]);
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut payload = [0; 64];
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut payload))
            .await
            .unwrap()
            .unwrap()
    });
    let held = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = held.local_addr().unwrap();
    let document: Config = serde_json::from_value(serde_json::json!({"tcp":[{
        "id":"stream", "listen":listen, "backends":[reference],
        "upstream":{"socks5":{"address":socks_address.to_string()}}
    }]}))
    .unwrap();
    discovery.refresh(&document).await.unwrap();
    let first = discovery
        .resolve_with_epoch(reference, Protocol::Tcp)
        .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(document.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active, metrics.clone(), 8).with_discovery(discovery.clone());
    let prepared = manager
        .prepare_with_inherited(&document, vec![(listen, OwnedFd::from(held))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"never forward to the stale endpoint")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let pending = serde_json::to_value(metrics.tcp_history.active(None, 128)).unwrap();
    assert_eq!(pending["records"][0]["phase"], "dialing");
    assert_eq!(pending["records"][0]["bytes_upstream"], "0");

    docker.set("api", true, "127.0.0.2");
    discovery.refresh(&document).await.unwrap();
    let second = discovery
        .resolve_with_epoch(reference, Protocol::Tcp)
        .unwrap();
    assert_ne!(first, second);
    release_tx.send(()).unwrap();
    assert_eq!(
        socks_task.await.unwrap(),
        0,
        "no payload after discovery epoch changed"
    );
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(closed, Ok(0) | Err(_)));
    manager.shutdown(Duration::from_secs(1)).await;
    let recent = serde_json::to_value(metrics.tcp_history.recent(None, 128)).unwrap();
    assert_eq!(recent["records"].as_array().unwrap().len(), 1);
    let row = &recent["records"][0];
    assert_eq!(row["outcome"], "endpoint_changed");
    assert_eq!(row["phase"], "dialing");
    assert_eq!(row["bytes_upstream"], "0");
    assert_eq!(row["bytes_downstream"], "0");
    assert!(
        row.get("endpoint").is_none(),
        "resolved endpoint is not exposed"
    );
}
