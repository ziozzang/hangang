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
use http_body_util::{BodyExt, Full};
use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    os::fd::OwnedFd,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn config(http_address: &str, tcp_address: &str, listen: SocketAddr, state: &str) -> Config {
    serde_json::from_value(serde_json::json!({
        "http": [{"id":"web", "backends":[
            {"id":"a", "address":http_address, "desired_state":state}
        ], "balance":{"active_health":{
            "path":"/ready", "interval_ms":1000, "timeout_ms":100,
            "healthy_statuses":[200], "unhealthy_statuses":[503],
            "healthy_successes":1, "unhealthy_http_failures":1,
            "unhealthy_tcp_failures":1, "unhealthy_timeouts":1,
            "initial_state":"checking"
        }}}],
        "tcp": [{"id":"stream", "listen":listen, "backends":[
            {"id":"a", "address":tcp_address, "desired_state":state}
        ], "health":{"interval_ms":1000, "timeout_ms":100,
            "healthy_successes":1, "unhealthy_failures":1,
            "initial_state":"checking"}}]
    }))
    .unwrap()
}

fn set_state(config: &mut Config, state: hangang::pool_member::DesiredState) {
    for backend in config.http[0]
        .backends
        .iter_mut()
        .chain(config.tcp[0].backends.iter_mut())
    {
        if let hangang::pool_member::Backend::Member(member) = backend {
            member.desired_state = state;
        }
    }
}

#[test]
fn startup_nonserving_and_successful_probes_never_open_admission() {
    for state in ["draining", "maintenance"] {
        let snapshot = Snapshot::new(config(
            "http://127.0.0.1:18001",
            "127.0.0.1:18002",
            "127.0.0.1:19000".parse().unwrap(),
            state,
        ))
        .unwrap();
        let http = &snapshot.http[0].balancer;
        let tcp = &snapshot.tcp_member_admissions["stream"][0];
        assert!(!http.available(0), "{state} HTTP must start closed");
        assert!(http.acquire(0).is_none());
        assert!(!tcp.is_open(), "{state} TCP must start closed");
        assert!(tcp.lease().is_none());
        snapshot.http[0].balancer.record_active_status(0, 200);
        snapshot.tcp_health["stream"].record_success(0);
        assert!(
            !http.available(0),
            "successful probe cannot override {state}"
        );
        assert!(!snapshot.tcp_health["stream"].available(0) || !tcp.is_open());
        assert!(tcp.lease().is_none());
    }
}

#[test]
fn transition_reserves_then_retires_old_owners_and_reactivation_is_fresh() {
    let first = Snapshot::new(config(
        "http://127.0.0.1:18001",
        "127.0.0.1:18002",
        "127.0.0.1:19000".parse().unwrap(),
        "serving",
    ))
    .unwrap();
    let old_http = first.http[0].balancer.clone();
    let old_tcp = first.tcp_member_admissions["stream"][0].clone();
    old_http.record_active_status(0, 200);
    first.tcp_health["stream"].record_success(0);
    let http_owner = old_http.acquire(0).unwrap();
    let tcp_owner = old_tcp.lease().unwrap();
    let mut draining_config = first.config.clone();
    set_state(
        &mut draining_config,
        hangang::pool_member::DesiredState::Draining,
    );
    let abandoned = Snapshot::replace(draining_config.clone(), &first).unwrap();
    assert!(old_http.available(0));
    assert!(old_tcp.is_open());
    assert!(first.retired_members.snapshot().is_empty());
    drop(abandoned);
    assert!(
        old_http.available(0),
        "candidate drop cannot drain live members"
    );
    assert!(old_tcp.is_open());

    let draining = Snapshot::replace(draining_config, &first).unwrap();
    assert!(!draining.http[0].balancer.available(0));
    assert!(!draining.tcp_member_admissions["stream"][0].is_open());
    draining.activated();
    assert!(!old_http.available(0));
    assert!(!old_tcp.is_open());
    assert_eq!(old_http.backend_state(0).unwrap().active_requests, Some(1));
    assert_eq!(old_tcp.active(), 1);
    assert_eq!(draining.retired_members.snapshot().len(), 2);

    let mut unchanged = draining.config.clone();
    unchanged.revision += 1;
    let still_draining = Snapshot::replace(unchanged, &draining).unwrap();
    still_draining.activated();
    assert!(!still_draining.http[0].balancer.available(0));
    assert!(!still_draining.tcp_member_admissions["stream"][0].is_open());
    assert_eq!(still_draining.retired_members.snapshot().len(), 2);

    let mut resumed = still_draining.config.clone();
    set_state(&mut resumed, hangang::pool_member::DesiredState::Serving);
    let serving = Snapshot::replace(resumed, &still_draining).unwrap();
    assert!(!Arc::ptr_eq(&old_http, &serving.http[0].balancer));
    assert!(!Arc::ptr_eq(
        &old_tcp,
        &serving.tcp_member_admissions["stream"][0]
    ));
    serving.activated();
    assert!(
        !serving.http[0].balancer.available(0),
        "reactivation needs a fresh first probe"
    );
    assert_eq!(
        serving.http[0]
            .balancer
            .backend_state(0)
            .unwrap()
            .initial_check_pending,
        Some(true)
    );
    assert!(serving.tcp_member_admissions["stream"][0].is_open());
    assert!(!serving.tcp_health["stream"].available(0));
    serving.http[0].balancer.record_active_status(0, 200);
    serving.tcp_health["stream"].record_success(0);
    assert!(serving.http[0].balancer.available(0));
    assert!(serving.tcp_health["stream"].available(0));
    assert!(!old_http.available(0));
    assert!(!old_tcp.is_open());
    drop(http_owner);
    drop(tcp_owner);
    assert!(serving.retired_members.snapshot().is_empty());
}

async fn tagged_tcp_origin() -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if socket.write_all(b"o").await.is_err() {
                    return;
                }
                let mut buf = [0; 32];
                while let Ok(n) = socket.read(&mut buf).await {
                    if n == 0 || socket.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, count, task)
}

async fn wait_tcp_count(gate: &hangang::member_admission::MemberAdmission, wanted: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while gate.active() != wanted {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("TCP admission count reached expected value");
}

#[tokio::test]
async fn existing_tcp_stream_survives_maintenance_while_new_connections_are_denied() {
    let (origin, accepted, origin_task) = tagged_tcp_origin().await;
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "tcp":[{"id":"stream", "listen":listen, "backends":[
            {"id":"a", "address":origin.to_string()}
        ]}]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, OwnedFd::from(bound))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let old = active.load_full();
    let old_gate = old.tcp_member_admissions["stream"][0].clone();
    let mut existing = TcpStream::connect(listen).await.unwrap();
    let mut tag = [0];
    tokio::time::timeout(Duration::from_secs(2), existing.read_exact(&mut tag))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tag, *b"o");
    assert_eq!(old_gate.active(), 1);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    let mut changed = old.config.clone();
    if let hangang::pool_member::Backend::Member(member) = &mut changed.tcp[0].backends[0] {
        member.desired_state = hangang::pool_member::DesiredState::Maintenance;
    }
    let candidate = Snapshot::replace(changed.clone(), &old).unwrap();
    assert!(
        old_gate.is_open(),
        "preparation cannot close existing admission"
    );
    let prepared = manager.prepare(&changed).await.unwrap();
    manager
        .commit_with_publication(prepared, || {
            candidate.activated();
            active.store(Arc::new(candidate));
        })
        .await
        .unwrap();
    assert!(!old_gate.is_open());
    assert_eq!(old_gate.active(), 1);
    assert!(!active.load().tcp_member_admissions["stream"][0].is_open());
    existing.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    tokio::time::timeout(Duration::from_secs(2), existing.read_exact(&mut pong))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &pong, b"ping",
        "established stream completes on old generation"
    );

    let mut rejected = TcpStream::connect(listen).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut tag))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0))
            || matches!(&closed, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "maintenance rejects new connection without origin bytes: {closed:?}"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    drop(existing);
    wait_tcp_count(&old_gate, 0).await;
    assert!(active.load().retired_members.snapshot().is_empty());
    manager.shutdown(Duration::from_millis(100)).await;
    origin_task.abort();
}

async fn http_origin(
    tag: &'static str,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    seen.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from_static(tag.as_bytes()),
                        )))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, count, task)
}

#[tokio::test]
async fn lua_pinned_nonserving_member_cannot_bypass_but_automatic_selection_uses_alternate() {
    let (a, a_requests, a_task) = http_origin("a").await;
    let (b, b_requests, b_task) = http_origin("b").await;
    let a_url = format!("http://{a}");
    let config: Config = serde_json::from_value(serde_json::json!({
        "http":[{"id":"web", "backends":[
            {"id":"a", "address":a_url, "desired_state":"draining"},
            {"id":"b", "address":format!("http://{b}")}
        ], "lua":"hangang.select_member('a')"}]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front_address = front.local_addr().unwrap();
    let front_task = tokio::spawn(async move {
        while let Ok((stream, peer)) = front.accept().await {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    for script in [
        "hangang.select_member('a')".to_owned(),
        format!("return {a_url:?}"),
    ] {
        let old = active.load_full();
        let mut next = old.config.clone();
        next.http[0].lua = Some(script);
        let candidate = Snapshot::replace(next, &old).unwrap();
        candidate.activated();
        active.store(Arc::new(candidate));
        let response = client
            .request(
                Request::builder()
                    .uri(format!("http://{front_address}/"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            503,
            "Lua cannot pin the draining address or member ID"
        );
        response.into_body().collect().await.unwrap();
    }
    assert_eq!(a_requests.load(Ordering::SeqCst), 0);
    assert_eq!(b_requests.load(Ordering::SeqCst), 0);
    let old = active.load_full();
    let mut next = old.config.clone();
    next.http[0].lua = None;
    let candidate = Snapshot::replace(next, &old).unwrap();
    candidate.activated();
    active.store(Arc::new(candidate));
    let response = client
        .request(
            Request::builder()
                .uri(format!("http://{front_address}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "b"
    );
    assert_eq!(a_requests.load(Ordering::SeqCst), 0);
    assert_eq!(b_requests.load(Ordering::SeqCst), 1);
    front_task.abort();
    a_task.abort();
    b_task.abort();
    policy.shutdown().await;
}
