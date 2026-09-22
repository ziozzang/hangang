use arc_swap::ArcSwap;
use hangang::{
    client_hello::SniMatch,
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
    tcp::TcpManager,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

fn reserve_address() -> SocketAddr {
    let socket = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    address
}

fn route(id: &str, listen: SocketAddr, backend: SocketAddr) -> TcpRoute {
    TcpRoute {
        country_policy: None,
        enabled: true,
        upstream: Default::default(),
        health: None,
        inbound_tls: None,
        priority: 0,
        max_connections: None,
        sni: None,
        id: id.into(),
        listen,
        backends: vec![backend.to_string().into()],
        deny_cidrs: Vec::new(),
    }
}

fn config(routes: Vec<TcpRoute>) -> Config {
    Config {
        geoip_database: None,
        cache: None,
        certificates: Vec::new(),
        revision: 0,
        http: Vec::new(),
        tcp: routes,
        workload_http: Vec::new(),
        udp: Vec::new(),
        public_http: Vec::new(),
        settings: Default::default(),
        cache_generation_floor: 0,
    }
}

fn manager() -> (Arc<ArcSwap<Snapshot>>, Arc<Metrics>, TcpManager) {
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active.clone(), metrics.clone(), 64);
    (active, metrics, manager)
}

async fn publish_and_commit(manager: &TcpManager, active: &Arc<ArcSwap<Snapshot>>, config: Config) {
    let prepared = manager.prepare(&config).await.unwrap();
    active.store(Arc::new(Snapshot::new(config).unwrap()));
    manager.commit(prepared).await;
}

#[tokio::test]
async fn prepare_failure_rolls_back_sockets_bound_earlier() {
    let free = reserve_address();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let occupied_address = occupied.local_addr().unwrap();
    let (_active, _metrics, manager) = manager();
    let candidate = config(vec![
        route("first", free, "127.0.0.1:9".parse().unwrap()),
        route("occupied", occupied_address, "127.0.0.1:9".parse().unwrap()),
    ]);

    assert!(manager.prepare(&candidate).await.is_err());
    let rebound = TcpListener::bind(free)
        .await
        .expect("the first prepared socket must be dropped on rollback");
    drop(rebound);
    drop(occupied);
    manager.shutdown(Duration::ZERO).await;
}

#[tokio::test]
async fn probe_rejects_reserved_and_occupied_listen_addresses() {
    let free = reserve_address();
    let occupied = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let occupied_address = occupied.local_addr().unwrap();
    let backend: SocketAddr = "127.0.0.1:9".parse().unwrap();
    // A free address probes fine and is released again.
    TcpManager::probe_bindable(&config(vec![route("a", free, backend)]), &[])
        .await
        .unwrap();
    let rebound = TcpListener::bind(free)
        .await
        .expect("probe releases the socket");
    drop(rebound);
    // Occupied by another process: rejected.
    let error =
        TcpManager::probe_bindable(&config(vec![route("b", occupied_address, backend)]), &[])
            .await
            .unwrap_err();
    assert!(error.to_string().contains("bind TCP listener"));
    // Colliding with the process's own public listener (same port, unspecified IP): rejected
    // by the kernel because every probe socket is held until the end.
    let public: SocketAddr = format!("0.0.0.0:{}", free.port()).parse().unwrap();
    let error = TcpManager::probe_bindable(&config(vec![route("c", free, backend)]), &[public])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("bind TCP listener"), "{error:#}");
    // Two routes that overlap at the socket level are rejected together
    // although each would bind on its own.
    let wildcard: SocketAddr = format!("0.0.0.0:{}", free.port()).parse().unwrap();
    let error = TcpManager::probe_bindable(
        &config(vec![
            route("d", wildcard, backend),
            route("e", free, backend),
        ]),
        &[],
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("bind TCP listener"), "{error:#}");
    // An exact match with a process listener is a collision, not a shared socket.
    let error = TcpManager::probe_bindable(&config(vec![route("f", free, backend)]), &[free])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("collides"), "{error:#}");
    let error = TcpManager::probe_bindable(&config(vec![]), &[free, free])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("used twice"), "{error:#}");
    // Everything is released afterwards.
    let rebound = TcpListener::bind(free)
        .await
        .expect("probe releases the sockets");
    drop(rebound);
    drop(occupied);
}

#[tokio::test]
async fn closed_gate_binds_but_defers_accepts_until_opened() {
    let (backend, backend_task) = spawn_read_to_end_echo().await;
    let listen = reserve_address();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active.clone(), metrics.clone(), 64).with_gate_closed();
    assert!(!manager.gate_open());
    publish_and_commit(
        &manager,
        &active,
        config(vec![route("echo", listen, backend)]),
    )
    .await;

    // The socket is bound (connect succeeds) but nothing is proxied while the
    // gate is closed: the backend sees no connection and the client no reply.
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"gated").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    let early =
        tokio::time::timeout(Duration::from_millis(300), client.read_to_end(&mut reply)).await;
    assert!(early.is_err(), "no data may flow while the gate is closed");
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);

    manager.open_gate();
    assert!(manager.gate_open());
    tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut reply))
        .await
        .expect("queued connection is served once the gate opens")
        .unwrap();
    assert_eq!(reply, b"gated");

    drop(client);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn proxies_echo_after_client_half_close() {
    let (backend, backend_task) = spawn_read_to_end_echo().await;
    // Keep ownership of the ephemeral port until the manager adopts it. A
    // dropped reservation can be claimed by another parallel test process.
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let (active, metrics, manager) = manager();
    let candidate = config(vec![route("echo", listen, backend)]);
    let prepared = manager
        .prepare_with_inherited(&candidate, vec![(listen, listener.into())])
        .await
        .unwrap();
    active.store(Arc::new(Snapshot::new(candidate).unwrap()));
    manager.commit(prepared).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"half-close").await.unwrap();
    client.shutdown().await.unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).await.unwrap();
    assert_eq!(reply, b"half-close");

    drop(client);
    manager.shutdown(Duration::from_secs(1)).await;
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
    backend_task.abort();
}

#[tokio::test]
async fn reload_uses_new_backend_and_removed_listener_drains_existing_stream() {
    let (backend_a, task_a) = spawn_tagged_echo(b'A').await;
    let (backend_b, task_b) = spawn_tagged_echo(b'B').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    publish_and_commit(
        &manager,
        &active,
        config(vec![route("switch", listen, backend_a)]),
    )
    .await;
    let mut established = TcpStream::connect(listen).await.unwrap();
    assert_eq!(read_byte(&mut established).await, b'A');

    publish_and_commit(
        &manager,
        &active,
        config(vec![route("switch", listen, backend_b)]),
    )
    .await;
    let mut fresh = TcpStream::connect(listen).await.unwrap();
    assert_eq!(read_byte(&mut fresh).await, b'B');

    publish_and_commit(&manager, &active, config(Vec::new())).await;
    established.write_all(b"still-alive").await.unwrap();
    let mut echoed = [0; 11];
    established.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"still-alive");
    assert!(TcpStream::connect(listen).await.is_err());

    drop(established);
    drop(fresh);
    manager.shutdown(Duration::from_secs(1)).await;
    task_a.abort();
    task_b.abort();
}

#[tokio::test]
async fn shutdown_cancels_streams_after_grace_without_leaking_active_count() {
    let (backend, backend_task) = spawn_tagged_echo(b'H').await;
    let listen = reserve_address();
    let (active, metrics, manager) = manager();
    publish_and_commit(
        &manager,
        &active,
        config(vec![route("hanging", listen, backend)]),
    )
    .await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    assert_eq!(read_byte(&mut client).await, b'H');
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);

    tokio::time::timeout(
        Duration::from_secs(1),
        manager.shutdown(Duration::from_millis(20)),
    )
    .await
    .expect("shutdown must cancel connections after its grace period");
    assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);

    let mut byte = [0];
    assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    backend_task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn exported_listener_is_strictly_adopted_by_the_next_manager() {
    let (backend, backend_task) = spawn_read_to_end_echo().await;
    let listen = reserve_address();
    let next_config = config(vec![route("inherited", listen, backend)]);
    let (old_active, _old_metrics, old) = manager();
    publish_and_commit(&old, &old_active, next_config.clone()).await;

    let inherited = old.export_listeners().await.unwrap();
    assert_eq!(inherited.len(), 1);
    let (new_active, _new_metrics, new) = manager();
    let prepared = new
        .prepare_with_inherited(&next_config, inherited)
        .await
        .unwrap();
    new_active.store(Arc::new(Snapshot::new(next_config).unwrap()));
    new.commit(prepared).await;
    old.shutdown(Duration::ZERO).await;

    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"inherited").await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"inherited");
    new.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn inherited_listener_address_must_match_its_descriptor() {
    let backend = "127.0.0.1:9".parse().unwrap();
    let actual = reserve_address();
    let declared = reserve_address();
    let socket = StdTcpListener::bind(actual).unwrap();
    socket.set_nonblocking(true).unwrap();
    let descriptor = socket.into();
    let (_active, _metrics, manager) = manager();
    let expected = config(vec![route("strict", declared, backend)]);
    let error = match manager
        .prepare_with_inherited(&expected, vec![(declared, descriptor)])
        .await
    {
        Ok(_) => panic!("mismatched descriptor was accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("address mismatch"));
    manager.shutdown(Duration::ZERO).await;
}

#[cfg(unix)]
#[tokio::test]
async fn shared_sni_listener_is_exported_and_inherited_once() {
    let listen = reserve_address();
    let backend = "127.0.0.1:9".parse().unwrap();
    let mut exact = route("exact", listen, backend);
    exact.sni = Some(SniMatch {
        host_regexes: Vec::new(),
        hosts: vec!["api.example.test".into()],
        max_client_hello_bytes: 65_536,
        hello_timeout_ms: 3_000,
    });
    let mut wildcard = route("wildcard", listen, backend);
    wildcard.sni = Some(SniMatch {
        host_regexes: Vec::new(),
        hosts: vec!["*.example.test".into()],
        max_client_hello_bytes: 65_536,
        hello_timeout_ms: 3_000,
    });
    let next_config = config(vec![exact, wildcard]);
    let (old_active, _old_metrics, old) = manager();
    publish_and_commit(&old, &old_active, next_config.clone()).await;

    let inherited = old.export_listeners().await.unwrap();
    assert_eq!(inherited.len(), 1, "one descriptor per shared address");
    let (new_active, _new_metrics, new) = manager();
    let prepared = new
        .prepare_with_inherited(&next_config, inherited)
        .await
        .unwrap();
    new_active.store(Arc::new(Snapshot::new(next_config).unwrap()));
    new.commit(prepared).await;
    old.shutdown(Duration::ZERO).await;
    new.shutdown(Duration::ZERO).await;
}

async fn read_byte(stream: &mut TcpStream) -> u8 {
    let mut byte = [0];
    stream.read_exact(&mut byte).await.unwrap();
    byte[0]
}

async fn spawn_read_to_end_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut input = Vec::new();
                stream.read_to_end(&mut input).await.unwrap();
                stream.write_all(&input).await.unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    (address, task)
}

async fn spawn_tagged_echo(tag: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let sequence = Arc::new(AtomicU64::new(0));
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, peer) = listener.accept().await.unwrap();
            let sequence = sequence.clone();
            tokio::spawn(async move {
                sequence.fetch_add(1, Ordering::Relaxed);
                stream.write_all(&[tag]).await.unwrap();
                let mut buffer = [0; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(count) => stream.write_all(&buffer[..count]).await.unwrap(),
                        Err(error) => panic!("backend read from {peer}: {error}"),
                    }
                }
            });
        }
    });
    (address, task)
}

#[test]
fn loopback_helpers_use_real_ip_addresses() {
    assert_eq!(reserve_address().ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
}

#[tokio::test]
async fn route_capacity_survives_revision_and_does_not_block_other_routes() {
    let (backend, task) = spawn_tagged_echo(b'A').await;
    let first = reserve_address();
    let mut second = reserve_address();
    while second == first {
        second = reserve_address();
    }
    let (active, _metrics, manager) = manager();
    let mut limited = route("limited", first, backend);
    limited.max_connections = Some(1);
    let mut cfg = config(vec![limited, route("other", second, backend)]);
    publish_and_commit(&manager, &active, cfg.clone()).await;
    let mut held = TcpStream::connect(first).await.unwrap();
    assert_eq!(read_byte(&mut held).await, b'A');
    cfg.revision += 1;
    let prepared = manager.prepare(&cfg).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(cfg, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    let mut rejected = TcpStream::connect(first).await.unwrap();
    let mut byte = [0];
    let reply = tokio::time::timeout(Duration::from_secs(1), rejected.read(&mut byte))
        .await
        .unwrap();
    assert!(matches!(reply, Ok(0)) || reply.is_err());
    let mut other = TcpStream::connect(second).await.unwrap();
    assert_eq!(read_byte(&mut other).await, b'A');
    held.write_all(b"Z").await.unwrap();
    assert_eq!(read_byte(&mut held).await, b'Z');
    drop(held);
    drop(other);
    drop(rejected);
    manager.shutdown(Duration::from_secs(1)).await;
    task.abort();
}

// Reserve a free port on the dual-stack wildcard address. Returns None when the
// host has no usable IPv6/dual-stack stack, so the test can skip cleanly.
fn reserve_dual_stack_address() -> Option<SocketAddr> {
    let socket = StdTcpListener::bind((std::net::Ipv6Addr::UNSPECIFIED, 0)).ok()?;
    let port = socket.local_addr().ok()?.port();
    drop(socket);
    Some(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
        port,
    ))
}

#[tokio::test]
async fn tcp_deny_cidrs_match_ipv4_mapped_peer_on_dual_stack_listener() {
    let Some(listen) = reserve_dual_stack_address() else {
        eprintln!("skipping: no dual-stack IPv6 available");
        return;
    };
    let (backend, backend_task) = spawn_tagged_echo(b'X').await;
    let (active, _metrics, manager) = manager();
    let mut denied = route("denied", listen, backend);
    denied.deny_cidrs = vec!["127.0.0.0/8".parse().unwrap()];

    // If the dual-stack listener cannot be prepared/bound here, skip rather than fail.
    let config = config(vec![denied]);
    let Ok(prepared) = manager.prepare(&config).await else {
        eprintln!("skipping: cannot bind dual-stack listener");
        backend_task.abort();
        return;
    };
    active.store(Arc::new(Snapshot::new(config).unwrap()));
    manager.commit(prepared).await;

    // Connect over IPv4 loopback; on a [::] listener the accepted peer is
    // ::ffff:127.0.0.1, which the IPv4 deny CIDR must now match.
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port());
    let Ok(mut client) = TcpStream::connect(v4).await else {
        eprintln!("skipping: cannot reach dual-stack listener over IPv4");
        backend_task.abort();
        return;
    };
    // A denied connection is accepted at TCP level then immediately closed
    // before any backend byte (the echo tag 'X') is proxied. Reading yields EOF.
    let mut buffer = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buffer)).await;
    assert!(
        matches!(read, Ok(Ok(0))),
        "IPv4-mapped peer must be denied (no backend byte proxied); got {read:?}"
    );
    backend_task.abort();
}

#[tokio::test]
async fn tcp_idle_timeout_closes_silent_sessions_but_keeps_active_ones() {
    // Regression for M-3: an established L4 session that transmits nothing
    // within the idle window is closed (bounding L4 slowloris), while a session
    // with periodic traffic is kept alive.
    let (backend, backend_task) = spawn_tagged_echo(b'I').await;
    let listen = reserve_address();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::with_idle_timeout(
        active.clone(),
        metrics.clone(),
        64,
        Duration::from_millis(300),
    );
    publish_and_commit(
        &manager,
        &active,
        config(vec![route("echo", listen, backend)]),
    )
    .await;

    // Silent session: read the backend's initial tag byte, then stay quiet.
    // After the idle window the proxy must close the connection (read -> EOF).
    let mut silent = TcpStream::connect(listen).await.unwrap();
    let mut tag = [0u8; 1];
    silent.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag[0], b'I');
    let mut buffer = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), silent.read(&mut buffer)).await;
    assert!(
        matches!(closed, Ok(Ok(0))),
        "a silent L4 session must be closed after the idle window; got {closed:?}"
    );

    // Active session: periodic traffic keeps it alive past the idle window.
    let mut active_conn = TcpStream::connect(listen).await.unwrap();
    active_conn.read_exact(&mut tag).await.unwrap();
    for _ in 0..6 {
        active_conn.write_all(b"x").await.unwrap();
        let mut echoed = [0u8; 1];
        active_conn.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed[0], b'x');
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Still usable well past the 300ms idle window (600ms of activity elapsed).
    active_conn.write_all(b"y").await.unwrap();
    let mut echoed = [0u8; 1];
    active_conn.read_exact(&mut echoed).await.unwrap();
    assert_eq!(echoed[0], b'y');

    backend_task.abort();
}

#[tokio::test]
async fn disabled_route_releases_listener_preserves_stream_and_reactivation_is_atomic() {
    let (backend, task) = spawn_tagged_echo(b'A').await;
    let listen = reserve_address();
    let (active, _, manager) = manager();
    let mut saved = route("toggle", listen, backend);
    publish_and_commit(&manager, &active, config(vec![saved.clone()])).await;
    let mut established = TcpStream::connect(listen).await.unwrap();
    assert_eq!(read_byte(&mut established).await, b'A');
    saved.enabled = false;
    publish_and_commit(&manager, &active, config(vec![saved.clone()])).await;
    assert_eq!(active.load().config.tcp.len(), 1);
    assert!(!active.load().config.tcp[0].enabled);
    assert!(TcpStream::connect(listen).await.is_err());
    established.write_all(b"kept").await.unwrap();
    let mut kept = [0; 4];
    established.read_exact(&mut kept).await.unwrap();
    assert_eq!(&kept, b"kept");
    let occupied = TcpListener::bind(listen).await.unwrap();
    TcpManager::probe_bindable(&config(vec![saved.clone()]), &[])
        .await
        .unwrap();
    saved.enabled = true;
    assert!(manager.prepare(&config(vec![saved.clone()])).await.is_err());
    assert!(!active.load().config.tcp[0].enabled);
    drop(occupied);
    publish_and_commit(&manager, &active, config(vec![saved])).await;
    let mut new = TcpStream::connect(listen).await.unwrap();
    assert_eq!(read_byte(&mut new).await, b'A');
    drop(new);
    drop(established);
    manager.shutdown(Duration::from_secs(1)).await;
    task.abort();
}
