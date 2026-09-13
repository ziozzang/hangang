#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    balance::InitialHealthState,
    client_hello::SniMatch,
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
    tcp::TcpManager,
    tcp_health::TcpHealthPolicy,
    upstream::UpstreamTls,
};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
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
    sync::oneshot,
    task::JoinHandle,
};

fn config(route: TcpRoute) -> Config {
    Config {
        tcp: vec![route],
        ..Config::default()
    }
}

fn route(listen: SocketAddr, backends: Vec<String>) -> TcpRoute {
    TcpRoute {
        id: "checked-stream".into(),
        enabled: true,
        priority: 0,
        upstream: Default::default(),
        health: Some(TcpHealthPolicy {
            interval_ms: 100,
            timeout_ms: 100,
            healthy_successes: 20,
            unhealthy_failures: 1,
            initial_state: InitialHealthState::Checking,
        }),
        sni: None,
        max_connections: None,
        listen,
        backends,
        deny_cidrs: Vec::new(),
    }
}

fn spawn_echo(listener: TcpListener, received: Arc<AtomicUsize>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let received = received.clone();
            tokio::spawn(async move {
                let mut bytes = [0_u8; 256];
                while let Ok(count) = socket.read(&mut bytes).await {
                    if count == 0 {
                        break;
                    }
                    received.fetch_add(count, Ordering::SeqCst);
                    if socket.write_all(&bytes[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    })
}

fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[11; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let length = body.len();
    let mut handshake = vec![
        1,
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

async fn until(mut condition: impl FnMut() -> bool, label: &str) {
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if condition() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

async fn echo(client: &mut TcpStream, bytes: &[u8]) {
    client.write_all(bytes).await.unwrap();
    let mut reply = vec![0; bytes.len()];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .expect("echo deadline")
        .unwrap();
    assert_eq!(reply, bytes);
}

async fn closed_after_admission(listen: SocketAddr, bytes: &[u8]) {
    let mut client = TcpStream::connect(listen).await.unwrap();
    // The gateway may close before the write reaches the socket. Either a
    // write error or EOF proves the excluded connection was not proxied.
    if client.write_all(bytes).await.is_err() {
        return;
    }
    let mut reply = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), client.read(&mut reply))
        .await
        .expect("excluded connection must close promptly");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "excluded connection forwarded data: {result:?}"
    );
}

#[tokio::test]
async fn listener_gates_first_bytes_skips_refused_member_recovers_and_preserves_existing_stream() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    // Binding the healthy endpoint to 127.0.0.1 excludes a wildcard listener
    // on this port. The other loopback address has no listener and refuses.
    let refused = SocketAddr::from(([127, 0, 0, 2], backend_address.port()));
    let received = Arc::new(AtomicUsize::new(0));
    let mut backend_task = spawn_echo(backend, received.clone());

    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let original = config(route(
        listen,
        vec![backend_address.to_string(), refused.to_string()],
    ));
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager =
        TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64).with_gate_closed();
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let health = active.load().tcp_health["checked-stream"].clone();
    assert!(!health.available(0));
    assert!(!health.available(1));

    // Queue client bytes while the process gate is closed. When it opens,
    // the first-check gate must close this stream without forwarding them.
    let mut early = TcpStream::connect(listen).await.unwrap();
    early.write_all(b"before-check").await.unwrap();
    manager.open_gate();
    let mut early_reply = [0_u8; 1];
    let early_result = tokio::time::timeout(Duration::from_secs(2), early.read(&mut early_reply))
        .await
        .expect("initially excluded connection closes");
    assert!(matches!(early_result, Ok(0) | Err(_)));
    assert_eq!(
        received.load(Ordering::SeqCst),
        0,
        "no client bytes reached the origin before qualification"
    );

    until(|| health.available(0), "healthy member qualification").await;
    assert!(!health.available(1), "refusing member stays excluded");
    for _ in 0..20 {
        let mut client = TcpStream::connect(listen).await.unwrap();
        echo(&mut client, b"ready").await;
    }
    let mut established = TcpStream::connect(listen).await.unwrap();
    echo(&mut established, b"held").await;

    backend_task.abort();
    let _ = (&mut backend_task).await;
    until(
        || !health.available(0),
        "all members excluded after probe failure",
    )
    .await;
    assert!(!health.available(1));
    let before = received.load(Ordering::SeqCst);
    closed_after_admission(listen, b"all-down").await;
    assert_eq!(received.load(Ordering::SeqCst), before);
    echo(&mut established, b"still-open").await;

    let replacement = TcpListener::bind(backend_address).await.unwrap();
    backend_task = spawn_echo(replacement, received.clone());
    until(
        || health.available(0),
        "backend recovery after consecutive probes",
    )
    .await;
    let mut recovered = TcpStream::connect(listen).await.unwrap();
    echo(&mut recovered, b"recovered").await;

    let mut disabled = original.clone();
    disabled.tcp[0].enabled = false;
    let prepared = manager.prepare(&disabled).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(disabled, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    echo(&mut established, b"after-disable").await;
    assert!(
        TcpStream::connect(listen).await.is_err(),
        "disabled route listener is removed"
    );

    drop(established);
    drop(recovered);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn sni_client_hello_is_not_forwarded_while_initial_check_is_pending() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let received = Arc::new(AtomicUsize::new(0));
    let backend_task = spawn_echo(backend, received.clone());
    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let mut checked = route(listen, vec![backend_address.to_string()]);
    checked.sni = Some(SniMatch {
        hosts: vec!["ready.example.test".into()],
        host_regexes: Vec::new(),
        max_client_hello_bytes: 4096,
        hello_timeout_ms: 1000,
    });
    let original = config(checked);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager =
        TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64).with_gate_closed();
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let health = active.load().tcp_health["checked-stream"].clone();
    assert!(!health.available(0));

    let hello = client_hello("ready.example.test");
    let mut pending = TcpStream::connect(listen).await.unwrap();
    pending.write_all(&hello).await.unwrap();
    manager.open_gate();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), pending.read(&mut byte))
        .await
        .expect("pending SNI stream closes promptly");
    assert!(matches!(result, Ok(0) | Err(_)));
    assert_eq!(received.load(Ordering::SeqCst), 0);

    until(|| health.available(0), "SNI member qualification").await;
    let mut qualified = TcpStream::connect(listen).await.unwrap();
    echo(&mut qualified, &hello).await;
    assert_eq!(received.load(Ordering::SeqCst), hello.len());

    drop(qualified);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn health_probe_uses_connect_address_instead_of_logical_backend_name() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let backend_task = spawn_echo(backend, Arc::new(AtomicUsize::new(0)));
    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let mut checked = route(listen, vec!["unreachable.invalid:443".into()]);
    checked.upstream.connect_address = Some(backend_address.to_string());
    checked.health.as_mut().unwrap().healthy_successes = 1;
    let original = config(checked);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64);
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let health = active.load().tcp_health["checked-stream"].clone();
    until(
        || health.available(0),
        "overridden connect address qualification",
    )
    .await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    echo(&mut client, b"override").await;
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn tcp_connect_to_unresponsive_tls_origin_does_not_qualify_health() {
    let raw_backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = raw_backend.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_task = accepted.clone();
    // Hold accepted sockets without sending a TLS ServerHello. A TCP-only
    // probe would mark this origin healthy; the full transport probe must not.
    let backend_task = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((socket, _)) = raw_backend.accept().await {
            accepted_task.fetch_add(1, Ordering::SeqCst);
            held.push(socket);
        }
    });
    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let mut checked = route(listen, vec![backend_address.to_string()]);
    checked.upstream.tls = Some(UpstreamTls {
        server_name: Some("origin.example.test".into()),
        insecure_skip_verify: true,
        ..UpstreamTls::default()
    });
    checked.health.as_mut().unwrap().healthy_successes = 1;
    let original = config(checked);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64);
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let health = active.load().tcp_health["checked-stream"].clone();
    until(
        || accepted.load(Ordering::SeqCst) >= 2,
        "two timed-out TLS probe connections",
    )
    .await;
    assert!(
        !health.available(0),
        "TCP accept alone cannot pass TLS health"
    );
    closed_after_admission(listen, b"not-qualified").await;
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn retired_tls_probe_cannot_qualify_replaced_route() {
    let pair = rcgen::generate_simple_self_signed(vec!["origin.example.test".into()]).unwrap();
    let server = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let (completed_tx, completed_rx) = oneshot::channel();
    let backend_task = tokio::spawn(async move {
        let (socket, _) = backend.accept().await.unwrap();
        accepted_tx.send(()).unwrap();
        release_rx.await.unwrap();
        let completed = acceptor.accept(socket).await.is_ok();
        let _ = completed_tx.send(completed);
    });

    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let mut checked = route(listen, vec![backend_address.to_string()]);
    checked.upstream.tls = Some(UpstreamTls {
        server_name: Some("origin.example.test".into()),
        insecure_skip_verify: true,
        ..UpstreamTls::default()
    });
    checked.health.as_mut().unwrap().healthy_successes = 1;
    checked.health.as_mut().unwrap().timeout_ms = 1000;
    checked.health.as_mut().unwrap().interval_ms = 1000;
    let original = config(checked);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64);
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    tokio::time::timeout(Duration::from_secs(2), accepted_rx)
        .await
        .expect("old TLS probe connects")
        .unwrap();

    let old_health = active.load().tcp_health["checked-stream"].clone();
    assert!(!old_health.available(0));
    let mut replaced = original.clone();
    // This new member refuses TCP connections. Reusing the old health state
    // would incorrectly admit it when the delayed TLS handshake completes.
    replaced.tcp[0].backends[0] =
        SocketAddr::from(([127, 0, 0, 2], backend_address.port())).to_string();
    let prepared = manager.prepare(&replaced).await.unwrap();
    let next = Snapshot::replace(replaced, &active.load_full()).unwrap();
    let new_health = next.tcp_health["checked-stream"].clone();
    assert!(!Arc::ptr_eq(&old_health, &new_health));
    active.store(Arc::new(next));
    manager.commit(prepared).await;

    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), completed_rx)
        .await
        .expect("retired server handshake finishes")
        .unwrap();
    assert!(!new_health.available(0));
    closed_after_admission(listen, b"retired-probe").await;
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.await.unwrap();
}

#[tokio::test]
async fn health_closes_during_tls_dial_before_any_client_hello_is_forwarded() {
    let pair = rcgen::generate_simple_self_signed(vec!["origin.example.test".into()]).unwrap();
    let server = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (client_dial_tx, client_dial_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let backend_task = tokio::spawn(async move {
        // The first dial is the immediate health probe. It times out; the
        // long interval keeps it from racing the later client dial.
        let (_probe_socket, _) = backend.accept().await.unwrap();
        let (client_socket, _) = backend.accept().await.unwrap();
        client_dial_tx.send(()).unwrap();
        release_rx.await.unwrap();
        let mut tls = acceptor.accept(client_socket).await.unwrap();
        let mut bytes = [0_u8; 512];
        tokio::time::timeout(Duration::from_secs(2), tls.read(&mut bytes))
            .await
            .expect("gateway closes TLS stream after health loss")
    });

    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held_listener.local_addr().unwrap();
    let mut checked = route(listen, vec![backend_address.to_string()]);
    checked.sni = Some(SniMatch {
        hosts: vec!["ready.example.test".into()],
        host_regexes: Vec::new(),
        max_client_hello_bytes: 4096,
        hello_timeout_ms: 1000,
    });
    checked.upstream.tls = Some(UpstreamTls {
        server_name: Some("origin.example.test".into()),
        insecure_skip_verify: true,
        ..UpstreamTls::default()
    });
    let health_policy = checked.health.as_mut().unwrap();
    health_policy.initial_state = InitialHealthState::Healthy;
    health_policy.interval_ms = 300_000;
    health_policy.timeout_ms = 100;
    health_policy.unhealthy_failures = 2;
    let original = config(checked);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(original.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 64);
    let prepared = manager
        .prepare_with_inherited(&original, vec![(listen, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let health = active.load().tcp_health["checked-stream"].clone();
    until(
        || {
            health
                .backend_state(0)
                .is_some_and(|state| state.probe_observed)
        },
        "initial TLS probe timeout",
    )
    .await;
    assert!(health.available(0), "one failure is below threshold");

    let hello = client_hello("ready.example.test");
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&hello).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), client_dial_rx)
        .await
        .expect("client upstream TLS dial reaches origin")
        .unwrap();
    health.record_failure(0);
    assert!(!health.available(0));
    release_tx.send(()).unwrap();
    let received = tokio::time::timeout(Duration::from_secs(2), backend_task)
        .await
        .expect("TLS server sees gateway close")
        .unwrap();
    assert!(
        matches!(received, Ok(0))
            || matches!(received, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof),
        "no buffered ClientHello reached unhealthy origin"
    );
    let mut byte = [0_u8];
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .expect("downstream closes after health loss");
    assert!(matches!(closed, Ok(0) | Err(_)));
    manager.shutdown(Duration::from_secs(1)).await;
}
