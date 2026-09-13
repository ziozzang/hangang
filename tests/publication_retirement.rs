#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
};
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    os::fd::OwnedFd,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

fn tcp_config(listen: SocketAddr, socks: SocketAddr) -> Config {
    serde_json::from_value(serde_json::json!({"tcp":[{
        "id":"stream", "listen":listen,
        "backends":[{"id":"a","address":"127.0.0.1:18444"}],
        "upstream":{"socks5":{"address":socks.to_string()}}
    }]}))
    .unwrap()
}

async fn wait_for_zero(gate: &hangang::member_admission::MemberAdmission) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while gate.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired pending dial released its admission");
}

#[tokio::test]
async fn publication_retires_only_the_old_tcp_generation_after_candidate_is_ready() {
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
        assert_eq!(&connect[..4], &[5, 1, 0, 1]);
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut payload = [0; 32];
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut payload))
            .await
            .expect("retired proxy closes SOCKS tunnel")
            .unwrap()
    });

    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let config = tcp_config(listen, socks_address);
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
    let established = old.tcp_member_activity["stream"].node(0).unwrap();
    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"never forward these bytes")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old_gate.active(), 1);
    assert_eq!(established.active(), 0);

    let mut changed = old.config.clone();
    if let hangang::pool_member::Backend::Member(member) = &mut changed.tcp[0].backends[0] {
        member.address = "127.0.0.1:18445".into();
    }
    let abandoned = Snapshot::replace(changed.clone(), &old).unwrap();
    assert!(
        old_gate.is_open(),
        "candidate preparation cannot retire live traffic"
    );
    assert!(!Arc::ptr_eq(
        &old_gate,
        &abandoned.tcp_member_admissions["stream"][0]
    ));
    drop(abandoned);
    assert!(
        old_gate.is_open(),
        "abandoned candidate cannot retire live traffic"
    );

    let candidate = Snapshot::replace(changed.clone(), &old).unwrap();
    let new_gate = candidate.tcp_member_admissions["stream"][0].clone();
    let prepared = manager.prepare(&changed).await.unwrap();
    manager
        .commit_with_publication(prepared, || {
            candidate.activated();
            active.store(Arc::new(candidate));
        })
        .await
        .unwrap();
    assert!(
        !old_gate.is_open(),
        "publication must close the displaced gate"
    );
    assert!(new_gate.is_open(), "new generation remains eligible");
    assert_eq!(
        old_gate.active(),
        1,
        "pending owner remains counted until dial exits"
    );
    release_tx.send(()).unwrap();
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0))
            || matches!(&closed, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "retired dial must not return backend data: {closed:?}"
    );
    assert_eq!(
        socks_task.await.unwrap(),
        0,
        "no client payload reached retired SOCKS tunnel"
    );
    wait_for_zero(&old_gate).await;
    assert_eq!(established.active(), 0);
    manager.shutdown(Duration::from_millis(100)).await;
}

#[test]
fn http_candidate_drop_preserves_old_lease_and_publication_retires_only_displaced_node() {
    let config: Config = serde_json::from_value(serde_json::json!({"http":[{
        "id":"web", "backends":[{"id":"a", "address":"http://127.0.0.1:18001"}]
    }]}))
    .unwrap();
    let old = Snapshot::new(config).unwrap();
    let old_balancer = old.http[0].balancer.clone();
    let lease = old_balancer.acquire(0).unwrap();
    assert_eq!(
        old_balancer.backend_state(0).unwrap().active_requests,
        Some(1)
    );
    let mut changed = old.config.clone();
    if let hangang::pool_member::Backend::Member(member) = &mut changed.http[0].backends[0] {
        member.address = "http://127.0.0.1:18002".into();
    }
    let mut invalid = changed.clone();
    invalid.http[0].backends.clear();
    assert!(Snapshot::replace(invalid, &old).is_err());
    assert!(
        old_balancer.available(0),
        "failed preparation leaves old admission open"
    );
    let abandoned = Snapshot::replace(changed.clone(), &old).unwrap();
    assert!(old_balancer.available(0));
    drop(abandoned);
    assert!(
        old_balancer.acquire(0).is_some(),
        "failed publication leaves old admission usable"
    );
    let candidate = Snapshot::replace(changed, &old).unwrap();
    let fresh = candidate.http[0].balancer.clone();
    assert!(!Arc::ptr_eq(&old_balancer, &fresh));
    candidate.activated();
    assert!(
        !old_balancer.available(0),
        "displaced node closes at publication"
    );
    assert!(old_balancer.acquire(0).is_none());
    assert!(fresh.available(0));
    assert_eq!(
        old_balancer.backend_state(0).unwrap().active_requests,
        Some(1)
    );
    drop(lease);
    assert_eq!(
        old_balancer.backend_state(0).unwrap().active_requests,
        Some(0)
    );
}

#[test]
fn compatible_tcp_reorder_keeps_the_shared_generation_open() {
    let config: Config = serde_json::from_value(serde_json::json!({"tcp":[{
        "id":"stream", "listen":"127.0.0.1:19000", "backends":[
            {"id":"a", "address":"127.0.0.1:18001"},
            {"id":"b", "address":"127.0.0.1:18002"}
        ]
    }]}))
    .unwrap();
    let old = Snapshot::new(config).unwrap();
    let a = old.tcp_member_admissions["stream"][0].clone();
    let b = old.tcp_member_admissions["stream"][1].clone();
    let lease = a.lease().unwrap();
    let mut changed = old.config.clone();
    changed.tcp[0].backends.reverse();
    let candidate = Snapshot::replace(changed, &old).unwrap();
    assert!(Arc::ptr_eq(
        &a,
        &candidate.tcp_member_admissions["stream"][1]
    ));
    assert!(Arc::ptr_eq(
        &b,
        &candidate.tcp_member_admissions["stream"][0]
    ));
    candidate.activated();
    assert!(a.is_open());
    assert!(b.is_open());
    assert_eq!(a.active(), 1);
    drop(lease);
    assert_eq!(a.active(), 0);
}

#[test]
fn draining_member_is_still_rejected_until_lifecycle_publication_is_supported() {
    let config: Config = serde_json::from_value(serde_json::json!({"tcp":[{
        "id":"stream", "listen":"127.0.0.1:19000", "backends":[
            {"id":"a", "address":"127.0.0.1:18001", "desired_state":"draining"}
        ]
    }]}))
    .unwrap();
    assert!(Snapshot::new(config).is_err());
}

#[test]
fn fresh_authority_history_retires_old_gates_without_reusing_cache_or_health() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "cache": {},
        "http":[{"id":"h", "backends":["http://127.0.0.1:18001"]}],
        "tcp":[{"id":"t", "listen":"127.0.0.1:19001", "backends":["127.0.0.1:18002"]}]
    }))
    .unwrap();
    let old = Snapshot::new(config.clone()).unwrap();
    let http = old.http[0].balancer.clone();
    let tcp = old.tcp_member_admissions["t"][0].clone();
    let candidate = Snapshot::replace_fresh(config.clone(), &old).unwrap();
    assert!(!Arc::ptr_eq(
        old.cache.as_ref().unwrap(),
        candidate.cache.as_ref().unwrap()
    ));
    assert!(!Arc::ptr_eq(&http, &candidate.http[0].balancer));
    assert!(!Arc::ptr_eq(&tcp, &candidate.tcp_member_admissions["t"][0]));
    drop(candidate);
    assert!(http.available(0));
    assert!(tcp.is_open());
    let next = Snapshot::replace_fresh(config, &old).unwrap();
    next.activated();
    next.activated();
    assert!(!http.available(0));
    assert!(!tcp.is_open());
    assert!(next.http[0].balancer.available(0));
    assert!(next.tcp_member_admissions["t"][0].is_open());
}
