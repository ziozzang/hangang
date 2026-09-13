#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
    tcp_member::StreamCounter,
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
    task::JoinHandle,
};

async fn origin(tag: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                if socket.write_all(&[tag]).await.is_err() {
                    return;
                }
                let mut bytes = [0_u8; 32];
                while let Ok(count) = socket.read(&mut bytes).await {
                    if count == 0 || socket.write_all(&bytes[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, task)
}

fn config(listen: SocketAddr, members: &[(&str, SocketAddr, u16)]) -> Config {
    let backends: Vec<_> = members
        .iter()
        .map(|(id, address, weight)| {
            serde_json::json!({"id":id, "address":address.to_string(), "weight":weight})
        })
        .collect();
    serde_json::from_value(serde_json::json!({
        "tcp":[{"id":"stream", "listen":listen, "backends":backends}]
    }))
    .unwrap()
}

fn counter(snapshot: &Snapshot, id: &str) -> Arc<StreamCounter> {
    let route = &snapshot.config.tcp[0];
    let index = route
        .backends
        .iter()
        .position(|member| member.id() == Some(id))
        .expect("member in current route");
    snapshot.tcp_member_activity[&route.id]
        .node(index)
        .expect("named member has a stream counter")
}

async fn manager(config: Config, bound: StdTcpListener) -> (Arc<ArcSwap<Snapshot>>, TcpManager) {
    let listen = bound.local_addr().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 16);
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, OwnedFd::from(bound))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    (active, manager)
}

async fn publish(manager: &TcpManager, active: &Arc<ArcSwap<Snapshot>>, next: Config) {
    let prepared = manager.prepare(&next).await.unwrap();
    let replacement = Snapshot::replace(next, &active.load_full()).unwrap();
    replacement.activated();
    active.store(Arc::new(replacement));
    manager.commit(prepared).await;
}

async fn connect_tag(listen: SocketAddr, expected: u8) -> TcpStream {
    let mut client = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(listen))
        .await
        .unwrap()
        .unwrap();
    let mut tag = [0_u8];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut tag))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tag, [expected], "connection reached the selected origin");
    client
}

async fn wait_count(counter: &StreamCounter, expected: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if counter.active() == expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("established stream count reached expected value");
}

#[tokio::test]
async fn held_stream_follows_named_id_through_reorder_and_weight_change() {
    let (a, a_task) = origin(b'a').await;
    let (b, b_task) = origin(b'b').await;
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let initial = config(listen, &[("a", a, 1), ("b", b, 1)]);
    let (active, manager) = manager(initial, bound).await;
    let first = connect_tag(listen, b'a').await;
    let a_count = counter(&active.load(), "a");
    let b_count = counter(&active.load(), "b");
    assert_eq!(a_count.active(), 1);
    assert_eq!(b_count.active(), 0);

    publish(
        &manager,
        &active,
        config(listen, &[("b", b, 1), ("a", a, 3)]),
    )
    .await;
    let current_a = counter(&active.load(), "a");
    let current_b = counter(&active.load(), "b");
    assert!(Arc::ptr_eq(&a_count, &current_a));
    assert!(Arc::ptr_eq(&b_count, &current_b));
    assert_eq!(active.load().config.tcp[0].backends[1].id(), Some("a"));
    assert_eq!(current_a.active(), 1);
    assert_eq!(current_b.active(), 0);
    let second = connect_tag(listen, b'a').await;
    assert_eq!(current_a.active(), 2);
    drop(first);
    wait_count(&current_a, 1).await;
    drop(second);
    wait_count(&current_a, 0).await;
    manager.shutdown(Duration::from_millis(100)).await;
    a_task.abort();
    b_task.abort();
}

#[tokio::test]
async fn same_id_endpoint_change_counts_old_and_new_established_streams() {
    let (old_address, old_task) = origin(b'o').await;
    let (new_address, new_task) = origin(b'n').await;
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let (active, manager) = manager(config(listen, &[("a", old_address, 1)]), bound).await;
    let mut old_client = connect_tag(listen, b'o').await;
    let old_count = counter(&active.load(), "a");
    assert_eq!(old_count.active(), 1);

    publish(&manager, &active, config(listen, &[("a", new_address, 1)])).await;
    let new_count = counter(&active.load(), "a");
    assert!(Arc::ptr_eq(&old_count, &new_count));
    assert_eq!(new_count.active(), 1);
    let new_client = connect_tag(listen, b'n').await;
    assert_eq!(new_count.active(), 2);
    old_client.write_all(b"ok").await.unwrap();
    let mut echo = [0_u8; 2];
    old_client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ok", "old stream remains on the old endpoint");
    drop(new_client);
    wait_count(&new_count, 1).await;
    drop(old_client);
    wait_count(&new_count, 0).await;
    manager.shutdown(Duration::from_millis(100)).await;
    old_task.abort();
    new_task.abort();
}

#[tokio::test]
async fn rename_and_intervening_removal_start_a_fresh_member_counter() {
    let (a, a_task) = origin(b'a').await;
    let (b, b_task) = origin(b'b').await;
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let (active, manager) = manager(config(listen, &[("a", a, 1), ("b", b, 1)]), bound).await;
    let old_client = connect_tag(listen, b'a').await;
    let old = counter(&active.load(), "a");
    assert_eq!(old.active(), 1);

    publish(
        &manager,
        &active,
        config(listen, &[("a-new", a, 1), ("b", b, 1)]),
    )
    .await;
    let renamed = counter(&active.load(), "a-new");
    assert!(!Arc::ptr_eq(&old, &renamed));
    assert_eq!(renamed.active(), 0);
    assert_eq!(old.active(), 1);
    publish(&manager, &active, config(listen, &[("b", b, 1)])).await;
    assert_eq!(old.active(), 1);
    publish(
        &manager,
        &active,
        config(listen, &[("a", a, 1), ("b", b, 1)]),
    )
    .await;
    let readded = counter(&active.load(), "a");
    assert!(!Arc::ptr_eq(&old, &readded));
    assert_eq!(readded.active(), 0);
    drop(old_client);
    wait_count(&old, 0).await;
    assert_eq!(readded.active(), 0);
    manager.shutdown(Duration::from_millis(100)).await;
    a_task.abort();
    b_task.abort();
}

#[tokio::test]
async fn failed_backend_dial_never_counts_as_established_stream() {
    let closed = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let (active, manager) = manager(config(listen, &[("failed", address, 1)]), bound).await;
    let count = counter(&active.load(), "failed");
    let mut client = TcpStream::connect(listen).await.unwrap();
    let mut byte = [0_u8];
    let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0, "failed outbound dial closes the downstream");
    assert_eq!(count.active(), 0);
    manager.shutdown(Duration::from_millis(100)).await;
}

#[test]
fn legacy_tcp_backend_has_no_named_member_counter() {
    let config: Config = serde_json::from_value(serde_json::json!({
        "tcp":[{"id":"stream", "listen":"127.0.0.1:19093",
            "backends":["127.0.0.1:18080"]}]
    }))
    .unwrap();
    let snapshot = Snapshot::new(config).unwrap();
    assert!(snapshot.tcp_member_activity["stream"].node(0).is_none());
}

#[tokio::test]
async fn established_member_lease_releases_on_idle_expiry_and_forced_shutdown() {
    for idle in [Duration::ZERO, Duration::from_millis(100)] {
        let (address, origin_task) = origin(b'a').await;
        let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
        let listen = bound.local_addr().unwrap();
        let config = config(listen, &[("a", address, 1)]);
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(config.clone()).unwrap(),
        ));
        let manager =
            TcpManager::with_idle_timeout(active.clone(), Arc::new(Metrics::default()), 16, idle);
        let prepared = manager
            .prepare_with_inherited(&config, vec![(listen, OwnedFd::from(bound))])
            .await
            .unwrap();
        manager.commit(prepared).await;
        let mut stream = connect_tag(listen, b'a').await;
        let count = counter(&active.load(), "a");
        assert_eq!(count.active(), 1);
        if idle.is_zero() {
            let mut disabled = config.clone();
            disabled.tcp[0].enabled = false;
            publish(&manager, &active, disabled).await;
            assert_eq!(counter(&active.load(), "a").active(), 1);
            manager.shutdown(Duration::ZERO).await;
        }
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(result, Ok(0) | Err(_)),
            "closed stream unexpectedly forwarded data"
        );
        wait_count(&count, 0).await;
        manager.shutdown(Duration::ZERO).await;
        origin_task.abort();
    }
}
