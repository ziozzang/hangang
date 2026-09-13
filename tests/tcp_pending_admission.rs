#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    member_admission::MemberAdmission,
    metrics::Metrics,
    tcp::TcpManager,
    tcp_member::StreamCounter,
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
    sync::oneshot,
    task::JoinHandle,
};

fn config(listen: SocketAddr, members: &[(&str, SocketAddr)], socks: Option<SocketAddr>) -> Config {
    let backends: Vec<_> = members
        .iter()
        .map(|(id, address)| serde_json::json!({"id":id, "address":address.to_string()}))
        .collect();
    let upstream = socks
        .map(|address| serde_json::json!({"socks5":{"address":address.to_string()}}))
        .unwrap_or_else(|| serde_json::json!({}));
    serde_json::from_value(serde_json::json!({
        "tcp":[{"id":"stream", "listen":listen, "backends":backends,
            "upstream":upstream}]
    }))
    .unwrap()
}

fn gate(snapshot: &Snapshot, index: usize) -> Arc<MemberAdmission> {
    snapshot.tcp_member_admissions["stream"][index].clone()
}

fn established(snapshot: &Snapshot, index: usize) -> Arc<StreamCounter> {
    snapshot.tcp_member_activity["stream"]
        .node(index)
        .expect("named member has established-stream counter")
}

async fn manager(config: Config, bound: StdTcpListener) -> (Arc<ArcSwap<Snapshot>>, TcpManager) {
    let listen = bound.local_addr().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, OwnedFd::from(bound))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    (active, manager)
}

async fn wait_count(gate: &MemberAdmission, wanted: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if gate.active() == wanted {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("pending admission count reached expected value");
}

async fn tagged_origin(tag: u8) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let task_count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            task_count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let _ = socket.write_all(&[tag]).await;
                let mut bytes = [0_u8; 32];
                while let Ok(n) = socket.read(&mut bytes).await {
                    if n == 0 || socket.write_all(&bytes[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (address, accepted, task)
}

#[tokio::test]
async fn retirement_during_socks_handshake_releases_pending_without_forwarding() {
    let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks_address = socks.local_addr().unwrap();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    let socks_task = tokio::spawn(async move {
        let (mut socket, _) = socks.accept().await.unwrap();
        let mut greeting = [0_u8; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        socket.write_all(&[5, 0]).await.unwrap();
        let mut connect = [0_u8; 10];
        socket.read_exact(&mut connect).await.unwrap();
        assert_eq!(&connect[..4], &[5, 1, 0, 1]);
        entered_tx.send(()).unwrap();
        release_rx.await.unwrap();
        socket
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut bytes = [0_u8; 32];
        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut bytes))
            .await
            .expect("proxy closes rejected SOCKS tunnel")
            .unwrap()
    });

    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let target: SocketAddr = "127.0.0.1:18444".parse().unwrap();
    let (active, manager) =
        manager(config(listen, &[("a", target)], Some(socks_address)), bound).await;
    let pending = gate(&active.load(), 0);
    let streams = established(&active.load(), 0);
    let mut client = TcpStream::connect(listen).await.unwrap();
    client
        .write_all(b"client bytes must not escape")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), entered_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pending.active(),
        1,
        "dial owns admission during SOCKS handshake"
    );
    assert_eq!(
        streams.active(),
        0,
        "handshake is not an established stream"
    );

    pending.retire();
    assert!(!pending.is_open());
    assert_eq!(
        pending.active(),
        1,
        "retirement does not erase the pending owner"
    );
    release_tx.send(()).unwrap();
    let mut byte = [0_u8];
    let closed = tokio::time::timeout(Duration::from_secs(2), client.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(closed, Ok(0))
            || matches!(&closed, Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "retired dial must close without response bytes: {closed:?}"
    );
    assert_eq!(
        socks_task.await.unwrap(),
        0,
        "SOCKS peer received no client payload"
    );
    wait_count(&pending, 0).await;
    assert_eq!(streams.active(), 0);
    manager.shutdown(Duration::from_millis(100)).await;
}

#[tokio::test]
async fn closed_member_is_skipped_before_dial_but_eligible_alternate_can_serve() {
    let (a, a_accepted, a_task) = tagged_origin(b'a').await;
    let (b, b_accepted, b_task) = tagged_origin(b'b').await;
    let bound = StdTcpListener::bind("127.0.0.1:0").unwrap();
    let listen = bound.local_addr().unwrap();
    let (active, manager) = manager(config(listen, &[("a", a), ("b", b)], None), bound).await;
    let a_gate = gate(&active.load(), 0);
    let b_gate = gate(&active.load(), 1);
    let a_streams = established(&active.load(), 0);
    let b_streams = established(&active.load(), 1);
    a_gate.retire();
    let mut client = TcpStream::connect(listen).await.unwrap();
    let mut tag = [0_u8];
    tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut tag))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tag, [b'b']);
    assert_eq!(a_accepted.load(Ordering::SeqCst), 0);
    assert_eq!(b_accepted.load(Ordering::SeqCst), 1);
    assert_eq!(a_gate.active(), 0);
    assert_eq!(a_streams.active(), 0);
    assert_eq!(b_gate.active(), 1);
    assert_eq!(b_streams.active(), 1);
    drop(client);
    wait_count(&b_gate, 0).await;

    b_gate.retire();
    let mut rejected = TcpStream::connect(listen).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), rejected.read(&mut tag))
            .await
            .unwrap()
            .unwrap(),
        0,
        "all closed members must fail before any backend dial"
    );
    assert_eq!(a_accepted.load(Ordering::SeqCst), 0);
    assert_eq!(b_accepted.load(Ordering::SeqCst), 1);
    assert_eq!(b_gate.active(), 0);
    assert_eq!(b_streams.active(), 0);
    manager.shutdown(Duration::from_millis(100)).await;
    a_task.abort();
    b_task.abort();
}
