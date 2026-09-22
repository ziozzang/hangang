use std::{net::SocketAddr, sync::Arc, time::Duration};

use hangang::udp::{Protocol, Route, UdpManager};
use tokio::{net::UdpSocket, sync::oneshot, time::timeout};

async fn free_addr() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    addr
}

fn route(id: &str, listen: SocketAddr, backend: SocketAddr) -> Route {
    Route {
        id: id.into(),
        enabled: true,
        listen,
        backends: vec![backend],
        idle_timeout_ms: 2_000,
        max_sessions: 8,
        max_datagram_bytes: 128,
        protocol: Protocol::Udp,
    }
}

async fn tagged_backend(tag: &'static [u8]) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut packet = [0u8; 256];
        while let Ok((size, peer)) = socket.recv_from(&mut packet).await {
            let _ = socket.send_to(tag, peer).await;
            if size == 0 {
                break;
            }
        }
    });
    (addr, task)
}

#[tokio::test]
async fn stale_prepared_commit_is_rejected_atomically() {
    let (backend_a, task_a) = tagged_backend(b"a").await;
    let (backend_b, task_b) = tagged_backend(b"b").await;
    let listen = free_addr().await;
    let manager = UdpManager::new();

    let first = route("relay", listen, backend_a);
    manager
        .commit(manager.prepare(&[first]).await.unwrap())
        .unwrap();

    // Both candidates observe the same epoch. Committing one must invalidate the other
    // without disturbing the newly committed listener.
    let candidate_b = manager
        .prepare(&[route("relay", listen, backend_b)])
        .await
        .unwrap();
    let stale = manager
        .prepare(&[route("relay", listen, backend_a)])
        .await
        .unwrap();
    manager.commit(candidate_b).unwrap();
    assert!(manager.commit(stale).is_err());

    let status = manager.status();
    assert_eq!(status.routes.len(), 1);
    assert_eq!(status.routes[0].backend_count, 1);

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"probe", listen).await.unwrap();
    let mut response = [0u8; 32];
    let (size, _) = timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..size], b"b");

    manager.shutdown_async().await;
    task_a.abort();
    task_b.abort();
}

#[tokio::test]
async fn connected_upstream_rejects_backend_source_spoof() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = backend.local_addr().unwrap();
    let spoof = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut packet = [0u8; 128];
        let Ok((_, peer)) = backend.recv_from(&mut packet).await else {
            return;
        };
        let _ = ready_tx.send(());
        let _ = spoof.send_to(b"spoof", peer).await;
        let _ = backend.send_to(b"valid", peer).await;
    });

    let listen = free_addr().await;
    let manager = UdpManager::new();
    manager
        .commit(
            manager
                .prepare(&[route("relay", listen, backend_addr)])
                .await
                .unwrap(),
        )
        .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"request", listen).await.unwrap();
    ready_rx.await.unwrap();
    let mut response = [0u8; 32];
    let (size, _) = timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..size], b"valid");

    manager.shutdown_async().await;
    task.abort();
}

#[tokio::test]
async fn shutdown_releases_listener_port_and_stops_active_flow() {
    let (backend, backend_task) = tagged_backend(b"reply").await;
    let listen = free_addr().await;
    let manager = UdpManager::new();
    manager
        .commit(
            manager
                .prepare(&[route("relay", listen, backend)])
                .await
                .unwrap(),
        )
        .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"active", listen).await.unwrap();
    let mut response = [0u8; 32];
    timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();

    manager.shutdown_async().await;
    let rebound = UdpSocket::bind(listen).await.unwrap();
    drop(rebound);
    client.send_to(b"after-shutdown", listen).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), client.recv_from(&mut response))
            .await
            .is_err()
    );
    backend_task.abort();
}

#[tokio::test]
async fn exact_route_update_blocks_old_backend_and_uses_new_backend() {
    let (old_backend, old_task) = tagged_backend(b"old").await;
    let (new_backend, new_task) = tagged_backend(b"new").await;
    let listen = free_addr().await;
    let manager = Arc::new(UdpManager::new());
    let first = route("relay", listen, old_backend);
    manager
        .commit(manager.prepare(std::slice::from_ref(&first)).await.unwrap())
        .unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"before", listen).await.unwrap();
    let mut response = [0u8; 32];
    let (size, _) = timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..size], b"old");

    let mut changed = first;
    changed.backends = vec![new_backend];
    manager
        .commit(manager.prepare(&[changed]).await.unwrap())
        .unwrap();
    client.send_to(b"after", listen).await.unwrap();
    let (size, _) = timeout(Duration::from_secs(1), client.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[..size], b"new");

    manager.shutdown_async().await;
    old_task.abort();
    new_task.abort();
}
