#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    geoip_runtime::{self, Published, Slot},
    metrics::Metrics,
    tcp::TcpManager,
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    os::fd::OwnedFd,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

// The public MaxMind test database predates this run. Rewrite only its fixed
// four-byte build_epoch metadata in an owned copy so production freshness
// checks still run unmodified; all address/tree records remain the fixture's.
fn current_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    const MARKER: &[u8] = b"build_epoch\x04\x02";
    let offsets = bytes
        .windows(MARKER.len())
        .enumerate()
        .filter_map(|(index, window)| (window == MARKER).then_some(index + MARKER.len()))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1, "fixture metadata layout changed");
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .checked_sub(3_600)
        .unwrap();
    let epoch = u32::try_from(epoch).unwrap();
    bytes[offsets[0]..offsets[0] + 4].copy_from_slice(&epoch.to_be_bytes());
    bytes
}

async fn echo_origin() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut received = Vec::new();
                if stream.read_to_end(&mut received).await.is_ok() {
                    let _ = stream.write_all(&received).await;
                }
            });
        }
    });
    (address, accepted, task)
}

fn source(path: &std::path::Path) -> Value {
    json!({"file":path,"max_age_days":1,"reload_interval_seconds":1})
}

fn route(listen: SocketAddr, origin: SocketAddr, on_unknown: &str) -> Value {
    json!({
        "id":"country", "listen":listen, "backends":[origin.to_string()],
        "country_policy":{"deny":["RU"],"on_unknown":on_unknown}
    })
}

async fn wait_for(mut condition: impl FnMut() -> bool, label: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

fn start_watcher(active: &Arc<ArcSwap<Snapshot>>) -> (CancellationToken, JoinHandle<()>) {
    let slot = active.load().geoip.as_ref().unwrap().clone();
    let current = active.clone();
    let published: Arc<Published> = Arc::new(move |candidate: &Arc<Slot>| {
        current
            .load()
            .geoip
            .as_ref()
            .is_some_and(|live| Arc::ptr_eq(live, candidate))
    });
    let cancel = CancellationToken::new();
    let task = tokio::spawn(geoip_runtime::watch(slot, published, cancel.clone()));
    (cancel, task)
}

async fn echo(front: SocketAddr, payload: &[u8]) {
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, payload);
}

async fn refused(front: SocketAddr) {
    let mut stream = TcpStream::connect(front).await.unwrap();
    let _ = stream.write_all(b"must-not-reach-origin").await;
    let _ = stream.shutdown().await;
    let mut answer = [0_u8; 1];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut answer))
        .await
        .expect("country rejection should promptly close the stream");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "country-denied stream was forwarded"
    );
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

async fn sni_attempt(front: SocketAddr, host: &str, allowed: bool) {
    let hello = client_hello(host);
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream.write_all(&hello).await.unwrap();
    let _ = stream.shutdown().await;
    let mut reply = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
        .await
        .expect("selected SNI connection should finish promptly");
    if allowed {
        result.unwrap();
        assert_eq!(reply, hello);
    } else {
        assert!(reply.is_empty(), "country-denied SNI stream reached origin");
    }
}

async fn publish(manager: &TcpManager, active: &Arc<ArcSwap<Snapshot>>, config: Config) {
    let prepared = manager.prepare(&config).await.unwrap();
    let current = active.load_full();
    let next = Arc::new(Snapshot::replace(config, &current).unwrap());
    assert!(Arc::ptr_eq(
        current.geoip.as_ref().unwrap(),
        next.geoip.as_ref().unwrap(),
    ));
    manager
        .commit_with_publication(prepared, || {
            next.activated();
            active.store(next);
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn tcp_unknown_country_is_explicit_and_invalid_database_closes_new_streams() {
    let dir = tempfile::tempdir().unwrap();
    let database_path = dir.path().join("country.mmdb");
    let good_database = current_fixture();
    std::fs::write(&database_path, &good_database).unwrap();
    let (origin, accepted, origin_task) = echo_origin().await;
    let held = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front = held.local_addr().unwrap();
    held.set_nonblocking(true).unwrap();

    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let mut document = json!({
        "geoip_database":source(&database_path),
        "tcp":[route(front, origin, "deny")]
    });
    let config: Config = serde_json::from_value(document.clone()).unwrap();
    let prepared = manager
        .prepare_with_inherited(&config, vec![(front, OwnedFd::from(held))])
        .await
        .unwrap();
    let snapshot = Arc::new(Snapshot::new(config).unwrap());
    snapshot.activated();
    active.store(snapshot);
    manager.commit(prepared).await;
    let (cancel, watcher) = start_watcher(&active);
    wait_for(
        || active.load().geoip.as_ref().unwrap().load().is_some(),
        "ready GeoIP slot",
    )
    .await;

    // A healthy database reports loopback as unknown. Explicit deny is not a
    // database error and must stop the stream before any origin connection.
    refused(front).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 0);
    document["tcp"][0]["country_policy"]["on_unknown"] = json!("allow");
    document["revision"] = json!(1);
    publish(
        &manager,
        &active,
        serde_json::from_value(document.clone()).unwrap(),
    )
    .await;
    echo(front, b"allowed-unknown").await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // A failed reload is not an unknown lookup. Even an explicit unknown=allow
    // policy must close while no verified database generation is available.
    std::fs::write(&database_path, b"invalid owned MMDB replacement").unwrap();
    wait_for(
        || active.load().geoip.as_ref().unwrap().load().is_none(),
        "invalid DB closure",
    )
    .await;
    refused(front).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    document["tcp"][0]["country_policy"]["enforce"] = json!(false);
    document["revision"] = json!(2);
    publish(&manager, &active, serde_json::from_value(document).unwrap()).await;
    echo(front, b"explicitly-disabled").await;
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    cancel.cancel();
    watcher.await.unwrap();
    manager.shutdown(Duration::from_secs(1)).await;
    origin_task.abort();
}

#[tokio::test]
async fn shared_sni_listener_applies_only_selected_route_country_policy() {
    let dir = tempfile::tempdir().unwrap();
    let database_path = dir.path().join("country.mmdb");
    std::fs::write(&database_path, current_fixture()).unwrap();
    let (allowed_origin, allowed_count, allowed_task) = echo_origin().await;
    let (denied_origin, denied_count, denied_task) = echo_origin().await;
    let held = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front = held.local_addr().unwrap();
    held.set_nonblocking(true).unwrap();

    let make_route = |id: &str, host: &str, origin: SocketAddr, on_unknown: &str| {
        json!({
            "id":id, "listen":front, "backends":[origin.to_string()],
            "sni":{"hosts":[host], "max_client_hello_bytes":4096, "hello_timeout_ms":1000},
            "country_policy":{"deny":["RU"],"on_unknown":on_unknown}
        })
    };
    let config: Config = serde_json::from_value(json!({
        "geoip_database":source(&database_path),
        "tcp":[
            make_route("allowed", "a.example.test", allowed_origin, "allow"),
            make_route("denied", "b.example.test", denied_origin, "deny")
        ]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let prepared = manager
        .prepare_with_inherited(&config, vec![(front, OwnedFd::from(held))])
        .await
        .unwrap();
    let snapshot = Arc::new(Snapshot::new(config).unwrap());
    snapshot.activated();
    active.store(snapshot);
    manager.commit(prepared).await;
    let (cancel, watcher) = start_watcher(&active);
    wait_for(
        || active.load().geoip.as_ref().unwrap().load().is_some(),
        "ready SNI GeoIP slot",
    )
    .await;

    sni_attempt(front, "a.example.test", true).await;
    assert_eq!(allowed_count.load(Ordering::SeqCst), 1);
    sni_attempt(front, "b.example.test", false).await;
    assert_eq!(denied_count.load(Ordering::SeqCst), 0);
    assert_eq!(allowed_count.load(Ordering::SeqCst), 1);

    cancel.cancel();
    watcher.await.unwrap();
    manager.shutdown(Duration::from_secs(1)).await;
    allowed_task.abort();
    denied_task.abort();
}

#[tokio::test]
async fn source_switch_releases_old_geoip_slot_while_accepted_stream_survives() {
    let dir = tempfile::tempdir().unwrap();
    let first_path = dir.path().join("first.mmdb");
    let second_path = dir.path().join("second.mmdb");
    let database = current_fixture();
    std::fs::write(&first_path, &database).unwrap();
    std::fs::write(&second_path, &database).unwrap();
    let (origin, accepted, origin_task) = echo_origin().await;
    let held_listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let front = held_listener.local_addr().unwrap();
    held_listener.set_nonblocking(true).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let config: Config = serde_json::from_value(json!({
        "geoip_database":source(&first_path),
        "tcp":[route(front, origin, "allow")]
    }))
    .unwrap();
    let prepared = manager
        .prepare_with_inherited(&config, vec![(front, OwnedFd::from(held_listener))])
        .await
        .unwrap();
    let snapshot = Arc::new(Snapshot::new(config).unwrap());
    snapshot.activated();
    active.store(snapshot);
    manager.commit(prepared).await;
    let (cancel, watcher) = start_watcher(&active);
    wait_for(
        || active.load().geoip.as_ref().unwrap().load().is_some(),
        "first GeoIP generation",
    )
    .await;

    let mut held = TcpStream::connect(front).await.unwrap();
    held.write_all(b"held-through-switch").await.unwrap();
    wait_for(
        || accepted.load(Ordering::SeqCst) == 1,
        "accepted origin connection",
    )
    .await;

    let current = active.load_full();
    let old_slot = current.geoip.as_ref().unwrap().clone();
    let old_weak = Arc::downgrade(&old_slot);
    let mut next_config = current.config.clone();
    next_config.revision += 1;
    next_config.geoip_database.as_mut().unwrap().file = second_path;
    let prepared = manager.prepare(&next_config).await.unwrap();
    let next = Arc::new(Snapshot::replace(next_config, &current).unwrap());
    assert!(!Arc::ptr_eq(next.geoip.as_ref().unwrap(), &old_slot));
    assert!(next.geoip.as_ref().unwrap().load().is_none());
    manager
        .commit_with_publication(prepared, || {
            next.activated();
            active.store(next);
        })
        .await
        .unwrap();
    cancel.cancel();
    watcher.await.unwrap();
    drop(current);
    drop(old_slot);

    // A new accept refreshes the listener route cache to the new pending
    // source. Its refusal must not close the already admitted stream.
    refused(front).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    wait_for(
        || old_weak.upgrade().is_none(),
        "retired GeoIP slot release while TCP stream is still open",
    )
    .await;
    held.shutdown().await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), held.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"held-through-switch");

    manager.shutdown(Duration::from_secs(1)).await;
    origin_task.abort();
}
