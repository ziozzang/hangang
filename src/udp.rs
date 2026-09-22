//! Bounded UDP and QUIC-passthrough relay.
//!
//! QUIC is treated as opaque datagrams. The relay does not inspect packets,
//! terminate TLS, or claim support for QUIC connection migration.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    sync::mpsc,
    task::JoinHandle,
    time::{Instant, sleep_until},
};

pub const MAX_ROUTES: usize = 64;
pub const MAX_TOTAL_SESSIONS: usize = 16_384;
pub const MAX_QUEUE: usize = 8;
pub const MAX_DATAGRAM_BYTES: usize = 65_507;
pub const MAX_BUFFERED_BYTES: usize = 64 * 1024 * 1024;

fn default_enabled() -> bool {
    true
}
fn default_idle_timeout_ms() -> u64 {
    30_000
}
fn default_max_sessions() -> usize {
    1_024
}
fn default_max_datagram_bytes() -> usize {
    MAX_DATAGRAM_BYTES
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp,
    Quic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub listen: SocketAddr,
    pub backends: Vec<SocketAddr>,
    #[serde(default = "default_idle_timeout_ms")]
    pub idle_timeout_ms: u64,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_max_datagram_bytes")]
    pub max_datagram_bytes: usize,
    #[serde(default)]
    pub protocol: Protocol,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RouteStatus {
    pub id: String,
    pub enabled: bool,
    pub listen: SocketAddr,
    pub protocol: Protocol,
    pub sessions: usize,
    pub max_sessions: usize,
    pub backend_count: usize,
    pub datagrams_received: u64,
    pub datagrams_forwarded: u64,
    pub responses_forwarded: u64,
    pub dropped_datagrams: u64,
    pub sessions_created: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub routes: Vec<RouteStatus>,
}

struct PreparedListener {
    route: Route,
    socket: Arc<UdpSocket>,
}

/// Prebound candidate. Dropping it leaves live listeners and flows unchanged.
pub struct Prepared {
    epoch: u64,
    listeners: Vec<PreparedListener>,
}

struct Listener {
    route: Route,
    socket: Arc<UdpSocket>,
    sessions: Arc<AtomicUsize>,
    counters: Arc<Counters>,
    cancel: tokio_util::sync::CancellationToken,
    task: JoinHandle<()>,
}

#[derive(Default)]
struct Counters {
    datagrams_received: AtomicU64,
    datagrams_forwarded: AtomicU64,
    responses_forwarded: AtomicU64,
    dropped_datagrams: AtomicU64,
    sessions_created: AtomicU64,
}

#[derive(Default)]
struct State {
    listeners: HashMap<String, Listener>,
    retired: Vec<JoinHandle<()>>,
    epoch: u64,
    shutting_down: bool,
}

pub struct UdpManager {
    state: Mutex<State>,
    gate: Arc<AtomicBool>,
    capacity: Arc<tokio::sync::Semaphore>,
    memory: Arc<tokio::sync::Semaphore>,
}

impl Default for UdpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpManager {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            gate: Arc::new(AtomicBool::new(true)),
            capacity: Arc::new(tokio::sync::Semaphore::new(MAX_TOTAL_SESSIONS)),
            memory: Arc::new(tokio::sync::Semaphore::new(MAX_BUFFERED_BYTES)),
        }
    }

    pub fn set_gate(&self, open: bool) {
        self.gate.store(open, Ordering::Release);
    }
    pub fn gate_open(&self) -> bool {
        self.gate.load(Ordering::Acquire)
    }

    pub async fn prepare(&self, routes: &[Route]) -> Result<Prepared> {
        validate_routes(routes)?;
        let (epoch, installed) = {
            let state = self.state.lock().expect("UDP state poisoned");
            ensure!(!state.shutting_down, "UDP manager is shut down");
            (
                state.epoch,
                state
                    .listeners
                    .values()
                    .map(|l| (l.route.listen, l.socket.clone()))
                    .collect::<HashMap<_, _>>(),
            )
        };
        let mut listeners = Vec::new();
        for route in routes.iter().filter(|r| r.enabled) {
            let socket = match installed.get(&route.listen) {
                Some(socket) => socket.clone(),
                None => Arc::new(UdpSocket::bind(route.listen).await.map_err(|error| {
                    anyhow::anyhow!("bind UDP route {} at {}: {error}", route.id, route.listen)
                })?),
            };
            listeners.push(PreparedListener {
                route: route.clone(),
                socket,
            });
        }
        Ok(Prepared { epoch, listeners })
    }

    /// Every fallible check precedes mutation. Callers serialize publication;
    /// an epoch check additionally rejects stale independently prepared plans.
    pub fn commit(&self, prepared: Prepared) -> Result<()> {
        let mut state = self.state.lock().expect("UDP state poisoned");
        ensure!(!state.shutting_down, "UDP manager is shut down");
        ensure!(state.epoch == prepared.epoch, "UDP candidate is stale");
        let next_epoch = state
            .epoch
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("UDP generation exhausted"))?;
        let mut previous = std::mem::take(&mut state.listeners);
        for candidate in prepared.listeners {
            if let Some(old) = previous.remove(&candidate.route.id) {
                if old.route == candidate.route && !old.task.is_finished() {
                    state.listeners.insert(old.route.id.clone(), old);
                    continue;
                }
                state.retired.push(stop_listener(old));
            }
            let listener = spawn_listener(
                candidate.route,
                candidate.socket,
                self.gate.clone(),
                self.capacity.clone(),
                self.memory.clone(),
            );
            state.listeners.insert(listener.route.id.clone(), listener);
        }
        for (_, old) in previous {
            state.retired.push(stop_listener(old));
        }
        state.epoch = next_epoch;
        Ok(())
    }

    pub fn status(&self) -> Status {
        let state = self.state.lock().expect("UDP state poisoned");
        let mut routes: Vec<_> = state
            .listeners
            .values()
            .map(|l| RouteStatus {
                id: l.route.id.clone(),
                enabled: l.route.enabled,
                listen: l.route.listen,
                protocol: l.route.protocol,
                sessions: l.sessions.load(Ordering::Acquire),
                max_sessions: l.route.max_sessions,
                backend_count: l.route.backends.len(),
                datagrams_received: l.counters.datagrams_received.load(Ordering::Relaxed),
                datagrams_forwarded: l.counters.datagrams_forwarded.load(Ordering::Relaxed),
                responses_forwarded: l.counters.responses_forwarded.load(Ordering::Relaxed),
                dropped_datagrams: l.counters.dropped_datagrams.load(Ordering::Relaxed),
                sessions_created: l.counters.sessions_created.load(Ordering::Relaxed),
            })
            .collect();
        routes.sort_by(|a, b| a.id.cmp(&b.id));
        Status { routes }
    }

    pub fn shutdown(&self) {
        self.set_gate(false);
        let mut state = self.state.lock().expect("UDP state poisoned");
        state.shutting_down = true;
        let listeners = std::mem::take(&mut state.listeners);
        for (_, l) in listeners {
            state.retired.push(stop_listener(l));
        }
    }

    pub async fn reap(&self) {
        let tasks = std::mem::take(&mut self.state.lock().expect("UDP state poisoned").retired);
        for task in tasks {
            let _ = task.await;
        }
    }

    pub async fn shutdown_async(&self) {
        self.shutdown();
        self.reap().await;
    }
}

impl Drop for UdpManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn stop_listener(listener: Listener) -> JoinHandle<()> {
    listener.cancel.cancel();
    listener.task
}

struct Packet {
    bytes: Vec<u8>,
    _memory: tokio::sync::OwnedSemaphorePermit,
}

struct Flow {
    sender: mpsc::Sender<Packet>,
    sequence: u64,
}

struct Session {
    client: SocketAddr,
    socket: Arc<UdpSocket>,
    upstream: UdpSocket,
    input: mpsc::Receiver<Packet>,
    route: Route,
    gate: Arc<AtomicBool>,
    cancel: tokio_util::sync::CancellationToken,
    counters: Arc<Counters>,
    _capacity: tokio::sync::OwnedSemaphorePermit,
    _buffer_memory: tokio::sync::OwnedSemaphorePermit,
}

fn spawn_listener(
    route: Route,
    socket: Arc<UdpSocket>,
    gate: Arc<AtomicBool>,
    capacity: Arc<tokio::sync::Semaphore>,
    memory: Arc<tokio::sync::Semaphore>,
) -> Listener {
    let counters = Arc::new(Counters::default());
    let sessions = Arc::new(AtomicUsize::new(0));
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(listener_loop(
        route.clone(),
        socket.clone(),
        gate,
        capacity,
        memory,
        counters.clone(),
        sessions.clone(),
        cancel.clone(),
    ));
    Listener {
        route,
        socket,
        counters,
        sessions,
        cancel,
        task,
    }
}

#[allow(clippy::too_many_arguments)]
async fn listener_loop(
    route: Route,
    socket: Arc<UdpSocket>,
    gate: Arc<AtomicBool>,
    capacity: Arc<tokio::sync::Semaphore>,
    memory: Arc<tokio::sync::Semaphore>,
    counters: Arc<Counters>,
    sessions_count: Arc<AtomicUsize>,
    cancel: tokio_util::sync::CancellationToken,
) {
    let mut flows: HashMap<SocketAddr, Flow> = HashMap::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut sequence = 0u64;
    let mut round_robin = 0usize;
    let mut buffer = vec![0u8; MAX_DATAGRAM_BYTES + 1];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            ended = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Ok((client, finished))) = ended
                    && flows.get(&client).is_some_and(|f| f.sequence == finished) { flows.remove(&client); }
                // A panicked/aborted session closes its sender too; reclaim that slot.
                flows.retain(|_, f| !f.sender.is_closed());
                sessions_count.store(flows.len(), Ordering::Release);
            }
            received = socket.recv_from(&mut buffer) => {
                let Ok((size, client)) = received else { break; };
                counters.datagrams_received.fetch_add(1, Ordering::Relaxed);
                if cancel.is_cancelled() || !gate.load(Ordering::Acquire) || size > route.max_datagram_bytes {
                    counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue;
                }
                if flows.get(&client).is_some_and(|f| f.sender.is_closed()) { flows.remove(&client); }
                if !flows.contains_key(&client) {
                    if flows.len() >= route.max_sessions { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue; }
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue; };
                    let Ok(buffer_permit) = memory.clone().try_acquire_many_owned((route.max_datagram_bytes + 1) as u32) else { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue; };
                    let backend = route.backends[round_robin % route.backends.len()];
                    let Ok(upstream) = bind_connected(backend).await else { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue; };
                    if cancel.is_cancelled() || !gate.load(Ordering::Acquire) { continue; }
                    round_robin = round_robin.wrapping_add(1);
                    let Some(next) = sequence.checked_add(1) else { break; }; sequence = next;
                    let (sender, input) = mpsc::channel(MAX_QUEUE);
                    flows.insert(client, Flow { sender, sequence });
                    sessions_count.store(flows.len(), Ordering::Release);
                    counters.sessions_created.fetch_add(1, Ordering::Relaxed);
                    let flow_sequence = sequence;
                    let session = Session { client, socket: socket.clone(), upstream, input, route: route.clone(), gate: gate.clone(), cancel: cancel.clone(), counters: counters.clone(), _capacity: permit, _buffer_memory: buffer_permit };
                    tasks.spawn(async move { session_loop(session).await; (client, flow_sequence) });
                }
                let Ok(permit) = memory.clone().try_acquire_many_owned(size as u32) else { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue; };
                let packet = Packet { bytes: buffer[..size].to_vec(), _memory: permit };
                if flows[&client].sender.try_send(packet).is_err() { counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); }
            }
        }
    }
    cancel.cancel();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    sessions_count.store(0, Ordering::Release);
}

async fn bind_connected(backend: SocketAddr) -> Result<UdpSocket> {
    let bind = match backend.ip() {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        IpAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    };
    let socket = UdpSocket::bind(bind).await?;
    socket.connect(backend).await?;
    Ok(socket)
}

async fn session_loop(mut session: Session) {
    let idle = Duration::from_millis(session.route.idle_timeout_ms);
    let mut deadline = Instant::now() + idle;
    let mut buffer = vec![0u8; session.route.max_datagram_bytes + 1];
    loop {
        if session.cancel.is_cancelled() || Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            _ = session.cancel.cancelled() => break,
            _ = sleep_until(deadline) => break,
            packet = session.input.recv() => {
                let Some(packet) = packet else { break; };
                if !session.gate.load(Ordering::Acquire) || session.cancel.is_cancelled() { break; }
                let sent = tokio::select! { biased; _ = session.cancel.cancelled() => break, sent = session.upstream.send(&packet.bytes) => sent };
                if sent.is_err() { session.counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); break; }
                session.counters.datagrams_forwarded.fetch_add(1, Ordering::Relaxed);
                deadline = Instant::now() + idle;
            }
            received = session.upstream.recv(&mut buffer) => {
                let Ok(size) = received else { break; };
                if size > session.route.max_datagram_bytes || !session.gate.load(Ordering::Acquire) || session.cancel.is_cancelled() {
                    session.counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); continue;
                }
                let sent = tokio::select! { biased; _ = session.cancel.cancelled() => break, sent = session.socket.send_to(&buffer[..size], session.client) => sent };
                if sent.is_err() { session.counters.dropped_datagrams.fetch_add(1, Ordering::Relaxed); break; }
                session.counters.responses_forwarded.fetch_add(1, Ordering::Relaxed);
                deadline = Instant::now() + idle;
            }
        }
    }
}

pub fn validate_routes(routes: &[Route]) -> Result<()> {
    ensure!(routes.len() <= MAX_ROUTES, "UDP routes exceed {MAX_ROUTES}");
    let mut ids = std::collections::HashSet::new();
    let mut listens = std::collections::HashSet::new();
    let mut total = 0usize;
    for route in routes {
        ensure!(
            !route.id.is_empty()
                && route.id.len() <= 64
                && route
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
            "UDP route id must be 1..64 ASCII letters, digits, dots, underscores or dashes"
        );
        ensure!(
            ids.insert(route.id.clone()),
            "duplicate UDP route id: {}",
            route.id
        );
        ensure!(
            route.listen.port() != 0
                && (route.listen.ip().is_unspecified() || is_unicast(route.listen.ip())),
            "UDP route {} listen must be a wildcard or unicast address with a nonzero port",
            route.id
        );
        if route.enabled {
            ensure!(
                listens.insert(route.listen),
                "duplicate UDP listener: {}",
                route.listen
            );
        }
        ensure!(
            !route.backends.is_empty() && route.backends.len() <= 64,
            "UDP route {} needs 1..64 backends",
            route.id
        );
        let mut backend_addresses = std::collections::HashSet::new();
        for backend in &route.backends {
            ensure!(backend_addresses.insert(backend), "duplicate UDP backend");
            ensure!(
                *backend != route.listen,
                "UDP backend cannot be its own listener"
            );
            ensure!(
                backend.port() != 0 && is_unicast(backend.ip()),
                "UDP route {} backend must be a unicast address with a nonzero port",
                route.id
            );
        }
        ensure!(
            (1..=MAX_DATAGRAM_BYTES).contains(&route.max_datagram_bytes),
            "UDP route {} max_datagram_bytes must be 1..65507",
            route.id
        );
        if route.protocol == Protocol::Quic {
            ensure!(
                route.max_datagram_bytes >= 1_200,
                "UDP route {} QUIC max_datagram_bytes must be at least 1200",
                route.id
            );
        }
        ensure!(
            (1..=16_384).contains(&route.max_sessions),
            "UDP route {} max_sessions must be 1..16384",
            route.id
        );
        ensure!(
            (100..=86_400_000).contains(&route.idle_timeout_ms),
            "UDP route {} idle_timeout_ms must be 100..86400000",
            route.id
        );
        total = total
            .checked_add(route.max_sessions)
            .ok_or_else(|| anyhow::anyhow!("UDP session limit overflow"))?;
    }
    for route in routes.iter().filter(|r| r.enabled) {
        for backend in &route.backends {
            ensure!(
                !routes.iter().filter(|r| r.enabled).any(|other| {
                    other.listen == *backend
                        || (other.listen.port() == backend.port()
                            && other.listen.ip().is_unspecified()
                            && backend.ip().is_loopback()
                            && other.listen.is_ipv4() == backend.is_ipv4())
                }),
                "UDP backend points to a configured local listener"
            );
        }
    }
    ensure!(
        total <= MAX_TOTAL_SESSIONS,
        "UDP max_sessions total exceeds {MAX_TOTAL_SESSIONS}"
    );
    Ok(())
}

fn is_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_multicast()
                && ip
                    .to_ipv4_mapped()
                    .is_none_or(|ip| is_unicast(IpAddr::V4(ip)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    async fn echo() -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut b = [0; 1024];
            while let Ok((n, peer)) = socket.recv_from(&mut b).await {
                let _ = socket.send_to(&b[..n], peer).await;
            }
        });
        (addr, task)
    }

    async fn tagged(tag: &'static [u8]) -> (SocketAddr, JoinHandle<()>) {
        let socket = UdpSocket::bind(if tag == b"v6" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .await
        .unwrap();
        let addr = socket.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut b = [0; 65_508];
            while let Ok((_, peer)) = socket.recv_from(&mut b).await {
                let _ = socket.send_to(tag, peer).await;
            }
        });
        (addr, task)
    }

    async fn listener_addr() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        drop(socket);
        address
    }

    #[tokio::test]
    async fn relays_and_isolates_client_flows() {
        let (backend, task) = echo().await;
        let manager = UdpManager::new();
        let route = Route {
            id: "r".into(),
            enabled: true,
            listen: "127.0.0.1:0".parse().unwrap(),
            backends: vec![backend],
            idle_timeout_ms: 1000,
            max_sessions: 8,
            max_datagram_bytes: 100,
            protocol: Protocol::Udp,
        };
        // Port zero is intentionally invalid for configuration, so bind a test port first.
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listen = probe.local_addr().unwrap();
        drop(probe);
        let route = Route { listen, ..route };
        manager
            .commit(manager.prepare(&[route]).await.unwrap())
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", listen).await.unwrap();
        let mut b = [0; 100];
        let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"hello");
        manager.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn validates_limits_and_unicast() {
        let mut route = Route {
            id: "r".into(),
            enabled: true,
            listen: "239.0.0.1:10".parse().unwrap(),
            backends: vec!["127.0.0.1:10".parse().unwrap()],
            ..Route::default_for_test()
        };
        assert!(validate_routes(&[route.clone()]).is_err());
        route.listen = "127.0.0.1:10".parse().unwrap();
        route.max_datagram_bytes = 0;
        assert!(validate_routes(&[route]).is_err());
    }

    #[tokio::test]
    async fn capacity_and_idle_expiry_reclaim_sessions() {
        let (backend, task) = echo().await;
        let listen = listener_addr().await;
        let manager = UdpManager::new();
        let route = Route {
            id: "limited".into(),
            enabled: true,
            listen,
            backends: vec![backend],
            idle_timeout_ms: 100,
            max_sessions: 1,
            max_datagram_bytes: 16,
            protocol: Protocol::Udp,
        };
        manager
            .commit(manager.prepare(&[route]).await.unwrap())
            .unwrap();
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        first.send_to(b"one", listen).await.unwrap();
        let mut b = [0; 16];
        timeout(Duration::from_secs(1), first.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        second.send_to(b"blocked", listen).await.unwrap();
        assert!(
            timeout(Duration::from_millis(40), second.recv_from(&mut b))
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(160)).await;
        second.send_to(b"again", listen).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(1), second.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"again");
        manager.shutdown();
        task.abort();
    }

    #[tokio::test]
    async fn oversized_datagrams_are_dropped_in_both_directions() {
        let listen = listener_addr().await;
        let oversized_backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let backend = oversized_backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let mut b = [0; 64];
            if let Ok((_, peer)) = oversized_backend.recv_from(&mut b).await {
                let _ = oversized_backend.send_to(&[9u8; 17], peer).await;
            }
        });
        let manager = UdpManager::new();
        let route = Route {
            id: "bounded".into(),
            enabled: true,
            listen,
            backends: vec![backend],
            idle_timeout_ms: 1000,
            max_sessions: 4,
            max_datagram_bytes: 8,
            protocol: Protocol::Udp,
        };
        manager
            .commit(manager.prepare(&[route]).await.unwrap())
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&[1u8; 9], listen).await.unwrap();
        let mut b = [0; 32];
        assert!(
            timeout(Duration::from_millis(100), client.recv_from(&mut b))
                .await
                .is_err()
        );
        client.send_to(&[1u8; 1], listen).await.unwrap();
        assert!(
            timeout(Duration::from_millis(100), client.recv_from(&mut b))
                .await
                .is_err()
        );
        manager.shutdown();
        backend_task.abort();
    }

    #[tokio::test]
    async fn changed_route_cancels_session_and_failed_bind_preserves_state() {
        let (first_backend, first_task) = tagged(b"one").await;
        let (second_backend, second_task) = tagged(b"two").await;
        let listen = listener_addr().await;
        let manager = UdpManager::new();
        let first = Route {
            id: "route".into(),
            enabled: true,
            listen,
            backends: vec![first_backend],
            idle_timeout_ms: 1000,
            max_sessions: 8,
            max_datagram_bytes: 32,
            protocol: Protocol::Udp,
        };
        manager
            .commit(manager.prepare(std::slice::from_ref(&first)).await.unwrap())
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"x", listen).await.unwrap();
        let mut b = [0; 32];
        let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"one");
        let mut changed = first.clone();
        changed.backends = vec![second_backend];
        manager
            .commit(manager.prepare(&[changed]).await.unwrap())
            .unwrap();
        client.send_to(b"x", listen).await.unwrap();
        let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"two");
        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut failed = first;
        failed.id = "new".into();
        failed.listen = occupied.local_addr().unwrap();
        assert!(manager.prepare(&[failed]).await.is_err());
        assert_eq!(manager.status().routes[0].id, "route");
        manager.shutdown();
        first_task.abort();
        second_task.abort();
    }

    #[tokio::test]
    async fn ipv6_relay_when_loopback_is_available() {
        let (backend, task) = tagged(b"v6").await;
        if backend.is_ipv4() {
            task.abort();
            return;
        }
        let Ok(socket) = UdpSocket::bind("[::1]:0").await else {
            task.abort();
            return;
        };
        let listen = socket.local_addr().unwrap();
        drop(socket);
        let manager = UdpManager::new();
        let route = Route {
            id: "v6".into(),
            enabled: true,
            listen,
            backends: vec![backend],
            idle_timeout_ms: 1000,
            max_sessions: 4,
            max_datagram_bytes: 32,
            protocol: Protocol::Udp,
        };
        manager
            .commit(manager.prepare(&[route]).await.unwrap())
            .unwrap();
        let client = UdpSocket::bind("[::1]:0").await.unwrap();
        client.send_to(b"v6", listen).await.unwrap();
        let mut b = [0; 32];
        let (n, _) = timeout(Duration::from_secs(1), client.recv_from(&mut b))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&b[..n], b"v6");
        manager.shutdown();
        task.abort();
    }

    impl Route {
        fn default_for_test() -> Self {
            Self {
                id: "r".into(),
                enabled: true,
                listen: "127.0.0.1:10".parse().unwrap(),
                backends: vec!["127.0.0.1:10".parse().unwrap()],
                idle_timeout_ms: 1000,
                max_sessions: 1,
                max_datagram_bytes: 100,
                protocol: Protocol::Udp,
            }
        }
    }
}
