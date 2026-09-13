use crate::{
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore},
    task::JoinHandle,
    time::{Instant, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

/// A transactional set of newly-bound sockets and the complete desired set.
/// Dropping it before `commit` closes the sockets and rolls preparation back.
pub struct Prepared {
    desired: HashSet<SocketAddr>,
    added: Vec<(SocketAddr, TcpListener, std::net::TcpListener)>,
}

struct ListenerHandle {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    export: std::net::TcpListener,
}

#[derive(Default)]
struct State {
    listeners: HashMap<SocketAddr, ListenerHandle>,
    shutting_down: bool,
    health_monitor: Option<AbortOnDrop>,
}

pub struct TcpManager {
    active: Arc<ArcSwap<Snapshot>>,
    metrics: Arc<Metrics>,
    permits: Arc<Semaphore>,
    connections: TaskTracker,
    connection_cancel: CancellationToken,
    state: Mutex<State>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    // Idle bound for established L4 sessions. Zero disables it (unbounded, the
    // historical behavior); a positive value closes a session that makes no
    // byte-level progress within the window, bounding L4 slowloris.
    idle_timeout: Duration,
    /// Accept gate. Listeners are bound (and inherited sockets adopted) while
    /// the gate is closed, but no connection is accepted until `open_gate`.
    /// A replacement generation keeps the gate closed until it has confirmed
    /// its snapshot against the shared configuration authority, so L4 traffic
    /// never runs on an unreconciled snapshot. Default: open.
    gate: tokio::sync::watch::Sender<bool>,
}

impl TcpManager {
    pub fn new(
        active: Arc<ArcSwap<Snapshot>>,
        metrics: Arc<Metrics>,
        max_connections: usize,
    ) -> Self {
        Self::with_idle_timeout(active, metrics, max_connections, Duration::ZERO)
    }

    pub fn with_idle_timeout(
        active: Arc<ArcSwap<Snapshot>>,
        metrics: Arc<Metrics>,
        max_connections: usize,
        idle_timeout: Duration,
    ) -> Self {
        Self {
            active,
            metrics,
            permits: Arc::new(Semaphore::new(max_connections)),
            connections: TaskTracker::new(),
            connection_cancel: CancellationToken::new(),
            state: Mutex::new(State::default()),
            discovery: None,
            idle_timeout,
            gate: tokio::sync::watch::Sender::new(true),
        }
    }

    /// Start with the accept gate closed; see `open_gate`.
    pub fn with_gate_closed(self) -> Self {
        self.gate.send_replace(false);
        self
    }

    /// Allow accept loops to take connections. Idempotent.
    pub fn open_gate(&self) {
        self.gate.send_replace(true);
    }

    pub fn gate_open(&self) -> bool {
        *self.gate.borrow()
    }

    pub fn with_discovery(mut self, discovery: Arc<crate::discovery::Discovery>) -> Self {
        self.discovery = Some(discovery);
        self
    }

    /// Validate the complete config and bind only addresses which are not
    /// already active. No accept loop starts until `commit`.
    pub async fn prepare(&self, config: &Config) -> Result<Prepared> {
        config.validate()?;
        let current = {
            let state = self.state.lock().await;
            ensure!(!state.shutting_down, "TCP manager is shutting down");
            state.listeners.keys().copied().collect::<HashSet<_>>()
        };

        let desired = config
            .tcp
            .iter()
            .filter(|route| route.enabled)
            .map(|route| route.listen)
            .collect::<HashSet<_>>();
        let mut added = Vec::new();
        // Keep configuration order so a later bind failure deterministically
        // drops every socket already prepared in this transaction.
        let mut accounted = current;
        for address in config
            .tcp
            .iter()
            .filter(|route| route.enabled)
            .map(|route| route.listen)
        {
            if !accounted.insert(address) {
                continue;
            }
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("bind TCP listener {address}"))?;
            let (listener, export) = retain_export_listener(listener)?;
            added.push((address, listener, export));
        }
        Ok(Prepared { desired, added })
    }

    /// Check that every TCP listen address in `config` can be bound on this
    /// host together with the process's own `reserved` listeners (public,
    /// admin, ACME). Used before a seed becomes the shared authority: a seed
    /// that no instance could start must never be persisted for the whole
    /// fleet. All sockets are held until the end of the probe so overlaps
    /// between the addresses themselves (`0.0.0.0:P` with `127.0.0.1:P`, a
    /// route colliding with the admin port, dual-stack `[::]:P` with
    /// `0.0.0.0:P`) are detected by the kernel rather than by a heuristic.
    /// The real bind happens later in `prepare`; an external process taking
    /// the port in between is reported there.
    pub async fn probe_bindable(config: &Config, reserved: &[SocketAddr]) -> Result<()> {
        let mut held = Vec::new();
        // Process roles never share an address with each other or with a
        // route; only routes may legitimately share one listener (SNI).
        let mut process = HashSet::new();
        for address in reserved.iter().copied() {
            ensure!(
                process.insert(address),
                "process listener address {address} is used twice"
            );
            held.push(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("bind process listener {address}"))?,
            );
        }
        let mut routes = HashSet::new();
        for address in config
            .tcp
            .iter()
            .filter(|route| route.enabled)
            .map(|route| route.listen)
        {
            ensure!(
                !process.contains(&address),
                "TCP route listen address {address} collides with a process listener"
            );
            if !routes.insert(address) {
                continue;
            }
            held.push(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("bind TCP listener {address}"))?,
            );
        }
        drop(held);
        Ok(())
    }

    /// Strictly import every configured TCP listener received from a previous
    /// worker. No missing listener is rebound and no unexpected descriptor is
    /// accepted, so a handoff is all-or-nothing.
    #[cfg(unix)]
    pub async fn prepare_with_inherited(
        &self,
        config: &Config,
        inherited: Vec<(SocketAddr, OwnedFd)>,
    ) -> Result<Prepared> {
        config.validate()?;
        {
            let state = self.state.lock().await;
            ensure!(!state.shutting_down, "TCP manager is shutting down");
            ensure!(
                state.listeners.is_empty(),
                "TCP manager already owns listeners"
            );
        }
        let desired = config
            .tcp
            .iter()
            .filter(|route| route.enabled)
            .map(|route| route.listen)
            .collect::<HashSet<_>>();
        ensure!(
            inherited.len() == desired.len(),
            "inherited TCP listener count does not match configuration"
        );

        let mut seen = HashSet::new();
        let mut added = Vec::with_capacity(inherited.len());
        for (declared, descriptor) in inherited {
            ensure!(
                seen.insert(declared),
                "duplicate inherited TCP listener {declared}"
            );
            ensure!(
                desired.contains(&declared),
                "unexpected inherited TCP listener {declared}"
            );
            ensure_listening_socket(&descriptor)?;
            let listener = std::net::TcpListener::from(descriptor);
            listener
                .set_nonblocking(true)
                .with_context(|| format!("set inherited TCP listener {declared} nonblocking"))?;
            let actual = listener
                .local_addr()
                .with_context(|| format!("inspect inherited TCP listener {declared}"))?;
            ensure!(
                actual == declared,
                "inherited TCP listener address mismatch: expected {declared}, got {actual}"
            );
            let export = listener
                .try_clone()
                .with_context(|| format!("retain inherited TCP listener {declared}"))?;
            let runtime = TcpListener::from_std(listener)
                .with_context(|| format!("adopt inherited TCP listener {declared}"))?;
            added.push((declared, runtime, export));
        }
        ensure!(
            seen == desired,
            "one or more configured TCP listeners are missing"
        );
        Ok(Prepared { desired, added })
    }

    /// Activate prepared sockets and stop listeners removed by the new
    /// configuration. Connection tasks are independent and continue draining.
    pub async fn commit(&self, prepared: Prepared) {
        let mut stopped = Vec::new();
        {
            let mut state = self.state.lock().await;
            if state.shutting_down {
                return;
            }

            if state.health_monitor.is_none() {
                let task = tokio::spawn(monitor_tcp_health(
                    self.active.clone(),
                    self.discovery.clone(),
                    self.gate.subscribe(),
                ));
                state.health_monitor = Some(AbortOnDrop(task.abort_handle()));
            }
            for (address, listener, export) in prepared.added {
                if state.listeners.contains_key(&address) {
                    continue;
                }
                let cancel = CancellationToken::new();
                let task = spawn_accept_loop(
                    address,
                    listener,
                    cancel.clone(),
                    self.active.clone(),
                    self.metrics.clone(),
                    self.permits.clone(),
                    self.connections.clone(),
                    self.connection_cancel.clone(),
                    self.discovery.clone(),
                    self.idle_timeout,
                    self.gate.subscribe(),
                );
                state.listeners.insert(
                    address,
                    ListenerHandle {
                        cancel,
                        task,
                        export,
                    },
                );
            }

            let removed = state
                .listeners
                .keys()
                .filter(|address| !prepared.desired.contains(address))
                .copied()
                .collect::<Vec<_>>();
            for address in removed {
                if let Some(handle) = state.listeners.remove(&address) {
                    handle.cancel.cancel();
                    stopped.push(handle.task);
                }
            }
        }
        for task in stopped {
            let _ = task.await;
        }
    }

    /// Duplicate the active listening descriptors for transfer to a new
    /// worker. Returned descriptors are close-on-exec until the private handoff
    /// protocol passes them with SCM_RIGHTS.
    #[cfg(unix)]
    pub async fn export_listeners(&self) -> Result<Vec<(SocketAddr, OwnedFd)>> {
        let state = self.state.lock().await;
        ensure!(!state.shutting_down, "TCP manager is shutting down");
        let mut listeners = state
            .listeners
            .iter()
            .map(|(address, handle)| {
                let cloned = handle
                    .export
                    .try_clone()
                    .with_context(|| format!("duplicate TCP listener {address}"))?;
                let raw = cloned.into_raw_fd();
                // SAFETY: into_raw_fd transfers ownership of this valid fd.
                Ok((*address, unsafe { OwnedFd::from_raw_fd(raw) }))
            })
            .collect::<Result<Vec<_>>>()?;
        listeners.sort_unstable_by_key(|(address, _)| *address);
        Ok(listeners)
    }

    /// Stop accepting, allow established streams to drain for `grace`, then
    /// cancel any connection tasks still alive and wait until they exit.
    /// Stop accepting on every listener at once (idempotent) without waiting
    /// for established streams. `shutdown` performs the same step before
    /// draining; calling this first lets a retiring generation close its
    /// accept loops before it waits for unrelated background work.
    pub async fn stop_accepting(&self) {
        let listeners = {
            let mut state = self.state.lock().await;
            if state.shutting_down {
                Vec::new()
            } else {
                state.shutting_down = true;
                state.health_monitor.take();
                state
                    .listeners
                    .drain()
                    .map(|(_, handle)| {
                        handle.cancel.cancel();
                        handle.task
                    })
                    .collect::<Vec<_>>()
            }
        };
        for task in listeners {
            let _ = task.await;
        }
    }

    pub async fn shutdown(&self, grace: Duration) {
        let deadline = Instant::now() + grace;
        self.stop_accepting().await;

        self.connections.close();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if timeout(remaining, self.connections.wait()).await.is_err() {
            self.connection_cancel.cancel();
            self.connections.wait().await;
        }
    }
}

type ListenerRoute = (
    TcpRoute,
    Arc<AtomicUsize>,
    Option<Arc<rustls::ClientConfig>>,
    Option<Arc<crate::tcp_health::TcpHealth>>,
);

struct ListenerRoutes {
    source: Weak<Snapshot>,
    routes: Vec<ListenerRoute>,
    legacy: Option<usize>,
    priorities: Vec<PriorityRoutes>,
    hello_settings: Option<(usize, u64)>,
}

struct PriorityRoutes {
    priority: i32,
    exact: HashMap<String, usize>,
    wildcard: HashMap<String, usize>,
    globs: Vec<(String, usize)>,
    regexes: Vec<(regex::Regex, usize)>,
}

impl ListenerRoutes {
    fn build(snapshot: &Arc<Snapshot>, address: SocketAddr) -> Option<Arc<Self>> {
        let mut routes = Vec::new();
        let mut legacy = None;
        let mut priorities = Vec::<PriorityRoutes>::new();
        let mut hello_settings = None;
        let mut found = false;
        for route in &snapshot.config.tcp {
            if !route.enabled || route.listen != address {
                continue;
            }
            found = true;
            let index = routes.len();
            routes.push((
                route.clone(),
                snapshot.admissions[&route.id].clone(),
                snapshot.upstream_tls.get(&route.id).cloned(),
                snapshot.tcp_health.get(&route.id).cloned(),
            ));
            if let Some(sni) = &route.sni {
                hello_settings = Some((sni.max_client_hello_bytes, sni.hello_timeout_ms));
                let group_index = if let Some(index) = priorities
                    .iter()
                    .position(|group| group.priority == route.priority)
                {
                    index
                } else {
                    priorities.push(PriorityRoutes {
                        priority: route.priority,
                        exact: HashMap::new(),
                        wildcard: HashMap::new(),
                        globs: Vec::new(),
                        regexes: Vec::new(),
                    });
                    priorities.len() - 1
                };
                let group = &mut priorities[group_index];
                for host in &sni.hosts {
                    let host = host.to_ascii_lowercase();
                    if let Some(suffix) = simple_wildcard_suffix(&host) {
                        group.wildcard.insert(suffix.to_owned(), index);
                    } else if crate::host_match::is_glob(&host) {
                        group.globs.push((host, index));
                    } else {
                        group.exact.insert(host, index);
                    }
                }
                if let Some(regexes) = snapshot.sni_regex.get(&route.id) {
                    group
                        .regexes
                        .extend(regexes.iter().cloned().map(|regex| (regex, index)));
                }
            } else {
                legacy = Some(index);
            }
        }
        priorities.sort_by_key(|group| std::cmp::Reverse(group.priority));
        found.then(|| {
            Arc::new(Self {
                source: Arc::downgrade(snapshot),
                routes,
                legacy,
                priorities,
                hello_settings,
            })
        })
    }

    fn route_for_server_name(&self, server_name: &str) -> Option<usize> {
        let server_name = server_name.to_ascii_lowercase();
        for group in &self.priorities {
            if let Some(index) = group.exact.get(&server_name) {
                return Some(*index);
            }
            if let Some((_, suffix)) = server_name.split_once('.')
                && let Some(index) = group.wildcard.get(suffix)
            {
                return Some(*index);
            }
            if let Some(index) = group.globs.iter().find_map(|(pattern, index)| {
                crate::host_match::matches(pattern, &server_name).then_some(*index)
            }) {
                return Some(index);
            }
            if let Some(index) = group
                .regexes
                .iter()
                .find_map(|(regex, index)| regex.is_match(&server_name).then_some(*index))
            {
                return Some(index);
            }
        }
        None
    }

    fn all_routes_deny(&self, peer: std::net::IpAddr) -> bool {
        self.routes.iter().all(|(route, _, _, _)| {
            route
                .deny_cidrs
                .iter()
                .any(|network| network.contains(&peer))
        })
    }
}

fn simple_wildcard_suffix(pattern: &str) -> Option<&str> {
    let suffix = pattern.strip_prefix("*.")?;
    (!suffix.bytes().any(|byte| matches!(byte, b'*' | b'?'))).then_some(suffix)
}

struct AbortOnDrop(tokio::task::AbortHandle);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn monitor_tcp_health(
    active: Arc<ArcSwap<Snapshot>>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    mut gate: tokio::sync::watch::Receiver<bool>,
) {
    let mut current = Weak::<Snapshot>::new();
    let mut tasks = tokio::task::JoinSet::new();
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let gate_closed = !*gate.borrow();
        if gate_closed && gate.wait_for(|open| *open).await.is_err() {
            break;
        }
        let snapshot = active.load_full();
        if current
            .upgrade()
            .is_some_and(|old| Arc::ptr_eq(&old, &snapshot))
        {
            continue;
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        current = Arc::downgrade(&snapshot);
        for route in &snapshot.config.tcp {
            if !route.enabled || route.health.is_none() {
                continue;
            }
            let health = Arc::downgrade(&snapshot.tcp_health[&route.id]);
            let tls = snapshot.upstream_tls.get(&route.id).cloned();
            let route = Arc::new(route.clone());
            for index in 0..route.backends.len() {
                tasks.spawn(run_tcp_probe(
                    route.clone(),
                    index,
                    health.clone(),
                    tls.clone(),
                    discovery.clone(),
                ));
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn run_tcp_probe(
    route: Arc<TcpRoute>,
    index: usize,
    health: Weak<crate::tcp_health::TcpHealth>,
    tls: Option<Arc<rustls::ClientConfig>>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
) {
    let policy = route.health.as_ref().expect("configured TCP probe");
    let mut ticker = tokio::time::interval(Duration::from_millis(policy.interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        let Some(health) = health.upgrade() else {
            break;
        };
        let configured = route.backends[index].address();
        let Some(target) = resolve_probe_target(configured, discovery.as_deref()) else {
            health.record_failure_current(index);
            continue;
        };
        if !health.observe_epoch(index, target.epoch) {
            continue;
        }
        // The complete connect, proxy negotiation and optional TLS handshake are
        // bounded by the probe deadline. No application or ClientHello bytes
        // from a downstream client are sent on a health connection.
        let outcome = timeout(
            Duration::from_millis(policy.timeout_ms),
            crate::upstream::connect_with_tls(&target.endpoint, &route.upstream, tls.clone()),
        )
        .await;
        // Never let a successful connection to a retired Docker generation
        // qualify the replacement, including address ABA after removal.
        if resolve_probe_target(configured, discovery.as_deref()).as_ref() != Some(&target) {
            continue;
        }
        if matches!(outcome, Ok(Ok(_))) {
            health.record_success_for(index, target.epoch);
        } else {
            health.record_failure_for(index, target.epoch);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_accept_loop(
    address: SocketAddr,
    listener: TcpListener,
    cancel: CancellationToken,
    active: Arc<ArcSwap<Snapshot>>,
    metrics: Arc<Metrics>,
    permits: Arc<Semaphore>,
    connections: TaskTracker,
    connection_cancel: CancellationToken,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    idle_timeout: Duration,
    mut gate: tokio::sync::watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let next_backend = Arc::new(StdMutex::new(HashMap::<String, usize>::new()));
        let mut routing_cache: Option<Arc<ListenerRoutes>> = None;
        loop {
            if !*gate.borrow() {
                // Connections queue in the kernel backlog until the gate opens
                // (or another generation sharing the socket accepts them).
                let opened = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    opened = gate.wait_for(|open| *open) => opened,
                };
                if opened.is_err() {
                    break;
                }
            }
            let accepted = tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let (client, peer) = match accepted {
                Ok((client, peer)) => {
                    // Canonicalize IPv4-mapped IPv6 peers (from a dual-stack
                    // `[::]` listener) so `deny_cidrs` with IPv4 ranges match
                    // the real IPv4 address instead of silently failing open.
                    (
                        client,
                        SocketAddr::new(peer.ip().to_canonical(), peer.port()),
                    )
                }
                Err(error) => {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(%address, %error, "TCP accept failed");
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                    }
                    continue;
                }
            };

            let snapshot = active.load_full();
            if routing_cache
                .as_ref()
                .is_none_or(|routes| !Weak::ptr_eq(&routes.source, &Arc::downgrade(&snapshot)))
            {
                routing_cache = ListenerRoutes::build(&snapshot, address);
            }
            let Some(routes) = routing_cache.clone() else {
                metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // This is decisive before SNI selection only if every possible route
            // denies the peer. It also keeps denied legacy traffic out of global
            // admission without weakening the selected-route check below.
            if routes.all_routes_deny(peer.ip()) {
                metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };
            let task_metrics = metrics.clone();
            let task_cancel = connection_cancel.clone();
            let task_discovery = discovery.clone();
            let task_backend_counter = next_backend.clone();
            connections.spawn(async move {
                let _permit = permit;
                let _active = ActiveConnection::new(task_metrics.clone());
                let mut client = client;
                let (route_index, consumed) = if let Some(route_index) = routes.legacy {
                    (route_index, Vec::new())
                } else {
                    let (max_client_hello_bytes, hello_timeout_ms) =
                        routes.hello_settings.expect("validated SNI listener settings");
                    let inspected = tokio::select! {
                        biased;
                        _ = task_cancel.cancelled() => return,
                        result = timeout(
                            Duration::from_millis(hello_timeout_ms),
                            crate::client_hello::read_client_hello(
                                &mut client,
                                max_client_hello_bytes,
                            ),
                        ) => result,
                    };
                    let hello = match inspected {
                        Ok(Ok(hello)) => hello,
                        Ok(Err(error)) => {
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%peer, %error, "TCP ClientHello rejected");
                            return;
                        }
                        Err(_) => {
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%peer, "TCP ClientHello timed out");
                            return;
                        }
                    };
                    let Some(route_index) = routes.route_for_server_name(&hello.server_name) else {
                        task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%peer, server_name=%hello.server_name, "TCP SNI did not match a route");
                        return;
                    };
                    (route_index, hello.consumed)
                };
                let (route, counter, upstream_tls, health) = routes.routes[route_index].clone();
                drop(routes);
                if route
                    .deny_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(&peer.ip()))
                {
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let _route_permit =
                    match crate::admission::acquire(&counter, route.max_connections) {
                        Ok(permit) => permit,
                        Err(_) => {
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                let Some(index) = next_backend_index(&task_backend_counter, &route, health.as_deref(), task_discovery.as_deref()) else {
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let Some(target) = resolve_probe_target(route.backends[index].address(), task_discovery.as_deref()) else {
                    task_metrics.errors.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                if health.as_ref().is_some_and(|health| !health.observe_epoch(index, target.epoch) || !health.available_for(index, target.epoch)) {
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let backend = target.endpoint.clone();
                let admission = TcpDialAdmission { configured: route.backends[index].address().to_owned(), target, health, discovery: task_discovery, index };
                if let Err(error) =
                    // SNI inspection remains passthrough. When this route also
                    // configures upstream TLS, the consumed ClientHello is sent
                    // as application data inside that explicitly requested TLS
                    // session, allowing a TLS-unwrapping stream endpoint.
                    proxy_connection(
                        client,
                        &admission,
                        &route.upstream,
                        upstream_tls,
                        &consumed,
                        idle_timeout,
                        task_cancel,
                    )
                    .await
                {
                    task_metrics.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%peer, %backend, %error, "TCP proxy connection failed");
                }
            });
        }
    })
}

fn resolve_probe_target(
    backend: &str,
    discovery: Option<&crate::discovery::Discovery>,
) -> Option<crate::discovery::ResolvedTarget> {
    if backend.starts_with("docker://") {
        discovery.and_then(|discovery| {
            discovery.resolve_with_epoch(backend, crate::discovery::Protocol::Tcp)
        })
    } else {
        Some(crate::discovery::ResolvedTarget {
            endpoint: backend.to_owned(),
            epoch: 0,
        })
    }
}

fn next_backend_index(
    counters: &StdMutex<HashMap<String, usize>>,
    route: &TcpRoute,
    health: Option<&crate::tcp_health::TcpHealth>,
    discovery: Option<&crate::discovery::Discovery>,
) -> Option<usize> {
    let mut counters = counters.lock().expect("TCP backend counter lock");
    // Configuration has at most 1024 routes. Bound retired route IDs retained
    // across many reloads without scanning the active configuration per accept.
    if !counters.contains_key(&route.id) && counters.len() >= 2048 {
        counters.clear();
    }
    let counter = counters.entry(route.id.clone()).or_default();
    let index = *counter % route.backends.len();
    *counter = counter.wrapping_add(1);
    (0..route.backends.len())
        .map(|offset| (index + offset) % route.backends.len())
        .find(|candidate| {
            health.is_none_or(|health| {
                resolve_probe_target(route.backends[*candidate].address(), discovery).is_some_and(
                    |target| {
                        health.observe_epoch(*candidate, target.epoch)
                            && health.available_for(*candidate, target.epoch)
                    },
                )
            })
        })
}

struct TcpDialAdmission {
    configured: String,
    target: crate::discovery::ResolvedTarget,
    health: Option<Arc<crate::tcp_health::TcpHealth>>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    index: usize,
}

async fn proxy_connection(
    client: TcpStream,
    admission: &TcpDialAdmission,
    options: &crate::upstream::OutboundOptions,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    consumed: &[u8],
    idle_timeout: Duration,
    cancel: CancellationToken,
) -> Result<()> {
    let mut upstream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        result = crate::upstream::connect_with_tls(&admission.target.endpoint, options, tls_config) => {
            result.context("connect TCP backend")?
        },
    };
    // The dial can await proxy negotiation and TLS. Revalidate immediately
    // before forwarding any downstream bytes, including a buffered ClientHello.
    ensure!(
        resolve_probe_target(&admission.configured, admission.discovery.as_deref()).as_ref()
            == Some(&admission.target),
        "TCP endpoint changed while connecting"
    );
    ensure!(
        admission
            .health
            .as_ref()
            .is_none_or(|health| health.available_for(admission.index, admission.target.epoch)),
        "TCP backend became unavailable while connecting"
    );
    if !consumed.is_empty() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            result = upstream.write_all(consumed) => result.context("forward TLS ClientHello")?,
        }
    }
    if idle_timeout.is_zero() {
        let mut client = client;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            result = copy_bidirectional(&mut client, &mut upstream) => {
                result.context("bidirectional TCP copy")?;
                Ok(())
            }
        }
    } else {
        // Wrap the client side so any byte-level progress in either direction
        // resets the idle timer; a session that transmits nothing within the
        // window is closed, bounding L4 slowloris without a hard total cap.
        let (mut client, watch) = crate::idle::IdleIo::new(client, idle_timeout);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(()),
            _ = watch.expired() => Ok(()),
            result = copy_bidirectional(&mut client, &mut upstream) => {
                result.context("bidirectional TCP copy")?;
                Ok(())
            }
        }
    }
}

struct ActiveConnection(Arc<Metrics>);

impl ActiveConnection {
    fn new(metrics: Arc<Metrics>) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Self(metrics)
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

fn retain_export_listener(listener: TcpListener) -> Result<(TcpListener, std::net::TcpListener)> {
    let listener = listener
        .into_std()
        .context("convert TCP listener for handoff retention")?;
    let export = listener
        .try_clone()
        .context("duplicate TCP listener for handoff retention")?;
    let runtime = TcpListener::from_std(listener).context("restore async TCP listener")?;
    Ok((runtime, export))
}

#[cfg(unix)]
fn ensure_listening_socket(descriptor: &OwnedFd) -> Result<()> {
    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: accepting and length are valid getsockopt output pointers.
    let result = unsafe {
        libc::getsockopt(
            descriptor.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result == -1 {
        return Err(std::io::Error::last_os_error()).context("inspect inherited TCP socket");
    }
    ensure!(
        accepting == 1,
        "inherited TCP descriptor is not a listening socket"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_listener_index_does_not_retain_the_global_snapshot() {
        let address: SocketAddr = "127.0.0.1:18443".parse().unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({
            "cache": {},
            "tcp": [{
                "id": "sni",
                "listen": address,
                "backends": ["127.0.0.1:9443"],
                "sni": {"hosts": ["api.example.test"]}
            }]
        }))
        .unwrap();
        let snapshot = Arc::new(Snapshot::new(config).unwrap());
        assert!(snapshot.cache.is_some());
        let weak = Arc::downgrade(&snapshot);
        let index = ListenerRoutes::build(&snapshot, address).unwrap();
        assert_eq!(index.routes.len(), 1);

        drop(snapshot);

        assert!(weak.upgrade().is_none());
        assert!(index.source.upgrade().is_none());
        assert_eq!(index.priorities[0].exact.get("api.example.test"), Some(&0));
    }
}
