use crate::{
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
    pool_member::{Backend, DesiredState},
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
    net::TcpListener,
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

    /// Resolve the same discovery view used by this instance's data plane.
    pub fn discovered_target(
        &self,
        backend: &str,
        protocol: crate::discovery::Protocol,
    ) -> Option<crate::discovery::ResolvedTarget> {
        self.discovery
            .as_ref()?
            .resolve_with_epoch(backend, protocol)
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
        let _ = self.commit_with_publication(prepared, || {}).await;
    }

    /// Acquire the listener mutation lock before publishing a snapshot. Once
    /// the callback runs there is no await until every listener is installed
    /// or cancelled. Cancellation while waiting leaves the snapshot untouched.
    pub async fn commit_with_publication(
        &self,
        prepared: Prepared,
        publish: impl FnOnce(),
    ) -> Result<()> {
        let mut stopped = Vec::new();
        {
            let mut state = self.state.lock().await;
            ensure!(
                !state.shutting_down,
                "TCP manager is shutting down before publication"
            );
            publish();

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
        Ok(())
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
    Option<Arc<crate::tcp_member::TcpMemberActivity>>,
    Arc<[Arc<crate::member_admission::MemberAdmission>]>,
    Option<Arc<crate::workload_tls::Prepared>>,
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
            let member_admissions = snapshot.tcp_member_admissions.get(&route.id)?;
            if member_admissions.len() != route.backends.len() {
                return None;
            }
            found = true;
            let index = routes.len();
            routes.push((
                route.clone(),
                snapshot.admissions[&route.id].clone(),
                snapshot.upstream_tls.get(&route.id).cloned(),
                snapshot.tcp_health.get(&route.id).cloned(),
                snapshot.tcp_member_activity.get(&route.id).cloned(),
                Arc::from(member_admissions.clone()),
                snapshot.tcp_inbound_tls.get(&route.id).cloned(),
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
        self.routes.iter().all(|(route, _, _, _, _, _, _)| {
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
                if matches!(&route.backends[index], Backend::Member(member) if member.desired_state == DesiredState::Maintenance)
                {
                    continue;
                }
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
            let task_active = active.clone();
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
                let (route, counter, upstream_tls, health, member_activity, member_admissions, inbound_tls) =
                    routes.routes[route_index].clone();
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
                // Mandatory inbound authentication finishes before selecting
                // a member or opening any upstream socket. Passthrough routes
                // never manufacture an authenticated workload identity.
                let (client, identity_lease): (crate::upstream::BoxIo, Option<WorkloadLease>) =
                    if let Some(policy) = &route.inbound_tls {
                        let Some(prepared) = inbound_tls else {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let Ok(handshake_permit) = workload_handshake_admission().try_acquire_owned() else {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let acceptor = tokio_rustls::TlsAcceptor::from(prepared.server_config.clone());
                        let accepted = tokio::select! {
                            biased;
                            _ = task_cancel.cancelled() => return,
                            accepted = timeout(Duration::from_millis(policy.handshake_timeout_ms), acceptor.accept(client)) => accepted,
                        };
                        let Ok(Ok(stream)) = accepted else {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let identity = stream.get_ref().1.peer_certificates()
                            .ok_or_else(|| anyhow::anyhow!("client certificate missing"))
                            .and_then(|chain| prepared.authorize_peer(chain));
                        let Ok(identity) = identity else {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        drop(handshake_permit);
                        let lifetime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
                            .and_then(|now| identity.expires_at.checked_sub(now.as_secs()))
                            .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds)));
                        let Some(deadline) = lifetime else {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let lease = WorkloadLease { active: task_active, route_id: route.id.clone(), prepared, expires_at: identity.expires_at, deadline };
                        if !lease.current() {
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        (Box::new(stream), Some(lease))
                    } else { (Box::new(client), None) };
                let Some(index) = next_backend_index(&task_backend_counter, &route, &member_admissions, health.as_deref(), task_discovery.as_deref()) else {
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                // The gate owns the pending dial as well as the eventual
                // stream. A concurrent closure between selection and acquire
                // conservatively rejects this connection before any dial.
                let Some(member_lease) = member_admissions[index].lease() else {
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
                let member_counter = if route.backends[index].id().is_some() {
                    let Some(counter) = member_activity.as_ref().and_then(|activity| activity.node(index)) else {
                        // A named route must have a prepared counter for every
                        // member. Do not serve it without activity ownership.
                        task_metrics.errors.fetch_add(1, Ordering::Relaxed);
                        return;
                    };
                    Some(counter)
                } else {
                    None
                };
                let backend = target.endpoint.clone();
                let admission = TcpDialAdmission {
                    configured: route.backends[index].address().to_owned(),
                    target,
                    health,
                    discovery: task_discovery,
                    member_counter,
                    member_lease,
                    index,
                };
                let connection = async {
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
                        identity_lease.as_ref(),
                    )
                    .await
                };
                let result = if let Some(lease) = &identity_lease {
                    tokio::select! {
                        biased;
                        _ = lease.revoked() => {
                            task_metrics.tcp_mtls_lease_terminations.fetch_add(1, Ordering::Relaxed);
                            Ok(())
                        },
                        result = connection => result,
                    }
                } else { connection.await };
                if let Err(error) = result {
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
    member_admissions: &[Arc<crate::member_admission::MemberAdmission>],
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
    let index = if route
        .backends
        .first()
        .is_some_and(|backend| backend.id().is_none())
    {
        *counter % route.backends.len()
    } else {
        let total_weight: usize = route
            .backends
            .iter()
            .map(|backend| backend.weight() as usize)
            .sum();
        let mut slot = *counter % total_weight;
        route
            .backends
            .iter()
            .position(|backend| {
                let weight = backend.weight() as usize;
                if slot < weight {
                    true
                } else {
                    slot -= weight;
                    false
                }
            })
            .expect("validated positive backend weights")
    };
    *counter = counter.wrapping_add(1);
    (0..route.backends.len())
        .map(|offset| (index + offset) % route.backends.len())
        .find(|candidate| {
            member_admissions
                .get(*candidate)
                .is_some_and(|gate| gate.is_open())
                && health.is_none_or(|health| {
                    resolve_probe_target(route.backends[*candidate].address(), discovery)
                        .is_some_and(|target| {
                            health.observe_epoch(*candidate, target.epoch)
                                && health.available_for(*candidate, target.epoch)
                        })
                })
        })
}

fn workload_handshake_admission() -> Arc<Semaphore> {
    static ADMISSION: std::sync::LazyLock<Arc<Semaphore>> = std::sync::LazyLock::new(|| {
        let limit = std::thread::available_parallelism()
            .map_or(2, |cpus| cpus.get().saturating_mul(2))
            .clamp(2, 64);
        Arc::new(Semaphore::new(limit))
    });
    ADMISSION.clone()
}

/// A connection belongs to one authenticated policy/material generation.
/// Changes withdraw existing opaque streams rather than reinterpreting their
/// already-authenticated peer under a new trust policy.
struct WorkloadLease {
    active: Arc<ArcSwap<Snapshot>>,
    route_id: String,
    prepared: Arc<crate::workload_tls::Prepared>,
    expires_at: u64,
    deadline: Instant,
}
impl WorkloadLease {
    fn current(&self) -> bool {
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        if now.as_secs() >= self.expires_at || Instant::now() >= self.deadline {
            return false;
        }
        let snapshot = self.active.load();
        snapshot
            .tcp_inbound_tls
            .get(&self.route_id)
            .is_some_and(|current| Arc::ptr_eq(current, &self.prepared))
    }
    async fn revoked(&self) {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if !self.current() {
                return;
            }
        }
    }
}

struct TcpDialAdmission {
    configured: String,
    target: crate::discovery::ResolvedTarget,
    health: Option<Arc<crate::tcp_health::TcpHealth>>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    member_counter: Option<Arc<crate::tcp_member::StreamCounter>>,
    member_lease: crate::member_admission::AdmissionLease,
    index: usize,
}

#[allow(clippy::too_many_arguments)]
async fn proxy_connection(
    client: crate::upstream::BoxIo,
    admission: &TcpDialAdmission,
    options: &crate::upstream::OutboundOptions,
    tls_config: Option<Arc<rustls::ClientConfig>>,
    consumed: &[u8],
    idle_timeout: Duration,
    cancel: CancellationToken,
    identity_lease: Option<&WorkloadLease>,
) -> Result<()> {
    ensure!(
        identity_lease.is_none_or(WorkloadLease::current),
        "workload identity no longer authorized"
    );
    let mut upstream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(()),
        result = crate::upstream::connect_with_tls(&admission.target.endpoint, options, tls_config) => {
            result.context("connect TCP backend")?
        },
    };
    ensure!(
        identity_lease.is_none_or(WorkloadLease::current),
        "workload identity changed while connecting"
    );
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
    ensure!(
        admission.member_lease.is_open(),
        "TCP member admission closed while connecting"
    );
    // Count only established streams. A failed dial or an endpoint/health
    // change during the dial never acquires a member lease. Keep the guard
    // through ClientHello forwarding, byte copy, cancellation, and idle exit.
    let _member_lease = admission
        .member_counter
        .as_ref()
        .map(|counter| {
            counter
                .acquire()
                .context("TCP member stream capacity exhausted")
        })
        .transpose()?;
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

    async fn counting_probe_endpoint() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let server = tokio::spawn({
            let hits = hits.clone();
            async move {
                while let Ok((_stream, _)) = listener.accept().await {
                    hits.fetch_add(1, Ordering::Release);
                }
            }
        });
        (address, hits, server)
    }

    async fn wait_for_probe_hits(hits: &AtomicUsize, count: usize) {
        timeout(Duration::from_secs(4), async {
            while hits.load(Ordering::Acquire) < count {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("TCP active probe did not reach endpoint");
    }

    #[tokio::test]
    async fn maintenance_skips_tcp_probes_while_draining_continues_and_serving_resumes() {
        let (draining_address, draining_hits, draining_server) = counting_probe_endpoint().await;
        let (maintenance_address, maintenance_hits, maintenance_server) =
            counting_probe_endpoint().await;
        let config: Config = serde_json::from_value(serde_json::json!({"tcp":[{
            "id":"member-tcp-probe-states",
            "listen":"127.0.0.1:18443",
            "backends":[
                {"id":"drain","address":draining_address.to_string()},
                {"id":"maint","address":maintenance_address.to_string()}
            ],
            "health":{
                "interval_ms":100,"timeout_ms":100,
                "healthy_successes":1,"unhealthy_failures":1
            }
        }]}))
        .unwrap();
        let mut initial = Snapshot::new(config.clone()).unwrap();
        for (index, state) in [DesiredState::Draining, DesiredState::Maintenance]
            .into_iter()
            .enumerate()
        {
            let Backend::Member(member) = &mut initial.config.tcp[0].backends[index] else {
                panic!("named fixture member expected");
            };
            member.desired_state = state;
        }
        let active = Arc::new(ArcSwap::from(Arc::new(initial)));
        let (_gate_sender, gate) = tokio::sync::watch::channel(true);
        let monitor = tokio::spawn(monitor_tcp_health(active.clone(), None, gate));
        wait_for_probe_hits(&draining_hits, 3).await;
        assert_eq!(maintenance_hits.load(Ordering::Acquire), 0);

        active.store(Arc::new(Snapshot::new(config).unwrap()));
        wait_for_probe_hits(&maintenance_hits, 2).await;
        monitor.abort();
        let _ = monitor.await;
        draining_server.abort();
        maintenance_server.abort();
    }

    #[tokio::test]
    async fn cancelled_publication_lock_wait_does_not_expose_candidate() {
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(Config::default()).unwrap(),
        ));
        let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 1);
        let prepared = manager.prepare(&Config::default()).await.unwrap();
        let changed = Config {
            revision: 1,
            ..Default::default()
        };
        let next = Arc::new(Snapshot::new(changed).unwrap());
        let lock = manager.state.lock().await;
        let mut commit = Box::pin(manager.commit_with_publication(prepared, || active.store(next)));
        assert!(futures_util::poll!(&mut commit).is_pending());
        assert_eq!(active.load().config.revision, 0);
        drop(commit);
        drop(lock);
        assert_eq!(active.load().config.revision, 0);
        assert!(manager.state.lock().await.listeners.is_empty());
        manager.shutdown(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn cancellation_during_listener_join_keeps_complete_publication() {
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(Config::default()).unwrap(),
        ));
        let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 1);
        let export = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = export.local_addr().unwrap();
        let cancel = CancellationToken::new();
        // A deliberately noncooperative old accept task keeps the join pending.
        let task = tokio::spawn(std::future::pending::<()>());
        let abort = task.abort_handle();
        manager.state.lock().await.listeners.insert(
            address,
            ListenerHandle {
                cancel: cancel.clone(),
                task,
                export,
            },
        );
        let prepared = manager.prepare(&Config::default()).await.unwrap();
        let changed = Config {
            revision: 1,
            ..Default::default()
        };
        let next = Arc::new(Snapshot::new(changed).unwrap());
        let mut commit = Box::pin(manager.commit_with_publication(prepared, || active.store(next)));
        assert!(futures_util::poll!(&mut commit).is_pending());
        assert_eq!(active.load().config.revision, 1);
        assert!(manager.state.lock().await.listeners.is_empty());
        assert!(cancel.is_cancelled());
        drop(commit);
        assert_eq!(active.load().config.revision, 1);
        abort.abort();
        manager.shutdown(Duration::ZERO).await;
    }

    #[tokio::test]
    async fn stopped_tcp_manager_rejects_snapshot_publication() {
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(Config::default()).unwrap(),
        ));
        let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 1);
        let prepared = manager.prepare(&Config::default()).await.unwrap();
        manager.stop_accepting().await;
        assert!(
            manager
                .commit_with_publication(prepared, || panic!("must not publish"))
                .await
                .is_err()
        );
        assert_eq!(active.load().config.revision, 0);
    }

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
