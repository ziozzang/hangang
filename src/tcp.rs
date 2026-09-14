use crate::{
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
    pool_member::{Backend, DesiredState},
    tcp_history::{Outcome, Phase},
    tcp_io::{CountedIo, Direction},
};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex, OnceLock, Weak,
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
    /// Installed before opening the accept gate. A missing handler rejects
    /// workload HTTP connections rather than treating them as raw TCP.
    workload_http: Arc<OnceLock<WorkloadHttpHandler>>,
}

struct WorkloadHttpHandler {
    proxy: Arc<crate::proxy::Proxy>,
    header_bytes: usize,
}

fn is_workload_http(config: &Config, address: SocketAddr) -> bool {
    config
        .workload_http
        .iter()
        .any(|listener| listener.enabled && listener.listen == address)
}

#[derive(PartialEq, Eq)]
enum ListenerRole {
    Tcp,
    WorkloadHttp,
    PublicHttp,
    PublicHttps,
}

fn listener_role(config: &Config, address: SocketAddr) -> ListenerRole {
    if let Some(listener) = config
        .public_http
        .iter()
        .find(|listener| listener.enabled && listener.listen == address)
    {
        if listener.certificates.is_empty() {
            ListenerRole::PublicHttp
        } else {
            ListenerRole::PublicHttps
        }
    } else if is_workload_http(config, address) {
        ListenerRole::WorkloadHttp
    } else {
        ListenerRole::Tcp
    }
}

fn desired_listens(config: &Config) -> HashSet<SocketAddr> {
    config
        .tcp
        .iter()
        .filter(|route| route.enabled)
        .map(|route| route.listen)
        .chain(
            config
                .workload_http
                .iter()
                .filter(|listener| listener.enabled)
                .map(|listener| listener.listen),
        )
        .chain(
            config
                .public_http
                .iter()
                .filter(|listener| listener.enabled)
                .map(|listener| listener.listen),
        )
        .collect()
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
            workload_http: Arc::new(OnceLock::new()),
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

    /// Install the authenticated HTTP handler before the accept gate opens.
    /// This is deliberately one-shot: a replacement proxy requires a new
    /// process generation and must not silently redirect existing TLS peers.
    pub fn set_workload_http(
        &self,
        proxy: Arc<crate::proxy::Proxy>,
        header_bytes: usize,
    ) -> Result<()> {
        ensure!(
            !self.gate_open(),
            "install workload HTTP handler before opening the accept gate"
        );
        ensure!(
            header_bytes > 0,
            "workload HTTP header limit must be positive"
        );
        ensure!(
            self.workload_http
                .set(WorkloadHttpHandler {
                    proxy,
                    header_bytes
                })
                .is_ok(),
            "workload HTTP handler already installed"
        );
        Ok(())
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

        let desired = desired_listens(config);
        let previous = self.active.load();
        for address in current.intersection(&desired) {
            ensure!(
                listener_role(&previous.config, *address) == listener_role(config, *address),
                "TCP, workload HTTP, public HTTP, and public HTTPS cannot exchange an active listener; remove it in a prior revision"
            );
        }
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
        for address in config
            .workload_http
            .iter()
            .filter(|listener| listener.enabled)
            .map(|listener| listener.listen)
        {
            ensure!(
                !config
                    .tcp
                    .iter()
                    .any(|route| route.enabled && route.listen == address),
                "workload HTTP listener overlaps a TCP route"
            );
            if !accounted.insert(address) {
                continue;
            }
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("bind workload HTTP listener {address}"))?;
            let (listener, export) = retain_export_listener(listener)?;
            added.push((address, listener, export));
        }
        for address in config
            .public_http
            .iter()
            .filter(|listener| listener.enabled)
            .map(|listener| listener.listen)
        {
            ensure!(
                accounted.insert(address),
                "public HTTP listener overlaps another listener at {address}"
            );
            let listener = TcpListener::bind(address)
                .await
                .with_context(|| format!("bind public HTTP listener {address}"))?;
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
        for address in config
            .workload_http
            .iter()
            .filter(|listener| listener.enabled)
            .map(|listener| listener.listen)
        {
            ensure!(
                !process.contains(&address) && routes.insert(address),
                "workload HTTP listener {address} collides with another listener"
            );
            held.push(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("bind workload HTTP listener {address}"))?,
            );
        }
        for address in config
            .public_http
            .iter()
            .filter(|listener| listener.enabled)
            .map(|listener| listener.listen)
        {
            ensure!(
                !process.contains(&address) && routes.insert(address),
                "public HTTP listener {address} collides with another listener"
            );
            held.push(
                TcpListener::bind(address)
                    .await
                    .with_context(|| format!("bind public HTTP listener {address}"))?,
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
        let desired = desired_listens(config);
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
                    self.workload_http.clone(),
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
    Option<Arc<crate::workload_material::Slot>>,
    Option<Arc<crate::country_policy::CompiledCountryPolicy>>,
);

struct ListenerRoutes {
    source: Weak<Snapshot>,
    geoip: Option<Arc<crate::geoip_runtime::Slot>>,
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
            let country_policy = route
                .country_policy
                .as_ref()
                .map(crate::country_policy::Policy::compile)
                .transpose()
                .ok()?
                .map(Arc::new);
            routes.push((
                route.clone(),
                snapshot.admissions[&route.id].clone(),
                snapshot.upstream_tls.get(&route.id).cloned(),
                snapshot.tcp_health.get(&route.id).cloned(),
                snapshot.tcp_member_activity.get(&route.id).cloned(),
                Arc::from(member_admissions.clone()),
                snapshot.tcp_inbound_tls.get(&route.id).cloned(),
                country_policy,
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
                geoip: snapshot.geoip.clone(),
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
        self.routes.iter().all(|(route, _, _, _, _, _, _, _)| {
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
    workload_http: Arc<OnceLock<WorkloadHttpHandler>>,
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
                    // Avoid delayed-ACK/Nagle stalls when TLS or a proxied
                    // request/response protocol emits a final short record.
                    if client.set_nodelay(true).is_err() {
                        metrics.errors.fetch_add(1, Ordering::Relaxed);
                        // Even transport setup failure has a bounded terminal
                        // observation for raw TCP. The workload HTTP role owns
                        // its own request telemetry and is excluded here.
                        if matches!(
                            listener_role(&active.load().config, address),
                            ListenerRole::Tcp
                        ) {
                            let mut history = metrics.tcp_history.begin(
                                SocketAddr::new(peer.ip().to_canonical(), peer.port()),
                                address,
                            );
                            history.set_outcome(Outcome::IoError);
                        }
                        continue;
                    }
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
            if let Some(configured) = snapshot
                .config
                .public_http
                .iter()
                .find(|configured| configured.enabled && configured.listen == address)
            {
                if !matches!(
                    listener_role(&snapshot.config, address),
                    ListenerRole::PublicHttp | ListenerRole::PublicHttps
                ) || snapshot
                    .config
                    .tcp
                    .iter()
                    .any(|route| route.enabled && route.listen == address)
                    || snapshot
                        .config
                        .workload_http
                        .iter()
                        .any(|listener| listener.enabled && listener.listen == address)
                {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(handler) = workload_http.get() else {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let lease = Arc::new(crate::metrics::ConnectionLease::new(
                    permit,
                    metrics.clone(),
                ));
                let listener_id = configured.id.clone();
                let proxy = handler.proxy.clone();
                let header_bytes = handler.header_bytes;
                let task_active = active.clone();
                let task_cancel = connection_cancel.clone();
                let task_metrics = metrics.clone();
                connections.spawn(async move {
                    crate::public_http::serve(
                        client,
                        peer,
                        task_active,
                        listener_id,
                        proxy,
                        header_bytes,
                        idle_timeout,
                        task_cancel,
                        task_metrics,
                        lease,
                    )
                    .await;
                });
                continue;
            }
            if let Some(configured) = snapshot
                .config
                .workload_http
                .iter()
                .find(|configured| configured.enabled && configured.listen == address)
            {
                // A malformed cross-role snapshot must never reinterpret a
                // raw TCP stream as authenticated HTTP (or vice versa).
                if snapshot
                    .config
                    .tcp
                    .iter()
                    .any(|route| route.enabled && route.listen == address)
                {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let Some(handler) = workload_http.get() else {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let permit = match permits.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let proxy = handler.proxy.clone();
                let header_bytes = handler.header_bytes;
                let listener_id = configured.id.clone();
                let task_active = active.clone();
                let task_cancel = connection_cancel.clone();
                let task_metrics = metrics.clone();
                let lease = Arc::new(crate::metrics::ConnectionLease::new(
                    permit,
                    task_metrics.clone(),
                ));
                connections.spawn(async move {
                    crate::workload_http::serve(
                        client,
                        peer,
                        task_active,
                        listener_id,
                        proxy,
                        header_bytes,
                        idle_timeout,
                        task_cancel,
                        task_metrics,
                        lease,
                    )
                    .await;
                });
                continue;
            }
            let mut history = metrics.tcp_history.begin(peer, address);
            if routing_cache
                .as_ref()
                .is_none_or(|routes| !Weak::ptr_eq(&routes.source, &Arc::downgrade(&snapshot)))
            {
                routing_cache = ListenerRoutes::build(&snapshot, address);
            }
            let Some(routes) = routing_cache.clone() else {
                history.set_outcome(Outcome::NoRoute);
                metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            // This is decisive before SNI selection only if every possible route
            // denies the peer. It also keeps denied legacy traffic out of global
            // admission without weakening the selected-route check below.
            if routes.all_routes_deny(peer.ip()) {
                history.set_outcome(Outcome::IpDenied);
                metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let permit = match permits.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    history.set_outcome(Outcome::Capacity);
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
                history.set_phase(Phase::Inspecting);
                let (route_index, consumed) = if let Some(route_index) = routes.legacy {
                    (route_index, Vec::new())
                } else {
                    let (max_client_hello_bytes, hello_timeout_ms) =
                        routes.hello_settings.expect("validated SNI listener settings");
                    let inspected = tokio::select! {
                        biased;
                        _ = task_cancel.cancelled() => { history.set_outcome(Outcome::Shutdown); return; },
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
                            history.set_outcome(Outcome::SniRejected);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%peer, %error, "TCP ClientHello rejected");
                            return;
                        }
                        Err(_) => {
                            history.set_outcome(Outcome::SniTimeout);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            tracing::debug!(%peer, "TCP ClientHello timed out");
                            return;
                        }
                    };
                    let Some(route_index) = routes.route_for_server_name(&hello.server_name) else {
                        history.set_outcome(Outcome::NoRoute);
                        task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!(%peer, server_name=%hello.server_name, "TCP SNI did not match a route");
                        return;
                    };
                    (route_index, hello.consumed)
                };
                let geoip = routes.geoip.clone();
                let (route, counter, upstream_tls, health, member_activity, member_admissions, inbound_tls, country_policy) =
                    routes.routes[route_index].clone();
                drop(routes);
                history.set_route(&route.id);
                if route
                    .deny_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(&peer.ip()))
                {
                    history.set_outcome(Outcome::IpDenied);
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                // Observe the accepted peer once on the selected SNI route.
                // Copy only metadata, then release the slot before forwarding.
                let observation = crate::country_observation::capture(geoip.as_ref(), peer.ip());
                drop(geoip);
                history.set_geoip(&observation);
                let country_decision = country_policy.as_ref().filter(|policy| policy.enforced())
                    .map(|policy| match observation.policy_country() {
                        Ok(country) if policy.evaluate_code(country) => crate::country_metrics::Decision::Allowed,
                        Ok(_) => crate::country_metrics::Decision::Denied,
                        Err(_) => crate::country_metrics::Decision::Unavailable,
                    });
                task_metrics.geoip.observe(crate::country_metrics::Protocol::Tcp, &observation, country_decision);
                if matches!(country_decision, Some(crate::country_metrics::Decision::Denied | crate::country_metrics::Decision::Unavailable)) {
                    history.set_outcome(if matches!(country_decision, Some(crate::country_metrics::Decision::Denied)) { Outcome::CountryDenied } else { Outcome::CountryUnavailable });
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let _route_permit =
                    match crate::admission::acquire(&counter, route.max_connections) {
                        Ok(permit) => permit,
                        Err(_) => {
                            history.set_outcome(Outcome::Capacity);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };
                // Mandatory inbound authentication finishes before selecting
                // a member or opening any upstream socket. Passthrough routes
                // never manufacture an authenticated workload identity.
                let (client, identity_lease): (crate::upstream::BoxIo, Option<WorkloadLease>) =
                    if let Some(policy) = &route.inbound_tls {
                        history.set_phase(Phase::Authenticating);
                        // ListenerRoutes may be cached across file rotations.
                        // Resolve the current slot generation for every new
                        // handshake; a missing/invalid generation stays closed.
                        let Some(prepared) = inbound_tls.and_then(|slot| slot.load()) else {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let Ok(handshake_permit) = workload_handshake_admission().try_acquire_owned() else {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let acceptor = tokio_rustls::TlsAcceptor::from(prepared.server_config.clone());
                        let accepted = tokio::select! {
                            biased;
                            _ = task_cancel.cancelled() => { history.set_outcome(Outcome::Shutdown); return; },
                            accepted = timeout(Duration::from_millis(policy.handshake_timeout_ms), acceptor.accept(client)) => accepted,
                        };
                        let Ok(Ok(stream)) = accepted else {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let identity = stream.get_ref().1.peer_certificates()
                            .ok_or_else(|| anyhow::anyhow!("client certificate missing"))
                            .and_then(|chain| prepared.authorize_peer(chain));
                        let Ok(identity) = identity else {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        drop(handshake_permit);
                        let lifetime = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()
                            .and_then(|now| identity.expires_at.checked_sub(now.as_secs()))
                            .and_then(|seconds| Instant::now().checked_add(Duration::from_secs(seconds)));
                        let Some(deadline) = lifetime else {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        };
                        let lease = WorkloadLease { active: task_active, route_id: route.id.clone(), prepared, expires_at: identity.expires_at, deadline };
                        if !lease.current() {
                            history.set_outcome(Outcome::MtlsRejected);
                            task_metrics.tcp_mtls_rejections.fetch_add(1, Ordering::Relaxed);
                            task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        (Box::new(stream), Some(lease))
                    } else { (Box::new(client), None) };
                history.set_outcome(Outcome::Interrupted);
                let Some(index) = next_backend_index(&task_backend_counter, &route, &member_admissions, health.as_deref(), task_discovery.as_deref()) else {
                    history.set_outcome(Outcome::NoBackend);
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                // The gate owns the pending dial as well as the eventual
                // stream. A concurrent closure between selection and acquire
                // conservatively rejects this connection before any dial.
                history.set_member(route.backends[index].id());
                let Some(member_lease) = member_admissions[index].lease() else {
                    history.set_outcome(Outcome::MemberUnavailable);
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                let Some(target) = resolve_probe_target(route.backends[index].address(), task_discovery.as_deref()) else {
                    history.set_outcome(Outcome::NoBackend);
                    task_metrics.errors.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                if health.as_ref().is_some_and(|health| !health.observe_epoch(index, target.epoch) || !health.available_for(index, target.epoch)) {
                    history.set_outcome(Outcome::MemberUnavailable);
                    task_metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let member_counter = if route.backends[index].id().is_some() {
                    let Some(counter) = member_activity.as_ref().and_then(|activity| activity.node(index)) else {
                        history.set_outcome(Outcome::MemberUnavailable);
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
                        &mut history,
                    )
                    .await
                };
                let result = if let Some(lease) = &identity_lease {
                    tokio::select! {
                        biased;
                        _ = lease.revoked() => {
                            task_metrics.tcp_mtls_lease_terminations.fetch_add(1, Ordering::Relaxed);
                            Ok(Outcome::IdentityRevoked)
                        },
                        result = connection => result,
                    }
                } else { connection.await };
                match result {
                    Ok(outcome) => history.set_outcome(outcome),
                    Err((outcome, error)) => {
                    history.set_outcome(outcome);
                    task_metrics.errors.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%peer, %backend, %error, "TCP proxy connection failed");
                    }
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

pub(crate) fn workload_handshake_admission() -> Arc<Semaphore> {
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
            .and_then(|slot| slot.load())
            .is_some_and(|current| Arc::ptr_eq(&current, &self.prepared))
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
    history: &mut crate::tcp_history::Guard,
) -> std::result::Result<Outcome, (Outcome, anyhow::Error)> {
    if !identity_lease.is_none_or(WorkloadLease::current) {
        return Err((
            Outcome::IdentityRevoked,
            anyhow::anyhow!("workload identity no longer authorized"),
        ));
    }
    history.set_phase(Phase::Dialing);
    let upstream = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Ok(Outcome::Shutdown),
        result = crate::upstream::connect_with_tls(&admission.target.endpoint, options, tls_config) => {
            result.map_err(|error| (Outcome::DialFailed, error.context("connect TCP backend")))?
        },
    };
    if !identity_lease.is_none_or(WorkloadLease::current) {
        return Err((
            Outcome::IdentityRevoked,
            anyhow::anyhow!("workload identity changed while connecting"),
        ));
    }
    // Revalidate after the dial, before any buffered or streamed bytes leave.
    if resolve_probe_target(&admission.configured, admission.discovery.as_deref()).as_ref()
        != Some(&admission.target)
    {
        return Err((
            Outcome::EndpointChanged,
            anyhow::anyhow!("TCP endpoint changed while connecting"),
        ));
    }
    if !admission
        .health
        .as_ref()
        .is_none_or(|health| health.available_for(admission.index, admission.target.epoch))
    {
        return Err((
            Outcome::MemberUnavailable,
            anyhow::anyhow!("TCP backend became unavailable while connecting"),
        ));
    }
    if !admission.member_lease.is_open() {
        return Err((
            Outcome::MemberUnavailable,
            anyhow::anyhow!("TCP member admission closed while connecting"),
        ));
    }
    // This lease still covers buffered ClientHello, copy and all cancellation.
    let _member_lease = admission
        .member_counter
        .as_ref()
        .map(|counter| {
            counter
                .acquire()
                .context("TCP member stream capacity exhausted")
        })
        .transpose()
        .map_err(|error| (Outcome::Capacity, error))?;
    history.set_phase(Phase::Forwarding);
    // Count successful destination writes. Read-ahead is not delivery; each
    // successful partial write survives future cancellation or a later error.
    let mut upstream = CountedIo::new(upstream, history.bytes(), Direction::Upstream);
    let client = CountedIo::new(client, history.bytes(), Direction::Downstream);
    if !consumed.is_empty() {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(Outcome::Shutdown),
            result = upstream.write_all(consumed) => {
                result.map_err(|error| (Outcome::IoError, anyhow::Error::new(error).context("forward TLS ClientHello")))?;
            },
        }
    }
    if idle_timeout.is_zero() {
        let mut client = client;
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(Outcome::Shutdown),
            result = copy_bidirectional(&mut client, &mut upstream) => {
                result.map_err(|error| (Outcome::IoError, anyhow::Error::new(error).context("bidirectional TCP copy")))?;
                Ok(Outcome::Eof)
            }
        }
    } else {
        let (mut client, watch) = crate::idle::IdleIo::new(client, idle_timeout);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Ok(Outcome::Shutdown),
            _ = watch.expired() => Ok(Outcome::IdleTimeout),
            result = copy_bidirectional(&mut client, &mut upstream) => {
                result.map_err(|error| (Outcome::IoError, anyhow::Error::new(error).context("bidirectional TCP copy")))?;
                Ok(Outcome::Eof)
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
