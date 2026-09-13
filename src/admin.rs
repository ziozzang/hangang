use crate::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::{Body, response},
    store,
    tcp::TcpManager,
};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited, StreamBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
};
use std::{
    convert::Infallible,
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

pub struct Manager {
    pub active: Arc<ArcSwap<Snapshot>>,
    pub tcp: Arc<TcpManager>,
    pub policy: Arc<PolicyPool>,
    pub metrics: Arc<Metrics>,
    pub state_path: PathBuf,
    pub config_store: Option<Arc<dyn crate::config_store::ConfigStore>>,
    pub writes: Mutex<()>,
    pub transactions: Arc<tokio::sync::Semaphore>,
    pub externally_managed: bool,
    pub ready: Arc<std::sync::atomic::AtomicBool>,
    pub stopping: std::sync::atomic::AtomicBool,
    /// Endpoint withdrawal differs from a write freeze: frozen generations
    /// still track controller authority while serving inherited connections.
    pub withdrawing: std::sync::atomic::AtomicBool,
    /// The shared store's authority epoch this instance follows. Recorded at
    /// startup or by the first successful poll; a store whose epoch differs
    /// afterwards was wiped and re-seeded, so its history is not ours.
    pub authority_epoch: std::sync::Mutex<Option<String>>,
    /// Readiness bookkeeping for the shared configuration authority.
    pub store_health: StoreHealth,
}

/// Why this instance is (or is not) known to agree with the shared authority.
///
/// Transport failures (`unavailable`, `missing`) are tolerated for a grace
/// window measured from the last confirmation, because the local snapshot's
/// validity does not depend on the store being reachable and N instances
/// share one store: withdrawing all of them on one blip turns a control-plane
/// incident into a data-plane outage. Authority disagreements (`rollback`,
/// `divergence`, `authority_changed`, `unpreparable`) withdraw immediately.
pub struct StoreHealth {
    grace: Duration,
    state: std::sync::Mutex<StoreHealthState>,
    /// Signalled on every confirmation so a watcher whose deadline timer is
    /// disarmed (it already fired) re-arms from the new confirmation.
    confirmations: tokio::sync::Notify,
}
#[derive(Default, Clone)]
struct StoreHealthState {
    last_confirmed: Option<std::time::Instant>,
    /// Current failure, if any: (reason code, detail).
    failure: Option<(&'static str, String)>,
}
/// Snapshot of `StoreHealth` for status reporting.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoreHealthReport {
    pub grace_seconds: u64,
    pub last_confirmed_seconds_ago: Option<u64>,
    pub reason: Option<&'static str>,
    pub detail: Option<String>,
    /// True while a tolerated transport failure is in progress.
    pub degraded: bool,
}
impl Default for StoreHealth {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}
impl StoreHealth {
    pub fn new(grace: Duration) -> Self {
        Self {
            grace,
            state: std::sync::Mutex::new(StoreHealthState::default()),
            confirmations: tokio::sync::Notify::new(),
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, StoreHealthState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// A poll proved agreement (or activated a newer revision).
    fn confirmed(&self) {
        {
            let mut state = self.lock();
            state.last_confirmed = Some(std::time::Instant::now());
            state.failure = None;
        }
        // A stored permit, so a confirmation between two select iterations
        // is not lost.
        self.confirmations.notify_one();
    }
    /// Record a failure. Returns whether readiness must be withdrawn now:
    /// always for authority disagreements, and for transport failures only
    /// once the grace window since the last confirmation has elapsed (or
    /// nothing was ever confirmed).
    fn failed(&self, reason: &'static str, detail: String, transport: bool) -> bool {
        let mut state = self.lock();
        state.failure = Some((reason, detail));
        if !transport {
            return true;
        }
        match state.last_confirmed {
            Some(at) => at.elapsed() >= self.grace,
            None => true,
        }
    }
    /// The instant at which the grace window since the last confirmation
    /// ends, independent of any poll in flight.
    pub fn deadline(&self) -> Option<tokio::time::Instant> {
        let state = self.lock();
        state
            .last_confirmed
            .map(|at| tokio::time::Instant::from_std(at + self.grace))
    }
    pub fn report(&self) -> StoreHealthReport {
        let state = self.lock();
        // Every tolerated (transport-class) failure is a degradation.
        let degraded = state.failure.as_ref().is_some_and(|(reason, _)| {
            matches!(
                *reason,
                "unavailable" | "indeterminate" | "missing" | "stalled"
            )
        });
        StoreHealthReport {
            grace_seconds: self.grace.as_secs(),
            last_confirmed_seconds_ago: state.last_confirmed.map(|at| at.elapsed().as_secs()),
            reason: state.failure.as_ref().map(|(reason, _)| *reason),
            detail: state.failure.as_ref().map(|(_, detail)| detail.clone()),
            degraded,
        }
    }
}
impl Manager {
    pub fn recorded_epoch(&self) -> Option<String> {
        self.authority_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    async fn prepare_snapshot(&self, config: Config) -> anyhow::Result<Arc<Snapshot>> {
        let previous = self.active.load_full();
        tokio::task::spawn_blocking(move || Snapshot::replace(config, &previous).map(Arc::new))
            .await?
    }
    pub async fn stop_updates(&self) {
        // Close admission before waiting for an in-flight transaction. A file
        // reload already queued on `writes` must not slip in after shutdown.
        self.withdraw_now();
        let _guard = self.writes.lock().await;
        // A reload that observed `stopping == false` before the first store may
        // have restored readiness while we waited for the writer lock.
        self.ready.store(false, Ordering::Release);
    }

    /// Freeze configuration writes for a listener handoff WITHOUT withdrawing
    /// readiness: the generation keeps serving from the shared sockets until
    /// it is told to drain, so a load balancer must keep sending to it.
    pub async fn freeze_updates(&self) {
        self.stopping.store(true, Ordering::Release);
        let _guard = self.writes.lock().await;
    }

    /// Freeze writes without waiting for an in-flight transaction or poll
    /// (retirement must close the accept loops promptly). A transaction that
    /// already passed its `stopping` check completes; the CAS it performs is
    /// as valid as before the freeze.
    pub fn freeze_now(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    /// Withdraw readiness and freeze writes immediately, without waiting for
    /// the writer lock; `stop_updates` (which waits) follows at drain time.
    pub fn withdraw_now(&self) {
        self.withdrawing.store(true, Ordering::Release);
        self.stopping.store(true, Ordering::Release);
        self.ready.store(false, Ordering::Release);
    }

    /// Resume after a failed supervised replacement. File mode retains its
    /// local authority. Controller mode preserves the last reported authority
    /// state; resuming does not prove that its watches are fresh. Shared-store
    /// readiness is restored only by confirmation from the authority.
    pub fn resume_updates(&self) {
        self.withdrawing.store(false, Ordering::Release);
        self.stopping.store(false, Ordering::Release);
        if self.config_store.is_none() && !self.externally_managed {
            self.advertise_ready();
        }
    }

    // The RMW acquires a concurrent withdrawal's ready=false publication.
    // The second flag check then prevents late confirmation from reviving it.
    fn advertise_ready(&self) {
        if self.withdrawing.load(Ordering::Acquire) {
            return;
        }
        self.ready.swap(true, Ordering::AcqRel);
        if self.withdrawing.load(Ordering::Acquire) {
            self.ready.store(false, Ordering::Release);
        }
    }

    /// Controller authority remains observable during a handoff freeze.
    /// Endpoint withdrawal, unlike freezing writes, suppresses confirmation.
    pub fn report_controller_authority(&self, healthy: bool) {
        if healthy {
            self.advertise_ready();
        } else {
            self.ready.store(false, Ordering::Release);
        }
    }

    pub async fn apply(self: &Arc<Self>, config: Config, expected: u64) -> anyhow::Result<Config> {
        // Complete a transaction even if its HTTP caller disconnects. Otherwise
        // a cancelled spawn_blocking save could persist without publication.
        anyhow::ensure!(
            !self.externally_managed,
            "configuration is controller managed"
        );
        let permit = self
            .transactions
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("configuration capacity exhausted"))?;
        let manager = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = manager.writes.lock().await;
            manager.apply_locked(config, expected, true, None).await
        })
        .await?
    }
    /// Controller snapshots use the same validation/activation boundary, but
    /// do not race a file watcher or persist to a second configuration source.
    pub async fn apply_external(self: &Arc<Self>, config: Config) -> anyhow::Result<Config> {
        self.apply_external_inner(config, None).await
    }
    /// Publish controller routing and its validated certificate resolver together.
    pub async fn apply_external_with_tls(
        self: &Arc<Self>,
        config: Config,
        tls: Arc<rustls::ServerConfig>,
    ) -> anyhow::Result<Config> {
        self.apply_external_inner(config, Some(tls)).await
    }
    async fn apply_external_inner(
        self: &Arc<Self>,
        mut config: Config,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> anyhow::Result<Config> {
        anyhow::ensure!(self.externally_managed, "controller source is disabled");
        let permit = self
            .transactions
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("configuration capacity exhausted"))?;
        let manager = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _guard = manager.writes.lock().await;
            anyhow::ensure!(
                !manager.stopping.load(Ordering::Acquire),
                "server is draining"
            );
            let current = manager.active.load_full();
            config.revision = current.config.revision;
            let applied = if config == current.config && tls.is_none() {
                config
            } else {
                manager
                    .apply_locked(config, current.config.revision, false, tls)
                    .await?
            };
            if !manager.stopping.load(Ordering::Acquire) {
                manager.advertise_ready();
            }
            Ok(applied)
        })
        .await?
    }
    /// File reload is read-only: do not overwrite a concurrently edited source.
    pub async fn reload_file(&self) -> anyhow::Result<bool> {
        anyhow::ensure!(
            !self.externally_managed,
            "configuration is controller managed"
        );
        let _guard = self.writes.lock().await;
        if let Some(store) = &self.config_store {
            // Agreement with the authority is checked even while activation
            // is frozen for a handoff: a frozen generation that can no longer
            // follow the store must not keep advertising readiness.
            return self.reconcile_store_locked(store.as_ref()).await;
        }
        let path = self.state_path.clone();
        let mut config = tokio::task::spawn_blocking(move || store::load(&path)).await??;
        let current = self.active.load_full();
        config.revision = current.config.revision;
        // The file omits the floor the active document carries; normalise
        // before comparing so an unchanged file is not reloaded forever.
        self.normalize_cache_generation(&mut config);
        if config == current.config {
            return Ok(false);
        }
        self.apply_locked(config, current.config.revision, false, None)
            .await?;
        Ok(true)
    }
    /// Record a store failure and withdraw readiness when the policy says so.
    fn store_failure(&self, reason: &'static str, detail: String, transport: bool) {
        if self.store_health.failed(reason, detail, transport) {
            self.ready.store(false, Ordering::Release);
        }
    }
    fn store_confirmed(&self) {
        self.store_health.confirmed();
        if !self.stopping.load(Ordering::Acquire) {
            self.advertise_ready();
        }
    }

    /// One poll of the shared authority. The caller holds `writes`.
    ///
    /// Transport-class failures keep the last good snapshot AND readiness
    /// for the grace window; authority disagreements withdraw readiness at
    /// once (see `StoreHealth`).
    async fn reconcile_store_locked(
        &self,
        store: &dyn crate::config_store::ConfigStore,
    ) -> anyhow::Result<bool> {
        use crate::config_store::StoreError;
        let stored = match store.load_latest().await {
            Ok(Some(stored)) => stored,
            Ok(None) => {
                self.store_failure("missing", "shared configuration is missing".into(), true);
                anyhow::bail!("shared configuration is missing");
            }
            Err(error) => {
                let reason = match &error {
                    StoreError::Unavailable(_) => "unavailable",
                    StoreError::Invalid(_) => "invalid",
                    StoreError::Indeterminate(_) => "indeterminate",
                };
                // A readable but invalid durable document is an authority
                // disagreement, not a transient inability to reach the store.
                self.store_failure(reason, format!("{error:#}"), error.is_transport());
                return Err(error.into());
            }
        };
        self.reconcile_stored(stored).await
    }

    /// Judge a durable document that is already in hand — a poll result, or
    /// the current document a CAS conflict returned — and activate it when
    /// it is newer. The caller holds `writes`.
    async fn reconcile_stored(&self, stored: crate::config_store::Stored) -> anyhow::Result<bool> {
        if let Err(error) = crate::config_store::ensure_reader_compatibility(&stored.config) {
            self.store_failure("invalid", format!("{error:#}"), false);
            return Err(error.into());
        }
        // A fresh attachment (first poll of a generation that inherited its
        // snapshot without an epoch) adopts the store's document like a fresh
        // start would, without comparing revisions across unknown histories.
        // The epoch is recorded only once the attachment succeeded
        // (agreement or activation), so a failed first attempt keeps its
        // fresh-attachment semantics and can retry.
        let fresh = match self.recorded_epoch().as_deref() {
            Some(epoch) if epoch != stored.epoch => {
                // The store was wiped and bootstrapped again: its
                // revisions belong to another history and must not
                // be compared with ours.
                self.store_failure(
                    "authority_changed",
                    format!(
                        "store epoch {} differs from the followed epoch",
                        stored.epoch
                    ),
                    false,
                );
                anyhow::bail!("shared configuration authority changed");
            }
            Some(_) => false,
            None => true,
        };
        let epoch = stored.epoch;
        let config = stored.config;
        let current = self.active.load_full();
        if !fresh && config.revision < current.config.revision {
            self.store_failure(
                "rollback",
                format!(
                    "store revision {} is older than the active revision {}",
                    config.revision, current.config.revision
                ),
                false,
            );
            anyhow::bail!("shared configuration revision is older than the active revision");
        }
        if config == current.config {
            self.attach_epoch(epoch);
            self.store_confirmed();
            return Ok(false);
        }
        if !fresh && config.revision == current.config.revision {
            self.store_failure(
                "divergence",
                format!(
                    "store document differs at the active revision {}",
                    config.revision
                ),
                false,
            );
            anyhow::bail!("shared configuration differs at the active revision");
        }
        if self.stopping.load(Ordering::Acquire) {
            // Frozen for a handoff (or draining): the newer revision cannot be
            // activated here, so this generation no longer agrees with the
            // authority. Fail closed; the successor activates it.
            self.store_failure(
                "stale",
                format!(
                    "revision {} is available while activation is frozen",
                    config.revision
                ),
                false,
            );
            anyhow::bail!("server is draining");
        }

        let revision = config.revision;
        let prepared = async {
            config.validate()?;
            // Even a fresh attachment may inherit a live protected route from
            // an earlier generation. A same-ID legacy downgrade needs an
            // explicit mode choice before replacing that active policy.
            config.validate_transition_from(&current.config)?;
            for route in &config.http {
                for script in route.scripts() {
                    self.policy.validate(script).await?;
                }
            }
            // A fresh attachment to an unknown history starts from a clean
            // snapshot: the inherited cache runtime's invalidation fence
            // belongs to another history and must not be carried over.
            let next = if fresh {
                let config = config.clone();
                let current = current.clone();
                tokio::task::spawn_blocking(move || {
                    Snapshot::replace_fresh(config, &current).map(Arc::new)
                })
                .await??
            } else {
                self.prepare_snapshot(config.clone()).await?
            };
            let tcp = self.tcp.prepare(&config).await?;
            anyhow::Ok((next, tcp))
        }
        .await;
        let (next, prepared) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                // Fail closed: this instance cannot serve the authoritative
                // revision, and the writer's instance cannot know that.
                self.store_failure(
                    "unpreparable",
                    format!("revision {revision}: {error:#}"),
                    false,
                );
                return Err(error);
            }
        };
        // Publication-time side effects (cache generation adoption) run
        // before the snapshot becomes visible, so no request can observe the
        // new revision with the previous invalidation fence.
        self.tcp
            .commit_with_publication(prepared, || {
                next.activated();
                self.active.store(next);
            })
            .await?;
        self.metrics.config_updates.fetch_add(1, Ordering::Relaxed);
        self.attach_epoch(epoch);
        self.store_confirmed();
        Ok(true)
    }

    /// Raise the incoming document's cache generation and floor to the
    /// highest generation this history has committed (see
    /// `Config::cache_generation_floor`). Applied to every write and to a
    /// reloaded file before it is compared with the active document.
    fn normalize_cache_generation(&self, config: &mut Config) {
        let floor = {
            let active = self.active.load();
            active
                .config
                .cache_generation_floor
                .max(config.cache_generation_floor)
                .max(
                    active
                        .config
                        .cache
                        .as_ref()
                        .map_or(0, |cache| cache.generation),
                )
                .max(config.cache.as_ref().map_or(0, |cache| cache.generation))
        };
        config.cache_generation_floor = floor;
        if let Some(next) = config.cache.as_mut()
            && next.generation < floor
        {
            next.generation = floor;
        }
    }

    fn attach_epoch(&self, epoch: String) {
        let mut recorded = self
            .authority_epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if recorded.is_none() {
            *recorded = Some(epoch);
        }
    }

    async fn apply_locked(
        &self,
        mut config: Config,
        expected: u64,
        persist: bool,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> anyhow::Result<Config> {
        if self.config_store.is_some() {
            crate::config_store::ensure_reader_compatibility(&config)?;
        }

        anyhow::ensure!(!self.stopping.load(Ordering::Acquire), "server is draining");
        if persist && let Some(store) = &self.config_store {
            // A precondition ahead of this instance (read from another
            // member a moment ago) or a missing epoch (a replacement
            // generation that inherited its snapshot) is resolved against the
            // authority first, so the document is judged — and, for route
            // mutations, was built — on the current base. A failed catch-up
            // is reported as what it is, not as a conflict.
            if self.active.load().config.revision < expected || self.recorded_epoch().is_none() {
                self.reconcile_store_locked(store.as_ref()).await?;
            }
        }
        anyhow::ensure!(
            self.active.load().config.revision == expected,
            "revision conflict"
        );
        // The cache invalidation generation never decreases at the authority:
        // a whole-document rollback, or re-enabling caching after it was
        // disabled, keeps the highest generation this instance ever
        // activated, so a purge that happened in between stays effective on
        // every instance (and a later purge cannot be skipped).
        self.normalize_cache_generation(&mut config);
        config.revision = expected
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("revision exhausted"))?;
        config.validate()?;
        for route in &config.http {
            for script in route.scripts() {
                self.policy.validate(script).await?;
            }
        }
        let mut next = self.prepare_snapshot(config.clone()).await?;
        if let Some(tls) = tls {
            Arc::get_mut(&mut next)
                .expect("unpublished snapshot is exclusive")
                .certificates = Some(Arc::new(arc_swap::ArcSwap::from(tls)));
        }
        let prepared = self.tcp.prepare(&config).await?;
        if persist {
            if let Some(store) = &self.config_store {
                let epoch = self
                    .recorded_epoch()
                    .ok_or_else(|| anyhow::anyhow!("shared configuration authority is unknown"))?;
                match store
                    .compare_and_swap(&epoch, expected, config.clone())
                    .await?
                {
                    crate::config_store::CasResult::Applied(committed) => {
                        anyhow::ensure!(
                            committed.config == config,
                            "store returned an unexpected committed snapshot"
                        );
                    }
                    crate::config_store::CasResult::Conflict { current } => {
                        if current.epoch != epoch {
                            self.store_failure(
                                "authority_changed",
                                format!(
                                    "store epoch {} differs from the followed epoch",
                                    current.epoch
                                ),
                                false,
                            );
                            anyhow::bail!("shared configuration authority changed");
                        }
                        // The conflict carries the authoritative document:
                        // judge and adopt it directly (evidence of staleness
                        // must not be discarded behind another read), so the
                        // client's next read on this instance is current.
                        // The losing transaction's prepared listeners are
                        // released first: the winner may use those addresses.
                        drop(prepared);
                        drop(next);
                        self.reconcile_stored(current).await?;
                        anyhow::bail!("revision conflict")
                    }
                }
            } else {
                store::save(self.state_path.clone(), config.clone()).await?;
            }
        }
        // Publication-time side effects (cache generation adoption) run
        // before the snapshot becomes visible, so no request can observe the
        // new revision with the previous invalidation fence.
        self.tcp
            .commit_with_publication(prepared, || {
                next.activated();
                self.active.store(next);
            })
            .await?;
        self.metrics.config_updates.fetch_add(1, Ordering::Relaxed);
        Ok(config)
    }
}
#[derive(Clone)]
pub struct Admin {
    pub acme_status: Option<Arc<std::sync::RwLock<crate::acme_runtime::Status>>>,
    pub file_tls_enabled: bool,
    pub manager: Arc<Manager>,
    pub token: Arc<String>,
    pub users: Arc<crate::admin_users::Store>,
    pub traffic: Arc<crate::traffic::TrafficHistory>,
    pub docker: Option<Arc<crate::docker_connections::DockerConnections>>,
    pub lifecycle: Option<Arc<crate::restart::ControlChannel>>,
    pub update_status_path: Option<PathBuf>,
    /// Admission for authenticated administration.
    pub requests: Arc<tokio::sync::Semaphore>,
    /// Separate, smaller admission for the assets served before
    /// authentication (`/ui/*`, `/openapi.json`). An unauthenticated peer can
    /// pin at most this many responses by refusing to read them; it can never
    /// consume the authenticated budget above.
    pub public_requests: Arc<tokio::sync::Semaphore>,
    /// Separate from static assets, so a slow unauthenticated asset reader
    /// cannot consume every login and first-run setup permit.
    pub auth_requests: Arc<tokio::sync::Semaphore>,
    /// Long-lived SSE readers never consume the ordinary request budget.
    pub events: Arc<Semaphore>,
}
impl Admin {
    /// Bounded admission for the embedded assets that need no token.
    pub const PUBLIC_REQUEST_LIMIT: usize = 16;
    pub const AUTH_REQUEST_LIMIT: usize = 8;
    pub const EVENT_STREAM_LIMIT: usize = 32;

    pub async fn handle(&self, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        if let Some(response) = public_asset(&req) {
            // Public assets take their own permit and retain it through the
            // body: slow readers are bounded by the public budget alone.
            let Ok(permit) = self.public_requests.clone().try_acquire_owned() else {
                return Ok(problem(
                    503,
                    "Service Unavailable",
                    "public asset capacity exhausted",
                ));
            };
            return Ok(crate::proxy::retain_request_permit(response, permit));
        }
        if matches!(
            req.uri().path(),
            "/v1/auth/setup" | "/v1/auth/bootstrap" | "/v1/auth/login"
        ) {
            let Ok(permit) = self.auth_requests.clone().try_acquire_owned() else {
                return Ok(problem(
                    503,
                    "Service Unavailable",
                    "authentication capacity exhausted",
                ));
            };
            let mut response = self.handle_public_auth(req).await;
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            return Ok(crate::proxy::retain_request_permit(response, permit));
        }
        if req.uri().path() == "/v1/events" {
            let Ok(permit) = self.events.clone().try_acquire_owned() else {
                let mut response = problem(
                    503,
                    "Service Unavailable",
                    "event stream capacity exhausted",
                );
                response
                    .headers_mut()
                    .insert("cache-control", "no-store".parse().unwrap());
                return Ok(response);
            };
            let mut response = self.handle_events(req, permit).await;
            response
                .headers_mut()
                .insert("cache-control", "no-store".parse().unwrap());
            return Ok(response);
        }
        let Ok(permit) = self.requests.clone().try_acquire_owned() else {
            return Ok(problem(
                503,
                "Service Unavailable",
                "administration capacity exhausted",
            ));
        };
        let mut response = self.handle_inner(req).await?;
        response
            .headers_mut()
            .insert("cache-control", "no-store".parse().unwrap());
        // Release the admission permit immediately for unauthenticated
        // responses instead of retaining it through the (tiny, fixed) body.
        // Otherwise an unauthenticated peer that stops reading — e.g. an
        // HTTP/2 client advertising a zero receive window across many streams —
        // could pin the whole admin request budget with 401s and lock out the
        // operator. Authenticated responses (which may be large or streamed)
        // still retain the permit through completion.
        if response.status() == hyper::StatusCode::UNAUTHORIZED
            || response.status() == hyper::StatusCode::FORBIDDEN
        {
            drop(permit);
            return Ok(response);
        }
        Ok(crate::proxy::retain_request_permit(response, permit))
    }

    fn status_value(&self) -> (serde_json::Value, u64) {
        let snapshot = self.manager.active.load();
        let metrics = &self.manager.metrics;
        let status = serde_json::json!({
            "revision": snapshot.config.revision,
            "http_routes": snapshot.config.http.len(),
            "tcp_routes": snapshot.config.tcp.len(),
            "workload_materials": snapshot.tcp_inbound_tls.iter().map(|(id, slot)|
                serde_json::json!({"kind":"tcp", "id":id, "ready":slot.load().is_some()}))
                .chain(snapshot.http_workload_tls.iter().map(|(id, slot)|
                    serde_json::json!({"kind":"http", "id":id, "ready":slot.load().is_some()})))
                .collect::<Vec<_>>(),
            "metrics": {
                "requests_total": metrics.requests.load(Ordering::Relaxed),
                "cache_hits_total": metrics.cache_hits.load(Ordering::Relaxed),
                "cache_misses_total": metrics.cache_misses.load(Ordering::Relaxed),
                "cache_bypasses_total": metrics.cache_bypasses.load(Ordering::Relaxed),
                "errors_total": metrics.errors.load(Ordering::Relaxed),
                "jwt_auth_rejections_total": metrics.jwt_auth_rejections.load(Ordering::Relaxed),
                "http_mtls_rejections_total": metrics.http_mtls_rejections.load(Ordering::Relaxed),
                "http_mtls_lease_terminations_total": metrics.http_mtls_lease_terminations.load(Ordering::Relaxed),
                "workload_auth_rejections_total": metrics.workload_auth_rejections.load(Ordering::Relaxed),
                "workload_route_terminations_total": metrics.workload_route_terminations.load(Ordering::Relaxed),
                "tcp_mtls_rejections_total": metrics.tcp_mtls_rejections.load(Ordering::Relaxed),
                "tcp_mtls_lease_terminations_total": metrics.tcp_mtls_lease_terminations.load(Ordering::Relaxed),
                "jwt_auth_unavailable_total": metrics.jwt_auth_unavailable.load(Ordering::Relaxed),
                "jwt_lease_terminations_total": metrics.jwt_lease_terminations.load(Ordering::Relaxed),
                "jwt_auth_capacity_rejections_total": metrics.jwt_auth_capacity_rejections.load(Ordering::Relaxed),
                "active_connections": metrics.active_connections.load(Ordering::Relaxed),
                "rejected_connections_total": metrics.rejected_connections.load(Ordering::Relaxed),
                "rejected_requests_total": metrics.rejected_requests.load(Ordering::Relaxed),
                "policy_errors_total": metrics.policy_errors.load(Ordering::Relaxed),
                "policy_capacity_rejections_total": metrics.policy_capacity_rejections.load(Ordering::Relaxed),
                "body_transform_errors_total": metrics.body_transform_errors.load(Ordering::Relaxed),
                "config_updates_total": metrics.config_updates.load(Ordering::Relaxed),
            },
            "acme": self.acme_status.as_ref().map(|status| status.read().expect("status lock").clone()).unwrap_or_default(),
            "state": { "draining": self.manager.stopping.load(Ordering::Acquire), "supervised": self.lifecycle.is_some(), "ready": self.manager.ready.load(Ordering::Acquire), "configuration_source": if self.manager.externally_managed {"kubernetes"} else if self.manager.config_store.is_some() {"shared"} else {"file"} },
            "process_id": std::process::id(),
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_seconds": STARTED.elapsed().as_secs(),
            "instance": {
                "id": instance_id(),
                "config_digest": config_digest(&snapshot.config),
            },
            "settings": snapshot.config.settings,
            "store": self.manager.config_store.as_ref().map(|_| {
                let health = self.manager.store_health.report();
                serde_json::json!({
                    "epoch": self.manager.recorded_epoch(),
                    "revision": snapshot.config.revision,
                    "ready": self.manager.ready.load(Ordering::Acquire),
                    "degraded": health.degraded,
                    "reason": health.reason,
                    "detail": health.detail,
                    "last_confirmed_seconds_ago": health.last_confirmed_seconds_ago,
                    "grace_seconds": health.grace_seconds,
                })
            }),
        });
        (status, snapshot.config.revision)
    }

    async fn handle_events(
        &self,
        req: Request<Incoming>,
        permit: OwnedSemaphorePermit,
    ) -> Response<Body> {
        if req.method() != hyper::Method::GET {
            return problem(405, "Method Not Allowed", "GET required");
        }
        if req.uri().query().is_some() {
            return problem(
                400,
                "Bad Request",
                "event streams do not accept query parameters",
            );
        }
        let actor = match self.authenticate(&req).await {
            Ok(Some(actor)) => actor,
            Ok(None) => {
                let mut response = problem(401, "Unauthorized", "a valid bearer token is required");
                response
                    .headers_mut()
                    .insert("www-authenticate", "Bearer".parse().unwrap());
                return response;
            }
            Err(_) => {
                return problem(
                    503,
                    "Authentication Unavailable",
                    "administrator account store unavailable",
                );
            }
        };
        let account_token = match actor {
            AdminActor::System => None,
            AdminActor::Account { token, .. } => Some(token),
        };
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let state = EventStreamState {
            admin: self.clone(),
            account_token,
            interval,
            cursor: self.traffic.latest_id(),
            done: false,
            _permit: permit,
        };
        let stream = futures_util::stream::unfold(state, |mut state| async move {
            if state.done {
                return None;
            }
            state.interval.tick().await;
            let may_read_traffic = match &state.account_token {
                Some(token) => match state.admin.users.session(token.clone()).await {
                    Ok(Some(user)) => user.role == crate::admin_users::Role::Admin,
                    Ok(None) => {
                        state.done = true;
                        return Some((
                            Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from_static(
                                b"event: auth_expired\ndata: {}\n\n",
                            ))),
                            state,
                        ));
                    }
                    Err(_) => return None,
                },
                None => true,
            };
            let (status, _) = state.admin.status_value();
            let mut events = format!(
                "event: status\ndata: {}\n\n",
                serde_json::to_string(&status).expect("status is serializable")
            );
            if may_read_traffic {
                let batch = state.admin.traffic.snapshot_since(Some(state.cursor), 128);
                state.cursor = batch.next_after;
                if batch.gap || !batch.records.is_empty() {
                    events.push_str("event: traffic\ndata: ");
                    events.push_str(
                        &serde_json::to_string(&batch).expect("traffic batch is serializable"),
                    );
                    events.push_str("\n\n");
                }
            }
            Some((
                Ok::<Frame<Bytes>, Infallible>(Frame::data(Bytes::from(events))),
                state,
            ))
        });
        let body = StreamBody::new(stream)
            .map_err(|never| match never {})
            .boxed_unsync();
        Response::builder()
            .status(200)
            .header("content-type", "text/event-stream; charset=utf-8")
            .header("cache-control", "no-store")
            .header("x-accel-buffering", "no")
            .body(body)
            .expect("static event response")
    }
    async fn handle_inner(&self, req: Request<Incoming>) -> Result<Response<Body>, Infallible> {
        let path = req.uri().path().to_owned();
        let actor = match self.authenticate(&req).await {
            Ok(actor) => actor,
            Err(_) => {
                return Ok(problem(
                    503,
                    "Authentication Unavailable",
                    "administrator account store unavailable",
                ));
            }
        };
        let Some(actor) = actor else {
            let is_new = path == "/v1/status"
                || path == "/v1/config/validate"
                || path == "/v1/lifecycle/restart"
                || path.starts_with("/v1/update/")
                || path.starts_with("/v1/audit/")
                || path.starts_with("/v1/routes/");
            let mut r = if is_new {
                problem(401, "Unauthorized", "a valid bearer token is required")
            } else {
                response(401, "unauthorized\n")
            };
            r.headers_mut()
                .insert("www-authenticate", "Bearer".parse().unwrap());
            return Ok(r);
        };
        if path == "/v1/auth/me" {
            return Ok(if req.method() == hyper::Method::GET {
                json_value(200, &serde_json::json!({"user":actor.user()}), None)
            } else {
                problem(405, "Method Not Allowed", "GET required")
            });
        }
        if path == "/v1/auth/logout" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            if let AdminActor::Account { token, .. } = actor
                && self.users.logout(token).await.is_err()
            {
                return Ok(problem(
                    503,
                    "Authentication Unavailable",
                    "administrator account store unavailable",
                ));
            }
            return Ok(empty_response(204, None));
        }
        if actor.role() == crate::admin_users::Role::Viewer && !viewer_allowed(&path, req.method())
        {
            return Ok(problem(403, "Forbidden", "administrator role required"));
        }
        if path == "/v1/audit/users" || path == "/v1/audit/users/prune" {
            return Ok(self.handle_user_audit(req, &path, &actor).await);
        }
        if path == "/v1/users" || path.starts_with("/v1/users/") {
            return Ok(self.handle_users(req, &path, &actor).await);
        }
        if path == "/v1/update/status" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let state = if let Some(path) = &self.update_status_path {
                let path = path.clone();
                match tokio::task::spawn_blocking(
                    move || -> anyhow::Result<crate::supervisor::UpdateStatus> {
                        use std::io::Read;
                        let mut bytes = Vec::new();
                        std::fs::File::open(path)?
                            .take(65537)
                            .read_to_end(&mut bytes)?;
                        anyhow::ensure!(bytes.len() <= 65536, "update status too large");
                        Ok(serde_json::from_slice(&bytes)?)
                    },
                )
                .await
                {
                    Ok(Ok(state)) => state,
                    _ => {
                        return Ok(problem(
                            503,
                            "Update Status Unavailable",
                            "update status could not be loaded",
                        ));
                    }
                }
            } else {
                crate::supervisor::UpdateStatus::initial(false)
            };
            return Ok(json_value(200, &state, None));
        }
        if path == "/v1/update/check" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            if self.update_status_path.is_none() {
                return Ok(problem(
                    503,
                    "Updater Unavailable",
                    "configure a signed release manifest and pinned public key",
                ));
            }
            let Some(channel) = &self.lifecycle else {
                return Ok(problem(
                    503,
                    "Supervisor Unavailable",
                    "supervisor required",
                ));
            };
            if channel
                .try_send_control(crate::restart::ControlMessage::UpdateRequested)
                .is_err()
            {
                return Ok(problem(
                    503,
                    "Supervisor Unavailable",
                    "control channel unavailable or busy",
                ));
            }
            return Ok(json_value(202, &serde_json::json!({"accepted":true}), None));
        }
        if path == "/v1/lifecycle/restart" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            let Some(channel) = &self.lifecycle else {
                return Ok(problem(
                    503,
                    "Supervisor Unavailable",
                    "start with --supervised to enable listener-preserving restart",
                ));
            };
            if channel
                .try_send_control(crate::restart::ControlMessage::RestartRequested)
                .is_err()
            {
                return Ok(problem(
                    503,
                    "Supervisor Unavailable",
                    "control channel unavailable",
                ));
            }
            return Ok(json_value(202, &serde_json::json!({"accepted":true}), None));
        }
        if path == "/v1/cache" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let snapshot = self.manager.active.load_full();
            let value = match &snapshot.cache {
                Some(cache) => {
                    serde_json::json!({"enabled":true,"config":snapshot.config.cache,"generation":cache.generation(),"stats":cache.store.stats().await,"active_fills":cache.active_fills()})
                }
                None => {
                    serde_json::json!({"enabled":false,"config":snapshot.config.cache,"stats":null,"active_fills":0})
                }
            };
            return Ok(json_value(200, &value, None));
        }
        if path == "/v1/docker/connection" || path == "/v1/docker/connection/test" {
            let Some(docker) = &self.docker else {
                return Ok(problem(
                    503,
                    "Docker Unavailable",
                    "Docker connection management is unavailable",
                ));
            };
            if path.ends_with("/test") {
                if req.method() != hyper::Method::POST {
                    return Ok(problem(405, "Method Not Allowed", "POST required"));
                }
                let config: crate::docker_connections::ConnectionConfig =
                    match read_json(req, 4096).await {
                        Ok(config) => config,
                        Err(response) => return Ok(response),
                    };
                return Ok(match docker.test_candidate(config).await {
                    Ok(()) => json_value(200, &serde_json::json!({"ok":true}), None),
                    Err(error) if error.is::<crate::docker_connections::Busy>() => problem(
                        503,
                        "Docker Busy",
                        "Docker connection work capacity exhausted",
                    ),
                    Err(error) => {
                        tracing::warn!(%error, "Docker candidate connection test failed");
                        problem(
                            422,
                            "Docker Connection Failed",
                            "the Docker connection could not be verified; check the server log for the validation stage",
                        )
                    }
                });
            }
            if req.method() == hyper::Method::GET {
                let view = docker.view().await;
                return Ok(json_value(200, &view, Some(view.revision)));
            }
            if req.method() != hyper::Method::PUT && req.method() != hyper::Method::DELETE {
                return Ok(problem(
                    405,
                    "Method Not Allowed",
                    "GET, PUT, or DELETE required",
                ));
            }
            let Some(expected) = req
                .headers()
                .get("if-match")
                .and_then(|v| v.to_str().ok())
                .and_then(parse_revision)
            else {
                return Ok(problem(
                    428,
                    "Precondition Required",
                    "If-Match must contain the quoted current revision",
                ));
            };
            let result = if req.method() == hyper::Method::PUT {
                let config: crate::docker_connections::ConnectionConfig =
                    match read_json(req, 4096).await {
                        Ok(config) => config,
                        Err(response) => return Ok(response),
                    };
                docker.put(expected, config).await
            } else {
                docker.delete(expected).await
            };
            return Ok(match result {
                Ok(Some(view)) => json_value(200, &view, Some(view.revision)),
                Ok(None) => problem(
                    409,
                    "Revision Conflict",
                    "Docker connection revision conflict",
                ),
                Err(error) if error.is::<crate::docker_connections::Busy>() => problem(
                    503,
                    "Docker Busy",
                    "Docker connection work capacity exhausted",
                ),
                Err(error) if error.is::<crate::docker_connections::Frozen>() => problem(
                    503,
                    "Docker Handoff",
                    "Docker connection changes are paused during restart",
                ),
                Err(error) => {
                    tracing::warn!(%error, "Docker connection update failed");
                    problem(
                        422,
                        "Docker Connection Invalid",
                        "Docker connection configuration could not be applied; check the server log for the validation stage",
                    )
                }
            });
        }
        if path == "/v1/cache/purge" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            let snapshot = self.manager.active.load_full();
            if self.manager.config_store.is_some() && !self.manager.externally_managed {
                // Fleet-wide purge: raise the invalidation generation through
                // the shared authority; every instance drops its entries when
                // it activates that revision (this one included).
                let Some(settings) = &snapshot.config.cache else {
                    return Ok(json_value(
                        200,
                        &serde_json::json!({"purged":true,"scope":"fleet","generation":null}),
                        None,
                    ));
                };
                let mut config = snapshot.config.clone();
                let bumped = match settings.bumped() {
                    Ok(bumped) => bumped,
                    Err(error) => {
                        return Ok(problem(
                            422,
                            "Cache Generation Exhausted",
                            &error.to_string(),
                        ));
                    }
                };
                let generation = bumped.generation;
                config.cache = Some(bumped);
                return Ok(
                    match self.manager.apply(config, snapshot.config.revision).await {
                        Ok(applied) => json_value(
                            200,
                            &serde_json::json!({"purged":true,"scope":"fleet","generation":generation,"revision":applied.revision}),
                            Some(applied.revision),
                        ),
                        Err(error) => apply_problem(error),
                    },
                );
            }
            if let Some(cache) = &snapshot.cache
                && let Err(error) = cache.purge().await
            {
                return Ok(problem(503, "Cache Unavailable", &error.to_string()));
            }
            return Ok(json_value(
                200,
                &serde_json::json!({"purged":true,"scope":"instance"}),
                None,
            ));
        }
        if path == "/v1/traffic" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let (after, limit) = match traffic_query(req.uri().query()) {
                Some(value) => value,
                None => {
                    return Ok(problem(
                        400,
                        "Bad Request",
                        "invalid traffic cursor or limit",
                    ));
                }
            };
            let batch = self.traffic.snapshot_since(after, limit);
            return Ok(json_value(200, &batch, None));
        }
        if path == "/v1/certificates" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let Some((offset, limit)) = certificate_inventory_query(req.uri().query()) else {
                return Ok(problem(
                    400,
                    "Bad Request",
                    "invalid certificate offset or limit",
                ));
            };
            static READS: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> =
                std::sync::OnceLock::new();
            let capacity = READS
                .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
                .clone();
            let Ok(permit) = capacity.try_acquire_owned() else {
                return Ok(problem(
                    503,
                    "Certificate Inventory Busy",
                    "try again shortly",
                ));
            };
            let snapshot = self.manager.active.load_full();
            let total = snapshot.config.certificates.len();
            let files: Vec<_> = snapshot
                .config
                .certificates
                .iter()
                .skip(offset)
                .take(limit)
                .cloned()
                .collect();
            let configured_tls = self.file_tls_enabled && snapshot.certificates.is_some();
            let revision = snapshot.config.revision;
            let now = crate::certificate_inventory::now_unix_ms();
            let acme = self.acme_status.as_ref().map(|status| {
                crate::certificate_inventory::InProcessAcme::from(
                    status.read().expect("status lock").clone(),
                )
            });
            let mode = if total > 0 {
                "configured_files"
            } else if acme.is_some() {
                "in_process_acme"
            } else {
                "other_or_none"
            };
            let read = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                crate::certificate_inventory::entries(&files, configured_tls, now)
            });
            let certificates = match tokio::time::timeout(Duration::from_secs(5), read).await {
                Ok(Ok(certificates)) => certificates,
                _ => {
                    return Ok(problem(
                        503,
                        "Certificate Inventory Unavailable",
                        "metadata read timed out or failed",
                    ));
                }
            };
            return Ok(json_value(
                200,
                &crate::certificate_inventory::Inventory {
                    revision,
                    mode,
                    total,
                    offset,
                    limit,
                    server_time_unix_ms: now,
                    certificates,
                    in_process_acme: acme,
                },
                Some(revision),
            ));
        }
        if path == "/v1/retired-members" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let Some((offset, limit)) = operations_query(req.uri().query()) else {
                return Ok(problem(
                    400,
                    "Bad Request",
                    "invalid retired member offset or limit",
                ));
            };
            let snapshot = self.manager.active.load();
            let all = snapshot.retired_members.snapshot();
            let total = all.len();
            let rows: Vec<_> = all.into_iter().skip(offset).take(limit).collect();
            return Ok(json_value(
                200,
                &serde_json::json!({
                    "total": total, "offset": offset, "limit": limit,
                    "capacity": crate::retired_members::CAPACITY, "rows": rows,
                }),
                Some(snapshot.config.revision),
            ));
        }
        if path == "/v1/operations" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let Some((offset, limit)) = operations_query(req.uri().query()) else {
                return Ok(problem(
                    400,
                    "Bad Request",
                    "invalid operations offset or limit",
                ));
            };
            let snapshot = self.manager.active.load();
            let total: usize = snapshot
                .http
                .iter()
                .map(|runtime| runtime.route.backends.len())
                .chain(snapshot.config.tcp.iter().map(|route| route.backends.len()))
                .sum();
            let mut rows = Vec::with_capacity(limit.min(total.saturating_sub(offset)));
            let mut position = 0usize;
            for runtime in &snapshot.http {
                if rows.len() == limit {
                    break;
                }
                if position + runtime.route.backends.len() <= offset {
                    position += runtime.route.backends.len();
                    continue;
                }
                let match_host = runtime
                    .route
                    .host
                    .clone()
                    .or_else(|| {
                        (!runtime.route.hosts.is_empty())
                            .then(|| format!("group:{}", runtime.route.hosts.join(", ")))
                    })
                    .or_else(|| {
                        runtime
                            .route
                            .host_regex
                            .as_ref()
                            .map(|pattern| format!("regex:{pattern}"))
                    });
                for (backend_index, address) in runtime.route.backends.iter().enumerate() {
                    if rows.len() == limit {
                        break;
                    }
                    if position >= offset && rows.len() < limit {
                        let mut state = runtime
                            .balancer
                            .backend_state(backend_index)
                            .expect("prepared HTTP backend state");
                        if address.address().starts_with("docker://") {
                            let current = self
                                .manager
                                .tcp
                                .discovered_target(
                                    address.address(),
                                    crate::discovery::Protocol::Http,
                                )
                                .and_then(|target| {
                                    runtime
                                        .balancer
                                        .backend_state_for(backend_index, target.epoch)
                                });
                            if let Some(current) = current {
                                state = current;
                            } else {
                                state.available = false;
                                state.probe_observed = state.probe_observed.map(|_| false);
                                state.initial_check_pending =
                                    runtime.route.balance.active_health.as_ref().map(|policy| {
                                        policy.initial_state
                                            == crate::balance::InitialHealthState::Checking
                                    });
                            }
                        }
                        rows.push(serde_json::json!({
                            "protocol": "http",
                            "route_id": runtime.route.id,
                            "backend_index": backend_index,
                            "address": address.address(),
                            "member_id": address.id(),
                            "desired_state": address.desired_state(),
                            "match_host": match_host,
                            "listen": null,
                            "balance_mode": runtime.route.balance.mode,
                            "weight": if address.id().is_some() { address.weight() } else {
                                runtime.route.balance.weights.get(backend_index).copied().unwrap_or(1)
                            },
                            "enabled": runtime.route.enabled,
                            "available": runtime.route.enabled && state.available,
                            "health_mode": state.health_mode,
                            "probe_observed": state.probe_observed,
                            "initial_check_pending": state.initial_check_pending,
                            "active_requests": state.active_requests,
                            "active_admissions": state.active_requests.unwrap_or_default(),
                            "admission_open": runtime.balancer.admission_open(backend_index),
                            "member_active_streams": null,
                            "route_active_connections": null
                        }));
                    }
                    position += 1;
                }
            }
            for route in &snapshot.config.tcp {
                if rows.len() == limit {
                    break;
                }
                if position + route.backends.len() <= offset {
                    position += route.backends.len();
                    continue;
                }
                let active_connections = snapshot
                    .admissions
                    .get(&route.id)
                    .map(|counter| counter.load(Ordering::Relaxed))
                    .unwrap_or_default();
                for (backend_index, address) in route.backends.iter().enumerate() {
                    if rows.len() == limit {
                        break;
                    }
                    if position >= offset && rows.len() < limit {
                        let health = snapshot
                            .tcp_health
                            .get(&route.id)
                            .and_then(|health| health.backend_state(backend_index));
                        rows.push(serde_json::json!({
                            "protocol": "tcp",
                            "route_id": route.id,
                            "backend_index": backend_index,
                            "address": address.address(),
                            "member_id": address.id(),
                            "desired_state": address.desired_state(),
                            "match_host": null,
                            "listen": route.listen.to_string(),
                            "balance_mode": "round_robin",
                            "weight": address.weight(),
                            "enabled": route.enabled,
                            "available": route.enabled && snapshot.tcp_member_admissions[&route.id][backend_index].is_open() && health.as_ref().is_none_or(|state| state.available),
                            "health_mode": if health.is_some() { "active_tcp" } else { "unmonitored" },
                            "probe_observed": health.as_ref().map(|state| state.probe_observed),
                            "initial_check_pending": health.as_ref().map(|state| state.initial_check_pending),
                            "active_requests": null,
                            "active_admissions": snapshot.tcp_member_admissions[&route.id][backend_index].active(),
                            "admission_open": snapshot.tcp_member_admissions[&route.id][backend_index].is_open(),
                            "member_active_streams": snapshot.tcp_member_activity.get(&route.id)
                                .and_then(|activity| activity.node(backend_index)).map(|counter| counter.active()),
                            "route_active_connections": active_connections
                        }));
                    }
                    position += 1;
                }
            }
            let configuration_source = if self.manager.externally_managed {
                "kubernetes"
            } else if self.manager.config_store.is_some() {
                "shared"
            } else {
                "file"
            };
            return Ok(json_value(
                200,
                &serde_json::json!({
                    "revision": snapshot.config.revision,
                    "instance_id": instance_id(),
                    "capabilities": {
                        "docker_enabled": self.docker.as_ref().is_some_and(|docker| docker.resolver().is_some()),
                        "self_restart_enabled": self.lifecycle.is_some(),
                        "signed_updates_enabled": self.lifecycle.is_some() && self.update_status_path.is_some(),
                        "configuration_source": configuration_source
                    },
                    "total": total,
                    "offset": offset,
                    "limit": limit,
                    "rows": rows
                }),
                Some(snapshot.config.revision),
            ));
        }
        if path == "/v1/status" {
            if req.method() != hyper::Method::GET {
                return Ok(problem(405, "Method Not Allowed", "GET required"));
            }
            let (status, revision) = self.status_value();
            return Ok(json_value(200, &status, Some(revision)));
        }
        if path == "/v1/util/hash-password" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct HashRequest {
                username: String,
                password: String,
            }
            let request: HashRequest = match read_json(req, 8 * 1024).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            // The password is hashed with a fresh salt and discarded; only
            // the credential line for `basic_auth.credentials` is returned.
            return Ok(
                match crate::basic_auth::hash_credential(&request.username, &request.password) {
                    Ok(credential) => json_value(
                        200,
                        &serde_json::json!({"credential": credential, "username": request.username}),
                        None,
                    ),
                    Err(error) => problem(422, "Invalid Credential", &error.to_string()),
                },
            );
        }
        if path == "/v1/config/validate" {
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "POST required"));
            }
            let config: Config = match read_json(req, 1024 * 1024).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            if let Err(error) = config.validate() {
                return Ok(problem(422, "Configuration Invalid", &error.to_string()));
            }
            if let Err(error) = config.validate_transition_from(&self.manager.active.load().config)
            {
                return Ok(problem(422, "Configuration Invalid", &error.to_string()));
            }
            for route in &config.http {
                for script in route.scripts() {
                    if let Err(error) = self.manager.policy.validate(script).await {
                        return Ok(problem(422, "Configuration Invalid", &error.to_string()));
                    }
                }
            }
            if let Err(error) = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                crate::certificates::load(&config.certificates)?;
                config.prepare_upstream_tls()?;
                config.prepare_host_regexes()?;
                Ok(())
            })
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("certificate validation task failed")))
            {
                return Ok(problem(422, "Configuration Invalid", &error.to_string()));
            }
            let revision = self.manager.active.load().config.revision;
            return Ok(json_value(
                200,
                &serde_json::json!({"valid":true,"revision":revision}),
                Some(revision),
            ));
        }
        if path == "/v1/routes/http" || path == "/v1/routes/tcp" {
            let is_http = path.ends_with("/http");
            if req.method() == hyper::Method::GET {
                let snapshot = self.manager.active.load();
                let value = if is_http {
                    serde_json::json!({"revision":snapshot.config.revision,"routes":snapshot.config.http})
                } else {
                    serde_json::json!({"revision":snapshot.config.revision,"routes":snapshot.config.tcp})
                };
                return Ok(json_value(200, &value, Some(snapshot.config.revision)));
            }
            if req.method() != hyper::Method::POST {
                return Ok(problem(405, "Method Not Allowed", "GET or POST required"));
            }
            let expected = match require_revision(&req, &self.manager).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            if is_http {
                let route: crate::config::HttpRoute = match read_json(req, 1024 * 1024).await {
                    Ok(value) => value,
                    Err(response) => return Ok(response),
                };
                let mut config = self.manager.active.load().config.clone();
                if config.http.iter().any(|existing| existing.id == route.id)
                    || config.tcp.iter().any(|existing| existing.id == route.id)
                {
                    return Ok(problem(409, "Route Conflict", "route id already exists"));
                }
                config.http.push(route.clone());
                return Ok(match self.manager.apply(config, expected).await {
                    Ok(config) => json_value(201, &route, Some(config.revision)),
                    Err(error) => apply_problem(error),
                });
            }
            let route: crate::config::TcpRoute = match read_json(req, 1024 * 1024).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            let mut config = self.manager.active.load().config.clone();
            if config.http.iter().any(|existing| existing.id == route.id)
                || config.tcp.iter().any(|existing| existing.id == route.id)
            {
                return Ok(problem(409, "Route Conflict", "route id already exists"));
            }
            config.tcp.push(route.clone());
            return Ok(match self.manager.apply(config, expected).await {
                Ok(config) => json_value(201, &route, Some(config.revision)),
                Err(error) => apply_problem(error),
            });
        }
        let route_item = path
            .strip_prefix("/v1/routes/http/")
            .map(|id| (true, id.to_owned()))
            .or_else(|| {
                path.strip_prefix("/v1/routes/tcp/")
                    .map(|id| (false, id.to_owned()))
            });
        if let Some((is_http, id)) = route_item {
            if id.is_empty() || id.contains('/') {
                return Ok(problem(404, "Not Found", "route not found"));
            }
            if req.method() == hyper::Method::GET {
                let snapshot = self.manager.active.load();
                let value = if is_http {
                    snapshot
                        .config
                        .http
                        .iter()
                        .find(|route| route.id == id)
                        .and_then(|route| serde_json::to_value(route).ok())
                } else {
                    snapshot
                        .config
                        .tcp
                        .iter()
                        .find(|route| route.id == id)
                        .and_then(|route| serde_json::to_value(route).ok())
                };
                return Ok(match value {
                    Some(value) => json_value(200, &value, Some(snapshot.config.revision)),
                    None => problem(404, "Not Found", "route not found"),
                });
            }
            if req.method() != hyper::Method::PUT && req.method() != hyper::Method::DELETE {
                return Ok(problem(
                    405,
                    "Method Not Allowed",
                    "GET, PUT or DELETE required",
                ));
            }
            let expected = match require_revision(&req, &self.manager).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            let mut config = self.manager.active.load().config.clone();
            if is_http {
                let Some(index) = config.http.iter().position(|route| route.id == id) else {
                    return Ok(problem(404, "Not Found", "route not found"));
                };
                if req.method() == hyper::Method::DELETE {
                    config.http.remove(index);
                    return Ok(match self.manager.apply(config, expected).await {
                        Ok(config) => empty_response(204, Some(config.revision)),
                        Err(error) => apply_problem(error),
                    });
                }
                let route: crate::config::HttpRoute = match read_json(req, 1024 * 1024).await {
                    Ok(value) => value,
                    Err(response) => return Ok(response),
                };
                if route.id != id {
                    return Ok(problem(400, "Invalid Route", "body id must match path id"));
                }
                config.http[index] = route.clone();
                return Ok(match self.manager.apply(config, expected).await {
                    Ok(config) => json_value(200, &route, Some(config.revision)),
                    Err(error) => apply_problem(error),
                });
            }
            let Some(index) = config.tcp.iter().position(|route| route.id == id) else {
                return Ok(problem(404, "Not Found", "route not found"));
            };
            if req.method() == hyper::Method::DELETE {
                config.tcp.remove(index);
                return Ok(match self.manager.apply(config, expected).await {
                    Ok(config) => empty_response(204, Some(config.revision)),
                    Err(error) => apply_problem(error),
                });
            }
            let route: crate::config::TcpRoute = match read_json(req, 1024 * 1024).await {
                Ok(value) => value,
                Err(response) => return Ok(response),
            };
            if route.id != id {
                return Ok(problem(400, "Invalid Route", "body id must match path id"));
            }
            config.tcp[index] = route.clone();
            return Ok(match self.manager.apply(config, expected).await {
                Ok(config) => json_value(200, &route, Some(config.revision)),
                Err(error) => apply_problem(error),
            });
        }
        if path == "/v1/docker/resolve" {
            if req.method() != hyper::Method::POST {
                return Ok(response(405, "POST required\n"));
            }
            let Some(docker) = &self.docker else {
                return Ok(response(404, "Docker integration is disabled\n"));
            };
            if content_length_exceeds(&req, 8192) {
                return Ok(response(400, "invalid or oversized Docker request\n"));
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Resolve {
                container: String,
                network: String,
                port: u16,
            }
            let bytes = match tokio::time::timeout(
                Duration::from_secs(3),
                Limited::new(req.into_body(), 8192).collect(),
            )
            .await
            {
                Ok(Ok(b)) => b.to_bytes(),
                _ => return Ok(response(400, "invalid or oversized Docker request\n")),
            };
            let query: Resolve = match serde_json::from_slice(&bytes) {
                Ok(q) => q,
                Err(_) => return Ok(response(400, "container, network and port are required\n")),
            };
            let Some(resolver) = docker.resolver() else {
                return Ok(response(404, "Docker integration is disabled\n"));
            };
            return Ok(
                match resolver
                    .resolve(&query.container, &query.network, query.port)
                    .await
                {
                    Ok(value) => {
                        let mut r = response(
                            200,
                            &serde_json::to_string(&value).expect("serializable resolution"),
                        );
                        r.headers_mut()
                            .insert("content-type", "application/json".parse().unwrap());
                        r
                    }
                    Err(error) => {
                        tracing::warn!(%error,"Docker resolution failed");
                        response(422, "Docker container resolution failed\n")
                    }
                },
            );
        }
        if path == "/healthz" && req.method() == hyper::Method::GET {
            if !self.manager.ready.load(Ordering::Acquire) {
                return Ok(response(503, "configuration not ready\n"));
            }
            return Ok(response(200, "ok\n"));
        }
        if path == "/metrics" && req.method() == hyper::Method::GET {
            let mut output = self.manager.metrics.render();
            let snapshot = self.manager.active.load();
            output.push_str("# TYPE hangang_workload_material_ready gauge\n# TYPE hangang_workload_material_unavailable gauge\n");
            for (kind, slots) in [
                ("tcp", &snapshot.tcp_inbound_tls),
                ("http", &snapshot.http_workload_tls),
            ] {
                use std::fmt::Write;
                let ready = slots.values().filter(|slot| slot.load().is_some()).count();
                let _ = writeln!(
                    output,
                    "hangang_workload_material_ready{{kind=\"{kind}\"}} {ready}"
                );
                let _ = writeln!(
                    output,
                    "hangang_workload_material_unavailable{{kind=\"{kind}\"}} {}",
                    slots.len() - ready
                );
            }
            let mut r = response(200, &output);
            r.headers_mut().insert(
                "content-type",
                "text/plain; version=0.0.4; charset=utf-8".parse().unwrap(),
            );
            return Ok(r);
        }
        if path != "/v1/config" {
            return Ok(response(404, "not found\n"));
        }
        if req.method() == hyper::Method::GET {
            let c = self.manager.active.load();
            return Ok(json_config(&c.config));
        }
        if req.method() != hyper::Method::PUT {
            let mut r = response(405, "method not allowed\n");
            r.headers_mut().insert("allow", "GET, PUT".parse().unwrap());
            return Ok(r);
        }
        let Some(expected) = req
            .headers()
            .get("if-match")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_revision)
        else {
            return Ok(response(
                428,
                "If-Match must contain the quoted current revision\n",
            ));
        };
        if self.manager.active.load().config.revision != expected {
            return Ok(response(409, "revision conflict\n"));
        }
        if !req
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .next()
                    .is_some_and(|v| v.trim().eq_ignore_ascii_case("application/json"))
            })
        {
            return Ok(response(415, "application/json required\n"));
        }
        if content_length_exceeds(&req, 1024 * 1024) {
            return Ok(response(413, "invalid or oversized body\n"));
        }
        let bytes = match tokio::time::timeout(
            Duration::from_secs(5),
            Limited::new(req.into_body(), 1024 * 1024).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            Ok(Err(_)) => return Ok(response(413, "invalid or oversized body\n")),
            Err(_) => return Ok(response(408, "body timeout\n")),
        };
        let config: Config = match serde_json::from_slice(&bytes) {
            Ok(c) => c,
            Err(_) => return Ok(response(400, "invalid configuration JSON\n")),
        };
        match self.manager.apply(config, expected).await {
            Ok(c) => Ok(json_config(&c)),
            Err(e) if e.to_string() == "configuration capacity exhausted" => {
                Ok(response(503, "configuration capacity exhausted\n"))
            }
            Err(e) if e.to_string() == "configuration is controller managed" => {
                Ok(response(409, "configuration is controller managed\n"))
            }
            Err(e) if e.to_string() == "revision conflict" => {
                Ok(response(409, "revision conflict\n"))
            }
            Err(e) => {
                tracing::warn!(error=%e,"configuration rejected");
                Ok(response(
                    422,
                    "configuration validation or activation failed; reload the current revision before retrying\n",
                ))
            }
        }
    }
}

struct EventStreamState {
    admin: Admin,
    account_token: Option<String>,
    interval: tokio::time::Interval,
    cursor: u64,
    done: bool,
    _permit: OwnedSemaphorePermit,
}

enum AdminActor {
    System,
    Account {
        user: crate::admin_users::User,
        token: String,
    },
}
impl AdminActor {
    fn role(&self) -> crate::admin_users::Role {
        match self {
            Self::System => crate::admin_users::Role::Admin,
            Self::Account { user, .. } => user.role,
        }
    }
    fn mutation_authority(&self) -> crate::admin_users::MutationAuthority {
        match self {
            Self::System => crate::admin_users::MutationAuthority::System,
            Self::Account { token, .. } => {
                crate::admin_users::MutationAuthority::Session(token.clone())
            }
        }
    }
    fn user(&self) -> crate::admin_users::User {
        match self {
            Self::System => crate::admin_users::User {
                id: 0,
                username: "system".to_owned(),
                role: crate::admin_users::Role::Admin,
                enabled: true,
            },
            Self::Account { user, .. } => user.clone(),
        }
    }
}

fn sole_bearer(headers: &hyper::HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(hyper::header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()?.strip_prefix("Bearer ")
}

fn viewer_allowed(path: &str, method: &hyper::Method) -> bool {
    *method == hyper::Method::GET
        && matches!(
            path,
            "/v1/status" | "/v1/update/status" | "/healthz" | "/metrics"
        )
}

fn traffic_query(query: Option<&str>) -> Option<(Option<u64>, usize)> {
    let mut after = None;
    let mut limit = 128;
    let mut seen_after = false;
    let mut seen_limit = false;
    if let Some(query) = query {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            match name {
                "after" if !seen_after => {
                    after = Some(value.parse::<u64>().ok()?);
                    seen_after = true;
                }
                "limit" if !seen_limit => {
                    limit = value.parse::<usize>().ok()?;
                    if !(1..=128).contains(&limit) {
                        return None;
                    }
                    seen_limit = true;
                }
                _ => return None,
            }
        }
    }
    Some((after, limit))
}

fn certificate_inventory_query(query: Option<&str>) -> Option<(usize, usize)> {
    let mut offset = 0;
    let mut limit = 32;
    let mut seen_offset = false;
    let mut seen_limit = false;
    if let Some(query) = query {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            match name {
                "offset" if !seen_offset => {
                    offset = value.parse().ok()?;
                    seen_offset = true;
                }
                "limit" if !seen_limit => {
                    limit = value.parse().ok()?;
                    if !(1..=crate::certificate_inventory::PAGE_LIMIT).contains(&limit) {
                        return None;
                    }
                    seen_limit = true;
                }
                _ => return None,
            }
        }
    }
    Some((offset, limit))
}

fn operations_query(query: Option<&str>) -> Option<(usize, usize)> {
    let mut offset = 0;
    let mut limit = 100;
    let mut seen_offset = false;
    let mut seen_limit = false;
    if let Some(query) = query {
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=')?;
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            match name {
                "offset" if !seen_offset => {
                    offset = value.parse().ok()?;
                    seen_offset = true;
                }
                "limit" if !seen_limit => {
                    limit = value.parse().ok()?;
                    if !(1..=128).contains(&limit) {
                        return None;
                    }
                    seen_limit = true;
                }
                _ => return None,
            }
        }
    }
    Some((offset, limit))
}

fn user_audit_query(query: Option<&str>) -> Option<(i64, usize)> {
    let mut after = None;
    let mut limit = None;
    let mut parsed = reqwest::Url::parse("http://audit.invalid/").ok()?;
    parsed.set_query(query);
    for (key, value) in parsed.query_pairs() {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        match key.as_ref() {
            "after" if after.is_none() => {
                let value = value.parse::<i64>().ok()?;
                if value > 9_007_199_254_740_991 {
                    return None;
                }
                after = Some(value);
            }
            "limit" if limit.is_none() => {
                let value = value.parse::<usize>().ok()?;
                if !(1..=100).contains(&value) {
                    return None;
                }
                limit = Some(value);
            }
            _ => return None,
        }
    }
    Some((after.unwrap_or(0), limit.unwrap_or(100)))
}

fn account_problem(error: anyhow::Error) -> Response<Body> {
    if error.is::<crate::admin_users::AuditCapacity>() {
        return problem(
            503,
            "Audit Capacity Exhausted",
            "account audit capacity exhausted; export and prune audit records before changing accounts",
        );
    }
    if error.is::<crate::admin_users::AuditConflict>() {
        return problem(
            409,
            "Audit Conflict",
            "audit history changed or prune boundary is invalid; refresh before retrying",
        );
    }
    if error.is::<crate::admin_users::AuthorizationRevoked>() {
        return problem(403, "Forbidden", "administrator role required");
    }
    if error.to_string().contains("password capacity exhausted") {
        return problem(
            503,
            "Authentication Busy",
            "password verification capacity exhausted",
        );
    }
    problem(
        503,
        "Authentication Unavailable",
        "administrator account store unavailable",
    )
}

fn auth_json<T: serde::Serialize>(status: u16, value: &T) -> Response<Body> {
    let mut response = json_value(status, value, None);
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

impl Admin {
    async fn authenticate(
        &self,
        request: &Request<Incoming>,
    ) -> anyhow::Result<Option<AdminActor>> {
        let Some(token) = sole_bearer(request.headers()) else {
            return Ok(None);
        };
        if !self.token.is_empty() && bool::from(token.as_bytes().ct_eq(self.token.as_bytes())) {
            return Ok(Some(AdminActor::System));
        }
        Ok(self
            .users
            .session(token.to_owned())
            .await?
            .map(|user| AdminActor::Account {
                user,
                token: token.to_owned(),
            }))
    }

    async fn handle_public_auth(&self, req: Request<Incoming>) -> Response<Body> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Credentials {
            username: String,
            password: String,
        }
        let path = req.uri().path().to_owned();
        if path == "/v1/auth/setup" {
            if req.method() != hyper::Method::GET {
                return problem(405, "Method Not Allowed", "GET required");
            }
            return match self.users.setup_required().await {
                Ok(required) => auth_json(200, &serde_json::json!({"bootstrap_required":required})),
                Err(error) => account_problem(error),
            };
        }
        if req.method() != hyper::Method::POST {
            return problem(405, "Method Not Allowed", "POST required");
        }
        if path == "/v1/auth/bootstrap" {
            let Some(supplied) = sole_bearer(req.headers()) else {
                return problem(401, "Unauthorized", "setup token required");
            };
            if self.token.is_empty()
                || !bool::from(supplied.as_bytes().ct_eq(self.token.as_bytes()))
            {
                return problem(401, "Unauthorized", "setup token required");
            }
            let payload: Credentials = match read_json(req, 4096).await {
                Ok(body) => body,
                Err(response) => return response,
            };
            if let Err(error) = crate::admin_users::validate_username(&payload.username)
                .and_then(|_| crate::admin_users::validate_password(&payload.password))
            {
                return problem(422, "Invalid User", &error.to_string());
            }
            return match self
                .users
                .bootstrap(payload.username, payload.password)
                .await
            {
                Ok(Some(user)) => auth_json(201, &serde_json::json!({"user":user})),
                Ok(None) => problem(409, "Setup Complete", "administrator already exists"),
                Err(error) => account_problem(error),
            };
        }
        let payload: Credentials = match read_json(req, 4096).await {
            Ok(body) => body,
            Err(response) => return response,
        };
        // Reject oversized/invalid candidate fields before reserving expensive
        // password memory. A valid-looking unknown name still runs Argon2id.
        if crate::admin_users::validate_username(&payload.username).is_err()
            || payload.password.len() > 1024
        {
            return problem(401, "Unauthorized", "invalid credentials");
        }
        match self.users.login(payload.username, payload.password).await {
            Ok(Some(login)) => auth_json(
                200,
                &serde_json::json!({"token":login.token,"expires_in_seconds":login.expires_in_seconds,"user":login.user}),
            ),
            Ok(None) => problem(401, "Unauthorized", "invalid credentials"),
            Err(error) => account_problem(error),
        }
    }

    async fn handle_user_audit(
        &self,
        req: Request<Incoming>,
        path: &str,
        actor: &AdminActor,
    ) -> Response<Body> {
        if path == "/v1/audit/users" {
            if req.method() != hyper::Method::GET {
                return problem(405, "Method Not Allowed", "GET required");
            }
            let Some((after, limit)) = user_audit_query(req.uri().query()) else {
                return problem(
                    400,
                    "Invalid Audit Query",
                    "after must be a nonnegative safe integer and limit must be 1..100; duplicate or unknown parameters are not accepted",
                );
            };
            return match self
                .users
                .audit_page(actor.mutation_authority(), after, limit)
                .await
            {
                Ok(page) => auth_json(200, &page),
                Err(error) => account_problem(error),
            };
        }
        if req.method() != hyper::Method::POST {
            return problem(405, "Method Not Allowed", "POST required");
        }
        if req.uri().query().is_some() {
            return problem(
                400,
                "Invalid Audit Query",
                "prune does not accept query parameters",
            );
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Prune {
            through_id: i64,
            expected_latest_id: i64,
        }
        let body: Prune = match read_json(req, 4096).await {
            Ok(body) => body,
            Err(response) => return response,
        };
        if !(1..=9_007_199_254_740_991).contains(&body.through_id)
            || !(1..=9_007_199_254_740_991).contains(&body.expected_latest_id)
        {
            return problem(
                400,
                "Invalid Audit Boundary",
                "audit boundaries must be positive safe integers",
            );
        }
        match self
            .users
            .prune_audit(
                actor.mutation_authority(),
                body.through_id,
                body.expected_latest_id,
            )
            .await
        {
            Ok(result) => auth_json(200, &result),
            Err(error) => account_problem(error),
        }
    }

    async fn handle_users(
        &self,
        req: Request<Incoming>,
        path: &str,
        actor: &AdminActor,
    ) -> Response<Body> {
        use crate::admin_users::{Change, Role};
        if path == "/v1/users" {
            if req.method() == hyper::Method::GET {
                return match self.users.list(actor.mutation_authority()).await {
                    Ok(users) => auth_json(200, &serde_json::json!({"users":users})),
                    Err(error) => account_problem(error),
                };
            }
            if req.method() != hyper::Method::POST {
                return problem(405, "Method Not Allowed", "GET or POST required");
            }
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Create {
                username: String,
                password: String,
                role: Role,
            }
            let payload: Create = match read_json(req, 4096).await {
                Ok(body) => body,
                Err(response) => return response,
            };
            if let Err(error) = crate::admin_users::validate_username(&payload.username)
                .and_then(|_| crate::admin_users::validate_password(&payload.password))
            {
                return problem(422, "Invalid User", &error.to_string());
            }
            return match self
                .users
                .create(
                    actor.mutation_authority(),
                    payload.username,
                    payload.password,
                    payload.role,
                )
                .await
            {
                Ok(Some(user)) => auth_json(201, &serde_json::json!({"user":user})),
                Ok(None) => problem(
                    409,
                    "User Conflict",
                    "user exists, account capacity exhausted, or setup required",
                ),
                Err(error) => account_problem(error),
            };
        }
        let Some(id) = path
            .strip_prefix("/v1/users/")
            .and_then(|value| value.parse::<i64>().ok())
            .filter(|id| *id > 0)
        else {
            return problem(404, "Not Found", "user not found");
        };
        if req.method() == hyper::Method::DELETE {
            return match self.users.delete(actor.mutation_authority(), id).await {
                Ok(Change::Applied) => empty_response(204, None),
                Ok(Change::Conflict) => problem(
                    409,
                    "Last Administrator",
                    "at least one enabled administrator is required",
                ),
                Ok(Change::NotFound) => problem(404, "Not Found", "user not found"),
                Err(error) => account_problem(error),
            };
        }
        if req.method() != hyper::Method::PUT {
            return problem(405, "Method Not Allowed", "PUT or DELETE required");
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Update {
            role: Option<Role>,
            enabled: Option<bool>,
            password: Option<String>,
        }
        let payload: Update = match read_json(req, 4096).await {
            Ok(body) => body,
            Err(response) => return response,
        };
        if payload.role.is_none() && payload.enabled.is_none() && payload.password.is_none() {
            return problem(400, "Invalid User", "at least one update field is required");
        }
        if let Some(password) = &payload.password
            && let Err(error) = crate::admin_users::validate_password(password)
        {
            return problem(422, "Invalid User", &error.to_string());
        }
        match self
            .users
            .update(
                actor.mutation_authority(),
                id,
                payload.role,
                payload.enabled,
                payload.password,
            )
            .await
        {
            Ok((Change::Applied, Some(user))) => auth_json(200, &serde_json::json!({"user":user})),
            Ok((Change::Conflict, _)) => problem(
                409,
                "Last Administrator",
                "at least one enabled administrator is required",
            ),
            Ok((Change::NotFound, _)) => problem(404, "Not Found", "user not found"),
            Ok((Change::Applied, None)) => problem(
                503,
                "Authentication Unavailable",
                "administrator account store unavailable",
            ),
            Err(error) => account_problem(error),
        }
    }
}

/// Assets served before authentication. Everything else requires the token.
fn public_asset(req: &Request<Incoming>) -> Option<Response<Body>> {
    if let Some(response) = crate::ui::serve(req) {
        return Some(response);
    }
    if req.uri().path() == "/openapi.json" {
        return Some(if req.method() == hyper::Method::GET {
            json_response(200, crate::api_spec::OPENAPI_JSON)
        } else {
            problem(405, "Method Not Allowed", "GET required")
        });
    }
    None
}

/// Wait until the instance has proven readiness against its configuration
/// authority (controller or shared store), or `deadline` elapses.
pub async fn await_readiness(ready: &std::sync::atomic::AtomicBool, deadline: Duration) -> bool {
    tokio::time::timeout(deadline, async {
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

static STARTED: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
pub fn initialize_clock() {
    std::sync::LazyLock::force(&STARTED);
}

fn problem(status: u16, title: &str, detail: &str) -> Response<Body> {
    let value =
        serde_json::json!({"type":"about:blank","title":title,"status":status,"detail":detail});
    let mut response = response(
        status,
        &serde_json::to_string(&value).expect("problem is serializable"),
    );
    response
        .headers_mut()
        .insert("content-type", "application/problem+json".parse().unwrap());
    response
}

fn json_response(status: u16, json: &str) -> Response<Body> {
    let mut response = response(status, json);
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    response
}

fn json_value<T: serde::Serialize>(
    status: u16,
    value: &T,
    revision: Option<u64>,
) -> Response<Body> {
    let mut response = json_response(
        status,
        &serde_json::to_string(value).expect("value is serializable"),
    );
    if let Some(revision) = revision {
        response
            .headers_mut()
            .insert("etag", format!("\"{revision}\"").parse().unwrap());
    }
    response
}

fn empty_response(status: u16, revision: Option<u64>) -> Response<Body> {
    let mut response = response(status, "");
    if let Some(revision) = revision {
        response
            .headers_mut()
            .insert("etag", format!("\"{revision}\"").parse().unwrap());
    }
    response
}

#[allow(clippy::result_large_err)] // Keep the already-built HTTP error response without another allocation.
async fn require_revision(
    request: &Request<Incoming>,
    manager: &Manager,
) -> Result<u64, Response<Body>> {
    let Some(expected) = request
        .headers()
        .get("if-match")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_revision)
    else {
        return Err(problem(
            428,
            "Precondition Required",
            "If-Match must contain the quoted current revision",
        ));
    };
    if expected > manager.active.load().config.revision && manager.config_store.is_some() {
        // Read-your-writes across a load balancer: the client observed a
        // newer revision on another member. Catch up before judging; a
        // failed catch-up is that failure, not a conflict.
        if let Err(error) = manager.reload_file().await
            && manager.active.load().config.revision != expected
        {
            return Err(apply_problem(error));
        }
    }
    if manager.active.load().config.revision != expected {
        return Err(problem(409, "Revision Conflict", "revision conflict"));
    }
    Ok(expected)
}

async fn read_json<T: serde::de::DeserializeOwned>(
    request: Request<Incoming>,
    limit: u64,
) -> Result<T, Response<Body>> {
    if !request
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        })
    {
        return Err(problem(
            415,
            "Unsupported Media Type",
            "application/json required",
        ));
    }
    if content_length_exceeds(&request, limit) {
        return Err(problem(
            413,
            "Content Too Large",
            "invalid or oversized body",
        ));
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        Limited::new(request.into_body(), limit as usize).collect(),
    )
    .await
    {
        Ok(Ok(body)) => body.to_bytes(),
        Ok(Err(_)) => {
            return Err(problem(
                413,
                "Content Too Large",
                "invalid or oversized body",
            ));
        }
        Err(_) => return Err(problem(408, "Request Timeout", "body timeout")),
    };
    serde_json::from_slice(&bytes).map_err(|error| problem(400, "Invalid JSON", &error.to_string()))
}

/// Random per-process identifier (16 hex chars) so that instances answering
/// behind one load-balanced address can be distinguished in status output.
pub fn instance_id() -> &'static str {
    static ID: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        let mut bytes = [0u8; 8];
        let provider = rustls::crypto::ring::default_provider();
        if provider.secure_random.fill(&mut bytes).is_err() {
            // Fall back to process identity + time; uniqueness, not secrecy.
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            bytes = (nanos ^ u64::from(std::process::id()).rotate_left(32)).to_le_bytes();
        }
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    });
    ID.as_str()
}

/// SHA-256 (first 16 hex chars) of the canonical JSON document, independent of
/// its revision, so two instances at one revision can be compared for content.
pub fn config_digest(config: &Config) -> String {
    use sha2::Digest;
    let mut canonical = config.clone();
    canonical.revision = 0;
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let digest = sha2::Sha256::digest(bytes);
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn apply_problem(error: anyhow::Error) -> Response<Body> {
    use crate::config_store::StoreError;
    if let Some(store) = error.downcast_ref::<StoreError>() {
        tracing::warn!(%error, "shared configuration store failed during a write");
        return match store {
            StoreError::Unavailable(_) => problem(
                503,
                "Store Unavailable",
                "the shared configuration store is unavailable; nothing was changed",
            ),
            StoreError::Indeterminate(_) => problem(
                500,
                "Indeterminate Outcome",
                "the shared configuration store did not acknowledge the write; it may have been applied. Reload the current revision before retrying",
            ),
            StoreError::Invalid(_) => problem(
                422,
                "Configuration Rejected",
                "the shared configuration store rejected the document; reload the current revision before retrying",
            ),
        };
    }
    if error.to_string() == "shared configuration authority changed" {
        return problem(
            409,
            "Authority Changed",
            "the shared configuration store was re-seeded under a different epoch; restart this instance to follow it",
        );
    }
    if error.to_string() == "shared configuration is missing" {
        return problem(
            503,
            "Store Empty",
            "the shared configuration store holds no document; nothing was changed",
        );
    }
    if error.to_string().starts_with("shared configuration") {
        return problem(
            409,
            "Authority Disagreement",
            "this instance does not agree with the shared configuration store; reload the current revision from a ready instance",
        );
    }
    if error.to_string() == "configuration capacity exhausted" {
        problem(
            503,
            "Service Unavailable",
            "configuration capacity exhausted",
        )
    } else if error.to_string() == "configuration is controller managed" {
        problem(
            409,
            "Controller Managed",
            "configuration is controller managed",
        )
    } else if error.to_string() == "revision conflict" {
        problem(409, "Revision Conflict", "revision conflict")
    } else {
        tracing::warn!(%error, "configuration rejected");
        problem(
            422,
            "Configuration Rejected",
            "configuration validation or activation failed; reload the current revision before retrying",
        )
    }
}
fn json_config(c: &Config) -> Response<Body> {
    let mut r = response(
        200,
        &serde_json::to_string(c).expect("configuration is serializable"),
    );
    r.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    r.headers_mut()
        .insert("etag", format!("\"{}\"", c.revision).parse().unwrap());
    r
}
fn parse_revision(s: &str) -> Option<u64> {
    s.strip_prefix('"')?.strip_suffix('"')?.parse().ok()
}
fn content_length_exceeds(request: &Request<Incoming>, limit: u64) -> bool {
    request
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > limit)
}
/// Polling handles both in-place writes and atomic file replacement. Failed
/// edits retain the last known-good runtime snapshot and are retried.
pub async fn watch_config(manager: Arc<Manager>, cancel: tokio_util::sync::CancellationToken) {
    // Each instance polls on its own jittered schedule so a fleet does not
    // hit the shared store in lockstep.
    let jitter = u64::from(instance_id().as_bytes()[0]) % 100;
    let mut interval = tokio::time::interval(Duration::from_millis(450 + jitter));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // A poll that cannot complete (store hanging past its own timeouts, or
    // the writer lock held by a stalled transaction) must not preserve
    // readiness forever: bound it and count it as a transport failure.
    let stall = manager
        .store_health
        .report()
        .grace_seconds
        .saturating_add(5);
    let deadline = Duration::from_secs(stall.max(6));
    let mut last_error = String::new();
    loop {
        tokio::select! { biased; _=cancel.cancelled()=>break, _=interval.tick()=>{} }
        let outcome = if manager.config_store.is_some() {
            // The grace deadline runs independently of the poll: a poll that
            // is still pending (lock contention, slow store) when the window
            // since the last confirmation ends withdraws readiness right
            // then, and a poll that never completes is abandoned.
            let reload = tokio::time::timeout(deadline, manager.reload_file());
            tokio::pin!(reload);
            // The deadline that already fired; a later confirmation moves the
            // live deadline past it and re-arms the timer.
            let mut expired: Option<tokio::time::Instant> = None;
            loop {
                let grace_end = manager.store_health.deadline();
                let armed = grace_end.filter(|at| expired.is_none_or(|fired| *at > fired));
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break Err(anyhow::anyhow!("shutting down")),
                    // A confirmation (by a writer's reconciliation) moves the
                    // deadline: recompute `armed` on the next iteration.
                    _ = manager.store_health.confirmations.notified() => {}
                    result = &mut reload => {
                        break match result {
                            Ok(outcome) => outcome,
                            Err(_) => {
                                manager.store_failure(
                                    "stalled",
                                    format!("reconciliation did not complete within {}s", deadline.as_secs()),
                                    true,
                                );
                                Err(anyhow::anyhow!("shared configuration reconciliation stalled"))
                            }
                        };
                    }
                    _ = async {
                        match armed {
                            Some(at) => tokio::time::sleep_until(at).await,
                            None => std::future::pending::<()>().await,
                        }
                    }, if armed.is_some() => {
                        // A confirmation may have moved the deadline while
                        // this timer was armed: re-arm from the current one
                        // and withdraw only once the live window has ended.
                        let live = manager.store_health.deadline();
                        if live.is_none_or(|at| at <= tokio::time::Instant::now()) {
                            expired = live.or(armed);
                            manager.store_failure(
                                "stalled",
                                "the grace window ended while a reconciliation was still pending".into(),
                                true,
                            );
                        }
                    }
                }
            }
        } else {
            manager.reload_file().await
        };
        match outcome {
            Ok(changed) => {
                if !last_error.is_empty() {
                    tracing::info!("configuration reconciliation recovered");
                }
                last_error.clear();
                if changed {
                    tracing::info!(
                        revision = manager.active.load().config.revision,
                        "configuration reloaded"
                    );
                }
            }
            Err(error) => {
                let message = error.to_string();
                if message != last_error {
                    let ready = manager.ready.load(Ordering::Acquire);
                    tracing::warn!(error=%error, ready, "configuration reload rejected; retaining active configuration");
                    last_error = message;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_revision() {
        assert_eq!(parse_revision("\"12\""), Some(12));
        for s in ["12", "*", "W/\"12\"", "\"12\",\"13\""] {
            assert_eq!(parse_revision(s), None);
        }
    }

    #[tokio::test]
    async fn stopping_rejects_a_reload_already_queued_for_the_writer() {
        let directory = tempfile::tempdir().unwrap();
        let state_path = directory.path().join("state.json");
        let edited = Config {
            tcp: vec![crate::config::TcpRoute {
                enabled: true,
                upstream: Default::default(),
                health: None,
                inbound_tls: None,
                priority: 0,
                sni: None,
                max_connections: None,
                id: "late".into(),
                listen: "127.0.0.1:39001".parse().unwrap(),
                backends: vec!["127.0.0.1:9".into()],
                deny_cidrs: Vec::new(),
            }],
            ..Config::default()
        };
        store::save(state_path.clone(), edited).await.unwrap();
        let active = Arc::new(ArcSwap::from_pointee(
            Snapshot::new(Config::default()).unwrap(),
        ));
        let metrics = Arc::new(Metrics::default());
        let manager = Arc::new(Manager {
            active: active.clone(),
            tcp: Arc::new(TcpManager::new(active, metrics.clone(), 1)),
            policy: Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1)),
            metrics,
            state_path,
            config_store: None,
            writes: Mutex::new(()),
            transactions: Arc::new(tokio::sync::Semaphore::new(32)),
            externally_managed: false,
            ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            stopping: std::sync::atomic::AtomicBool::new(false),
            withdrawing: std::sync::atomic::AtomicBool::new(false),
            authority_epoch: std::sync::Mutex::new(None),
            store_health: Default::default(),
        });

        let writer = manager.writes.lock().await;
        let reload = tokio::spawn({
            let manager = manager.clone();
            async move { manager.reload_file().await }
        });
        tokio::task::yield_now().await;
        let stopping = tokio::spawn({
            let manager = manager.clone();
            async move { manager.stop_updates().await }
        });
        tokio::task::yield_now().await;
        assert!(manager.stopping.load(Ordering::Acquire));
        assert!(!manager.ready.load(Ordering::Acquire));
        drop(writer);

        assert!(
            reload
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("draining")
        );
        stopping.await.unwrap();
        assert!(!manager.ready.load(Ordering::Acquire));
        assert_eq!(manager.active.load().config, Config::default());
        manager.resume_updates();
        assert!(!manager.stopping.load(Ordering::Acquire));
        assert!(manager.ready.load(Ordering::Acquire));
    }
}
