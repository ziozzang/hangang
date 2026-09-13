//! Bounded Kubernetes list/watch controller for `networking.k8s.io/v1` Ingress.
//!
//! Every publication is built from complete Service, Ingress, and (when
//! enabled) Secret caches. API and validation failures retain the last
//! successfully published snapshot.
//!
//! Hostnames are owned by namespaces. A host pattern claimed by several
//! namespaces belongs to the namespace of the oldest claiming Ingress
//! (`metadata.creationTimestamp`, then `metadata.uid`), so every replica of
//! the controller reaches the same decision from the same set of objects
//! regardless of the order in which it observed them.
//!
//! Freshness is tracked per watched kind. When a kind has not been confirmed
//! by a list (dated at the moment its snapshot was taken), watch event,
//! bookmark, or normal watch closure for longer than
//! `ControllerOptions::stale_after`, or a kind's cache is incomplete, the sink
//! is told that the controller is no longer authoritative so a load balancer
//! can stop routing to this replica while it keeps serving its last snapshot.
//! The deadline is checked while lists and snapshot preparation are in
//! progress too, so a stalled relist cannot hold readiness past it.
use crate::{config::Config, ingress, tls};
use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use reqwest::{Client, RequestBuilder, StatusCode, Url};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinSet, time::Instant};
use tokio_util::sync::CancellationToken;

const DEFAULT_CA: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
const DEFAULT_TOKEN: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const MAX_CA_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_WATCH_EVENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TLS_BYTES: usize = 1024 * 1024;
/// Secrets are listed in small pages because unrelated Secrets in the same
/// namespace can be large; an oversized page is retried with a smaller one.
const SECRET_LIST_PAGE_SIZE: usize = 50;
/// Retained bytes per resource kind after stripping unneeded fields.
const MAX_CACHE_BYTES_PER_KIND: usize = 64 * 1024 * 1024;
/// Minimum spacing between the starts of two full relists, whatever the
/// outcome of the previous one. Jittered per replica so a fleet that observes
/// the same expiry or outage does not relist in lockstep.
const MIN_RELIST_INTERVAL: Duration = Duration::from_secs(5);
/// Bounded timer that re-checks an incomplete cache when no deletion arrives.
const CAPACITY_RELIST_TIMER: Duration = Duration::from_secs(60);
/// A watch that closes sooner than this is treated as an empty closure and
/// reconnects with backoff instead of immediately.
const EMPTY_WATCH_THRESHOLD: Duration = Duration::from_secs(1);
const MAX_EMPTY_WATCH_BACKOFF: Duration = Duration::from_secs(5);
const STATUS_PATCH_ATTEMPTS: usize = 3;
/// Ingress status patches in flight at once.
const STATUS_PATCH_CONCURRENCY: usize = 4;
/// Ownership pattern for hostless rules and class default backends.
const CATCH_ALL_HOST: &str = "*";
const TLS_SECRET_SELECTOR: &str = "type=kubernetes.io/tls";

#[derive(Clone, Debug)]
pub struct ControllerOptions {
    pub api_server: Url,
    pub ca_path: PathBuf,
    pub token_path: PathBuf,
    /// `None` watches all namespaces. Secret watching must be explicitly enabled.
    pub namespace: Option<String>,
    pub ingress_class: String,
    pub watch_secrets: bool,
    /// An IP address or or DNS name written to selected Ingress status.
    pub publish_address: Option<String>,
    pub list_page_size: usize,
    pub max_objects: usize,
    pub watch_timeout: Duration,
    pub request_timeout: Duration,
    /// How long a watched kind may go without a list, event, bookmark, or
    /// watch closure before the controller stops reporting itself
    /// authoritative. Must exceed `watch_timeout`, since an idle watch only
    /// proves liveness when the server closes it.
    pub stale_after: Duration,
}

impl ControllerOptions {
    pub fn in_cluster(ingress_class: impl Into<String>) -> Result<Self> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST")
            .context("KUBERNETES_SERVICE_HOST is missing")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT_HTTPS")
            .or_else(|_| std::env::var("KUBERNETES_SERVICE_PORT"))
            .unwrap_or_else(|_| "443".into());
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host
        };
        let api_server = Url::parse(&format!("https://{host}:{port}/"))?;
        Ok(Self {
            api_server,
            ca_path: DEFAULT_CA.into(),
            token_path: DEFAULT_TOKEN.into(),
            namespace: None,
            ingress_class: ingress_class.into(),
            watch_secrets: false,
            publish_address: None,
            list_page_size: 500,
            max_objects: 10_000,
            watch_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(40),
            stale_after: Duration::from_secs(60),
        })
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.api_server.scheme() == "https",
            "Kubernetes API URL must use HTTPS"
        );
        ensure!(
            self.api_server.username().is_empty() && self.api_server.password().is_none(),
            "Kubernetes API URL must not contain credentials"
        );
        ensure!(
            self.api_server.query().is_none() && self.api_server.fragment().is_none(),
            "Kubernetes API URL must not contain a query or fragment"
        );
        ensure!(
            !self.ingress_class.is_empty() && self.ingress_class.len() <= 253,
            "invalid ingress class"
        );
        if let Some(namespace) = &self.namespace {
            ensure!(dns_subdomain(namespace), "invalid Kubernetes namespace");
        }
        ensure!(
            (1..=5_000).contains(&self.list_page_size),
            "list page size must be 1..5000"
        );
        ensure!(
            (1..=100_000).contains(&self.max_objects),
            "max objects must be 1..100000"
        );
        ensure!(
            self.watch_timeout >= Duration::from_secs(1)
                && self.watch_timeout <= Duration::from_secs(300),
            "watch timeout must be 1..300 seconds"
        );
        ensure!(
            self.request_timeout > self.watch_timeout
                && self.request_timeout <= Duration::from_secs(360),
            "request timeout must exceed watch timeout and be at most 360 seconds"
        );
        ensure!(
            self.stale_after > self.watch_timeout && self.stale_after <= Duration::from_secs(3600),
            "stale threshold must exceed the watch timeout and be at most 3600 seconds"
        );
        if let Some(address) = &self.publish_address {
            ensure!(valid_publish_address(address), "invalid publish address");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct TlsCertificate {
    pub hosts: Vec<String>,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ControllerSnapshot {
    pub config: Config,
    pub certificates: Vec<TlsCertificate>,
}

#[async_trait]
pub trait ConfigSink: Send + Sync {
    async fn apply(&self, snapshot: ControllerSnapshot) -> Result<()>;

    /// Whether the controller's view of the API is currently authoritative.
    /// `false` is reported when any watched kind has been silent for longer
    /// than `ControllerOptions::stale_after`, when a kind's cache is
    /// incomplete, or before the first publication; `true` once every kind is
    /// fresh and complete again. The last accepted snapshot keeps being
    /// served either way: this is the readiness signal for a load balancer.
    async fn report_authority(&self, healthy: bool, reason: &str) {
        let _ = (healthy, reason);
    }
}

/// Host pattern (exact name, `*.suffix`, or the catch-all `*`) to the namespace
/// that owns it.
type HostOwners = BTreeMap<String, String>;
type ObjectKey = (String, String);

/// The last successfully published snapshot, the Ingresses it admitted, and
/// the hostname ownership it established (kept for change logging only;
/// ownership is decided from the current objects alone).
struct Published {
    snapshot: ControllerSnapshot,
    admitted: ingress::IngressIdentities,
    owners: HostOwners,
}

/// Result of building and validating one publication.
struct Admission {
    admitted: ingress::IngressIdentities,
    owners: HostOwners,
}

enum Outcome {
    /// The candidate was invalid or the sink rejected it.
    Rejected,
    /// The candidate equals the published snapshot.
    Unchanged,
    /// The sink accepted a new snapshot.
    Applied,
}

/// Per-kind evidence that the cache still mirrors the API server, and the
/// authority state last reported to the sink.
struct Health {
    stale_after: Duration,
    kinds: Vec<ResourceKind>,
    fresh_at: BTreeMap<ResourceKind, Instant>,
    activation_failed: bool,
    reported: bool,
}
impl Health {
    fn new(options: &ControllerOptions) -> Self {
        Self {
            stale_after: options.stale_after,
            kinds: ResourceKind::enabled(options.watch_secrets),
            fresh_at: BTreeMap::new(),
            activation_failed: false,
            reported: false,
        }
    }
    fn touch(&mut self, kind: ResourceKind) {
        self.touch_at(kind, Instant::now());
    }
    /// Record the moment the API server confirmed `kind`: for a list, the
    /// moment its snapshot `resourceVersion` was taken, not the moment the
    /// whole relist finished.
    fn touch_at(&mut self, kind: ResourceKind, at: Instant) {
        self.fresh_at.insert(kind, at);
    }
    /// Why the cache is not authoritative, or `None` when every kind is fresh
    /// and complete and a snapshot has been published.
    fn defect(&self, incomplete: &BTreeSet<ResourceKind>, published: bool) -> Option<String> {
        if self.activation_failed {
            return Some("the desired configuration could not be activated".into());
        }
        let now = Instant::now();
        for kind in &self.kinds {
            match self.fresh_at.get(kind) {
                None => return Some(format!("{kind:?} objects have not been listed yet")),
                Some(at) if now.duration_since(*at) > self.stale_after => {
                    return Some(format!(
                        "{kind:?} watch has been silent for {}s",
                        now.duration_since(*at).as_secs()
                    ));
                }
                Some(_) => {}
            }
            if incomplete.contains(kind) {
                return Some(format!(
                    "{kind:?} cache is incomplete until a relist succeeds"
                ));
            }
        }
        if !published {
            return Some("no configuration has been published yet".into());
        }
        None
    }
    /// The earliest moment at which a currently fresh kind becomes stale.
    fn deadline(&self) -> Option<Instant> {
        let now = Instant::now();
        self.kinds
            .iter()
            .filter_map(|kind| self.fresh_at.get(kind))
            .map(|at| *at + self.stale_after)
            .filter(|at| *at > now)
            .min()
    }
}

pub struct Controller {
    options: ControllerOptions,
    client: Arc<arc_swap::ArcSwap<Client>>,
    client_ca: Arc<std::sync::Mutex<Vec<u8>>>,
    sink: Arc<dyn ConfigSink>,
}

impl Controller {
    pub fn new(options: ControllerOptions, sink: Arc<dyn ConfigSink>) -> Result<Self> {
        options.validate()?;
        let ca = read_bounded(&options.ca_path, MAX_CA_BYTES).context("read Kubernetes API CA")?;
        let client = build_client(&ca)?;
        Ok(Self {
            options,
            client: Arc::new(arc_swap::ArcSwap::from_pointee(client)),
            client_ca: Arc::new(std::sync::Mutex::new(ca)),
            sink,
        })
    }

    pub async fn run(&self, cancel: CancellationToken) {
        let mut delay = Duration::from_millis(200);
        let mut last_good: Option<Published> = None;
        let mut last_list: Option<Instant> = None;
        let mut health = Health::new(&self.options);
        // The current cache and the latest watch version per kind. They are
        // kept across a failed capacity-recovery relist so watching resumes
        // from where it stopped instead of stalling behind list retries.
        let mut current: Option<(ResourceCache, BTreeMap<ResourceKind, String>)> = None;
        // Status patches run in one background task so publication never
        // waits for the API server's status endpoint.
        let statuses = Arc::new(StatusQueue::new(self.options.max_objects));
        let status_worker = tokio::spawn({
            let controller = self.clone_for_task();
            let queue = statuses.clone();
            let cancel = cancel.clone();
            async move { controller.status_worker(queue, cancel).await }
        });
        let none = BTreeSet::new();
        while !cancel.is_cancelled() {
            if let Some(started) = last_list {
                let incomplete = current.as_ref().map(|(cache, _)| &cache.incomplete);
                let until = started + jitter(MIN_RELIST_INTERVAL);
                if !self
                    .pause_until(until, &mut health, incomplete, last_good.is_some(), &cancel)
                    .await
                {
                    break;
                }
            }
            last_list = Some(Instant::now());
            // A stalled or long paginated list must not hold readiness past
            // the stale threshold: the freshness timer stays armed meanwhile.
            let listed = {
                let incomplete = current
                    .as_ref()
                    .map_or(&none, |(cache, _)| &cache.incomplete);
                let published = last_good.is_some();
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    result = self.drive(self.list_all(), &mut health, incomplete, published) => result,
                }
            };
            match listed {
                Ok(fresh) => {
                    delay = Duration::from_millis(200);
                    for (kind, at) in fresh.confirmed {
                        health.touch_at(kind, at);
                    }
                    current = Some((fresh.cache, fresh.versions));
                }
                Err(error) if current.is_some() => {
                    tracing::warn!(%error, "Kubernetes recovery list failed; continuing with the incomplete cache");
                }
                Err(error) => {
                    tracing::warn!(%error, "Kubernetes list failed; keeping last good configuration");
                    let until = Instant::now() + jitter(delay);
                    if !self
                        .pause_until(until, &mut health, None, last_good.is_some(), &cancel)
                        .await
                    {
                        break;
                    }
                    delay = (delay * 2).min(Duration::from_secs(10));
                    continue;
                }
            }
            let Some((cache, versions)) = current.as_mut() else {
                continue;
            };
            self.publish(cache, &mut last_good, &mut health, &statuses)
                .await;

            let watch_cancel = cancel.child_token();
            let (tx, mut rx) = mpsc::channel(256);
            let mut tasks = JoinSet::new();
            for kind in ResourceKind::enabled(self.options.watch_secrets) {
                let tx = tx.clone();
                let child = watch_cancel.clone();
                let version = versions.get(&kind).cloned().unwrap_or_default();
                let watcher = self.clone_for_task();
                tasks.spawn(async move { watcher.watch_loop(kind, version, tx, child).await });
            }
            drop(tx);

            // A capacity-incomplete cache schedules a rate-limited relist; the
            // timer only fires once the cache can actually admit more objects.
            let mut relist_at: Option<Instant> = (!cache.incomplete.is_empty())
                .then(|| Instant::now() + jitter(CAPACITY_RELIST_TIMER));
            let mut discard = false;
            loop {
                let stale_at = health.deadline();
                // Cancellation is checked first so shutdown does not keep
                // draining a full channel.
                let message = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep_until(relist_at.unwrap_or_else(Instant::now)), if relist_at.is_some() => {
                        if cache.recoverable(self.options.max_objects) {
                            tracing::info!("relisting Kubernetes resources to recover objects rejected at capacity");
                            break;
                        }
                        relist_at = Some(Instant::now() + jitter(CAPACITY_RELIST_TIMER));
                        continue;
                    }
                    _ = tokio::time::sleep_until(stale_at.unwrap_or_else(Instant::now)), if stale_at.is_some() => {
                        self.assess(&mut health, &cache.incomplete, last_good.is_some(), false).await;
                        continue;
                    }
                    message = rx.recv() => match message {
                        Some(message) => message,
                        None => break,
                    },
                };
                match message {
                    WatchMessage::Event(kind, action, object) => {
                        health.touch(kind);
                        match cache.apply_bounded(kind, action, object, self.options.max_objects) {
                            Ok(()) => {
                                if matches!(action, WatchAction::Delete)
                                    && cache.recoverable(self.options.max_objects)
                                {
                                    // The relist itself is spaced by the outer loop.
                                    schedule(&mut relist_at, Instant::now());
                                }
                                self.publish(cache, &mut last_good, &mut health, &statuses)
                                    .await;
                            }
                            Err(error) if error.is::<CapacityExceeded>() => {
                                cache.mark_incomplete(kind);
                                tracing::warn!(resource=?kind, %error, "Kubernetes watch object rejected at capacity; the cache is incomplete and a relist is scheduled");
                                schedule(
                                    &mut relist_at,
                                    Instant::now() + jitter(CAPACITY_RELIST_TIMER),
                                );
                                self.assess(
                                    &mut health,
                                    &cache.incomplete,
                                    last_good.is_some(),
                                    false,
                                )
                                .await;
                            }
                            Err(error) => {
                                tracing::warn!(%error, "invalid Kubernetes watch event ignored")
                            }
                        }
                    }
                    WatchMessage::Alive(kind) => {
                        health.touch(kind);
                        self.assess(&mut health, &cache.incomplete, last_good.is_some(), false)
                            .await;
                    }
                    WatchMessage::Tick(kind) => {
                        health.touch(kind);
                        self.publish(cache, &mut last_good, &mut health, &statuses)
                            .await;
                    }
                    WatchMessage::Expired => {
                        discard = true;
                        break;
                    }
                }
            }
            // Watchers may be blocked on a full channel: cancel them, close the
            // receiver so any send fails immediately, and only then join.
            watch_cancel.cancel();
            drop(rx);
            while let Some(finished) = tasks.join_next().await {
                if let Ok((kind, version)) = finished
                    && !version.is_empty()
                {
                    versions.insert(kind, version);
                }
            }
            if discard {
                current = None;
            }
        }
        // The loop only exits on cancellation, which the worker observes too.
        let _ = status_worker.await;
    }

    fn clone_for_task(&self) -> Self {
        Self {
            options: self.options.clone(),
            client: self.client.clone(),
            client_ca: self.client_ca.clone(),
            sink: self.sink.clone(),
        }
    }

    /// Sleep until `until`, re-evaluating freshness whenever a kind's staleness
    /// deadline passes meanwhile. Returns `false` when cancelled.
    async fn pause_until(
        &self,
        until: Instant,
        health: &mut Health,
        incomplete: Option<&BTreeSet<ResourceKind>>,
        published: bool,
        cancel: &CancellationToken,
    ) -> bool {
        let none = BTreeSet::new();
        loop {
            let wake = health.deadline().map_or(until, |at| at.min(until));
            tokio::select! {
                _ = cancel.cancelled() => return false,
                _ = tokio::time::sleep_until(wake) => {}
            }
            self.assess(health, incomplete.unwrap_or(&none), published, false)
                .await;
            if Instant::now() >= until {
                return true;
            }
        }
    }

    /// Await `future` while keeping the freshness deadlines armed: whenever a
    /// kind's staleness deadline passes before the future completes, the
    /// authority state is re-assessed and reported. Lists and snapshot
    /// preparation can take longer than `stale_after`, and a replica must not
    /// keep claiming authority for the duration.
    async fn drive<T>(
        &self,
        future: impl std::future::Future<Output = T>,
        health: &mut Health,
        incomplete: &BTreeSet<ResourceKind>,
        published: bool,
    ) -> T {
        let mut future = std::pin::pin!(future);
        loop {
            let stale_at = health.deadline();
            tokio::select! {
                biased;
                output = &mut future => return output,
                _ = tokio::time::sleep_until(stale_at.unwrap_or_else(Instant::now)), if stale_at.is_some() => {
                    self.assess(health, incomplete, published, false).await;
                }
            }
        }
    }

    /// Report the authority state to the sink when it changes. A sink that
    /// marks itself ready on every accepted snapshot (the runtime does) must
    /// hear `false` again after an apply that happened while unhealthy.
    async fn assess(
        &self,
        health: &mut Health,
        incomplete: &BTreeSet<ResourceKind>,
        published: bool,
        applied: bool,
    ) {
        let defect = health.defect(incomplete, published);
        let healthy = defect.is_none();
        let changed = healthy != health.reported;
        // An apply while unhealthy flipped the sink to ready: say it again.
        let reassert = applied && !healthy;
        if !changed && !reassert {
            return;
        }
        health.reported = healthy;
        let reason = defect.unwrap_or_else(|| "every watched kind is fresh and complete".into());
        match (healthy, changed) {
            (true, _) => tracing::info!(%reason, "Kubernetes cache is authoritative"),
            (false, true) => {
                tracing::warn!(%reason, "Kubernetes cache is not authoritative; reporting not ready")
            }
            (false, false) => {
                tracing::debug!(%reason, "Kubernetes cache is still not authoritative")
            }
        }
        self.sink.report_authority(healthy, &reason).await;
    }

    /// Reconcile the cache into the sink and, when it was accepted, queue
    /// Ingress status updates for the admitted objects. Status work never
    /// blocks publication; results are folded back into the cache here, and
    /// queued work for objects the cache no longer holds is dropped.
    async fn publish(
        &self,
        cache: &mut ResourceCache,
        last_good: &mut Option<Published>,
        health: &mut Health,
        statuses: &StatusQueue,
    ) {
        for ((namespace, name), current) in statuses.take_results() {
            cache.update_status(&namespace, &name, &current);
        }
        let published = last_good.is_some();
        let outcome = self
            .drive(
                self.reconcile(cache, last_good),
                health,
                &cache.incomplete,
                published,
            )
            .await;
        // Fresh API watches alone cannot establish agreement if the latest
        // desired snapshot failed to activate (including a handoff freeze).
        // Clear this only when reconciliation applies or confirms the desired
        // snapshot, not on a subsequent bookmark or freshness check.
        health.activation_failed = matches!(outcome, Outcome::Rejected);
        if let Some(address) = &self.options.publish_address {
            let admitted = match outcome {
                Outcome::Rejected => None,
                _ => last_good.as_ref().map(|published| &published.admitted),
            };
            sync_statuses(
                statuses,
                cache,
                admitted,
                &self.options.ingress_class,
                address,
            );
        }
        self.assess(
            health,
            &cache.incomplete,
            last_good.is_some(),
            matches!(outcome, Outcome::Applied),
        )
        .await;
    }

    async fn reconcile(&self, cache: &ResourceCache, last_good: &mut Option<Published>) -> Outcome {
        let resources = cache.clone();
        let options = self.options.clone();
        let prepared = tokio::task::spawn_blocking(move || resources.snapshot(&options))
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("Kubernetes snapshot worker failed")));
        match prepared {
            Ok((snapshot, admission)) => {
                if let Some(published) = last_good.as_ref() {
                    log_ownership_changes(&published.owners, &admission.owners);
                }
                if let Some(published) = last_good.as_mut()
                    && published.snapshot == snapshot
                {
                    published.admitted = admission.admitted;
                    published.owners = admission.owners;
                    return Outcome::Unchanged;
                }
                match self.sink.apply(snapshot.clone()).await {
                    Ok(()) => {
                        *last_good = Some(Published {
                            snapshot,
                            admitted: admission.admitted,
                            owners: admission.owners,
                        });
                        Outcome::Applied
                    }
                    Err(error) => {
                        tracing::warn!(%error, "Kubernetes snapshot rejected; keeping last good configuration");
                        Outcome::Rejected
                    }
                }
            }
            Err(error) => {
                tracing::warn!(%error, "Kubernetes resources are invalid; keeping last good configuration");
                Outcome::Rejected
            }
        }
    }

    async fn list_all(&self) -> Result<Listing> {
        let mut listing = Listing::default();
        for kind in ResourceKind::enabled(self.options.watch_secrets) {
            let (objects, version, confirmed) = self.list_kind(kind).await?;
            listing
                .cache
                .replace(kind, objects, self.options.max_objects)?;
            listing.versions.insert(kind, version);
            listing.confirmed.insert(kind, confirmed);
        }
        Ok(listing)
    }

    /// Returns the objects, the collection `resourceVersion`, and the moment
    /// that version was taken (the first page's response): later pages are
    /// served from the same snapshot, so they do not make it any fresher.
    async fn list_kind(&self, kind: ResourceKind) -> Result<(Vec<Value>, String, Instant)> {
        let mut objects = Vec::new();
        let mut continuation = None::<String>;
        let mut version = None::<(String, Instant)>;
        let mut seen_tokens = BTreeSet::new();
        let mut page_size = match kind {
            ResourceKind::Secret => self.options.list_page_size.min(SECRET_LIST_PAGE_SIZE),
            _ => self.options.list_page_size,
        };
        loop {
            let mut url = self.resource_url(kind)?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("limit", &page_size.to_string());
                // A `resourceVersion=0` list is served from the API server's
                // watch cache, which ignores `limit`. Secrets are read from
                // storage instead so their pages are really bounded.
                if kind != ResourceKind::Secret {
                    query.append_pair("resourceVersion", "0");
                }
                if let Some(token) = &continuation {
                    query.append_pair("continue", token);
                }
                if kind == ResourceKind::Secret {
                    query.append_pair("fieldSelector", TLS_SECRET_SELECTOR);
                }
            }
            let response = self
                .authorize(self.api_client().await?.get(url))
                .await?
                .timeout(self.options.request_timeout)
                .send()
                .await?;
            if response.status() == StatusCode::GONE {
                bail!("Kubernetes list resource version expired")
            }
            let status = response.status();
            let bytes = match bounded_body(response, MAX_RESPONSE_BYTES).await {
                Ok(bytes) => bytes,
                Err(error) if error.is::<ResponseTooLarge>() && page_size > 1 => {
                    // The same page (same continue token) is requested again
                    // with fewer objects; `limit` may change between pages.
                    page_size = (page_size / 2).max(1);
                    tracing::warn!(resource=?kind, page_size, "Kubernetes list page exceeded the response limit; retrying with a smaller page");
                    continue;
                }
                Err(error) => return Err(error),
            };
            ensure!(
                status.is_success(),
                "Kubernetes list returned {status}: {}",
                bounded_text(&bytes)
            );
            let page: Value = serde_json::from_slice(&bytes).context("decode Kubernetes list")?;
            let page_version = page
                .pointer("/metadata/resourceVersion")
                .and_then(Value::as_str)
                .context("Kubernetes list resourceVersion missing")?;
            if let Some((expected, _)) = &version {
                ensure!(
                    expected == page_version,
                    "Kubernetes paginated list changed resourceVersion"
                );
            } else {
                version = Some((page_version.to_owned(), Instant::now()));
            }
            let items = page
                .get("items")
                .and_then(Value::as_array)
                .context("Kubernetes list items missing")?;
            ensure!(
                objects.len() + items.len() <= self.options.max_objects,
                "Kubernetes object limit exceeded"
            );
            objects.extend(items.iter().cloned());
            continuation = page
                .pointer("/metadata/continue")
                .and_then(Value::as_str)
                .filter(|v| !v.is_empty())
                .map(str::to_owned);
            let Some(token) = &continuation else { break };
            ensure!(
                seen_tokens.insert(token.clone()),
                "Kubernetes list repeated a continue token"
            );
        }
        let (version, confirmed) = version.context("Kubernetes list returned no page")?;
        Ok((objects, version, confirmed))
    }

    /// Returns the kind and the last observed `resourceVersion` so a restart
    /// can resume from it.
    async fn watch_loop(
        &self,
        kind: ResourceKind,
        mut version: String,
        tx: mpsc::Sender<WatchMessage>,
        cancel: CancellationToken,
    ) -> (ResourceKind, String) {
        let mut delay = Duration::from_millis(200);
        let mut empty_backoff = Duration::from_millis(200);
        loop {
            let started = Instant::now();
            let result = tokio::select! {
                _ = cancel.cancelled() => break,
                value = self.watch_once(kind, &mut version, &tx, &cancel) => value,
            };
            match result {
                Ok(WatchEnd::Expired) => {
                    send_or_cancel(&tx, WatchMessage::Expired, &cancel).await;
                    break;
                }
                Ok(WatchEnd::Closed) => {
                    delay = Duration::from_millis(200);
                    if !send_or_cancel(&tx, WatchMessage::Tick(kind), &cancel).await {
                        break;
                    }
                    // A server that closes the watch immediately would otherwise
                    // drive a reconnect and tick storm.
                    if started.elapsed() < EMPTY_WATCH_THRESHOLD {
                        tokio::select! { _ = cancel.cancelled() => break, _ = tokio::time::sleep(jitter(empty_backoff)) => {} }
                        empty_backoff = (empty_backoff * 2).min(MAX_EMPTY_WATCH_BACKOFF);
                    } else {
                        empty_backoff = Duration::from_millis(200);
                    }
                }
                Err(error) => {
                    tracing::warn!(resource=?kind, %error, "Kubernetes watch disconnected");
                    tokio::select! { _ = cancel.cancelled() => break, _ = tokio::time::sleep(jitter(delay)) => {} }
                    delay = (delay * 2).min(Duration::from_secs(10));
                }
            }
        }
        (kind, version)
    }

    async fn watch_once(
        &self,
        kind: ResourceKind,
        version: &mut String,
        tx: &mpsc::Sender<WatchMessage>,
        cancel: &CancellationToken,
    ) -> Result<WatchEnd> {
        let mut url = self.resource_url(kind)?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("watch", "true");
            query.append_pair("allowWatchBookmarks", "true");
            query.append_pair("resourceVersion", version);
            query.append_pair(
                "timeoutSeconds",
                &self.options.watch_timeout.as_secs().to_string(),
            );
            if kind == ResourceKind::Secret {
                query.append_pair("fieldSelector", TLS_SECRET_SELECTOR);
            }
        }
        let response = self
            .authorize(self.api_client().await?.get(url))
            .await?
            .timeout(self.options.request_timeout)
            .send()
            .await?;
        if response.status() == StatusCode::GONE {
            return Ok(WatchEnd::Expired);
        }
        ensure!(
            response.status().is_success(),
            "Kubernetes watch returned {}",
            response.status()
        );
        // An accepted watch only proves that `version` is still within the
        // server's history. It says nothing about whether events after it
        // have been delivered yet, so freshness is confirmed by the events,
        // bookmarks, and normal closure that follow, never by the response
        // headers alone.
        let mut stream = response.bytes_stream();
        let mut buffer = Vec::new();
        loop {
            let chunk = tokio::select! { _ = cancel.cancelled() => return Ok(WatchEnd::Closed), chunk = stream.next() => chunk };
            let Some(chunk) = chunk else { break };
            buffer.extend_from_slice(&chunk?);
            ensure!(
                buffer.len() <= MAX_WATCH_EVENT_BYTES,
                "Kubernetes watch event exceeds limit"
            );
            while let Some(event) = take_json(&mut buffer)? {
                let action = event
                    .get("type")
                    .and_then(Value::as_str)
                    .context("watch event type missing")?;
                let object = event
                    .get("object")
                    .cloned()
                    .context("watch event object missing")?;
                if action == "ERROR" {
                    if object.get("code").and_then(Value::as_u64) == Some(410) {
                        return Ok(WatchEnd::Expired);
                    }
                    bail!(
                        "Kubernetes watch error: {}",
                        bounded_text(&serde_json::to_vec(&object)?)
                    );
                }
                if let Some(rv) = object
                    .pointer("/metadata/resourceVersion")
                    .and_then(Value::as_str)
                {
                    *version = rv.to_owned();
                }
                let message = match action {
                    "ADDED" | "MODIFIED" => WatchMessage::Event(kind, WatchAction::Upsert, object),
                    "DELETED" => WatchMessage::Event(kind, WatchAction::Delete, object),
                    "BOOKMARK" => WatchMessage::Alive(kind),
                    _ => bail!("unsupported Kubernetes watch event type"),
                };
                ensure!(
                    send_or_cancel(tx, message, cancel).await,
                    "controller stopped"
                );
            }
        }
        ensure!(
            buffer.iter().all(u8::is_ascii_whitespace),
            "truncated Kubernetes watch event"
        );
        Ok(WatchEnd::Closed)
    }

    async fn authorize(&self, request: RequestBuilder) -> Result<RequestBuilder> {
        let token_path = self.options.token_path.clone();
        let token = tokio::task::spawn_blocking(move || read_bounded(&token_path, MAX_TOKEN_BYTES))
            .await??;
        let token = std::str::from_utf8(&token)?.trim();
        ensure!(
            !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace()),
            "invalid Kubernetes bearer token"
        );
        Ok(request.bearer_auth(token))
    }

    async fn api_client(&self) -> Result<Client> {
        let ca_path = self.options.ca_path.clone();
        let ca =
            tokio::task::spawn_blocking(move || read_bounded(&ca_path, MAX_CA_BYTES)).await??;
        let mut current = self.client_ca.lock().expect("Kubernetes CA mutex poisoned");
        if *current != ca {
            let client = build_client(&ca)?;
            self.client.store(Arc::new(client));
            *current = ca;
        }
        Ok(self.client.load().as_ref().clone())
    }

    fn resource_url(&self, kind: ResourceKind) -> Result<Url> {
        let path = match (&self.options.namespace, kind) {
            (Some(ns), ResourceKind::Service) => format!("api/v1/namespaces/{ns}/services"),
            (None, ResourceKind::Service) => "api/v1/services".into(),
            (Some(ns), ResourceKind::Secret) => format!("api/v1/namespaces/{ns}/secrets"),
            (None, ResourceKind::Secret) => "api/v1/secrets".into(),
            (Some(ns), ResourceKind::Ingress) => {
                format!("apis/networking.k8s.io/v1/namespaces/{ns}/ingresses")
            }
            (None, ResourceKind::Ingress) => "apis/networking.k8s.io/v1/ingresses".into(),
        };
        self.options
            .api_server
            .join(&path)
            .context("build Kubernetes API URL")
    }

    fn ingress_url(&self, namespace: &str, name: &str, subresource: &str) -> Result<Url> {
        let path = format!(
            "apis/networking.k8s.io/v1/namespaces/{namespace}/ingresses/{name}{subresource}"
        );
        self.options
            .api_server
            .join(&path)
            .context("build Kubernetes API URL")
    }

    /// Drain the status queue with bounded concurrency until cancelled.
    async fn status_worker(self, queue: Arc<StatusQueue>, cancel: CancellationToken) {
        let mut tasks = JoinSet::new();
        loop {
            while tasks.len() < STATUS_PATCH_CONCURRENCY {
                let Some((key, request)) = queue.start() else {
                    break;
                };
                let controller = self.clone_for_task();
                let cancel = cancel.clone();
                let base = (resource_version(&request.object), request.desired);
                tasks.spawn(async move {
                    let outcome = controller
                        .patch_status(&key, request.desired, &request.object, &cancel)
                        .await;
                    (key, base, outcome)
                });
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = queue.notify.notified() => {}
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    match finished {
                        Some(Ok((key, base, outcome))) => queue.complete(key, base, outcome),
                        Some(Err(error)) => tracing::warn!(%error, "Ingress status worker failed"),
                        None => {}
                    }
                }
            }
        }
        tasks.shutdown().await;
    }

    /// Merge the configured address into (or out of) the object's current
    /// address list and patch it with the observed `resourceVersion` as a
    /// precondition. A `409 Conflict` reads the object again and merges into
    /// the fresh list, provided the re-read object is still the one the
    /// decision was made for (same uid and spec generation, still selected);
    /// otherwise the work is dropped and the next reconciliation decides
    /// again from the cache. Returns the server's current object after a
    /// successful patch (or when the list already satisfied the request), or
    /// `None` when cancelled, dropped, or when the object disappeared.
    async fn patch_status(
        &self,
        (namespace, name): &ObjectKey,
        desired: Desired,
        object: &Value,
        cancel: &CancellationToken,
    ) -> Result<Option<Value>> {
        let address = self
            .options
            .publish_address
            .as_deref()
            .context("publish address is not configured")?;
        let entry = address_entry(address);
        let mut current = object.clone();
        let mut backoff = Duration::from_millis(100);
        for attempt in 1..=STATUS_PATCH_ATTEMPTS {
            let list = status_entries(&current);
            let merged = merge_entries(&list, &entry, desired);
            if merged == list {
                return Ok(Some(current));
            }
            let rv = resource_version(&current);
            ensure!(!rv.is_empty(), "Ingress resourceVersion missing");
            let body = serde_json::json!({"metadata":{"resourceVersion":rv},"status":{"loadBalancer":{"ingress":merged}}});
            let request = self
                .authorize(
                    self.api_client()
                        .await?
                        .patch(self.ingress_url(namespace, name, "/status")?)
                        .header("content-type", "application/merge-patch+json")
                        .body(serde_json::to_vec(&body)?),
                )
                .await?;
            let response = tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                response = request.timeout(self.options.request_timeout).send() => response?,
            };
            let status = response.status();
            let bytes = bounded_body(response, MAX_WATCH_EVENT_BYTES).await?;
            if status.is_success() {
                return Ok(serde_json::from_slice(&bytes).ok());
            }
            ensure!(
                status == StatusCode::CONFLICT,
                "Ingress status patch returned {status}"
            );
            if attempt == STATUS_PATCH_ATTEMPTS {
                break;
            }
            tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                _ = tokio::time::sleep(jitter(backoff)) => {}
            }
            backoff *= 2;
            let request = self
                .authorize(
                    self.api_client()
                        .await?
                        .get(self.ingress_url(namespace, name, "")?),
                )
                .await?;
            let response = tokio::select! {
                _ = cancel.cancelled() => return Ok(None),
                response = request.timeout(self.options.request_timeout).send() => response?,
            };
            if response.status() == StatusCode::NOT_FOUND {
                return Ok(None);
            }
            let status = response.status();
            let bytes = bounded_body(response, MAX_WATCH_EVENT_BYTES).await?;
            ensure!(status.is_success(), "Ingress read returned {status}");
            current = serde_json::from_slice(&bytes).context("decode Ingress")?;
            if !same_target(object, &current, &self.options.ingress_class) {
                tracing::info!(namespace=%namespace, name=%name, "Ingress status update dropped: the object was recreated, changed, or left the class since it was queued");
                return Ok(None);
            }
        }
        bail!("Ingress status patch conflicted {STATUS_PATCH_ATTEMPTS} times")
    }
}

/// Bring the status queue in line with the cache. Every selected Ingress
/// whose published address list disagrees with the admitted set gets work
/// queued: admitted objects gain the configured address, withdrawn ones lose
/// it. Entries written by other replicas or controllers are never touched.
/// Queued work for objects that no longer exist, are no longer selected, or
/// already carry the right list is dropped, so the queue holds at most one
/// shared handle per live selected Ingress and never outgrows the cache
/// under create/delete churn. `admitted` is `None` when the candidate was
/// rejected: nothing new is queued, but the pruning still happens, and
/// whatever was dropped is recomputed from the cache by the next
/// reconciliation that succeeds.
fn sync_statuses(
    statuses: &StatusQueue,
    cache: &ResourceCache,
    admitted: Option<&ingress::IngressIdentities>,
    class: &str,
    address: &str,
) {
    let entry = address_entry(address);
    let mut keep = BTreeSet::new();
    let mut desired = Vec::new();
    for object in cache.entries(ResourceKind::Ingress) {
        if selected(object, class) != Some(true) {
            continue;
        }
        let Ok(key) = object_key(object) else {
            continue;
        };
        let Some(admitted) = admitted else {
            keep.insert(key);
            continue;
        };
        let carried = status_entries(object)
            .iter()
            .any(|item| carries(item, &entry));
        let action = if admitted.contains(&key) {
            Desired::Add
        } else {
            Desired::Remove
        };
        if carried == (action == Desired::Add) {
            continue;
        }
        keep.insert(key.clone());
        desired.push((key, action, object.clone()));
    }
    statuses.sync(&keep, desired);
}

/// Whether a conflict re-read still describes the object a status decision
/// was made for: the same uid (not recreated under the same name), the same
/// spec generation (not changed since admission was decided), and still
/// selected by this controller's class. Objects from servers that omit uid
/// or generation compare equal on those fields.
fn same_target(queued: &Value, current: &Value, class: &str) -> bool {
    queued.pointer("/metadata/uid") == current.pointer("/metadata/uid")
        && queued.pointer("/metadata/generation") == current.pointer("/metadata/generation")
        && selected(current, class) == Some(true)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Desired {
    Add,
    Remove,
}

struct StatusRequest {
    desired: Desired,
    /// The cached Ingress when the request was queued: its `resourceVersion`
    /// is the patch precondition and its status the list to merge into.
    object: Arc<Value>,
}

/// (base `resourceVersion`, desired change) identifying one unit of work.
type StatusBase = (String, Desired);

#[derive(Default)]
struct StatusState {
    /// Latest desired state per object; a newer request replaces an older one.
    queued: BTreeMap<ObjectKey, StatusRequest>,
    in_flight: BTreeMap<ObjectKey, StatusBase>,
    /// Work completed but not yet folded back into the controller's cache;
    /// requests repeating it are dropped until the cache catches up.
    satisfied: BTreeMap<ObjectKey, StatusBase>,
    /// Stripped server responses (`resourceVersion` and status only).
    results: Vec<(ObjectKey, Value)>,
}
impl StatusState {
    /// Queue one request unless the same work is in flight or already done
    /// and not yet absorbed by the cache. Returns whether the worker should
    /// be woken.
    fn admit(
        &mut self,
        key: ObjectKey,
        desired: Desired,
        object: Arc<Value>,
        limit: usize,
    ) -> bool {
        let base = (resource_version(&object), desired);
        if self.satisfied.get(&key) == Some(&base) || self.in_flight.get(&key) == Some(&base) {
            return false;
        }
        if self.queued.len() >= limit && !self.queued.contains_key(&key) {
            tracing::warn!(namespace=%key.0, name=%key.1, limit, "Ingress status queue is full; the update is deferred to a later reconciliation");
            return false;
        }
        self.queued.insert(key, StatusRequest { desired, object });
        true
    }
}

/// Coalescing status queue shared by the controller loop and its worker. It
/// holds at most one entry per Ingress, and `sync` drops entries for objects
/// the cache no longer holds, so its size follows the cache's live selected
/// Ingresses rather than the history of objects that ever existed. Queued
/// objects are the cache's own shared handles; the explicit `limit` (the
/// object limit) is a second line of defence, not the working bound.
struct StatusQueue {
    state: std::sync::Mutex<StatusState>,
    notify: tokio::sync::Notify,
    limit: usize,
}
impl StatusQueue {
    fn new(limit: usize) -> Self {
        Self {
            state: std::sync::Mutex::new(StatusState::default()),
            notify: tokio::sync::Notify::new(),
            limit,
        }
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, StatusState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    /// Drop queued work for every object outside `keep`, then queue
    /// `desired`, all under one lock. Work already in flight for a dropped
    /// object finishes on its own: its conflict handling refuses an object
    /// that changed identity, and a vanished object answers 404.
    fn sync(&self, keep: &BTreeSet<ObjectKey>, desired: Vec<(ObjectKey, Desired, Arc<Value>)>) {
        let mut state = self.lock();
        state.queued.retain(|key, _| keep.contains(key));
        let mut wake = false;
        for (key, action, object) in desired {
            wake |= state.admit(key, action, object, self.limit);
        }
        drop(state);
        if wake {
            self.notify.notify_one();
        }
    }
    /// Queued entries, for tests and diagnostics.
    #[cfg(test)]
    fn queued_len(&self) -> usize {
        self.lock().queued.len()
    }
    /// Move the first queued object that is not already being patched to the
    /// in-flight set.
    fn start(&self) -> Option<(ObjectKey, StatusRequest)> {
        let mut state = self.lock();
        let key = state
            .queued
            .keys()
            .find(|key| !state.in_flight.contains_key(*key))
            .cloned()?;
        let request = state.queued.remove(&key)?;
        let base = (resource_version(&request.object), request.desired);
        state.in_flight.insert(key.clone(), base);
        Some((key, request))
    }
    fn complete(&self, key: ObjectKey, base: StatusBase, outcome: Result<Option<Value>>) {
        let mut state = self.lock();
        state.in_flight.remove(&key);
        match outcome {
            Ok(Some(current)) => {
                state.satisfied.insert(key.clone(), base);
                state.results.push((key, status_view(&current)));
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(namespace=%key.0, name=%key.1, %error, "Ingress status update failed; it will be retried on the next event");
            }
        }
    }
    /// Completed patches to fold into the cache. Their duplicate guards are
    /// released at the same time because the cache then carries the result.
    fn take_results(&self) -> Vec<(ObjectKey, Value)> {
        let mut state = self.lock();
        let results = std::mem::take(&mut state.results);
        for (key, _) in &results {
            state.satisfied.remove(key);
        }
        results
    }
}

fn address_entry(address: &str) -> Value {
    if address.parse::<IpAddr>().is_ok() {
        serde_json::json!({"ip":address})
    } else {
        serde_json::json!({"hostname":address})
    }
}
/// The part of a server response that `ResourceCache::update_status` reads,
/// so pending results hold the status list rather than whole objects.
fn status_view(current: &Value) -> Value {
    let mut view = serde_json::json!({"metadata":{}});
    if let Some(rv) = current.pointer("/metadata/resourceVersion") {
        view["metadata"]["resourceVersion"] = rv.clone();
    }
    if let Some(status) = current.pointer("/status/loadBalancer") {
        view["status"] = serde_json::json!({"loadBalancer": status});
    }
    view
}
fn status_entries(ingress: &Value) -> Vec<Value> {
    ingress
        .pointer("/status/loadBalancer/ingress")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
/// Whether a load-balancer entry names the configured address.
fn carries(item: &Value, entry: &Value) -> bool {
    ["ip", "hostname"]
        .iter()
        .any(|field| entry.get(field).is_some() && item.get(field) == entry.get(field))
}
fn merge_entries(list: &[Value], entry: &Value, desired: Desired) -> Vec<Value> {
    let mut merged: Vec<Value> = list
        .iter()
        .filter(|item| desired == Desired::Add || !carries(item, entry))
        .cloned()
        .collect();
    if desired == Desired::Add && !merged.iter().any(|item| carries(item, entry)) {
        merged.push(entry.clone());
    }
    merged
}
fn resource_version(object: &Value) -> String {
    object
        .pointer("/metadata/resourceVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn schedule(slot: &mut Option<Instant>, at: Instant) {
    *slot = Some(slot.map_or(at, |current| current.min(at)));
}

/// Scale a delay by a random factor in `0.8..=1.2`. The generator is seeded
/// once per process, so replicas that observe the same expiry, outage, or
/// conflict retry at different moments instead of in lockstep.
fn jitter(base: Duration) -> Duration {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    static SEED: std::sync::OnceLock<RandomState> = std::sync::OnceLock::new();
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let mut hasher = SEED.get_or_init(RandomState::new).build_hasher();
    hasher.write_u64(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    let unit = (hasher.finish() % 1_000_001) as f64 / 1_000_000.0;
    base.mul_f64(0.8 + 0.4 * unit)
}

fn log_ownership_changes(before: &HostOwners, after: &HostOwners) {
    for (pattern, owner) in after {
        match before.get(pattern) {
            Some(previous) if previous == owner => {}
            Some(previous) => {
                tracing::info!(host=%pattern, from=%previous, to=%owner, "hostname ownership moved to an older claimant")
            }
            None => tracing::info!(host=%pattern, namespace=%owner, "hostname ownership granted"),
        }
    }
    for (pattern, previous) in before {
        if !after.contains_key(pattern) {
            tracing::info!(host=%pattern, namespace=%previous, "hostname ownership released");
        }
    }
}

/// Send unless cancelled; returns false when the message was not delivered.
async fn send_or_cancel(
    tx: &mpsc::Sender<WatchMessage>,
    message: WatchMessage,
    cancel: &CancellationToken,
) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => false,
        result = tx.send(message) => result.is_ok(),
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ResourceKind {
    Service,
    Ingress,
    Secret,
}
impl ResourceKind {
    fn enabled(secrets: bool) -> Vec<Self> {
        let mut kinds = vec![Self::Service, Self::Ingress];
        if secrets {
            kinds.push(Self::Secret);
        }
        kinds
    }
}
#[derive(Clone, Copy)]
enum WatchAction {
    Upsert,
    Delete,
}
/// A completed list: the cache, the watch start version per kind, and the
/// moment each kind's snapshot was taken.
#[derive(Default)]
struct Listing {
    cache: ResourceCache,
    versions: BTreeMap<ResourceKind, String>,
    confirmed: BTreeMap<ResourceKind, Instant>,
}
enum WatchMessage {
    Event(ResourceKind, WatchAction, Value),
    /// The kind's watch sent a bookmark: nothing changed, but the cache is
    /// confirmed current up to that version.
    Alive(ResourceKind),
    /// The kind's watch closed normally; republish so failed status work is
    /// retried.
    Tick(ResourceKind),
    Expired,
}
enum WatchEnd {
    Expired,
    Closed,
}

#[derive(Debug)]
struct CapacityExceeded(&'static str);
impl std::fmt::Display for CapacityExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Kubernetes {} exceeded", self.0)
    }
}
impl std::error::Error for CapacityExceeded {}

#[derive(Debug)]
struct ResponseTooLarge;
impl std::fmt::Display for ResponseTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kubernetes API response exceeds limit")
    }
}
impl std::error::Error for ResponseTooLarge {}

#[derive(Clone)]
struct Cached {
    // Reconciliation workers share immutable objects, including Secrets.
    // Cloning a snapshot must not duplicate all cached bytes.
    object: Arc<Value>,
    bytes: usize,
}
#[derive(Clone, Copy, Default)]
struct Usage {
    count: usize,
    bytes: usize,
}

#[derive(Default, Clone)]
struct ResourceCache {
    values: BTreeMap<(ResourceKind, String, String), Cached>,
    usage: BTreeMap<ResourceKind, Usage>,
    /// Kinds for which a watch event was rejected at capacity. Such a cache
    /// is served but is not authoritative until a relist succeeds.
    incomplete: BTreeSet<ResourceKind>,
}
impl ResourceCache {
    fn replace(
        &mut self,
        kind: ResourceKind,
        objects: Vec<Value>,
        max_objects: usize,
    ) -> Result<()> {
        let mut replacement = BTreeMap::new();
        let mut usage = Usage::default();
        for object in objects {
            let (namespace, name) = object_key(&object)?;
            let stripped = strip(kind, &object);
            let bytes = ingress::serialized_len(&stripped);
            usage.count += 1;
            usage.bytes += bytes;
            ensure!(usage.count <= max_objects, CapacityExceeded("object limit"));
            ensure!(
                usage.bytes <= MAX_CACHE_BYTES_PER_KIND,
                CapacityExceeded("cache byte limit")
            );
            ensure!(
                replacement
                    .insert(
                        (kind, namespace, name),
                        Cached {
                            object: Arc::new(stripped),
                            bytes,
                        }
                    )
                    .is_none(),
                "duplicate Kubernetes object"
            );
        }
        self.values.retain(|(found, _, _), _| *found != kind);
        self.values.extend(replacement);
        self.usage.insert(kind, usage);
        self.incomplete.remove(&kind);
        Ok(())
    }
    fn apply_bounded(
        &mut self,
        kind: ResourceKind,
        action: WatchAction,
        object: Value,
        max_objects: usize,
    ) -> Result<()> {
        let (namespace, name) = object_key(&object)?;
        let key = (kind, namespace, name);
        let usage = self.usage.entry(kind).or_default();
        match action {
            WatchAction::Upsert => {
                let stripped = strip(kind, &object);
                let bytes = ingress::serialized_len(&stripped);
                let (old_count, old_bytes) = self
                    .values
                    .get(&key)
                    .map_or((0, 0), |cached| (1, cached.bytes));
                ensure!(
                    usage.count - old_count < max_objects,
                    CapacityExceeded("object limit")
                );
                ensure!(
                    usage.bytes - old_bytes + bytes <= MAX_CACHE_BYTES_PER_KIND,
                    CapacityExceeded("cache byte limit")
                );
                usage.count = usage.count - old_count + 1;
                usage.bytes = usage.bytes - old_bytes + bytes;
                self.values.insert(
                    key,
                    Cached {
                        object: Arc::new(stripped),
                        bytes,
                    },
                );
            }
            WatchAction::Delete => {
                if let Some(cached) = self.values.remove(&key) {
                    usage.count -= 1;
                    usage.bytes -= cached.bytes;
                }
            }
        }
        Ok(())
    }
    fn mark_incomplete(&mut self, kind: ResourceKind) {
        self.incomplete.insert(kind);
    }
    fn has_capacity(&self, kind: ResourceKind, max_objects: usize) -> bool {
        let usage = self.usage.get(&kind).copied().unwrap_or_default();
        usage.count < max_objects && usage.bytes < MAX_CACHE_BYTES_PER_KIND
    }
    /// An incomplete kind can be recovered by a relist once it has capacity.
    fn recoverable(&self, max_objects: usize) -> bool {
        self.incomplete
            .iter()
            .any(|kind| self.has_capacity(*kind, max_objects))
    }
    fn get(&self, kind: ResourceKind, namespace: &str, name: &str) -> Option<&Value> {
        self.values
            .get(&(kind, namespace.to_owned(), name.to_owned()))
            .map(|cached| cached.object.as_ref())
    }
    fn objects(&self, kind: ResourceKind) -> impl Iterator<Item = &Value> {
        self.entries(kind).map(Arc::as_ref)
    }
    /// Shared handles to the cached objects of one kind, for work that
    /// outlives the borrow (status patches).
    fn entries(&self, kind: ResourceKind) -> impl Iterator<Item = &Arc<Value>> {
        self.values
            .range((kind, String::new(), String::new())..)
            .take_while(move |((found, _, _), _)| *found == kind)
            .map(|(_, cached)| &cached.object)
    }
    /// Adopt the `resourceVersion` and status of a server response for an
    /// Ingress the controller just patched or read.
    fn update_status(&mut self, namespace: &str, name: &str, current: &Value) {
        let key = (ResourceKind::Ingress, namespace.to_owned(), name.to_owned());
        let Some(cached) = self.values.get_mut(&key) else {
            return;
        };
        let Some(rv) = current.pointer("/metadata/resourceVersion").cloned() else {
            return;
        };
        let object = Arc::make_mut(&mut cached.object);
        object["metadata"]["resourceVersion"] = rv;
        object["status"] = current.get("status").cloned().unwrap_or(Value::Null);
        let bytes = ingress::serialized_len(&*object);
        let usage = self.usage.entry(ResourceKind::Ingress).or_default();
        usage.bytes = usage.bytes - cached.bytes + bytes;
        cached.bytes = bytes;
    }

    /// Build the candidate snapshot, the identities of the Ingresses it
    /// admits, and the hostname ownership it implies. Every decision is a
    /// function of the cached objects alone.
    fn snapshot(&self, options: &ControllerOptions) -> Result<(ControllerSnapshot, Admission)> {
        let mut resources: Vec<Value> = self
            .objects(ResourceKind::Service)
            .cloned()
            .map(|mut object| {
                object["apiVersion"] = Value::String("v1".into());
                object["kind"] = Value::String("Service".into());
                object
            })
            .collect();
        let service_count = resources.len();
        let selected_ingresses: Vec<&Value> = self
            .objects(ResourceKind::Ingress)
            .filter(|ingress| selected(ingress, &options.ingress_class) == Some(true))
            .collect();
        let (authorized, owners) = authorize_hosts(&selected_ingresses);
        for ingress in selected_ingresses {
            let Ok(identity) = object_key(ingress) else {
                continue;
            };
            if !authorized.contains(&identity) {
                continue;
            }
            let mut object = ingress.clone();
            object["apiVersion"] = Value::String("networking.k8s.io/v1".into());
            object["kind"] = Value::String("Ingress".into());
            resources.push(object);
        }
        let (config, valid) =
            ingress::import_validated(&Value::Array(resources.clone()), &options.ingress_class)?;
        if !options.watch_secrets {
            return Ok((
                ControllerSnapshot {
                    config,
                    certificates: Vec::new(),
                },
                Admission {
                    admitted: valid,
                    owners,
                },
            ));
        }
        let mut accepted = Vec::new();
        let mut certificates: BTreeMap<Vec<u8>, TlsCertificate> = BTreeMap::new();
        let mut claims: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let mut material_bytes = 0usize;
        for object in resources.iter().skip(service_count) {
            let identity = object_key(object)?;
            if !valid.contains(&identity) {
                continue;
            }
            let checked = (|| -> Result<Vec<(Vec<u8>, TlsCertificate)>> {
                use sha2::{Digest, Sha256};
                let candidates = self.certificates(&[object], &options.ingress_class)?;
                tls::sni_server_config(
                    candidates
                        .iter()
                        .map(|c| tls::SniCertificate {
                            hosts: c.hosts.clone(),
                            default: false,
                            cert_pem: c.cert_pem.clone(),
                            key_pem: c.key_pem.clone(),
                        })
                        .collect(),
                )?;
                let mut additions: BTreeMap<Vec<u8>, TlsCertificate> = BTreeMap::new();
                for candidate in candidates {
                    let mut hash = Sha256::new();
                    for cert in
                        rustls_pemfile::certs(&mut std::io::Cursor::new(&candidate.cert_pem))
                    {
                        let cert = cert?;
                        hash.update((cert.len() as u64).to_be_bytes());
                        hash.update(cert.as_ref());
                    }
                    let fingerprint = hash.finalize().to_vec();
                    for host in &candidate.hosts {
                        ensure!(
                            claims.get(host).is_none_or(|old| old == &fingerprint),
                            "conflicting TLS host claim"
                        );
                    }
                    let mut combined: BTreeSet<_> = candidate.hosts.iter().cloned().collect();
                    let previous = additions
                        .get(&fingerprint)
                        .or_else(|| certificates.get(&fingerprint));
                    if let Some(old) = previous {
                        combined.extend(old.hosts.iter().cloned());
                    }
                    ensure!(combined.len() <= 128, "TLS host count exceeds 128");
                    // Keep the already-accounted PEM representation: equivalent
                    // DER may arrive with different whitespace or key encoding.
                    let material = previous.cloned().unwrap_or(candidate);
                    additions.insert(
                        fingerprint,
                        TlsCertificate {
                            hosts: combined.into_iter().collect(),
                            ..material
                        },
                    );
                }
                let added_bytes: usize = additions
                    .iter()
                    .filter(|(key, _)| !certificates.contains_key(*key))
                    .map(|(_, c)| c.cert_pem.len() + c.key_pem.len())
                    .sum();
                ensure!(
                    material_bytes + added_bytes <= 16 * 1024 * 1024,
                    "TLS material exceeds 16 MiB"
                );
                ensure!(
                    certificates.len()
                        + additions
                            .iter()
                            .filter(|(key, _)| !certificates.contains_key(*key))
                            .count()
                        <= 1024,
                    "too many TLS certificates"
                );
                Ok(additions.into_iter().collect())
            })();
            match checked {
                Ok(additions) => {
                    for (fingerprint, certificate) in additions {
                        for host in &certificate.hosts {
                            claims.insert(host.clone(), fingerprint.clone());
                        }
                        if !certificates.contains_key(&fingerprint) {
                            material_bytes +=
                                certificate.cert_pem.len() + certificate.key_pem.len();
                        }
                        certificates.insert(fingerprint, certificate);
                    }
                    accepted.push(object.clone());
                }
                Err(error) => {
                    tracing::warn!(namespace=%identity.0, name=%identity.1, %error, "Ingress withdrawn because TLS claims are invalid");
                }
            }
        }
        resources.truncate(service_count);
        resources.extend(accepted);
        let (config, admitted) =
            ingress::import_validated(&Value::Array(resources), &options.ingress_class)?;
        Ok((
            ControllerSnapshot {
                config,
                certificates: certificates.into_values().collect(),
            },
            Admission { admitted, owners },
        ))
    }
    fn certificates(&self, ingresses: &[&Value], class: &str) -> Result<Vec<TlsCertificate>> {
        let mut claims: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for ingress in ingresses {
            if selected(ingress, class) != Some(true) {
                continue;
            }
            let namespace = ingress
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .unwrap_or("default");
            for tls in ingress
                .pointer("/spec/tls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let secret = tls
                    .get("secretName")
                    .and_then(Value::as_str)
                    .context("Ingress TLS secretName missing")?;
                ensure!(dns_subdomain(secret), "invalid Ingress TLS secret name");
                let hosts = tls
                    .get("hosts")
                    .and_then(Value::as_array)
                    .context("Ingress TLS hosts missing")?;
                ensure!(
                    !hosts.is_empty() && hosts.len() <= 256,
                    "Ingress TLS needs 1..256 hosts"
                );
                let entry = claims
                    .entry((namespace.to_owned(), secret.to_owned()))
                    .or_default();
                for host in hosts {
                    let host = host.as_str().context("Ingress TLS host must be a string")?;
                    ensure!(valid_tls_host(host), "invalid Ingress TLS host");
                    entry.insert(host.to_ascii_lowercase());
                }
            }
        }
        let mut result = Vec::new();
        for ((namespace, name), hosts) in claims {
            let secret = self
                .get(ResourceKind::Secret, &namespace, &name)
                .with_context(|| format!("TLS Secret {namespace}/{name} is missing"))?;
            ensure!(
                secret.get("type").and_then(Value::as_str) == Some("kubernetes.io/tls"),
                "Secret {namespace}/{name} is not kubernetes.io/tls"
            );
            let cert = decode_secret(secret, "tls.crt")?;
            let key = decode_secret(secret, "tls.key")?;
            tls::server_config(&cert, &key)
                .with_context(|| format!("invalid TLS Secret {namespace}/{name}"))?;
            // A wildcard claim needs a real wildcard SAN. The resolver's probe
            // name check alone would accept a certificate that only names the
            // probe host and can never serve a real subdomain.
            if hosts.iter().any(|host| host.starts_with("*.")) {
                let names = certificate_dns_names(&cert)
                    .with_context(|| format!("invalid TLS Secret {namespace}/{name}"))?;
                for host in hosts.iter().filter(|host| host.starts_with("*.")) {
                    ensure!(
                        names.iter().any(|san| san == host),
                        "TLS Secret {namespace}/{name} has no wildcard SAN for {host}"
                    );
                }
            }
            result.push(TlsCertificate {
                hosts: hosts.into_iter().collect(),
                cert_pem: cert,
                key_pem: key,
            });
        }
        Ok(result)
    }
}

/// Decide which selected Ingresses may publish their hostnames.
///
/// Every host pattern an Ingress claims (rule hosts, TLS hosts, and the
/// catch-all for hostless rules or default backends) must be owned by the
/// Ingress's namespace. A pattern is owned by the namespace of its OLDEST
/// claimant: `metadata.creationTimestamp` first, then `metadata.uid`, then
/// namespace/name for objects that carry neither. These are API-server facts
/// every replica sees identically, so the result depends only on the current
/// objects and never on the order in which a replica observed them.
/// An exact host and a wildcard covering it cannot belong to different
/// namespaces: the wildcard is withdrawn when any such exact host is older
/// than it, otherwise the younger exact hosts are. Returns the authorized
/// identities and the resulting ownership map.
fn authorize_hosts(ingresses: &[&Value]) -> (ingress::IngressIdentities, HostOwners) {
    struct Claimant {
        age: Age,
        identity: ObjectKey,
        claims: BTreeSet<String>,
    }
    let mut claimants: Vec<Claimant> = Vec::new();
    for ingress in ingresses {
        let identity = match object_key(ingress) {
            Ok(identity) => identity,
            Err(error) => {
                tracing::warn!(%error, "Ingress skipped: invalid identity");
                continue;
            }
        };
        match host_claims(ingress) {
            Ok(claims) => claimants.push(Claimant {
                age: age_of(ingress),
                identity,
                claims,
            }),
            Err(error) => {
                tracing::warn!(namespace=%identity.0, name=%identity.1, %error, "Ingress withdrawn: hostname claim is invalid");
            }
        }
    }
    claimants.sort_by(|a, b| a.age.cmp(&b.age).then_with(|| a.identity.cmp(&b.identity)));
    // Oldest claimant per pattern; the vector is sorted, so the first wins.
    let mut oldest: BTreeMap<String, usize> = BTreeMap::new();
    for (index, claimant) in claimants.iter().enumerate() {
        for claim in &claimant.claims {
            oldest.entry(claim.clone()).or_insert(index);
        }
    }
    let mut owners: HostOwners = oldest
        .iter()
        .map(|(pattern, index)| (pattern.clone(), claimants[*index].identity.0.clone()))
        .collect();
    // Overlap between an exact host and the wildcard covering it, across
    // namespaces: the older side wins, decided per wildcard.
    let mut dropped = BTreeSet::new();
    for (wildcard, wildcard_index) in oldest.iter().filter(|(p, _)| p.starts_with("*.")) {
        let suffix = &wildcard[2..];
        let conflicts: Vec<&String> = owners
            .keys()
            .filter(|exact| !exact.starts_with("*.") && *exact != CATCH_ALL_HOST)
            .filter(|exact| {
                exact
                    .split_once('.')
                    .is_some_and(|(_, rest)| rest == suffix)
            })
            .filter(|exact| owners.get(*exact) != owners.get(wildcard))
            .collect();
        if conflicts.is_empty() {
            continue;
        }
        if conflicts
            .iter()
            .any(|exact| oldest[*exact] < *wildcard_index)
        {
            dropped.insert(wildcard.clone());
        } else {
            dropped.extend(conflicts.into_iter().cloned());
        }
    }
    for pattern in &dropped {
        tracing::warn!(host=%pattern, "hostname claim rejected: it overlaps an older host owned by another namespace");
        owners.remove(pattern);
    }
    let mut authorized = BTreeSet::new();
    for claimant in claimants {
        let denied: Vec<&String> = claimant
            .claims
            .iter()
            .filter(|claim| owners.get(*claim) != Some(&claimant.identity.0))
            .collect();
        if denied.is_empty() {
            authorized.insert(claimant.identity);
        } else {
            tracing::warn!(namespace=%claimant.identity.0, name=%claimant.identity.1, hosts=?denied, "Ingress withdrawn: hostname is owned by an older Ingress in another namespace");
        }
    }
    (authorized, owners)
}

/// Ordering key for hostname ownership: objects with a creation timestamp
/// sort before those without, older timestamps first, then by uid.
/// Kubernetes serializes `creationTimestamp` as RFC 3339 in UTC with fixed
/// width, so the lexical order is the chronological order.
type Age = (bool, String, bool, String);
fn age_of(object: &Value) -> Age {
    let created = object
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let uid = object
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    (
        created.is_none(),
        created.unwrap_or_default(),
        uid.is_none(),
        uid.unwrap_or_default(),
    )
}

/// Host patterns an Ingress claims: rule hosts, TLS hosts, and the catch-all
/// for hostless HTTP rules or a default backend. Every pattern must be an
/// exact DNS name or a one-label wildcard so that it can be owned.
fn host_claims(ingress: &Value) -> Result<BTreeSet<String>> {
    let mut claims = BTreeSet::new();
    let spec = &ingress["spec"];
    if spec.get("defaultBackend").is_some_and(|v| !v.is_null()) {
        claims.insert(CATCH_ALL_HOST.to_owned());
    }
    for rule in spec["rules"].as_array().into_iter().flatten() {
        match rule.get("host").and_then(Value::as_str) {
            Some(host) if !host.is_empty() => {
                let host = host.to_ascii_lowercase();
                ensure!(valid_tls_host(&host), "invalid Ingress rule host {host:?}");
                claims.insert(host);
            }
            _ => {
                if rule.get("http").is_some_and(|http| !http.is_null()) {
                    claims.insert(CATCH_ALL_HOST.to_owned());
                }
            }
        }
    }
    for tls in spec["tls"].as_array().into_iter().flatten() {
        for host in tls["hosts"].as_array().into_iter().flatten() {
            let host = host
                .as_str()
                .context("Ingress TLS host must be a string")?
                .to_ascii_lowercase();
            ensure!(valid_tls_host(&host), "invalid Ingress TLS host {host:?}");
            claims.insert(host);
        }
    }
    Ok(claims)
}

/// Retain only the fields the controller reads so unrelated payloads (large
/// Secret values, managed fields, annotations) do not occupy cache memory.
fn strip(kind: ResourceKind, object: &Value) -> Value {
    let mut metadata = serde_json::Map::new();
    for field in ["name", "namespace", "resourceVersion"] {
        if let Some(value) = object.pointer(&format!("/metadata/{field}")) {
            metadata.insert(field.to_owned(), value.clone());
        }
    }
    let mut stripped = serde_json::Map::new();
    match kind {
        ResourceKind::Secret => {
            if let Some(kind) = object.get("type") {
                stripped.insert("type".to_owned(), kind.clone());
            }
            let mut data = serde_json::Map::new();
            for field in ["tls.crt", "tls.key"] {
                if let Some(value) = object.get("data").and_then(|d| d.get(field)) {
                    data.insert(field.to_owned(), value.clone());
                }
            }
            if !data.is_empty() {
                stripped.insert("data".to_owned(), Value::Object(data));
            }
        }
        ResourceKind::Service => {
            let mut spec = serde_json::Map::new();
            for field in ["type", "ports"] {
                if let Some(value) = object.pointer(&format!("/spec/{field}")) {
                    spec.insert(field.to_owned(), value.clone());
                }
            }
            stripped.insert("spec".to_owned(), Value::Object(spec));
        }
        ResourceKind::Ingress => {
            // Creation time and uid decide hostname ownership; uid and
            // generation bind queued status work to the object it was
            // decided for.
            for field in ["creationTimestamp", "uid", "generation"] {
                if let Some(value) = object.pointer(&format!("/metadata/{field}")) {
                    metadata.insert(field.to_owned(), value.clone());
                }
            }
            if let Some(class) =
                object.pointer("/metadata/annotations/kubernetes.io~1ingress.class")
            {
                metadata.insert(
                    "annotations".to_owned(),
                    serde_json::json!({"kubernetes.io/ingress.class": class}),
                );
            }
            if let Some(spec) = object.get("spec") {
                stripped.insert("spec".to_owned(), spec.clone());
            }
            if let Some(status) = object.pointer("/status/loadBalancer") {
                stripped.insert(
                    "status".to_owned(),
                    serde_json::json!({"loadBalancer": status}),
                );
            }
        }
    }
    stripped.insert("metadata".to_owned(), Value::Object(metadata));
    Value::Object(stripped)
}

fn selected(ingress: &Value, class: &str) -> Option<bool> {
    let selected = ingress
        .pointer("/spec/ingressClassName")
        .and_then(Value::as_str)
        .or_else(|| {
            ingress
                .pointer("/metadata/annotations/kubernetes.io~1ingress.class")
                .and_then(Value::as_str)
        });
    selected.map(|value| value == class)
}
fn object_key(object: &Value) -> Result<(String, String)> {
    let namespace = object
        .pointer("/metadata/namespace")
        .and_then(Value::as_str)
        .unwrap_or("default");
    let name = object
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .context("Kubernetes object name missing")?;
    ensure!(
        dns_subdomain(namespace) && dns_subdomain(name),
        "invalid Kubernetes object identity"
    );
    Ok((namespace.to_owned(), name.to_owned()))
}
fn decode_secret(secret: &Value, key: &str) -> Result<Vec<u8>> {
    let encoded = secret
        .get("data")
        .and_then(|data| data.get(key))
        .and_then(Value::as_str)
        .with_context(|| format!("TLS Secret {key} missing"))?;
    ensure!(
        encoded.len() <= MAX_TLS_BYTES * 2,
        "encoded TLS Secret value exceeds limit"
    );
    let decoded = STANDARD
        .decode(encoded)
        .context("decode TLS Secret value")?;
    ensure!(
        !decoded.is_empty() && decoded.len() <= MAX_TLS_BYTES,
        "TLS Secret value is empty or exceeds limit"
    );
    Ok(decoded)
}
/// Lower-cased DNS subject alternative names of the leaf certificate.
fn certificate_dns_names(cert_pem: &[u8]) -> Result<Vec<String>> {
    let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(cert_pem))
        .next()
        .context("TLS certificate missing")??;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("invalid TLS certificate: {error}"))?;
    Ok(parsed
        .subject_alternative_name()
        .map_err(|error| anyhow::anyhow!("invalid subject alternative names: {error}"))?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .filter_map(|name| match name {
                    x509_parser::extensions::GeneralName::DNSName(name) => {
                        Some(name.to_ascii_lowercase())
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default())
}
fn take_json(buffer: &mut Vec<u8>) -> Result<Option<Value>> {
    let whitespace = buffer
        .iter()
        .take_while(|byte| byte.is_ascii_whitespace())
        .count();
    if whitespace > 0 {
        buffer.drain(..whitespace);
    }
    if buffer.is_empty() {
        return Ok(None);
    }
    let mut stream = serde_json::Deserializer::from_slice(buffer).into_iter::<Value>();
    match stream.next() {
        Some(Ok(value)) => {
            let used = stream.byte_offset();
            buffer.drain(..used);
            Ok(Some(value))
        }
        Some(Err(error)) if error.is_eof() => Ok(None),
        Some(Err(error)) => Err(error.into()),
        None => Ok(None),
    }
}
async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(ResponseTooLarge.into());
    }
    let mut output = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if output.len() + chunk.len() > limit {
            return Err(ResponseTooLarge.into());
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}
fn build_client(ca: &[u8]) -> Result<Client> {
    let certificates =
        reqwest::Certificate::from_pem_bundle(ca).context("parse Kubernetes API CA bundle")?;
    ensure!(
        !certificates.is_empty(),
        "Kubernetes API CA bundle is empty"
    );
    let mut builder = Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .tls_built_in_root_certs(false)
        .connect_timeout(Duration::from_secs(10));
    for certificate in certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder.build().context("build Kubernetes API client")
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    std::fs::File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut output)?;
    ensure!(output.len() <= limit, "file exceeds limit");
    Ok(output)
}
fn bounded_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).into_owned()
}
fn dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}
fn valid_tls_host(value: &str) -> bool {
    let host = value.strip_prefix("*.").unwrap_or(value);
    !host.contains('*') && dns_subdomain(host)
}
fn valid_publish_address(value: &str) -> bool {
    value.parse::<IpAddr>().is_ok() || dns_subdomain(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn object(name: &str) -> Value {
        serde_json::json!({"metadata":{"name":name}})
    }
    #[test]
    fn watch_growth_obeys_list_object_limit_and_allows_updates_and_deletes() {
        let mut cache = ResourceCache::default();
        cache
            .apply_bounded(ResourceKind::Service, WatchAction::Upsert, object("a"), 1)
            .unwrap();
        assert!(
            cache
                .apply_bounded(ResourceKind::Service, WatchAction::Upsert, object("b"), 1)
                .is_err()
        );
        assert_eq!(cache.objects(ResourceKind::Service).count(), 1);
        cache
            .apply_bounded(ResourceKind::Service, WatchAction::Upsert, object("a"), 1)
            .unwrap();
        cache
            .apply_bounded(ResourceKind::Service, WatchAction::Delete, object("a"), 1)
            .unwrap();
        cache
            .apply_bounded(ResourceKind::Service, WatchAction::Upsert, object("b"), 1)
            .unwrap();
        assert_eq!(cache.objects(ResourceKind::Service).count(), 1);
    }
    #[test]
    fn capacity_rejection_marks_the_cache_incomplete_until_a_relist() {
        let mut cache = ResourceCache::default();
        cache
            .apply_bounded(ResourceKind::Ingress, WatchAction::Upsert, object("a"), 1)
            .unwrap();
        let error = cache
            .apply_bounded(ResourceKind::Ingress, WatchAction::Upsert, object("b"), 1)
            .unwrap_err();
        assert!(error.is::<CapacityExceeded>(), "{error}");
        cache.mark_incomplete(ResourceKind::Ingress);
        // Still full: a relist would fail, so it is not yet recoverable.
        assert!(!cache.recoverable(1));
        cache
            .apply_bounded(ResourceKind::Ingress, WatchAction::Delete, object("a"), 1)
            .unwrap();
        assert!(cache.recoverable(1));
        cache
            .replace(ResourceKind::Ingress, vec![object("b")], 1)
            .unwrap();
        assert!(!cache.recoverable(1));
        assert!(cache.incomplete.is_empty());
        assert_eq!(cache.objects(ResourceKind::Ingress).count(), 1);
    }
    #[test]
    fn secret_cache_is_stripped_and_byte_bounded() {
        let mut cache = ResourceCache::default();
        let unrelated = serde_json::json!({
            "metadata":{"name":"blob","namespace":"blue","resourceVersion":"1","managedFields":[{"manager":"x".repeat(4096)}]},
            "type":"Opaque",
            "data":{"payload":"y".repeat(1024 * 1024)}
        });
        cache
            .apply_bounded(ResourceKind::Secret, WatchAction::Upsert, unrelated, 10_000)
            .unwrap();
        let usage = cache.usage[&ResourceKind::Secret];
        assert!(
            usage.bytes < 256,
            "unrelated payload retained: {}",
            usage.bytes
        );
        let cached = cache.get(ResourceKind::Secret, "blue", "blob").unwrap();
        assert!(cached.get("data").is_none());
        assert_eq!(cached["type"], "Opaque");
        assert_eq!(cached["metadata"]["resourceVersion"], "1");
        assert!(cached["metadata"].get("managedFields").is_none());

        // Each TLS Secret is retained at the 2 MiB encoded maximum; the byte
        // budget rejects growth before the object count limit does.
        let material = "A".repeat(2 * MAX_TLS_BYTES);
        let big = |index: usize| {
            serde_json::json!({
                "metadata":{"name":format!("tls-{index}"),"namespace":"blue"},
                "type":"kubernetes.io/tls",
                "data":{"tls.crt":material,"tls.key":"Zm9v"}
            })
        };
        let mut rejected = None;
        for index in 0..64 {
            if let Err(error) = cache.apply_bounded(
                ResourceKind::Secret,
                WatchAction::Upsert,
                big(index),
                10_000,
            ) {
                assert!(error.is::<CapacityExceeded>(), "{error}");
                rejected = Some(index);
                break;
            }
        }
        let rejected = rejected.expect("byte budget never enforced");
        assert!(rejected < 40, "rejected only at {rejected}");
        assert!(cache.usage[&ResourceKind::Secret].bytes <= MAX_CACHE_BYTES_PER_KIND);
        // Replacing an existing object of the same size is still allowed and
        // deleting one releases its bytes.
        cache
            .apply_bounded(ResourceKind::Secret, WatchAction::Upsert, big(0), 10_000)
            .unwrap();
        cache
            .apply_bounded(ResourceKind::Secret, WatchAction::Delete, big(0), 10_000)
            .unwrap();
        cache
            .apply_bounded(
                ResourceKind::Secret,
                WatchAction::Upsert,
                big(rejected),
                10_000,
            )
            .unwrap();
        // A list is bounded by the same budget.
        let objects: Vec<Value> = (0..40).map(big).collect();
        let error = cache
            .replace(ResourceKind::Secret, objects, 10_000)
            .unwrap_err();
        assert!(error.is::<CapacityExceeded>(), "{error}");
    }
    #[test]
    fn parses_fragmented_watch_values() {
        let mut bytes = br#" {"type":"ADDED","object":{"metadata":{"name":"x"}}}"#.to_vec();
        assert_eq!(take_json(&mut bytes).unwrap().unwrap()["type"], "ADDED");
        assert!(take_json(&mut bytes).unwrap().is_none());
        let mut partial = br#"{"type":"ADD"#.to_vec();
        assert!(take_json(&mut partial).unwrap().is_none());
    }
}

#[cfg(test)]
mod tls_isolation_tests {
    use super::*;
    use serde_json::json;
    #[tokio::test]
    async fn rejected_new_snapshot_withdraws_authority_until_apply_recovers() {
        use std::sync::atomic::AtomicBool;
        struct Sink {
            reject: AtomicBool,
            ready: AtomicBool,
        }
        #[async_trait]
        impl ConfigSink for Sink {
            async fn apply(&self, _: ControllerSnapshot) -> Result<()> {
                ensure!(
                    !self.reject.load(Ordering::Acquire),
                    "injected activation failure"
                );
                Ok(())
            }
            async fn report_authority(&self, healthy: bool, _: &str) {
                self.ready.store(healthy, Ordering::Release);
            }
        }
        let sink = Arc::new(Sink {
            reject: AtomicBool::new(false),
            ready: AtomicBool::new(false),
        });
        let options = options();
        let controller = Controller {
            options: options.clone(),
            client: Arc::new(arc_swap::ArcSwap::from_pointee(Client::new())),
            client_ca: Arc::new(std::sync::Mutex::new(Vec::new())),
            sink: sink.clone(),
        };
        let mut health = Health::new(&options);
        for kind in ResourceKind::enabled(options.watch_secrets) {
            health.touch(kind);
        }
        let mut cache = cache();
        let mut last_good = None;
        let statuses = StatusQueue::new(options.max_objects);
        controller
            .publish(&mut cache, &mut last_good, &mut health, &statuses)
            .await;
        assert!(sink.ready.load(Ordering::Acquire));
        let accepted = last_good.as_ref().unwrap().snapshot.clone();
        let mut changed = ingress("a-good", "good.example", "good");
        changed["spec"]["rules"][0]["http"]["paths"][0]["path"] = "/changed".into();
        cache
            .apply_bounded(
                ResourceKind::Ingress,
                WatchAction::Upsert,
                changed,
                options.max_objects,
            )
            .unwrap();
        sink.reject.store(true, Ordering::Release);
        controller
            .publish(&mut cache, &mut last_good, &mut health, &statuses)
            .await;
        assert_eq!(last_good.as_ref().unwrap().snapshot, accepted);
        assert!(
            !sink.ready.load(Ordering::Acquire),
            "fresh watches do not prove that the desired snapshot was applied"
        );
        controller
            .assess(&mut health, &cache.incomplete, true, false)
            .await;
        assert!(
            !sink.ready.load(Ordering::Acquire),
            "freshness alone must not erase activation failure"
        );
        sink.reject.store(false, Ordering::Release);
        controller
            .publish(&mut cache, &mut last_good, &mut health, &statuses)
            .await;
        assert!(sink.ready.load(Ordering::Acquire));
        assert_ne!(last_good.as_ref().unwrap().snapshot, accepted);
    }
    fn options() -> ControllerOptions {
        ControllerOptions {
            api_server: "https://localhost/".parse().unwrap(),
            ca_path: "unused".into(),
            token_path: "unused".into(),
            namespace: None,
            ingress_class: "hangang".into(),
            watch_secrets: true,
            publish_address: None,
            list_page_size: 100,
            max_objects: 1000,
            watch_timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(40),
            stale_after: Duration::from_secs(60),
        }
    }
    fn ingress(name: &str, host: &str, secret: &str) -> Value {
        ingress_in("blue", name, host, Some(secret))
    }
    fn ingress_in(namespace: &str, name: &str, host: &str, secret: Option<&str>) -> Value {
        let mut object = json!({"metadata":{"name":name,"namespace":namespace},"spec":{"ingressClassName":"hangang","rules":[{"host":host,"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}});
        if let Some(secret) = secret {
            object["spec"]["tls"] = json!([{"hosts":[host],"secretName":secret}]);
        }
        object
    }
    /// Stamp the API-server facts that decide ownership.
    fn aged(mut object: Value, created: &str, uid: &str) -> Value {
        object["metadata"]["creationTimestamp"] = created.into();
        object["metadata"]["uid"] = uid.into();
        object
    }
    fn secret(name: &str, host: &str) -> Value {
        secret_in("blue", name, host)
    }
    fn secret_in(namespace: &str, name: &str, host: &str) -> Value {
        let pair = rcgen::generate_simple_self_signed(vec![host.into()]).unwrap();
        json!({"metadata":{"name":name,"namespace":namespace},"type":"kubernetes.io/tls","data":{"tls.crt":STANDARD.encode(pair.cert.pem()),"tls.key":STANDARD.encode(pair.signing_key.serialize_pem())}})
    }
    fn service_in(namespace: &str) -> Value {
        json!({"metadata":{"name":"api","namespace":namespace},"spec":{"ports":[{"port":80}]}})
    }
    fn cache() -> ResourceCache {
        let mut cache = ResourceCache::default();
        cache
            .replace(ResourceKind::Service, vec![service_in("blue")], 1000)
            .unwrap();
        cache
            .replace(
                ResourceKind::Ingress,
                vec![
                    ingress("a-good", "good.example", "good"),
                    ingress("z-bad", "bad.example", "bad"),
                ],
                1000,
            )
            .unwrap();
        cache
            .replace(
                ResourceKind::Secret,
                vec![secret("good", "good.example"), secret("bad", "bad.example")],
                1000,
            )
            .unwrap();
        cache
    }
    impl ResourceCache {
        fn upsert(&mut self, kind: ResourceKind, object: Value) {
            self.apply_bounded(kind, WatchAction::Upsert, object, 1000)
                .unwrap();
        }
        fn delete(&mut self, kind: ResourceKind, namespace: &str, name: &str) {
            self.apply_bounded(
                kind,
                WatchAction::Delete,
                json!({"metadata":{"name":name,"namespace":namespace}}),
                1000,
            )
            .unwrap();
        }
        fn publish(&self) -> (ControllerSnapshot, HostOwners) {
            let (snapshot, admission) = self.snapshot(&options()).unwrap();
            (snapshot, admission.owners)
        }
        fn admitted(&self) -> ingress::IngressIdentities {
            self.snapshot(&options()).unwrap().1.admitted
        }
    }
    fn hosts(snapshot: &ControllerSnapshot) -> Vec<Option<String>> {
        snapshot
            .config
            .http
            .iter()
            .map(|r| r.host.clone())
            .collect()
    }
    #[test]
    fn invalid_secret_is_withdrawn_per_ingress_and_recovers() {
        let base = cache();
        for failure in [
            "missing",
            "bad-pem",
            "wrong-host",
            "wrong-key",
            "missing-claim",
        ] {
            let mut cache = base.clone();
            match failure {
                "missing" => cache.delete(ResourceKind::Secret, "blue", "bad"),
                "bad-pem" => {
                    let mut bad = secret("bad", "bad.example");
                    bad["data"]["tls.crt"] = STANDARD.encode("bad PEM").into();
                    cache.upsert(ResourceKind::Secret, bad);
                }
                "wrong-host" => {
                    cache.upsert(ResourceKind::Secret, secret("bad", "elsewhere.example"))
                }
                "wrong-key" => {
                    let mut bad = secret("bad", "bad.example");
                    bad["data"]["tls.key"] =
                        secret("other", "bad.example")["data"]["tls.key"].clone();
                    cache.upsert(ResourceKind::Secret, bad);
                }
                _ => {
                    let mut claim = ingress("z-bad", "bad.example", "bad");
                    claim["spec"]["tls"][0]
                        .as_object_mut()
                        .unwrap()
                        .remove("secretName");
                    cache.upsert(ResourceKind::Ingress, claim);
                }
            }
            let (snapshot, _) = cache.publish();
            assert_eq!(snapshot.config.http.len(), 1, "{failure}");
            assert_eq!(
                snapshot.config.http[0].host.as_deref(),
                Some("good.example")
            );
            assert_eq!(snapshot.certificates.len(), 1);
            // The withdrawn object is not admitted, so it must not receive
            // the published address.
            assert_eq!(
                cache.admitted(),
                BTreeSet::from([("blue".to_owned(), "a-good".to_owned())]),
                "{failure}"
            );
        }
        let (snapshot, owners) = base.publish();
        assert_eq!(snapshot.config.http.len(), 2);
        assert_eq!(snapshot.certificates.len(), 2);
        assert_eq!(owners["good.example"], "blue");
        assert_eq!(owners["bad.example"], "blue");
        assert_eq!(base.admitted().len(), 2);
    }
    #[test]
    fn shared_secret_is_deduplicated_and_conflicting_claim_is_isolated() {
        let mut cache = cache();
        cache
            .replace(
                ResourceKind::Ingress,
                vec![
                    ingress("a-good", "good.example", "good"),
                    ingress("z-shared", "good.example", "good"),
                ],
                1000,
            )
            .unwrap();
        let (snapshot, _) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 2);
        assert_eq!(snapshot.certificates.len(), 1);
        cache.upsert(ResourceKind::Secret, secret("other", "good.example"));
        cache.upsert(
            ResourceKind::Ingress,
            ingress("z-conflict", "good.example", "other"),
        );
        let (snapshot, _) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 2);
        assert_eq!(snapshot.certificates.len(), 1);

        // Conflicting claims inside one Ingress must be isolated before the
        // final resolver is built, just like conflicts between two Ingresses.
        let mut conflicting = ingress("z-conflict", "good.example", "good");
        conflicting["spec"]["tls"]
            .as_array_mut()
            .unwrap()
            .push(json!({"hosts":["good.example"],"secretName":"other"}));
        cache.upsert(ResourceKind::Ingress, conflicting);
        let (snapshot, _) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 2);
        assert_eq!(snapshot.certificates.len(), 1);
    }
    #[test]
    fn cross_namespace_host_claim_goes_to_the_oldest_ingress() {
        // `alpha` sorts before `zulu` and has no TLS, but `zulu` created its
        // Ingress first. Ownership follows creation, not name order.
        let victim = aged(
            ingress_in("zulu", "app", "api.example.test", Some("api-tls")),
            "2026-01-01T00:00:00Z",
            "0000-victim",
        );
        let attacker = |secret: Option<&str>| {
            aged(
                ingress_in("alpha", "app", "api.example.test", secret),
                "2026-02-01T00:00:00Z",
                "0000-attacker",
            )
        };
        let mut cache = ResourceCache::default();
        cache
            .replace(
                ResourceKind::Service,
                vec![service_in("alpha"), service_in("zulu")],
                1000,
            )
            .unwrap();
        cache
            .replace(
                ResourceKind::Ingress,
                vec![attacker(None), victim.clone()],
                1000,
            )
            .unwrap();
        cache
            .replace(
                ResourceKind::Secret,
                vec![secret_in("zulu", "api-tls", "api.example.test")],
                1000,
            )
            .unwrap();
        // A cold start over the contested host publishes the oldest claimant
        // and serves the victim's certificate only in front of its backend.
        let (snapshot, owners) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 1);
        assert_eq!(
            snapshot.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.zulu.svc:80"]
        );
        assert_eq!(snapshot.certificates.len(), 1);
        assert_eq!(owners["api.example.test"], "zulu");
        assert_eq!(
            cache.admitted(),
            BTreeSet::from([("zulu".to_owned(), "app".to_owned())])
        );
        // A newer TLS claim with its own valid certificate does not evict
        // the older owner either.
        cache.upsert(
            ResourceKind::Secret,
            secret_in("alpha", "api-tls", "api.example.test"),
        );
        cache.upsert(ResourceKind::Ingress, attacker(Some("api-tls")));
        let (snapshot, owners) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 1);
        assert_eq!(
            snapshot.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.zulu.svc:80"]
        );
        assert_eq!(snapshot.certificates.len(), 1);
        assert_eq!(owners["api.example.test"], "zulu");
        // Ownership survives while the older object still claims the host,
        // even if it is temporarily withdrawn for a missing Secret.
        cache.delete(ResourceKind::Secret, "zulu", "api-tls");
        let (snapshot, owners) = cache.publish();
        assert!(snapshot.config.http.is_empty());
        assert!(snapshot.certificates.is_empty());
        assert_eq!(owners["api.example.test"], "zulu");
        // Once the older object is gone the host goes to the remaining
        // claimant.
        cache.delete(ResourceKind::Ingress, "zulu", "app");
        let (snapshot, owners) = cache.publish();
        assert_eq!(
            snapshot.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.alpha.svc:80"]
        );
        assert_eq!(owners["api.example.test"], "alpha");
        // Recreating the victim renews its timestamp: it is now the newcomer.
        cache.upsert(
            ResourceKind::Ingress,
            aged(victim, "2026-03-01T00:00:00Z", "0000-recreated"),
        );
        cache.upsert(
            ResourceKind::Secret,
            secret_in("zulu", "api-tls", "api.example.test"),
        );
        let (_, owners) = cache.publish();
        assert_eq!(owners["api.example.test"], "alpha");
    }
    #[test]
    fn ownership_depends_only_on_the_object_set() {
        // Two replicas that observed the same objects in different orders,
        // and one that observed a prior owner meanwhile deleted, all agree.
        let blue = aged(
            ingress_in("blue", "app", "api.example.test", None),
            "2026-01-01T00:00:00Z",
            "aaaa",
        );
        let red = aged(
            ingress_in("red", "app", "api.example.test", None),
            "2026-01-02T00:00:00Z",
            "bbbb",
        );
        let services = vec![service_in("blue"), service_in("red")];
        let mut cold = ResourceCache::default();
        cold.replace(ResourceKind::Service, services.clone(), 1000)
            .unwrap();
        cold.replace(ResourceKind::Ingress, vec![red.clone(), blue.clone()], 1000)
            .unwrap();
        let mut warm = ResourceCache::default();
        warm.replace(ResourceKind::Service, services, 1000).unwrap();
        warm.replace(ResourceKind::Ingress, vec![red.clone()], 1000)
            .unwrap();
        let (first, owners) = warm.publish();
        assert_eq!(owners["api.example.test"], "red");
        assert_eq!(
            first.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.red.svc:80"]
        );
        warm.upsert(ResourceKind::Ingress, blue.clone());
        let (from_history, warm_owners) = warm.publish();
        let (from_cold, cold_owners) = cold.publish();
        assert_eq!(from_history, from_cold);
        assert_eq!(warm_owners, cold_owners);
        assert_eq!(cold_owners["api.example.test"], "blue");
        assert_eq!(from_cold.config.http.len(), 1);
        assert_eq!(
            from_cold.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.blue.svc:80"]
        );
        // Equal timestamps are broken by uid, never by namespace order.
        let mut tied = cold.clone();
        tied.upsert(
            ResourceKind::Ingress,
            aged(red, "2026-01-01T00:00:00Z", "0000"),
        );
        let (snapshot, owners) = tied.publish();
        assert_eq!(owners["api.example.test"], "red");
        assert_eq!(
            snapshot.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.red.svc:80"]
        );
        // Objects without a timestamp sort after every dated object.
        let mut undated = cold.clone();
        undated.upsert(
            ResourceKind::Ingress,
            ingress_in("alpha", "app", "api.example.test", None),
        );
        let (_, owners) = undated.publish();
        assert_eq!(owners["api.example.test"], "blue");
    }
    #[test]
    fn exact_and_wildcard_hosts_cannot_be_owned_by_different_namespaces() {
        let exact = |created: &str| {
            aged(
                ingress_in("app", "exact", "api.example.test", None),
                created,
                "exact",
            )
        };
        let wild = aged(
            ingress_in("platform", "wild", "*.example.test", None),
            "2026-01-02T00:00:00Z",
            "wild",
        );
        let mut cache = ResourceCache::default();
        cache
            .replace(
                ResourceKind::Service,
                vec![service_in("app"), service_in("platform")],
                1000,
            )
            .unwrap();
        // The wildcard is older: the newer exact host is rejected.
        cache
            .replace(
                ResourceKind::Ingress,
                vec![exact("2026-01-03T00:00:00Z"), wild.clone()],
                1000,
            )
            .unwrap();
        let (snapshot, owners) = cache.publish();
        assert_eq!(hosts(&snapshot), [Some("*.example.test".to_owned())]);
        assert_eq!(
            owners,
            HostOwners::from([("*.example.test".to_owned(), "platform".to_owned())])
        );
        // The exact host is older: the wildcard is rejected.
        cache.upsert(ResourceKind::Ingress, exact("2026-01-01T00:00:00Z"));
        let (snapshot, owners) = cache.publish();
        assert_eq!(hosts(&snapshot), [Some("api.example.test".to_owned())]);
        assert_eq!(
            owners,
            HostOwners::from([("api.example.test".to_owned(), "app".to_owned())])
        );
        // A wildcard blocked by one older exact host does not also block a
        // younger exact host elsewhere.
        cache.upsert(
            ResourceKind::Ingress,
            aged(
                ingress_in("app", "web", "web.example.test", None),
                "2026-01-04T00:00:00Z",
                "web",
            ),
        );
        let (snapshot, _) = cache.publish();
        assert_eq!(
            hosts(&snapshot),
            [
                Some("api.example.test".to_owned()),
                Some("web.example.test".to_owned())
            ]
        );
        // The same namespace may hold both, and exact routes come first.
        cache.upsert(
            ResourceKind::Ingress,
            ingress_in("platform", "exact2", "api.example.test", None),
        );
        cache.delete(ResourceKind::Ingress, "app", "exact");
        cache.delete(ResourceKind::Ingress, "app", "web");
        let (snapshot, owners) = cache.publish();
        assert_eq!(
            hosts(&snapshot),
            [
                Some("api.example.test".to_owned()),
                Some("*.example.test".to_owned())
            ]
        );
        assert_eq!(owners["api.example.test"], "platform");
        assert_eq!(owners["*.example.test"], "platform");
    }
    #[test]
    fn catch_all_routes_are_owned_by_one_namespace() {
        let mut cache = ResourceCache::default();
        cache
            .replace(
                ResourceKind::Service,
                vec![service_in("alpha"), service_in("zulu")],
                1000,
            )
            .unwrap();
        let hostless = |namespace: &str, created: &str| {
            aged(
                json!({"metadata":{"name":"catch","namespace":namespace},"spec":{"ingressClassName":"hangang","rules":[{"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}}),
                created,
                namespace,
            )
        };
        let default = aged(
            json!({"metadata":{"name":"default","namespace":"alpha"},"spec":{"ingressClassName":"hangang","defaultBackend":{"service":{"name":"api","port":{"number":80}}}}}),
            "2026-01-03T00:00:00Z",
            "default",
        );
        cache
            .replace(
                ResourceKind::Ingress,
                vec![
                    hostless("alpha", "2026-01-02T00:00:00Z"),
                    hostless("zulu", "2026-01-01T00:00:00Z"),
                    default,
                ],
                1000,
            )
            .unwrap();
        let (snapshot, owners) = cache.publish();
        assert_eq!(snapshot.config.http.len(), 1);
        assert_eq!(
            snapshot.config.http[0]
                .backends
                .iter()
                .map(|backend| backend.address())
                .collect::<Vec<_>>(),
            ["http://api.zulu.svc:80"]
        );
        assert_eq!(
            owners,
            HostOwners::from([(CATCH_ALL_HOST.to_owned(), "zulu".to_owned())])
        );
    }
    #[test]
    fn wildcard_tls_claim_requires_a_wildcard_san() {
        let mut cache = ResourceCache::default();
        cache
            .replace(ResourceKind::Service, vec![service_in("blue")], 1000)
            .unwrap();
        cache
            .replace(
                ResourceKind::Ingress,
                vec![ingress("wild", "*.example.test", "wild")],
                1000,
            )
            .unwrap();
        // Only the resolver's probe name: verify_server_name accepts it for
        // the probe, but no real subdomain could ever be served.
        cache
            .replace(
                ResourceKind::Secret,
                vec![secret("wild", "hangang-certificate-check.example.test")],
                1000,
            )
            .unwrap();
        let (snapshot, _) = cache.publish();
        assert!(snapshot.config.http.is_empty());
        assert!(snapshot.certificates.is_empty());
        cache.upsert(ResourceKind::Secret, secret("wild", "*.example.test"));
        let (snapshot, _) = cache.publish();
        assert_eq!(hosts(&snapshot), [Some("*.example.test".to_owned())]);
        assert_eq!(snapshot.certificates.len(), 1);
        assert_eq!(snapshot.certificates[0].hosts, ["*.example.test"]);
    }
    #[test]
    fn aggregate_budget_withdraws_only_the_excess_ingress_and_secret_withdrawal_converges() {
        let mut cache = cache();
        let paths: Vec<Value> = (0..ingress::MAX_ROUTES)
            .map(|i| json!({"path":format!("/p{i}"),"pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}))
            .collect();
        let big = json!({"metadata":{"name":"z-big","namespace":"blue"},"spec":{"ingressClassName":"hangang","rules":[{"host":"big.example","http":{"paths":paths}}]}});
        cache.delete(ResourceKind::Ingress, "blue", "z-bad");
        cache.upsert(ResourceKind::Ingress, big);
        // Individually valid, but 1 + 1024 routes exceed the aggregate budget:
        // only the object that overflows it is withdrawn, and it is not
        // admitted for status publication either.
        let (snapshot, _) = cache.publish();
        assert_eq!(hosts(&snapshot), [Some("good.example".to_owned())]);
        assert_eq!(snapshot.certificates.len(), 1);
        assert_eq!(
            cache.admitted(),
            BTreeSet::from([("blue".to_owned(), "a-good".to_owned())])
        );
        // Deleting the claimed Secret still withdraws the route and its
        // certificate while the over-budget object stays excluded.
        cache.delete(ResourceKind::Secret, "blue", "good");
        let (snapshot, _) = cache.publish();
        assert!(snapshot.config.http.is_empty());
        assert!(snapshot.certificates.is_empty());
        cache.upsert(ResourceKind::Secret, secret("good", "good.example"));
        let (snapshot, _) = cache.publish();
        assert_eq!(hosts(&snapshot), [Some("good.example".to_owned())]);
        assert_eq!(snapshot.certificates.len(), 1);
    }
    #[test]
    fn status_lists_are_merged_never_replaced() {
        let ours = address_entry("192.0.2.1");
        let other = json!({"ip":"192.0.2.9"});
        let tagged = json!({"ip":"192.0.2.1","ports":[{"port":443,"protocol":"TCP"}]});
        assert_eq!(
            merge_entries(&[], &ours, Desired::Add),
            std::slice::from_ref(&ours)
        );
        assert_eq!(
            merge_entries(std::slice::from_ref(&other), &ours, Desired::Add),
            [other.clone(), ours.clone()]
        );
        // Another writer's richer entry for our address counts as present.
        assert_eq!(
            merge_entries(std::slice::from_ref(&tagged), &ours, Desired::Add),
            std::slice::from_ref(&tagged)
        );
        assert_eq!(
            merge_entries(&[other.clone(), tagged], &ours, Desired::Remove),
            std::slice::from_ref(&other)
        );
        assert_eq!(
            merge_entries(std::slice::from_ref(&other), &ours, Desired::Remove),
            std::slice::from_ref(&other)
        );
        let name = address_entry("lb.example.test");
        assert!(carries(&json!({"hostname":"lb.example.test"}), &name));
        assert!(!carries(&json!({"ip":"lb.example.test"}), &name));
    }
    impl StatusQueue {
        /// Queue one request without pruning anything else.
        fn enqueue(&self, key: ObjectKey, desired: Desired, object: Arc<Value>) {
            let mut keep: BTreeSet<ObjectKey> = self.lock().queued.keys().cloned().collect();
            keep.insert(key.clone());
            self.sync(&keep, vec![(key, desired, object)]);
        }
    }
    #[test]
    fn status_queue_coalesces_and_skips_work_the_cache_has_not_seen_yet() {
        let queue = StatusQueue::new(1000);
        let key = ("blue".to_owned(), "main".to_owned());
        let at = |rv: &str| Arc::new(json!({"metadata":{"resourceVersion":rv}}));
        queue.enqueue(key.clone(), Desired::Add, at("11"));
        queue.enqueue(key.clone(), Desired::Remove, at("11"));
        let (started, request) = queue.start().unwrap();
        assert_eq!(started, key);
        assert_eq!(request.desired, Desired::Remove);
        // The same work is not queued again while it is in flight, but a
        // different desire for the object is.
        queue.enqueue(key.clone(), Desired::Remove, at("11"));
        assert!(queue.start().is_none());
        queue.enqueue(key.clone(), Desired::Add, at("11"));
        assert!(queue.start().is_none(), "one patch per object at a time");
        queue.complete(
            key.clone(),
            ("11".into(), Desired::Remove),
            Ok(Some(json!({"metadata":{"resourceVersion":"12"}}))),
        );
        let (_, request) = queue.start().unwrap();
        assert_eq!(request.desired, Desired::Add);
        queue.complete(
            key.clone(),
            ("11".into(), Desired::Add),
            Ok(Some(json!({"metadata":{"resourceVersion":"13"}}))),
        );
        // Completed work is skipped until the cache has absorbed the result.
        queue.enqueue(key.clone(), Desired::Add, at("11"));
        assert!(queue.start().is_none());
        assert_eq!(queue.take_results().len(), 2);
        queue.enqueue(key.clone(), Desired::Add, at("11"));
        assert!(queue.start().is_some());
        // Failures release the object for the next event.
        queue.complete(
            key.clone(),
            ("11".into(), Desired::Add),
            Err(anyhow::anyhow!("x")),
        );
        queue.enqueue(key, Desired::Add, at("11"));
        assert!(queue.start().is_some());
    }
    /// Create/delete churn with unique names while every patch stalls: the
    /// queue must follow the live objects, not the history, and must not be
    /// the last owner of objects the cache already released.
    #[test]
    fn status_queue_follows_the_live_cache_under_churn_with_stalled_patches() {
        let mut cache = ResourceCache::default();
        cache
            .replace(ResourceKind::Service, vec![service_in("blue")], 1000)
            .unwrap();
        cache
            .replace(
                ResourceKind::Ingress,
                vec![ingress_in("blue", "main", "main.example", None)],
                1000,
            )
            .unwrap();
        let queue = StatusQueue::new(20);
        let sync = |cache: &ResourceCache, queue: &StatusQueue| {
            let admitted = cache.admitted();
            sync_statuses(queue, cache, Some(&admitted), "hangang", "192.0.2.1");
        };
        sync(&cache, &queue);
        // The worker takes `main` and stalls on it for the whole test.
        let (started, _) = queue.start().unwrap();
        assert_eq!(started, ("blue".to_owned(), "main".to_owned()));
        assert_eq!(queue.queued_len(), 0);
        let mut released = Vec::new();
        for index in 0..200 {
            let name = format!("churn-{index}");
            cache.upsert(
                ResourceKind::Ingress,
                ingress_in("blue", &name, &format!("{name}.example"), None),
            );
            sync(&cache, &queue);
            assert_eq!(queue.queued_len(), 1, "one live object, one queued request");
            let handle = cache
                .entries(ResourceKind::Ingress)
                .find(|object| object["metadata"]["name"] == name)
                .cloned()
                .unwrap();
            cache.delete(ResourceKind::Ingress, "blue", &name);
            sync(&cache, &queue);
            assert_eq!(
                queue.queued_len(),
                0,
                "work for a deleted object stayed queued at {index}"
            );
            released.push(handle);
        }
        // The test's clones are the only remaining owners: nothing retains
        // the deleted objects' bytes.
        assert!(
            released.iter().all(|handle| Arc::strong_count(handle) == 1),
            "the queue still owns released objects"
        );
        // A rejected candidate prunes but queues nothing.
        cache.upsert(
            ResourceKind::Ingress,
            ingress_in("blue", "late", "late.example", None),
        );
        sync_statuses(&queue, &cache, None, "hangang", "192.0.2.1");
        assert_eq!(queue.queued_len(), 0);
        sync(&cache, &queue);
        assert_eq!(queue.queued_len(), 1);
        cache.delete(ResourceKind::Ingress, "blue", "late");
        sync_statuses(&queue, &cache, None, "hangang", "192.0.2.1");
        assert_eq!(
            queue.queued_len(),
            0,
            "a rejected candidate must still prune"
        );
        // Selection changes prune too, and the explicit limit is the last
        // line of defence.
        cache.upsert(
            ResourceKind::Ingress,
            ingress_in("blue", "late", "late.example", None),
        );
        sync(&cache, &queue);
        let mut other = ingress_in("blue", "late", "late.example", None);
        other["spec"]["ingressClassName"] = "other".into();
        cache.upsert(ResourceKind::Ingress, other);
        sync(&cache, &queue);
        assert_eq!(queue.queued_len(), 0, "an unselected object stayed queued");
        let small = StatusQueue::new(3);
        for index in 0..5 {
            small.enqueue(
                ("blue".to_owned(), format!("n{index}")),
                Desired::Add,
                Arc::new(json!({"metadata":{"resourceVersion":"1"}})),
            );
        }
        assert_eq!(small.queued_len(), 3);
    }
    #[test]
    fn conflict_reread_must_describe_the_object_the_decision_was_made_for() {
        let queued = json!({"metadata":{"name":"app","uid":"u1","generation":3},"spec":{"ingressClassName":"hangang"}});
        assert!(same_target(&queued, &queued, "hangang"));
        let mut newer_status = queued.clone();
        newer_status["metadata"]["resourceVersion"] = "99".into();
        newer_status["status"] = json!({"loadBalancer":{"ingress":[{"ip":"192.0.2.9"}]}});
        assert!(
            same_target(&queued, &newer_status, "hangang"),
            "a status-only change keeps the target"
        );
        let mut recreated = queued.clone();
        recreated["metadata"]["uid"] = "u2".into();
        assert!(!same_target(&queued, &recreated, "hangang"));
        let mut respecified = queued.clone();
        respecified["metadata"]["generation"] = 4.into();
        assert!(!same_target(&queued, &respecified, "hangang"));
        let mut reclassed = queued.clone();
        reclassed["spec"]["ingressClassName"] = "other".into();
        assert!(!same_target(&queued, &reclassed, "hangang"));
        let mut unmarked = queued.clone();
        unmarked["metadata"].as_object_mut().unwrap().remove("uid");
        assert!(!same_target(&queued, &unmarked, "hangang"));
        // Servers that omit uid and generation compare equal on them.
        let bare = json!({"metadata":{"name":"app"},"spec":{"ingressClassName":"hangang"}});
        assert!(same_target(&bare, &bare, "hangang"));
        let stripped = strip(ResourceKind::Ingress, &queued);
        assert_eq!(stripped["metadata"]["uid"], "u1");
        assert_eq!(stripped["metadata"]["generation"], 3);
        assert_eq!(
            status_view(&newer_status),
            json!({"metadata":{"resourceVersion":"99"},"status":{"loadBalancer":{"ingress":[{"ip":"192.0.2.9"}]}}})
        );
    }
    #[test]
    fn jitter_stays_within_twenty_percent() {
        let base = Duration::from_secs(5);
        let mut distinct = BTreeSet::new();
        for _ in 0..64 {
            let value = jitter(base);
            assert!(value >= Duration::from_secs(4) && value <= Duration::from_secs(6));
            distinct.insert(value);
        }
        assert!(distinct.len() > 1, "jitter never varied");
    }
}
