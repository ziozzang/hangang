use crate::config::{HttpRoute, HttpRuntime, Snapshot};
use crate::metrics::Metrics;
use crate::policy::{PolicyInput, PolicyPool};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Body as _;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::{BTreeMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::future::Future;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug)]
pub struct BodyError(BoxError);

impl BodyError {
    pub fn from_error(error: impl Error + Send + Sync + 'static) -> Self {
        Self(Box::new(error))
    }
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl Error for BodyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
impl From<reqwest::Error> for BodyError {
    fn from(error: reqwest::Error) -> Self {
        Self(Box::new(error))
    }
}

impl From<http_body_util::LengthLimitError> for BodyError {
    fn from(error: http_body_util::LengthLimitError) -> Self {
        Self(Box::new(error))
    }
}

#[derive(Clone, Copy)]
struct ResponseSecurityFinalized;

pub type Body = http_body_util::combinators::UnsyncBoxBody<Bytes, BodyError>;

/// A legacy trusted peer receives a local one-second cap; explicit TTL is stricter.
fn native_evidence_expiry(
    headers: &HeaderMap,
    started: std::time::Instant,
) -> Option<std::time::Instant> {
    let mut values = headers.get_all("x-hopae-evidence-ttl-ms").iter();
    let ttl = match values.next() {
        Some(value) => {
            let text = value.to_str().ok()?;
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            text.parse::<u64>()
                .ok()
                .filter(|v| (1..=1000).contains(v))?
        }
        None => 1000,
    };
    if values.next().is_some() {
        return None;
    }
    let expiry = started.checked_add(Duration::from_millis(ttl))?;
    (std::time::Instant::now() < expiry).then_some(expiry)
}

enum MachineLease {
    Fixed(std::time::Instant),
    Renewing(Arc<Renewal>),
}
static RENEWAL_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4096);
struct Renewal {
    expires: std::sync::Mutex<std::time::Instant>,
    failed: std::sync::atomic::AtomicBool,
    task: std::sync::Mutex<Option<tokio::task::AbortHandle>>,
    _slot: tokio::sync::SemaphorePermit<'static>,
}
impl Drop for Renewal {
    fn drop(&mut self) {
        if let Some(task) = self
            .task
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            task.abort();
        }
    }
}
impl Renewal {
    fn current(&self) -> bool {
        let current = !self.failed.load(Ordering::Acquire)
            && self
                .expires
                .lock()
                .is_ok_and(|expiry| std::time::Instant::now() < *expiry);
        if !current {
            self.failed.store(true, Ordering::Release);
        }
        current
    }
    fn identity(headers: &HeaderMap) -> Option<Vec<HeaderValue>> {
        [
            "x-forwarded-user",
            "x-hopae-principal-kind",
            "x-hopae-aal",
            "x-hopae-service-id",
        ]
        .into_iter()
        .map(|name| {
            let mut values = headers.get_all(name).iter();
            let value = values.next()?.clone();
            values.next().is_none().then_some(value)
        })
        .collect()
    }
    fn start(
        client: Arc<crate::hopae_native::Client>,
        mut context: HeaderMap,
        headers: &HeaderMap,
        started: std::time::Instant,
    ) -> Option<Arc<Self>> {
        if !headers.contains_key("x-hopae-evidence-ttl-ms") {
            return None;
        }
        let expires = native_evidence_expiry(headers, started)?;
        if expires.saturating_duration_since(std::time::Instant::now()) < Duration::from_millis(100)
        {
            return None;
        }
        let identity = Self::identity(headers)?;
        for value in context.values_mut() {
            value.set_sensitive(true);
        }
        let lease = Arc::new(Self {
            expires: std::sync::Mutex::new(expires),
            failed: std::sync::atomic::AtomicBool::new(false),
            task: std::sync::Mutex::new(None),
            _slot: RENEWAL_SLOTS.try_acquire().ok()?,
        });
        let weak = Arc::downgrade(&lease);
        let task = tokio::spawn(async move {
            loop {
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let expiry = match state.expires.lock() {
                    Ok(v) => *v,
                    Err(_) => return,
                };
                if !state.current() {
                    return;
                }
                let delay = expiry.saturating_duration_since(std::time::Instant::now()) / 2;
                drop(state);
                tokio::time::sleep(delay).await;
                let Some(state) = weak.upgrade() else {
                    return;
                };
                if !state.current() {
                    return;
                }
                // Retain only a Weak reference across I/O so dropping the stream
                // immediately aborts verification and drops its private context.
                drop(state);
                let began = std::time::Instant::now();
                let remaining = expiry.saturating_duration_since(began);
                let reply = tokio::time::timeout(remaining, client.verify(&context)).await;
                let Some(state) = weak.upgrade() else {
                    return;
                };
                let renewed = match reply {
                    Ok(Ok(reply))
                        if reply.status().is_success()
                            && reply.headers().contains_key("x-hopae-evidence-ttl-ms")
                            && Self::identity(reply.headers()).as_ref() == Some(&identity) =>
                    {
                        native_evidence_expiry(reply.headers(), began).filter(|deadline| {
                            deadline.saturating_duration_since(std::time::Instant::now())
                                >= Duration::from_millis(100)
                        })
                    }
                    _ => None,
                };
                if !state.current() || renewed.is_none() {
                    state.failed.store(true, Ordering::Release);
                    return;
                }
                match state.expires.lock() {
                    Ok(mut deadline) => {
                        if state.failed.load(Ordering::Acquire)
                            || std::time::Instant::now() >= *deadline
                        {
                            state.failed.store(true, Ordering::Release);
                            return;
                        }
                        *deadline = renewed.unwrap();
                    }
                    Err(_) => {
                        state.failed.store(true, Ordering::Release);
                        return;
                    }
                };
            }
        });
        *lease.task.lock().ok()? = Some(task.abort_handle());
        Some(lease)
    }
}

/// Fixed native route context. Only the selected immutable runtime supplies it.
#[derive(Clone, Copy)]
struct NativeAuthorization<'a> {
    class: crate::native_observed::AuthenticationClass,
    issuer: &'a str,
    route_id: &'a str,
    canonical_path: Option<&'a str>,
}
impl NativeAuthorization<'_> {
    fn apply(self, headers: &mut HeaderMap) -> Result<(), u16> {
        if self.class != crate::native_observed::AuthenticationClass::Human {
            return Ok(());
        }
        let path = self.canonical_path.ok_or(503u16)?;
        // AFTER configured/static headers: client or configured lookalikes
        // cannot override the exact selected route or canonical ingress path.
        headers.insert("x-hopae-contract", HeaderValue::from_static("1"));
        headers.insert(
            "x-hangang-route-id",
            HeaderValue::from_str(self.route_id).map_err(|_| 503u16)?,
        );
        headers.insert(
            "x-hangang-canonical-path",
            HeaderValue::from_str(path).map_err(|_| 503u16)?,
        );
        Ok(())
    }
}

/// Result of an external authorization call.
enum AuthOutcome {
    /// 2xx: forward the request, injecting these copied response headers.
    /// The second value carries `Set-Cookie` fields from the authorization
    /// response (session refresh) to append to the final client response when
    /// `forward_response` is enabled. Scope binds a native machine to its service;
    /// the final tuple is authenticated point-query metadata, not a capability.
    Allow(
        HeaderMap,
        Vec<HeaderValue>,
        Option<String>,
        Option<MachineLease>,
        Option<(String, u8)>, // authenticated typed point-query metadata, not a capability
    ),
    /// Fail closed with this status and a generic message.
    Deny(u16),
    /// Forward this response (SSO redirect/challenge) to the client verbatim.
    Forward(Box<Response<Body>>),
}

const MAX_INSPECT_BODY: usize = 1024 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_TUNNEL_IDLE: Duration = Duration::from_secs(60);

// Default-client upstream connect timeout, set once at startup by the parent.
static CONNECT_TIMEOUT: std::sync::OnceLock<Duration> = std::sync::OnceLock::new();

pub fn set_connect_timeout(timeout: Duration) {
    let _ = CONNECT_TIMEOUT.set(timeout);
}

fn connect_timeout() -> Duration {
    *CONNECT_TIMEOUT.get().unwrap_or(&Duration::from_secs(3))
}

enum FailureObservation {
    Local(IpAddr, crate::path_failure_bans::Observation),
    Redis(IpAddr, crate::security_redis::Observation),
}
#[derive(Clone)]
struct FailureCapture(Arc<std::sync::Mutex<Option<FailureObservation>>>);
#[derive(Clone)]
struct SecurityCountry(crate::country_observation::Observation);

fn security_view<B>(request: &Request<B>) -> Request<()> {
    let mut view = Request::new(());
    *view.uri_mut() = request.uri().clone();
    *view.method_mut() = request.method().clone();
    if let Some(host) = request.headers().get(header::HOST) {
        view.headers_mut().insert(header::HOST, host.clone());
    }
    view
}

fn security_denied(status: u16) -> Response<Body> {
    let mut denied = response(
        status,
        match status {
            429 => "too many requests",
            404 => "not found",
            403 => "forbidden",
            400 => "bad request",
            _ => "service unavailable",
        },
    );
    denied
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    if status == 429 {
        denied
            .headers_mut()
            .insert("retry-after", HeaderValue::from_static("1"));
    }
    denied
}

#[derive(Clone)]
pub struct Proxy {
    guard: Option<Arc<crate::guard::GuardClient>>,
    /// Hopae risk contexts (ADR-0023): key and level thresholds.
    risk_context: Option<Arc<crate::risk_context::Settings>>,
    /// ADR 0019 decision events; `None` (the default) captures nothing.
    decisions: Option<Arc<crate::decision::Emitter>>,
    request_inspectors: Arc<tokio::sync::Semaphore>,
    native_bodies: Arc<tokio::sync::Semaphore>,
    native_routes: Arc<crate::native_route_owner::Registry>,
    route_owner_queries: bool,
    request_spools: Arc<crate::request_block_spool::Pool>,
    acme_http01: Arc<crate::acme_http01::Admission>,
    active: Arc<ArcSwap<Snapshot>>,
    policy: Arc<PolicyPool>,
    metrics: Arc<Metrics>,
    traffic: Option<Arc<crate::traffic::TrafficHistory>>,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    outbound: Arc<crate::http_outbound::Pools>,
    requests: Arc<tokio::sync::Semaphore>,
    inspections: Arc<tokio::sync::Semaphore>,
    jwt_verifications: Arc<tokio::sync::Semaphore>,
    transformations: Arc<tokio::sync::Semaphore>,
    discovery: Arc<arc_swap::ArcSwapOption<crate::discovery::Discovery>>,
    // Optional unauthenticated health path on the public listener, for external
    // load balancers that cannot present the admin bearer token.
    health_path: Option<Arc<str>>,
    // Readiness shared with the control plane; false until a controller's first
    // reconcile completes. Normal/file mode is ready from start.
    ready: Arc<std::sync::atomic::AtomicBool>,
    // When false (default), requests whose path contains `.`/`..` dot segments
    // (raw or percent-encoded) are rejected. This keeps route matching and the
    // forwarded path in agreement, closing a path-confusion authorization
    // bypass against prefix routes. Set true to forward raw dot segments.
    allow_dot_segments: bool,
    // Fallback time budget for the upstream to return response headers, used
    // when a route does not set its own `upstream_timeout_ms`.
    default_upstream_timeout: Duration,
    // CIDRs whose peers are trusted to supply forwarding headers. When the
    // socket peer is in this set, the effective client IP/proto/host/port are
    // taken from the incoming X-Forwarded-* headers instead of the socket.
    trusted_proxies: Arc<Vec<ipnet::IpNet>>,
    // Response headers removed from every upstream response (e.g. `server`),
    // streaming-safe. Per-route rules are in the route's response_*_headers.
    remove_response_headers: Arc<Vec<HeaderName>>,
    // Status used to redirect plaintext requests on require_tls routes: a 3xx
    // sends a Location to the https URL; 426 sends Upgrade Required (no Location).
    https_redirect_code: u16,
    // Emit a per-request access log line (target `hangang::access`) with client,
    // method, host, path, status and time-to-response-head latency.
    access_log: bool,
    // Idle budget for an upgraded (WebSocket) tunnel. The listener's transport
    // idle watchdog ends when hyper hands the socket to the tunnel, so the
    // tunnel keeps its own watch over the downstream bytes in both directions.
    tunnel_idle: Duration,
    pub tunnels: TaskTracker,
    pub shutdown: CancellationToken,
    // A per-request clone must not cancel every active connection when it is
    // dropped. The final shared guard owns shutdown of background probes.
    _shutdown_guard: Arc<ShutdownGuard>,
}

struct ShutdownGuard(CancellationToken);

struct TrafficContext {
    geoip: crate::country_observation::Observation,
    peer_ip: IpAddr,
    peer_port: u16,
    client_ip: IpAddr,
    // Method/URI clones share their parsed backing storage with the request.
    // The full path remains available for policy matching without allocating
    // another potentially long attacker-controlled path per active request.
    method: Method,
    uri: Uri,
    route_id: Option<String>,
    listener: crate::traffic::ListenerInput,
    protocol: &'static str,
    tls: bool,
    started: std::time::Instant,
}

impl TrafficContext {
    fn new(request: &Request<Incoming>, peer: SocketAddr) -> Self {
        // Listener evidence is inserted by the accepting server, never read
        // from request headers. Named evidence wins over generic transport.
        let listener = if let Some(evidence) =
            request.extensions().get::<crate::public_http::Evidence>()
        {
            crate::traffic::ListenerInput::Public(evidence.listener_id().to_owned())
        } else if let Some(evidence) = request.extensions().get::<crate::workload_http::Evidence>()
        {
            crate::traffic::ListenerInput::Workload(evidence.listener_id().to_owned())
        } else if request
            .extensions()
            .get::<crate::tls::TransportInfo>()
            .is_some()
        {
            crate::traffic::ListenerInput::Default
        } else {
            crate::traffic::ListenerInput::Unknown
        };
        Self {
            geoip: Default::default(),
            peer_ip: peer.ip(),
            peer_port: peer.port(),
            client_ip: peer.ip(),
            method: request.method().clone(),
            uri: if crate::acme_http01::shaped(request.uri().path()) {
                Uri::from_static("/.well-known/acme-challenge/_redacted")
            } else {
                request.uri().clone()
            },
            route_id: None,
            listener,
            protocol: if request.version() == Version::HTTP_2 {
                "h2"
            } else {
                "h1"
            },
            tls: request
                .extensions()
                .get::<crate::tls::TransportInfo>()
                .is_some_and(|info| info.tls),
            started: std::time::Instant::now(),
        }
    }

    fn record(&self, history: &crate::traffic::TrafficHistory, status: u16, policy_revision: u64) {
        history.record_with_policy_revision(
            crate::traffic::TrafficInput {
                geoip: Some(&self.geoip),
                peer_ip: self.peer_ip,
                peer_port: self.peer_port,
                client_ip: self.client_ip,
                method: self.method.as_str(),
                path: self.uri.path(),
                route_id: self.route_id.as_deref(),
                listener: self.listener.clone(),
                status,
                response_head_ms: self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                protocol: self.protocol,
                tls: self.tls,
            },
            policy_revision,
        );
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// A long response or upgraded tunnel retains both listener and route policy
/// generations. Unrelated publications can reuse the prepared route Arc.
#[derive(Clone)]
struct WorkloadRouteLease {
    active: Arc<ArcSwap<Snapshot>>,
    route_id: String,
    runtime: Arc<crate::workload_auth::Runtime>,
    evidence: crate::workload_http::Evidence,
}

impl WorkloadRouteLease {
    fn current(&self) -> bool {
        let snapshot = self.active.load();
        self.evidence.current(&snapshot)
            && snapshot
                .workload_routes
                .get(&self.route_id)
                .is_some_and(|runtime| Arc::ptr_eq(runtime, &self.runtime))
    }
}

#[derive(Clone)]
struct JwtRouteLease {
    active: Arc<ArcSwap<Snapshot>>,
    route_id: String,
    route: Arc<HttpRoute>,
    runtime: Arc<crate::jwt_runtime::Runtime>,
    session: crate::jwt_runtime::Session,
}

impl JwtRouteLease {
    fn current(&self) -> bool {
        let snapshot = self.active.load();
        snapshot
            .jwt_routes
            .get(&self.route_id)
            .is_some_and(|route| Arc::ptr_eq(route, &self.route))
            && self.runtime.session_current(&self.session)
    }
}

#[derive(Clone, Default)]
struct AuthRouteLease {
    /// The native request retains its exact activated snapshot, not a caller's
    /// revision claim. Even equal-revision fresh-authority replacement retires it.
    native_snapshot: Option<(Arc<ArcSwap<Snapshot>>, Arc<Snapshot>)>,
    pumgye: Option<(Arc<ArcSwap<Snapshot>>, u64)>,
    pumgye_remote: Option<(Arc<crate::pumgye::AuthorityRuntime>, u64)>,
    workload: Option<WorkloadRouteLease>,
    jwt: Option<JwtRouteLease>,
    hopae_expires: Option<std::time::Instant>,
    hopae_renewal: Option<Arc<Renewal>>,
}

#[derive(Clone, Copy, Default)]
struct AuthRetirement {
    native_route: bool,
    pumgye: bool,
    workload: bool,
    jwt: bool,
    hopae: bool,
}

impl AuthRetirement {
    fn any(self) -> bool {
        self.native_route || self.workload || self.jwt || self.pumgye || self.hopae
    }

    fn record(self, metrics: &Metrics) {
        if self.workload {
            metrics
                .workload_route_terminations
                .fetch_add(1, Ordering::Relaxed);
        }
        if self.jwt {
            metrics
                .jwt_lease_terminations
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl AuthRouteLease {
    fn retirement(&self) -> AuthRetirement {
        AuthRetirement {
            native_route: self
                .native_snapshot
                .as_ref()
                .is_some_and(|(active, captured)| !Arc::ptr_eq(&active.load(), captured)),
            pumgye: self
                .pumgye
                .as_ref()
                .is_some_and(|(active, revision)| active.load().config.revision != *revision)
                || self
                    .pumgye_remote
                    .as_ref()
                    .is_some_and(|(runtime, revision)| !runtime.lease_current(*revision)),
            workload: self.workload.as_ref().is_some_and(|lease| !lease.current()),
            jwt: self.jwt.as_ref().is_some_and(|lease| !lease.current()),
            hopae: self
                .hopae_expires
                .is_some_and(|expiry| std::time::Instant::now() >= expiry)
                || self
                    .hopae_renewal
                    .as_ref()
                    .is_some_and(|lease| !lease.current()),
        }
    }

    async fn revoked(&self) -> AuthRetirement {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let retired = self.retirement();
            if retired.any() {
                return retired;
            }
        }
    }
}

async fn auth_retired(lease: Option<&AuthRouteLease>) -> AuthRetirement {
    if let Some(lease) = lease {
        lease.revoked().await
    } else {
        std::future::pending::<AuthRetirement>().await
    }
}

fn retired_auth_response(
    lease: Option<&AuthRouteLease>,
    metrics: &Metrics,
) -> Option<Response<Body>> {
    let retired = lease?.retirement();
    if !retired.any() {
        return None;
    }
    retired.record(metrics);
    Some(response(503, "route authorization retired"))
}

// The Hyper connection watcher handles listener-material retirement; this
// body guard also retires a route whose workload or JWT rules changed while
// an SSE or other streaming response remains open.
struct AuthResponseBody {
    body: Body,
    lease: AuthRouteLease,
    timer: std::pin::Pin<Box<tokio::time::Sleep>>,
    metrics: Arc<Metrics>,
    terminated: bool,
}

impl AuthResponseBody {
    fn new(body: Body, lease: AuthRouteLease, metrics: Arc<Metrics>) -> Self {
        Self {
            body,
            lease,
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(250))),
            metrics,
            terminated: false,
        }
    }
}

impl hyper::body::Body for AuthResponseBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
        if self.terminated {
            return std::task::Poll::Ready(None);
        }
        let retired = self.lease.retirement();
        if retired.any() {
            self.terminated = true;
            retired.record(&self.metrics);
            return std::task::Poll::Ready(Some(Err(BodyError::from_error(
                std::io::Error::other("route authorization retired"),
            ))));
        }
        if self.timer.as_mut().poll(cx).is_ready() {
            self.timer
                .as_mut()
                .reset(tokio::time::Instant::now() + Duration::from_millis(250));
            // Register the next wake even when the upstream body is idle.
            let _ = self.timer.as_mut().poll(cx);
        }
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

impl Proxy {
    pub fn new(
        active: Arc<ArcSwap<Snapshot>>,
        policy: Arc<PolicyPool>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self::with_client_config(
            active,
            policy,
            metrics,
            crate::tls::client_config(None).expect("built-in TLS roots"),
        )
    }
    pub fn with_client_config(
        active: Arc<ArcSwap<Snapshot>>,
        policy: Arc<PolicyPool>,
        metrics: Arc<Metrics>,
        tls: rustls::ClientConfig,
    ) -> Self {
        Self::with_client_config_and_idle_limit(active, policy, metrics, tls, 256)
    }
    pub fn with_client_config_and_idle_limit(
        active: Arc<ArcSwap<Snapshot>>,
        policy: Arc<PolicyPool>,
        metrics: Arc<Metrics>,
        tls: rustls::ClientConfig,
        idle_per_host: usize,
    ) -> Self {
        let outbound = Arc::new(crate::http_outbound::Pools::new(tls.clone(), idle_per_host));
        let mut connector = HttpConnector::new();
        connector.enforce_http(false);
        connector.set_connect_timeout(Some(connect_timeout()));
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(connector);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(idle_per_host.clamp(1, 4096))
            .build(connector);
        let shutdown = CancellationToken::new();
        let discovery = Arc::new(arc_swap::ArcSwapOption::empty());
        crate::active_probe::spawn_monitor_with_discovery(
            active.clone(),
            outbound.clone(),
            discovery.clone(),
            shutdown.clone(),
        );
        let native_routes = crate::native_route_owner::Registry::new(active.clone(), 128)
            .expect("fixed native route capacity");
        Self {
            active,
            guard: None,
            risk_context: None,
            decisions: None,
            request_inspectors: Arc::new(tokio::sync::Semaphore::new(4)),
            native_bodies: Arc::new(tokio::sync::Semaphore::new(128)),
            native_routes,
            route_owner_queries: false,
            request_spools: Arc::new(crate::request_block_spool::Pool::new()),
            acme_http01: Arc::new(crate::acme_http01::Admission::new()),
            policy,
            metrics,
            traffic: None,
            client,
            outbound,
            requests: Arc::new(tokio::sync::Semaphore::new(4096)),
            inspections: Arc::new(tokio::sync::Semaphore::new(32)),
            jwt_verifications: crate::jwt_runtime::verification_admission(),
            transformations: Arc::new(tokio::sync::Semaphore::new(32)),
            discovery,
            health_path: None,
            ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            allow_dot_segments: false,
            default_upstream_timeout: HEADER_TIMEOUT,
            trusted_proxies: Arc::new(Vec::new()),
            remove_response_headers: Arc::new(Vec::new()),
            https_redirect_code: 308,
            access_log: false,
            tunnel_idle: DEFAULT_TUNNEL_IDLE,
            tunnels: TaskTracker::new(),
            _shutdown_guard: Arc::new(ShutdownGuard(shutdown.clone())),
            shutdown,
        }
    }

    pub fn with_route_owner_queries(mut self, enabled: bool) -> Self {
        self.route_owner_queries = enabled;
        self
    }
    pub fn route_owner_on(
        &self,
        prepared: crate::route_owner_grpc::PreparedConfiguration,
        listener: tokio::net::TcpListener,
    ) -> anyhow::Result<crate::route_owner_grpc::Server> {
        crate::route_owner_grpc::Server::from_listener(
            prepared,
            self.native_routes.clone(),
            listener,
        )
    }
    /// Prepare an independent read-only native route observation listener.
    /// Runtime/supervisor ownership of the returned server remains explicit.
    pub async fn bind_route_owner(
        &self,
        configuration: crate::route_owner_grpc::Configuration,
        forbidden_credentials: &[&str],
    ) -> anyhow::Result<crate::route_owner_grpc::Server> {
        crate::route_owner_grpc::Server::bind(
            configuration,
            self.native_routes.clone(),
            forbidden_credentials,
        )
        .await
    }
    pub fn with_decision_events(mut self, emitter: Option<Arc<crate::decision::Emitter>>) -> Self {
        self.decisions = emitter;
        self
    }

    pub fn with_guard(mut self, guard: Option<Arc<crate::guard::GuardClient>>) -> Self {
        self.guard = guard;
        self
    }

    pub fn with_risk_context(
        mut self,
        settings: Option<Arc<crate::risk_context::Settings>>,
    ) -> Self {
        self.risk_context = settings;
        self
    }

    pub fn with_health_path(mut self, path: Option<String>) -> Self {
        self.health_path = path.map(Arc::from);
        self
    }

    pub fn with_readiness(mut self, ready: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.ready = ready;
        self
    }

    pub fn with_dot_segments_allowed(mut self, allow: bool) -> Self {
        self.allow_dot_segments = allow;
        self
    }

    pub fn with_upstream_timeout(mut self, timeout: Duration) -> Self {
        self.default_upstream_timeout = timeout;
        self
    }

    pub fn with_trusted_proxies(mut self, cidrs: Vec<ipnet::IpNet>) -> Self {
        self.trusted_proxies = Arc::new(cidrs);
        self
    }

    /// Global response header removals. Framing/representation names
    /// (`content-length`, `content-encoding`, `content-range`, hop-by-hop) are
    /// dropped here as a runtime guard: the CLI rejects them up front via
    /// `config::is_protected_response_header`, and removing them from a
    /// streamed response would corrupt the client-visible representation.
    pub fn with_removed_response_headers(mut self, names: Vec<HeaderName>) -> Self {
        let names = names
            .into_iter()
            .filter(|name| {
                let allowed = !crate::config::is_protected_response_header(name.as_str());
                if !allowed {
                    tracing::warn!(header = %name, "ignoring protected global response header removal");
                }
                allowed
            })
            .collect();
        self.remove_response_headers = Arc::new(names);
        self
    }

    pub fn with_https_redirect_code(mut self, code: u16) -> Self {
        self.https_redirect_code = code;
        self
    }

    pub fn with_access_log(mut self, enabled: bool) -> Self {
        self.access_log = enabled;
        self
    }

    pub fn with_traffic_history(mut self, traffic: Arc<crate::traffic::TrafficHistory>) -> Self {
        self.traffic = Some(traffic);
        self
    }

    /// Idle budget for upgraded (WebSocket) tunnels; a tunnel with no bytes in
    /// either direction for this long is closed. Defaults to 60s.
    pub fn with_tunnel_idle_timeout(mut self, timeout: Duration) -> Self {
        self.tunnel_idle = timeout;
        self
    }

    fn https_redirect(
        &self,
        request: &Request<Body>,
        edge: &EdgeContext,
        code: u16,
    ) -> Response<Body> {
        if code == 426 {
            let mut denied = response(426, "TLS required");
            denied.headers_mut().insert(
                header::UPGRADE,
                HeaderValue::from_static("TLS/1.2, HTTP/1.1"),
            );
            denied
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("Upgrade"));
            return denied;
        }
        let host = edge
            .forwarded_host
            .as_ref()
            .and_then(|h| h.to_str().ok())
            .or_else(|| {
                request
                    .headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
            })
            .unwrap_or("");
        // Only a well-formed authority may become redirect URL text. Route
        // matching already fell back to the request-target authority when the
        // Host header did not parse; concatenating that raw Host (for example
        // `evil.test/#`) into Location would let the client choose the
        // redirect target's path structure. Drop any :port so the redirect
        // targets the default HTTPS port.
        let Some(host) = host
            .parse::<hyper::http::uri::Authority>()
            .ok()
            .filter(|a| !a.host().is_empty() && !a.as_str().contains('@'))
            .map(|a| a.host().to_owned())
        else {
            return response(StatusCode::BAD_REQUEST.as_u16(), "invalid Host");
        };
        let path = request
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");
        let mut redirect = response(code, "redirecting to https");
        if let Ok(value) = HeaderValue::from_str(&format!("https://{host}{path}")) {
            redirect.headers_mut().insert(header::LOCATION, value);
        }
        redirect
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize(
        &self,
        auth: &crate::config::ExternalAuth,
        static_headers: &[(HeaderName, HeaderValue)],
        native: Option<&Arc<crate::hopae_native::Client>>,
        expected: Option<NativeAuthorization<'_>>,
        original: &mut Request<Body>,
        edge: &EdgeContext,
        risk: Option<&crate::risk_context::Evidence>,
    ) -> AuthOutcome {
        let expected_class = expected.map(|scope| scope.class);
        let started = std::time::Instant::now();
        let operation = async move {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(&auth.url)
                .body(full_body(Bytes::new()))
                .map_err(|_| 503u16)?;
            *request.headers_mut() = auth_request_headers(auth, static_headers, original, edge)?;
            if let Some(scope) = expected {
                scope.apply(request.headers_mut())?;
            }
            // The signed risk context (Hopae ADR-0023), bound to the very
            // headers of this verify call; omitted without evidence.
            if auth.risk_context
                && let Some(settings) = &self.risk_context
            {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                match risk.and_then(|e| {
                    crate::risk_context::header_for(settings, e, request.headers(), now)
                }) {
                    Some((level, value)) => {
                        request
                            .headers_mut()
                            .insert(crate::risk_context::HEADER, value);
                        self.metrics.risk_context_sent(level);
                    }
                    None => self.metrics.risk_context_omitted(),
                }
            }
            let renewal_context = auth
                .renew_native_evidence
                .then(|| request.headers().clone());
            let response = if let Some(native) = native {
                native.verify(request.headers()).await.map_err(|_| 503u16)?
            } else {
                self.client
                    .request(request)
                    .await
                    .map_err(|_| 503u16)?
                    .map(|body| body.map_err(BodyError::from_error).boxed_unsync())
            };
            let (mut parts, body_stream) = response.into_parts();
            if auth.terminal_response
                && connection_tokens(&parts.headers)
                    .iter()
                    .any(|name| name.as_str() == "x-hangang-auth-terminal")
            {
                return Err(503);
            }
            // Honor the auth server's Connection token list before copying
            // configured identity headers or forwarding an SSO response.
            strip_hop_by_hop(&mut parts.headers);
            let status = parts.status;
            if status.is_success()
                && let Some(class) = expected_class
            {
                // Inspect the authenticated native response BEFORE configurable
                // header forwarding; old Service routes may omit kind from the
                // response_headers allowlist without changing this trust check.
                if native.is_none() {
                    return Err(503);
                }
                let expected_kind = match class {
                    crate::native_observed::AuthenticationClass::Service => "service",
                    crate::native_observed::AuthenticationClass::Workload => "workload",
                    crate::native_observed::AuthenticationClass::Human => "human",
                };
                if class == crate::native_observed::AuthenticationClass::Human {
                    if native_human_policy_identity(
                        &parts.headers,
                        expected.map(|scope| scope.issuer).ok_or(503u16)?,
                    )
                    .is_none()
                    {
                        return Err(503);
                    }
                } else {
                    let mut kinds = parts.headers.get_all("x-hopae-principal-kind").iter();
                    if kinds.next().and_then(|v| v.to_str().ok()) != Some(expected_kind)
                        || kinds.next().is_some()
                        || crate::pumgye::identity(&parts.headers).is_none_or(|(_, aal)| aal != 0)
                    {
                        return Err(503);
                    }
                }
            }
            let typed_identity = expected_class.and_then(|class| {
                if class == crate::native_observed::AuthenticationClass::Human {
                    return native_human_policy_identity(
                        &parts.headers,
                        expected.map(|scope| scope.issuer)?,
                    )
                    .map(|(subject, aal)| (subject.to_owned(), aal));
                }
                crate::pumgye::identity(&parts.headers)
                    .map(|(subject, aal)| (subject.to_owned(), aal))
            });
            let service_identity = if native.is_some()
                && status.is_success()
                && expected_class != Some(crate::native_observed::AuthenticationClass::Human)
                && (parts.headers.contains_key("x-hopae-principal-kind")
                    || parts
                        .headers
                        .get_all("x-hopae-aal")
                        .iter()
                        .any(|v| v.as_bytes() == b"0")
                    || parts
                        .headers
                        .get_all("x-forwarded-user")
                        .iter()
                        .any(|v| v.as_bytes().starts_with(b"s_")))
            {
                crate::pumgye::identity(&parts.headers).ok_or(503u16)?.1 == 0
            } else {
                false
            };
            let evidence_expires = if service_identity {
                Some(if auth.renew_native_evidence {
                    MachineLease::Renewing(
                        Renewal::start(
                            native.unwrap().clone(),
                            renewal_context.unwrap(),
                            &parts.headers,
                            started,
                        )
                        .ok_or(503u16)?,
                    )
                } else {
                    MachineLease::Fixed(
                        native_evidence_expiry(&parts.headers, started).ok_or(503u16)?,
                    )
                })
            } else {
                None
            };
            let service_scope = if service_identity {
                let mut values = parts.headers.get_all("x-hopae-service-id").iter();
                let scope = values.next().and_then(|v| v.to_str().ok()).ok_or(503u16)?;
                if values.next().is_some()
                    || scope.is_empty()
                    || scope.len() > 128
                    || !scope
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
                {
                    return Err(503);
                }
                Some(scope.to_owned())
            } else {
                None
            };
            if service_identity && auth.terminal_response {
                return Err(503);
            }
            let mut headers = HeaderMap::new();
            let mut size = 0;
            for name in &auth.response_headers {
                for value in parts.headers.get_all(name) {
                    size += name.len() + value.as_bytes().len();
                    if size > 16 * 1024 {
                        return Err(503);
                    }
                    headers.append(
                        HeaderName::from_bytes(name.as_bytes()).map_err(|_| 503u16)?,
                        value.clone(),
                    );
                }
            }
            let body = Limited::new(body_stream, 64 * 1024)
                .collect()
                .await
                .map_err(|_| 503u16)?
                .to_bytes();
            let terminal_values: Vec<_> = parts
                .headers
                .get_all("x-hangang-auth-terminal")
                .iter()
                .collect();
            if auth.terminal_response && !terminal_values.is_empty() {
                if terminal_values.len() != 1 || terminal_values[0].as_bytes() != b"1" {
                    return Err(503);
                }
                if !status.is_success() {
                    return Err(503);
                }
                let mut forwarded = Response::builder()
                    .status(status)
                    .body(full_body(body))
                    .map_err(|_| 503u16)?;
                let mut forwarded_size = 0_usize;
                for name in ["content-type", "cache-control", "set-cookie"] {
                    for value in parts.headers.get_all(name) {
                        forwarded_size = forwarded_size
                            .checked_add(name.len() + value.as_bytes().len())
                            .ok_or(503u16)?;
                        if forwarded_size > 16 * 1024 {
                            return Err(503);
                        }
                        forwarded
                            .headers_mut()
                            .append(HeaderName::from_static(name), value.clone());
                    }
                }
                // Login callbacks may carry a session credential in their URI.
                // Do not expose that URI as Referer on an auth-driven redirect.
                forwarded
                    .headers_mut()
                    .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
                return Ok(AuthOutcome::Forward(Box::new(forwarded)));
            }
            if status.is_success() {
                let mut cookies = Vec::new();
                if auth.forward_response {
                    let mut cookie_bytes = 0_usize;
                    for value in parts.headers.get_all(header::SET_COOKIE) {
                        cookie_bytes = cookie_bytes
                            .checked_add(value.as_bytes().len())
                            .ok_or(503u16)?;
                        if cookie_bytes > 16 * 1024 || cookies.len() >= 16 {
                            return Err(503);
                        }
                        cookies.push(value.clone());
                    }
                }
                return Ok(AuthOutcome::Allow(
                    headers,
                    cookies,
                    service_scope,
                    evidence_expires,
                    typed_identity,
                ));
            }
            // SSO passthrough: forward a redirect/challenge to the client so the
            // authorization service can drive login/ban redirects and cookies.
            if auth.forward_response
                && (status.is_redirection()
                    || status == StatusCode::UNAUTHORIZED
                    || status == StatusCode::FORBIDDEN)
            {
                let mut forwarded = Response::builder()
                    .status(status)
                    .body(full_body(body))
                    .map_err(|_| 503u16)?;
                let mut forwarded_size = 0_usize;
                for name in [
                    "location",
                    "set-cookie",
                    "www-authenticate",
                    "content-type",
                    "cache-control",
                ] {
                    for value in parts.headers.get_all(name) {
                        forwarded_size = forwarded_size
                            .checked_add(name.len() + value.as_bytes().len())
                            .ok_or(503u16)?;
                        if forwarded_size > 16 * 1024 {
                            return Err(503);
                        }
                        forwarded
                            .headers_mut()
                            .append(HeaderName::from_static(name), value.clone());
                    }
                }
                forwarded
                    .headers_mut()
                    .insert("referrer-policy", HeaderValue::from_static("no-referrer"));
                return Ok(AuthOutcome::Forward(Box::new(forwarded)));
            }
            match status {
                StatusCode::UNAUTHORIZED => Ok(AuthOutcome::Deny(401)),
                StatusCode::FORBIDDEN => Ok(AuthOutcome::Deny(403)),
                _ => Ok(AuthOutcome::Deny(503)),
            }
        };
        match timeout(Duration::from_millis(auth.timeout_ms), operation).await {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(status)) => AuthOutcome::Deny(status),
            Err(_) => AuthOutcome::Deny(503),
        }
    }

    /// Decide observation at the response head using one *current* policy
    /// generation. The request's captured route and client identity remain
    /// unchanged; publication affects only this recording decision.
    fn record_response_head(&self, context: &TrafficContext, status: u16) {
        let current = self.active.load_full();
        let action = current.settings.http_recording.as_ref().map_or(
            crate::http_recording::Action::Record,
            |policy| {
                policy.action(crate::http_recording::Input {
                    method: context.method.as_str(),
                    path: context.uri.path(),
                    route_id: context.route_id.as_deref(),
                    status,
                    peer_ip: context.peer_ip,
                    client_ip: context.client_ip,
                })
            },
        );
        if action == crate::http_recording::Action::Drop {
            if let Some(history) = &self.traffic {
                history.record_filtered();
            }
            return;
        }
        let revision = current.config.revision;
        if let Some(history) = &self.traffic {
            context.record(history, status, revision);
        }
        if self.access_log {
            // The trace has the same bounded, query-free metadata as the ring.
            // In particular, never emit a raw Host or a path-and-query.
            let method = crate::traffic::bounded_ascii(context.method.as_str(), 16);
            let path = crate::traffic::bounded_path(context.uri.path());
            let route = context
                .route_id
                .as_deref()
                .map(|id| crate::traffic::bounded_ascii(id, 128));
            tracing::info!(
                target: "hangang::access",
                peer = %context.peer_ip,
                client = %context.client_ip,
                method = %method,
                path = %path,
                route = ?route,
                status,
                policy_revision = revision,
                latency_ms = context.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                "request"
            );
        }
    }

    pub async fn handle(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<Body>, Infallible> {
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let snapshot = self.active.load_full();
        let retired = request
            .extensions()
            .get::<crate::public_http::Evidence>()
            .is_some_and(|e| !e.current(&snapshot));
        let trusted: &[ipnet::IpNet] = if request
            .extensions()
            .get::<crate::workload_http::Evidence>()
            .is_some()
        {
            &[]
        } else if let Some(e) = request.extensions().get::<crate::public_http::Evidence>() {
            e.trusted_proxy_cidrs()
        } else {
            snapshot
                .settings
                .trusted_proxy_cidrs
                .as_deref()
                .map(Vec::as_slice)
                .unwrap_or(&self.trusted_proxies)
        };
        let transport_tls = request
            .extensions()
            .get::<crate::tls::TransportInfo>()
            .is_some_and(|transport| transport.tls);
        let response_authority =
            response_security_authority(request.headers(), request.uri(), transport_tls);
        let mut context = if retired
            || response_authority.is_none()
            || connection_tokens(request.headers())
                .iter()
                .any(is_forwarding_identity_header)
        {
            None
        } else {
            self.resolve_edge(&request, peer, trusted)
                .ok()
                .and_then(|edge| {
                    let authority = edge
                        .forwarded_host
                        .as_ref()
                        .and_then(|h| h.to_str().ok())
                        .and_then(|h| h.parse().ok())
                        .or_else(|| response_authority.clone())?;
                    Some(crate::response_security::Context {
                        authority,
                        https: edge.proto == "https",
                        explicit_port: edge.explicit_forwarded_port,
                    })
                })
        };
        if context.is_none() && !retired {
            context = response_authority.map(|authority| crate::response_security::Context {
                authority,
                // Invalid forwarding does not erase authenticated TLS. Neither
                // URI scheme nor client forwarding fields establish transport.
                https: transport_tls,
                explicit_port: None,
            });
        }
        let mut response = self
            .handle_unfinalized(request, peer, snapshot.clone(), context.clone())
            .await?;
        if response
            .extensions_mut()
            .remove::<ResponseSecurityFinalized>()
            .is_some()
        {
            Ok(response)
        } else {
            Ok(crate::response_security::apply(
                response,
                &snapshot.settings.response_security,
                context,
            ))
        }
    }

    async fn handle_unfinalized(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
        snapshot: Arc<Snapshot>,
        response_context: Option<crate::response_security::Context>,
    ) -> Result<Response<Body>, Infallible> {
        // Decision capture is a fixed-size stack value. With decision events
        // off it stays inactive and every recording call is a branch.
        let Some(emitter) = &self.decisions else {
            let mut inactive = crate::decision::Capture::disabled();
            return self
                .handle_captured(request, peer, snapshot, response_context, &mut inactive)
                .await;
        };
        let mut decision = emitter.capture(request.method(), snapshot.config.revision);
        let response = self
            .handle_captured(request, peer, snapshot, response_context, &mut decision)
            .await?;
        emitter.finish(decision, response.status().as_u16());
        Ok(response)
    }

    async fn handle_captured(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        snapshot: Arc<Snapshot>,
        response_context: Option<crate::response_security::Context>,
        decision: &mut crate::decision::Capture,
    ) -> Result<Response<Body>, Infallible> {
        // Canonicalize the peer address so an IPv4-mapped IPv6 address
        // (`::ffff:a.b.c.d`, produced by a dual-stack `[::]` listener for an
        // IPv4 client) is compared and forwarded as the real IPv4 address.
        // Without this, `deny_cidrs` with IPv4 ranges never matches and the
        // forwarded X-Forwarded-For / X-Real-IP / x-original-client-ip carry
        // the mapped form.
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let mut traffic = (self.traffic.is_some() || self.access_log)
            .then(|| TrafficContext::new(&request, peer));
        // Unauthenticated health probe for external load balancers. Answered
        // before route matching and before acquiring a request permit, so it
        // stays responsive under data-plane saturation. Reports 503 while
        // draining or before the control plane is ready, so a balancer can
        // deregister the instance instead of sending it traffic.
        // One snapshot per request, captured before the health check so the
        // probe decision, routing and the document's settings all come from
        // the same activation.
        if request
            .extensions()
            .get::<crate::public_http::Evidence>()
            .is_some_and(|evidence| !evidence.current(&snapshot))
        {
            self.metrics
                .rejected_requests
                .fetch_add(1, Ordering::Relaxed);
            if let Some(context) = traffic.as_mut() {
                self.record_response_head(context, 503);
            }
            return Ok(response(503, "public listener configuration retired"));
        }
        // Identity outputs are reserved across the snapshot. A public fallback
        // can share an origin with a protected route; client lookalike fields
        // must never reach that origin, routing, external auth, or Lua.
        for name in &snapshot.authentication_identity_headers {
            request.headers_mut().remove(name);
        }
        let health_path = snapshot
            .settings
            .health_path
            .clone()
            .or_else(|| self.health_path.clone());
        let ban_scope = snapshot
            .config
            .settings
            .failure_ban_scope
            .unwrap_or_default();
        if ban_scope != crate::path_failure_bans::Scope::Url
            && !snapshot.settings.path_failure_bans.is_empty()
        {
            if connection_tokens(request.headers())
                .iter()
                .any(is_forwarding_identity_header)
            {
                return Ok(security_denied(400));
            }
            let trusted: &[ipnet::IpNet] = if request
                .extensions()
                .get::<crate::workload_http::Evidence>()
                .is_some()
            {
                &[]
            } else if let Some(evidence) =
                request.extensions().get::<crate::public_http::Evidence>()
            {
                evidence.trusted_proxy_cidrs()
            } else {
                snapshot
                    .settings
                    .trusted_proxy_cidrs
                    .as_deref()
                    .map(Vec::as_slice)
                    .unwrap_or(&self.trusted_proxies)
            };
            let edge = match self.resolve_edge(&request, peer, trusted) {
                Ok(edge) => edge,
                Err(_) => return Ok(security_denied(400)),
            };
            let forwarded = edge
                .forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok());
            let result = if let Some(redis) = &snapshot.settings.security_redis {
                redis
                    .check_bans(
                        snapshot
                            .config
                            .settings
                            .path_failure_bans
                            .as_deref()
                            .unwrap_or(&[]),
                        &security_view(&request),
                        forwarded,
                        edge.client_ip,
                        ban_scope,
                    )
                    .await
                    .map_err(|error| error.status())
            } else {
                crate::path_failure_bans::precheck(
                    &snapshot.settings.path_failure_bans,
                    &request,
                    forwarded,
                    edge.client_ip,
                    ban_scope,
                )
            };
            if let Err(status) = result {
                crate::security_events::record("ip_ban_rejected", edge.client_ip, status, None);
                decision.client(edge.client_ip);
                decision.refuse(
                    crate::decision::Stage::Enforcement,
                    crate::decision::Reason::IpBanned,
                );
                return Ok(security_denied(status));
            }
        }
        if let Some(path) = &health_path
            && request.uri().path() == path.as_ref()
        {
            return Ok(match *request.method() {
                Method::GET | Method::HEAD => {
                    if self.shutdown.is_cancelled()
                        || !self.ready.load(std::sync::atomic::Ordering::Relaxed)
                    {
                        response(503, "draining")
                    } else {
                        response(200, "ok")
                    }
                }
                _ => response(
                    StatusCode::METHOD_NOT_ALLOWED.as_u16(),
                    "method not allowed",
                ),
            });
        }
        let permit = match self.requests.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics
                    .rejected_requests
                    .fetch_add(1, Ordering::Relaxed);
                if let Some(context) = traffic.as_mut() {
                    let trusted_proxies: &[ipnet::IpNet] = request
                        .extensions()
                        .get::<crate::public_http::Evidence>()
                        .map(|evidence| evidence.trusted_proxy_cidrs())
                        .unwrap_or_else(|| {
                            snapshot
                                .settings
                                .trusted_proxy_cidrs
                                .as_deref()
                                .map(Vec::as_slice)
                                .unwrap_or(&self.trusted_proxies)
                        });
                    let direct_workload = request
                        .extensions()
                        .get::<crate::workload_http::Evidence>()
                        .is_some();
                    if let Ok(edge) = self.resolve_edge(
                        &request,
                        peer,
                        if direct_workload {
                            &[]
                        } else {
                            trusted_proxies
                        },
                    ) {
                        context.client_ip = edge.client_ip;
                    }
                    self.record_response_head(context, 503);
                }
                return Ok(response(503, "request capacity exhausted"));
            }
        };
        let debug_gateway_header = snapshot.settings.debug_gateway_header == Some(true);
        let capture = (!snapshot.settings.path_failure_bans.is_empty())
            .then(|| FailureCapture(Arc::new(std::sync::Mutex::new(None))));
        if let Some(capture) = &capture {
            request.extensions_mut().insert(capture.clone());
        }
        let mut response = self
            .handle_inner(request, peer, snapshot.clone(), traffic.as_mut(), decision)
            .await?;
        response = crate::response_security::apply(
            response,
            &snapshot.settings.response_security,
            response_context.clone(),
        );
        let observation = capture.and_then(|capture| {
            capture
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        });
        if let Some(observation) = observation {
            let status = response.status().as_u16();
            let (ip, events) = match observation {
                FailureObservation::Local(ip, observation) => {
                    if observation.is_failure(status) {
                        crate::security_events::record("url_failure", ip, status, None);
                    }
                    (ip, Ok(observation.record(status)))
                }
                FailureObservation::Redis(ip, observation) => {
                    if observation.is_failure(status) {
                        crate::security_events::record("url_failure", ip, status, None);
                    }
                    (ip, observation.record(status).await)
                }
            };
            match events {
                Ok(events) => {
                    for event in events {
                        crate::security_events::record(
                            "ip_ban_created",
                            ip,
                            429,
                            Some(&event.path),
                        );
                    }
                }
                Err(_) => {
                    crate::security_events::record("security_backend_unavailable", ip, 503, None);
                    response = crate::response_security::apply(
                        security_denied(503),
                        &snapshot.settings.response_security,
                        response_context.clone(),
                    );
                }
            }
        }
        // Apply after every route/auth/cache/Lua/transform path so legacy
        // configuration and origins cannot expose the deployment fingerprint.
        if !debug_gateway_header {
            response.headers_mut().remove("x-hangang-gateway");
            let (parts, body) = response.into_parts();
            response = Response::from_parts(
                parts,
                body.map_frame(|frame| match frame.into_trailers() {
                    Ok(mut trailers) => {
                        trailers.remove("x-hangang-gateway");
                        hyper::body::Frame::trailers(trailers)
                    }
                    Err(frame) => frame,
                })
                .boxed_unsync(),
            );
        }
        response.extensions_mut().insert(ResponseSecurityFinalized);
        if let Some(context) = &traffic {
            self.record_response_head(context, response.status().as_u16());
        }
        Ok(retain_request_permit(response, permit))
    }

    fn select_http_backend(&self, runtime: &Arc<crate::config::HttpRuntime>) -> Option<usize> {
        runtime.balancer.select_where(|index| {
            let backend = runtime.route.backends[index].address();
            if !backend.starts_with("docker://") {
                return true;
            }
            self.discovery
                .load()
                .as_ref()
                .and_then(|discovery| {
                    discovery.resolve_with_epoch(backend, crate::discovery::Protocol::Http)
                })
                .is_some_and(|target| {
                    runtime.balancer.observe_epoch(index, target.epoch)
                        && runtime.balancer.available_for(index, target.epoch)
                })
        })
    }

    pub fn with_discovery(self, discovery: Arc<crate::discovery::Discovery>) -> Self {
        self.discovery.store(Some(discovery));
        self
    }

    pub fn with_inspection_limit(mut self, limit: usize) -> Self {
        self.inspections = Arc::new(tokio::sync::Semaphore::new(limit));
        self
    }

    pub fn with_transform_limit(mut self, limit: usize) -> Self {
        self.transformations = Arc::new(tokio::sync::Semaphore::new(limit));
        self
    }

    pub fn with_request_limit(mut self, limit: usize) -> Self {
        self.requests = Arc::new(tokio::sync::Semaphore::new(limit));
        self
    }

    async fn handle_inner(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        snapshot: Arc<Snapshot>,
        mut traffic: Option<&mut TrafficContext>,
        decision: &mut crate::decision::Capture,
    ) -> Result<Response<Body>, Infallible> {
        use crate::decision::{Reason, Stage};
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let workload_evidence = request
            .extensions()
            .get::<crate::workload_http::Evidence>()
            .cloned();
        // Routes and the document's `settings` (which override the process
        // defaults when set) come from the snapshot captured by `handle`.
        let allow_dot_segments = snapshot
            .settings
            .allow_dot_segments
            .unwrap_or(self.allow_dot_segments);
        // Reject dot-segment paths before routing so a normalizing backend
        // cannot resolve `/public/../admin` to `/admin` after it matched a
        // less-privileged prefix route. Opt out with allow_dot_segments.
        if !allow_dot_segments && path_has_dot_segment(request.uri().path()) {
            return Ok(response(
                StatusCode::BAD_REQUEST.as_u16(),
                "path must not contain dot segments",
            ));
        }
        // Canonicalize request framing before anything is forwarded. The HTTP/1
        // parser already rejects conflicting Content-Length fields, but the
        // HTTP/2 receiver validates only the first one and hyper represents a
        // disagreement as an unknown body length while keeping every field.
        // Forwarding that to an HTTP/1 upstream would emit both invalid
        // Content-Length fields plus chunked framing: request-smuggling bait.
        if canonicalize_content_length(request.headers_mut()).is_err() {
            return Ok(response(
                StatusCode::BAD_REQUEST.as_u16(),
                "invalid or conflicting Content-Length",
            ));
        }
        if connection_tokens(request.headers())
            .iter()
            .any(is_forwarding_identity_header)
        {
            // Removing a nominated XFF/XFP header and falling back to the
            // trusted socket peer or TLS hop would weaken deny_cidrs or
            // require_tls. Reject the ambiguous request instead.
            return Ok(response(
                StatusCode::BAD_REQUEST.as_u16(),
                "forwarding identity header cannot be hop-by-hop",
            ));
        }
        // Remove arbitrary headers nominated by the client's Connection list
        // before any security-sensitive consumer sees them: trusted-proxy
        // identity, route matching, cache policy, or authorization. Standard
        // hop headers stay until WebSocket validation and final forwarding.
        drop_client_connection_marked_headers(request.headers_mut());
        // HTTP/2 may split Cookie into separate fields. All consumers must
        // see the same RFC 9113 value, including matching, auth and HTTP/1
        // upstreams on routes without Lua.
        if join_cookie_headers(request.headers_mut()).is_err() {
            return Ok(response(
                StatusCode::BAD_REQUEST.as_u16(),
                "invalid Cookie header",
            ));
        }
        if workload_evidence.is_some() {
            // An authenticated workload is the direct TLS peer. No CIDR-only
            // proxy delegation applies on this listener, and an external auth
            // service must not see copied client-supplied Forwarded fields.
            strip_forwarding_headers(request.headers_mut());
        }
        // The terminal marker has meaning only on a response from the
        // configured authorization service, never as a client request field.
        request.headers_mut().remove("x-hangang-auth-terminal");
        // Only Hangang produces a risk context, only for an authorization
        // call (Hopae ADR-0023); a client copy never reaches a service.
        request.headers_mut().remove(crate::risk_context::HEADER);
        if request.headers().keys().any(|name| {
            snapshot.http_match_headers.contains(name)
                && has_duplicate_header(request.headers(), name.as_str())
        }) {
            return Ok(response(
                StatusCode::BAD_REQUEST.as_u16(),
                "ambiguous duplicate route-match header",
            ));
        }
        // Resolve the effective client from forwarding headers when the socket
        // peer is a trusted proxy, so deny rules, external-auth client IP, the
        // cache partition, and the regenerated forwarding headers all reflect
        // the real client rather than the fronting proxy.
        let trusted_proxies: &[ipnet::IpNet] = request
            .extensions()
            .get::<crate::public_http::Evidence>()
            .map(|evidence| evidence.trusted_proxy_cidrs())
            .unwrap_or_else(|| {
                snapshot
                    .settings
                    .trusted_proxy_cidrs
                    .as_deref()
                    .map(Vec::as_slice)
                    .unwrap_or(&self.trusted_proxies)
            });
        let edge = match self.resolve_edge(
            &request,
            peer,
            if workload_evidence.is_some() {
                &[]
            } else {
                trusted_proxies
            },
        ) {
            Ok(edge) => edge,
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_REQUEST.as_u16(),
                    "invalid Host or forwarded client address",
                ));
            }
        };
        if let Some(context) = traffic.as_mut() {
            context.client_ip = edge.client_ip;
        }
        decision.client(edge.client_ip);
        let mut guard_evidence = None;
        let mut risk_level: Option<crate::risk_context::Level> = None;
        if let Some(guard) = &self.guard {
            let started = decision.clock();
            let (rejected, evidence, unavailable) =
                guard.admission(edge.client_ip, request.uri().path()).await;
            if decision.active() {
                decision.network(guard.decision_stage(
                    rejected,
                    evidence.as_ref(),
                    unavailable,
                    started,
                ));
            }
            if let Some(status) = rejected {
                decision.refuse(
                    Stage::Network,
                    if unavailable {
                        Reason::NetworkUnavailable
                    } else {
                        Reason::NetworkDenied
                    },
                );
                return Ok(security_denied(status));
            }
            guard_evidence = evidence;
        }
        let peer = SocketAddr::new(edge.client_ip, peer.port());
        if let Some(capture) = request.extensions().get::<FailureCapture>().cloned() {
            let scope = snapshot
                .config
                .settings
                .failure_ban_scope
                .unwrap_or_default();
            let forwarded = edge
                .forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok());
            let observed = if let Some(redis) = &snapshot.settings.security_redis {
                let rules = snapshot
                    .config
                    .settings
                    .path_failure_bans
                    .as_deref()
                    .unwrap_or(&[]);
                let view = security_view(&request);
                match redis
                    .check_bans(rules, &view, forwarded, edge.client_ip, scope)
                    .await
                {
                    Ok(()) => redis
                        .observe(rules, &view, forwarded, edge.client_ip)
                        .await
                        .map(|observation| FailureObservation::Redis(edge.client_ip, observation)),
                    Err(error) => Err(error),
                }
                .map_err(|error| error.status())
            } else {
                crate::path_failure_bans::check(
                    &snapshot.settings.path_failure_bans,
                    &request,
                    forwarded,
                    edge.client_ip,
                    scope,
                )
                .map(|observation| FailureObservation::Local(edge.client_ip, observation))
            };
            match observed {
                Ok(observation) => {
                    *capture
                        .0
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(observation);
                }
                Err(status) => {
                    decision.refuse(
                        Stage::Enforcement,
                        if status == 429 {
                            Reason::IpBanned
                        } else {
                            Reason::Error
                        },
                    );
                    crate::security_events::record(
                        if status == 429 {
                            "ip_ban_rejected"
                        } else {
                            "security_backend_unavailable"
                        },
                        edge.client_ip,
                        status,
                        None,
                    );
                    return Ok(security_denied(status));
                }
            }
        }
        if let Err(status) = crate::path_csrf::check(
            &snapshot.settings.path_csrf,
            &request,
            edge.forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok()),
            edge.proto,
            edge.explicit_forwarded_port,
        ) {
            decision.refuse(Stage::Enforcement, Reason::RequestBlocked);
            crate::security_events::record("url_csrf_denied", edge.client_ip, status, None);
            return Ok(security_denied(status));
        }
        if let Err(status) = crate::path_blocks::check(
            snapshot
                .config
                .settings
                .path_blocks
                .as_deref()
                .unwrap_or(&[]),
            &request,
            edge.forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok()),
        ) {
            decision.refuse(Stage::Enforcement, Reason::RequestBlocked);
            crate::security_events::record("path_blocked", edge.client_ip, status, None);
            let mut denied = response(
                status,
                if status == 404 {
                    "not found"
                } else {
                    "bad request"
                },
            );
            denied.headers_mut().insert(
                "cache-control",
                hyper::header::HeaderValue::from_static("no-store"),
            );
            return Ok(denied);
        }
        match crate::path_allowlists::check(
            &snapshot.settings.path_allowlists,
            &request,
            edge.forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok()),
            edge.client_ip,
            snapshot.geoip.as_ref(),
        ) {
            Ok(Some(country)) => {
                request.extensions_mut().insert(SecurityCountry(country));
            }
            Ok(None) => {}
            Err(status) => {
                decision.refuse(Stage::Enforcement, Reason::UrlNotAllowlisted);
                crate::security_events::record(
                    "url_allowlist_rejected",
                    edge.client_ip,
                    status,
                    None,
                );
                return Ok(security_denied(status));
            }
        }
        let rate_result = if let Some(redis) = &snapshot.settings.security_redis {
            redis
                .check_rates(
                    snapshot
                        .config
                        .settings
                        .path_rate_limits
                        .as_deref()
                        .unwrap_or(&[]),
                    &security_view(&request),
                    edge.forwarded_host
                        .as_ref()
                        .and_then(|host| host.to_str().ok()),
                )
                .await
                .map_err(|error| error.status())
        } else {
            crate::path_rate_limits::check(
                &snapshot.settings.path_rate_limits,
                &request,
                edge.forwarded_host
                    .as_ref()
                    .and_then(|host| host.to_str().ok()),
            )
        };
        if let Err(status) = rate_result {
            decision.refuse(
                Stage::Enforcement,
                if status == 429 {
                    Reason::RateLimited
                } else {
                    Reason::Error
                },
            );
            crate::security_events::record(
                if status == 429 {
                    "url_rate_limited"
                } else {
                    "security_backend_unavailable"
                },
                edge.client_ip,
                status,
                None,
            );
            let mut denied = response(
                status,
                if status == 429 {
                    "too many requests"
                } else {
                    "bad request"
                },
            );
            if status == 429 {
                denied
                    .headers_mut()
                    .insert("retry-after", hyper::header::HeaderValue::from_static("1"));
            }
            denied.headers_mut().insert(
                "cache-control",
                hyper::header::HeaderValue::from_static("no-store"),
            );
            return Ok(denied);
        }
        if let Some(reply) = crate::acme_http01::serve(
            &snapshot.http,
            &request,
            self.discovery.load_full(),
            &self.acme_http01,
        )
        .await
        {
            return Ok(reply);
        }
        let connection_lease = request
            .extensions()
            .get::<Arc<crate::metrics::ConnectionLease>>()
            .cloned();
        // Replacing the body preserves request extensions, including OnUpgrade.
        let (parts, body) = request.into_parts();
        let request = Request::from_parts(parts, RequestDataBody { body }.boxed_unsync());
        let mut request = match crate::request_blocks::check(
            &snapshot.settings.request_blocks,
            request,
            edge.forwarded_host.as_ref().and_then(|h| h.to_str().ok()),
            &self.request_inspectors,
            &self.request_spools,
        )
        .await
        {
            Ok(request) => request,
            Err(status) => {
                decision.refuse(Stage::Enforcement, Reason::RequestBlocked);
                crate::security_events::record("request_blocked", edge.client_ip, status, None);
                return Ok(security_denied(status));
            }
        };

        let request_policy_fence = crate::request_blocks::policy_fence(&request);
        let public_admission = request
            .extensions()
            .get::<crate::public_http::Evidence>()
            .cloned();
        {
            let current = self.active.load_full();
            if request_policy_fence
                .as_ref()
                .is_some_and(|f| !f.current(&current.settings.request_blocks))
                || public_admission
                    .as_ref()
                    .is_some_and(|e| !e.current(&current))
            {
                return Ok(security_denied(503));
            }
        }

        let (protected_resource, canonical_resource_path) = match crate::resource_guard::check(
            &snapshot.resource_guards,
            &snapshot.authentication_path_guards,
            &request,
            edge.forwarded_host
                .as_ref()
                .and_then(|host| host.to_str().ok()),
        ) {
            Ok(guard) => guard,
            Err(status) => {
                decision.refuse(Stage::Enforcement, Reason::ResourceNamespaceRefused);
                return Ok(response(status, "resource namespace refused"));
            }
        };
        let mut inspected = None;
        let mut selected: Option<Arc<HttpRuntime>> = None;
        for runtime in &snapshot.http {
            if !runtime.route.enabled
                || !basic_match_path(
                    &runtime.route,
                    &request,
                    runtime.host_regex.as_ref(),
                    canonical_resource_path
                        .as_deref()
                        .unwrap_or(request.uri().path()),
                )
            {
                continue;
            }
            if runtime.route.json.is_empty() {
                selected = Some(runtime.clone());
                break;
            }
            if request
                .headers()
                .get(header::CONTENT_ENCODING)
                .is_some_and(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
            {
                return Ok(response(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE.as_u16(),
                    "compressed JSON inspection is unsupported",
                ));
            }
            if inspected.is_none() {
                let Ok(permit) = self.inspections.clone().try_acquire_owned() else {
                    self.metrics
                        .rejected_requests
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(response(503, "JSON inspection capacity exhausted"));
                };
                match inspect_json_body(request).await {
                    Ok((restored, json)) => {
                        request = restored.map(|body| {
                            RequestBody {
                                body,
                                _permit: permit,
                                _backend: None,
                                _route: None,
                            }
                            .boxed_unsync()
                        });
                        inspected = Some(json);
                    }
                    Err(InspectError::TooLarge) => {
                        return Ok(response(
                            StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                            "request body exceeds inspection limit",
                        ));
                    }
                    Err(InspectError::Timeout) => {
                        return Ok(response(
                            StatusCode::REQUEST_TIMEOUT.as_u16(),
                            "request body inspection timed out",
                        ));
                    }
                    Err(InspectError::Invalid) => {
                        return Ok(response(
                            StatusCode::BAD_REQUEST.as_u16(),
                            "invalid JSON request body",
                        ));
                    }
                }
            }
            if json_match(&runtime.route, inspected.as_ref().expect("inspected body")) {
                selected = Some(runtime.clone());
                break;
            }
        }

        // The parsed tree can greatly exceed the wire size. Release it as soon
        // as matching ends; the inspection permit stays with the restored body.
        drop(inspected);
        let Some(runtime) = selected else {
            return Ok(response(
                StatusCode::NOT_FOUND.as_u16(),
                "no matching route",
            ));
        };
        if let Some(context) = traffic.as_mut() {
            context.route_id = Some(runtime.route.id.clone());
        }
        decision.route(&runtime);
        // This node could not prepare the route's external authorization
        // (a static header variable is unusable here). Fail closed before any
        // authorization call, Lua, cache or upstream contact.
        if runtime.auth_unavailable.is_some() {
            self.metrics
                .rejected_requests
                .fetch_add(1, Ordering::Relaxed);
            decision.refuse(Stage::Enforcement, Reason::RouteAuthorizationUnavailable);
            return Ok(response(503, "route authorization unavailable"));
        }
        if protected_resource.is_some_and(|id| {
            !runtime
                .route
                .resource_policy
                .as_ref()
                .is_some_and(|policy| policy.enforce && policy.resource_id == id)
        }) {
            decision.refuse(Stage::Enforcement, Reason::ResourceNamespaceRefused);
            return Ok(response(403, "resource namespace refused"));
        }
        if workload_evidence.is_some() && runtime.workload_auth.is_none() {
            // A dedicated workload listener never exposes ordinary public or
            // legacy routes merely because the client has a valid certificate.
            self.metrics
                .workload_auth_rejections
                .fetch_add(1, Ordering::Relaxed);
            decision.refuse(Stage::Identity, Reason::WorkloadDenied);
            return Ok(response(
                403,
                "route is not bound to this workload listener",
            ));
        }
        let (workload_identity, workload_route_lease) =
            if let Some(prepared) = &runtime.workload_auth {
                let outcome = prepared.authorize(workload_evidence.as_ref(), &snapshot);
                if decision.active() {
                    decision.identity(crate::decision::Identity {
                        authority: crate::decision::IdentityAuthority::Hangang,
                        verdict: if outcome.is_ok() {
                            crate::decision::IdentityVerdict::Authenticated
                        } else {
                            crate::decision::IdentityVerdict::Denied
                        },
                        principal: crate::decision::Principal::Workload,
                        aal: None,
                        factor: crate::decision::FactorKind::Certificate,
                        subject: outcome
                            .as_ref()
                            .ok()
                            .map(|identity| crate::decision::Subject::new(identity.uri.as_bytes())),
                        latency_us: 0,
                        transport: crate::decision::Transport::Local,
                        risk: None,
                    });
                }
                match outcome {
                    Ok(identity) => (
                        Some(identity.clone()),
                        Some(WorkloadRouteLease {
                            active: self.active.clone(),
                            route_id: runtime.route.id.clone(),
                            runtime: prepared.clone(),
                            evidence: workload_evidence
                                .as_ref()
                                .expect("authorized workload has evidence")
                                .clone(),
                        }),
                    ),
                    Err(denial) => {
                        self.metrics
                            .workload_auth_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        decision.refuse(
                            Stage::Identity,
                            if matches!(denial, crate::workload_auth::Denial::Retired) {
                                Reason::AuthorizationRetired
                            } else {
                                Reason::WorkloadDenied
                            },
                        );
                        let (status, message) = match denial {
                            crate::workload_auth::Denial::Forbidden => {
                                (403, "workload identity is not allowed")
                            }
                            crate::workload_auth::Denial::Retired => {
                                (503, "workload listener generation retired")
                            }
                        };
                        return Ok(response(status, message));
                    }
                }
            } else {
                (None, None)
            };
        let mut auth_route_lease = workload_route_lease.map(|workload| AuthRouteLease {
            native_snapshot: None,
            workload: Some(workload),
            jwt: None,
            pumgye: None,
            pumgye_remote: None,
            hopae_expires: None,
            hopae_renewal: None,
        });
        if runtime.native_resource.is_some() {
            auth_route_lease
                .get_or_insert_with(Default::default)
                .native_snapshot = Some((self.active.clone(), snapshot.clone()));
        }
        if runtime
            .route
            .resource_policy
            .as_ref()
            .is_some_and(|policy| policy.enforce && policy.has_pumgye())
        {
            auth_route_lease.get_or_insert_with(Default::default).pumgye =
                Some((self.active.clone(), snapshot.config.revision));
        }
        // Canonical-domain policy precedes require_tls so an alias needs only
        // one redirect. The destination is entirely operator configured; the
        // request contributes only its already parsed path and query.
        if let Some(policy) = runtime.route.canonical_domain.as_ref()
            && let Some(redirect) = canonical_domain_redirect(
                &request,
                &edge,
                canonical_resource_path
                    .as_deref()
                    .unwrap_or(request.uri().path()),
                policy,
            )
        {
            return Ok(redirect);
        }
        // Enforce TLS for require_tls routes reached over plaintext.
        if runtime.route.require_tls && edge.proto != "https" {
            return Ok(self.https_redirect(
                &request,
                &edge,
                runtime.route.https_redirect_code.unwrap_or_else(|| {
                    snapshot
                        .settings
                        .https_redirect_code
                        .unwrap_or(self.https_redirect_code)
                }),
            ));
        }
        let route_permit =
            match crate::admission::acquire(&runtime.admission, runtime.route.max_requests) {
                Ok(permit) => permit,
                Err(_) => {
                    self.metrics
                        .rejected_requests
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(response(503, "route capacity exhausted"));
                }
            };
        if runtime
            .route
            .deny_cidrs
            .iter()
            .any(|net| net.contains(&peer.ip()))
        {
            return Ok(response(
                StatusCode::FORBIDDEN.as_u16(),
                "client address denied",
            ));
        }

        // One copied observation supplies admission, telemetry and every Lua
        // phase. It never retains the database or performs per-record lookups.
        let geoip = request
            .extensions()
            .get::<SecurityCountry>()
            .map(|captured| captured.0.clone())
            .unwrap_or_else(|| {
                crate::country_observation::capture(snapshot.geoip.as_ref(), peer.ip())
            });
        if let Some(context) = traffic {
            context.geoip = geoip.clone();
        }
        if decision.active() {
            decision.country(geoip.policy_country().ok().flatten());
        }
        let country_decision = runtime
            .country_policy
            .as_ref()
            .filter(|policy| policy.enforced())
            .map(|policy| match geoip.policy_country() {
                Ok(country) if policy.evaluate_code(country) => {
                    crate::country_metrics::Decision::Allowed
                }
                Ok(_) => crate::country_metrics::Decision::Denied,
                Err(_) => crate::country_metrics::Decision::Unavailable,
            });
        self.metrics.geoip.observe(
            crate::country_metrics::Protocol::Http,
            &geoip,
            country_decision,
        );
        match country_decision {
            Some(crate::country_metrics::Decision::Denied) => {
                return Ok(response(403, "client country denied"));
            }
            Some(crate::country_metrics::Decision::Unavailable) => {
                return Ok(response(503, "country database unavailable"));
            }
            _ => {}
        }

        // Native language preference filtering is an access decision on the
        // already selected route, never a route predicate or Lua override.
        if let Some(policy) = &runtime.language_policy
            && runtime
                .route
                .language_policy
                .as_ref()
                .is_some_and(|p| p.enforce)
        {
            let language = match crate::language_policy::AcceptLanguage::parse_values(
                request
                    .headers()
                    .get_all(header::ACCEPT_LANGUAGE)
                    .iter()
                    .map(|value| value.as_bytes()),
            ) {
                Ok(language) => language,
                Err(_) => return Ok(response(400, "invalid Accept-Language preference")),
            };
            if !policy.allows(&language) {
                return Ok(response(403, "language preference denied"));
            }
        }

        // Cache access follows route admission and IP policy. Sensitive/dynamic
        // policy routes bypass entirely; hits must not depend on origin health.
        let mut cache_fill = None;
        let only_if_cached = crate::cache_policy::only_if_cached(request.headers());
        if only_if_cached
            && runtime.route.access_mode != crate::config::AccessMode::Protected
            && runtime.route.jwt_auth.is_none()
            && runtime.route.workload_auth.is_none()
        {
            return Ok(response(504, "only-if-cached cannot be satisfied"));
        }
        if let Some(cache) = &snapshot.cache
            && runtime.route.cache.is_some()
            && crate::cache_policy::route_eligible(&runtime.route)
            && crate::cache_policy::request_eligible(&request)
        {
            let tls = request
                .extensions()
                .get::<crate::tls::TransportInfo>()
                .is_some_and(|info| info.tls);
            // Global response-header removals shape the stored response, so
            // they are part of the entry's identity: changing them (in either
            // direction) moves to a fresh namespace instead of serving
            // entries captured under other rules. Route rules are already in
            // the route fingerprint.
            let removals: &[HeaderName] = snapshot
                .settings
                .remove_response_headers
                .as_deref()
                .map(Vec::as_slice)
                .unwrap_or(&self.remove_response_headers);
            let partition = format!(
                "peer={};tls={tls};strip={}",
                peer.ip(),
                removals
                    .iter()
                    .map(|name| name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let epoch = cache.epoch();
            if let Some(key) =
                crate::cache_policy::key(&request, &runtime.cache_fingerprint, &partition, epoch)
            {
                match cache.lookup(key, epoch).await {
                    crate::cache::Lookup::Hit(entry) => {
                        if let Some(mut reply) = crate::cache::cached_response(entry) {
                            self.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
                            // The entry was captured under the same global
                            // removals (part of its key) and route rules
                            // (part of the route fingerprint), after any
                            // response transform: nothing is re-applied here,
                            // so transform-set headers are never overwritten.
                            if let Some(permit) = route_permit {
                                reply.extensions_mut().insert(permit);
                            }
                            return Ok(reply);
                        }
                    }
                    crate::cache::Lookup::Fill(fill) => {
                        self.metrics.cache_misses.fetch_add(1, Ordering::Relaxed);
                        cache_fill = Some(fill);
                    }
                    crate::cache::Lookup::Bypass => {
                        self.metrics.cache_bypasses.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }

        let transforms =
            runtime.route.request_transform.is_some() || runtime.route.response_transform.is_some();
        let conditional_response = runtime
            .response_transform
            .as_ref()
            .is_some_and(|config| config.when_prefix.is_some());
        let mut transform_request_no_transform =
            crate::transform_body::no_transform(request.headers());
        let mut transform_request_preconditions = [
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
            header::IF_UNMODIFIED_SINCE,
        ]
        .iter()
        .any(|name| request.headers().contains_key(name));

        let mut transform_request_range = request.headers().contains_key(header::RANGE)
            || request.headers().contains_key(header::IF_RANGE);
        let mut transform_request_partial = request.headers().contains_key(header::CONTENT_RANGE);
        // Identity headers established by authentication on this request. They
        // are re-asserted after the request transform so a later header rewrite
        // cannot replace the authenticated identity the upstream relies on.
        let mut established_identity: Vec<(HeaderName, HeaderValue)> = Vec::new();
        // Includes compatibility identity names whose authenticated value is
        // null: those names must remain absent all the way to the origin.
        let auth_reserved = runtime.auth_reserved.as_slice();
        // Session cookies issued by the authorization service on a 2xx.
        let mut auth_cookies: Vec<HeaderValue> = Vec::new();
        let mut consumed_service_credential = false;
        // A policy-selected backend is an authorization/routing decision. A
        // later connection retry must not replace it with a balancer-selected
        // backend the policy never approved.
        let mut policy_pinned_backend = false;
        let resource_policy = runtime
            .route
            .resource_policy
            .as_ref()
            .filter(|policy| policy.enforce);
        let mut resource_allowed = match (resource_policy, workload_identity.as_ref()) {
            (Some(policy), Some(identity))
                if matches!(
                    policy.principal,
                    crate::resource_policy::PrincipalSource::Workload
                ) =>
            {
                policy.allows(
                    request.method().as_str(),
                    crate::resource_policy::PrincipalEvidence::Workload(identity),
                )
            }
            (None, _) => true,
            _ => false,
        };
        if let (Some(identity), Some(name)) = (
            workload_identity.as_ref(),
            runtime
                .route
                .workload_auth
                .as_ref()
                .and_then(|policy| policy.identity_header.as_ref()),
        ) {
            let name: HeaderName = name.parse().expect("validated workload identity header");
            let value = match HeaderValue::from_str(&identity.uri) {
                Ok(value) => value,
                Err(_) => return Ok(response(503, "workload identity cannot be forwarded")),
            };
            request.headers_mut().insert(name.clone(), value.clone());
            established_identity.push((name, value));
        }
        if let Some(jwt) = &runtime.route.jwt_auth {
            for name in runtime
                .jwt_auth
                .as_ref()
                .map(|prepared| prepared.reserved_headers())
                .unwrap_or(&[])
            {
                request.headers_mut().remove(name);
            }
            let jwt_started = decision.clock();
            let authenticated = match bearer_token(request.headers()) {
                Some(token) => match &runtime.jwt_auth {
                    Some(prepared) => {
                        prepared
                            .authenticate_session(token, self.jwt_verifications.clone())
                            .await
                    }
                    None => Err(crate::jwt_runtime::AuthFailure::Unavailable),
                },
                None => Err(crate::jwt_runtime::AuthFailure::Invalid),
            };
            if decision.active() {
                use crate::jwt_runtime::AuthFailure;
                decision.identity(crate::decision::Identity {
                    authority: crate::decision::IdentityAuthority::Hangang,
                    verdict: match &authenticated {
                        Ok(_) => crate::decision::IdentityVerdict::Authenticated,
                        Err(AuthFailure::Invalid) => crate::decision::IdentityVerdict::Challenge,
                        Err(AuthFailure::Forbidden) => crate::decision::IdentityVerdict::Denied,
                        Err(_) => crate::decision::IdentityVerdict::Unavailable,
                    },
                    principal: crate::decision::Principal::Unknown,
                    aal: None,
                    factor: crate::decision::FactorKind::Bearer,
                    subject: authenticated.as_ref().ok().map(|session| {
                        crate::decision::Subject::new(session.verified().subject.as_bytes())
                    }),
                    latency_us: crate::decision::elapsed_us(jwt_started),
                    transport: crate::decision::Transport::Local,
                    risk: None,
                });
                if let Err(error) = &authenticated {
                    decision.refuse(
                        Stage::Identity,
                        match error {
                            AuthFailure::Invalid | AuthFailure::Forbidden => Reason::JwtDenied,
                            _ => Reason::AuthenticationUnavailable,
                        },
                    );
                }
            }
            let session = match authenticated {
                Ok(session) => session,
                Err(error) => {
                    use crate::jwt_runtime::AuthFailure;
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    let status = match error {
                        AuthFailure::Invalid | AuthFailure::Forbidden => {
                            self.metrics
                                .jwt_auth_rejections
                                .fetch_add(1, Ordering::Relaxed);
                            if error == AuthFailure::Invalid {
                                401
                            } else {
                                403
                            }
                        }
                        AuthFailure::Unavailable => {
                            self.metrics
                                .jwt_auth_unavailable
                                .fetch_add(1, Ordering::Relaxed);
                            503
                        }
                        AuthFailure::Capacity => {
                            self.metrics
                                .jwt_auth_capacity_rejections
                                .fetch_add(1, Ordering::Relaxed);
                            503
                        }
                    };
                    let mut denied = response(
                        status,
                        if status == 503 {
                            "JWT verification unavailable"
                        } else {
                            "JWT authorization refused"
                        },
                    );
                    if status == 401 {
                        denied
                            .headers_mut()
                            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
                    }
                    if status == 403 {
                        denied.headers_mut().insert(
                            header::WWW_AUTHENTICATE,
                            HeaderValue::from_static("Bearer error=\"insufficient_scope\""),
                        );
                    }
                    return Ok(denied);
                }
            };
            let verified = session.verified();
            if let Some(policy) = resource_policy
                && matches!(
                    policy.principal,
                    crate::resource_policy::PrincipalSource::Jwt
                )
            {
                resource_allowed = policy.allows(
                    request.method().as_str(),
                    crate::resource_policy::PrincipalEvidence::Jwt(verified),
                );
            }
            if let Some(name) = &jwt.identity_header {
                let name: HeaderName = name.parse().expect("validated JWT identity header");
                let Ok(value) = HeaderValue::from_bytes(verified.subject.as_bytes()) else {
                    return Ok(response(401, "JWT subject cannot be forwarded"));
                };
                request.headers_mut().insert(name.clone(), value.clone());
                established_identity.push((name, value));
            }
            let prepared = runtime
                .jwt_auth
                .as_ref()
                .expect("validated JWT route has a prepared verifier")
                .clone();
            let Some(route) = snapshot.jwt_routes.get(&runtime.route.id).cloned() else {
                self.metrics
                    .jwt_auth_unavailable
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                return Ok(response(503, "JWT route generation unavailable"));
            };
            auth_route_lease
                .get_or_insert_with(AuthRouteLease::default)
                .jwt = Some(JwtRouteLease {
                active: self.active.clone(),
                route_id: runtime.route.id.clone(),
                route,
                runtime: prepared,
                session,
            });
        }
        if let Some(basic) = &runtime.route.basic_auth {
            let prepared = runtime
                .basic_auth
                .as_ref()
                .expect("validated Basic authentication is prepared in the snapshot");
            // Compatibility credentials carry an explicit, validated set of
            // upstream identity headers. Clear every configured name before
            // authentication, even when the matching consumer omitted a
            // value, so a client cannot impersonate another consumer.
            for name in prepared.reserved_headers() {
                request.headers_mut().remove(name);
            }
            let verified = if basic.accept_proxy_authorization {
                crate::basic_auth::verify_with_proxy(prepared, request.headers())
            } else {
                crate::basic_auth::verify(prepared, request.headers())
            };
            if decision.active() {
                decision.identity(crate::decision::Identity {
                    authority: crate::decision::IdentityAuthority::Hangang,
                    verdict: if verified.is_some() {
                        crate::decision::IdentityVerdict::Authenticated
                    } else {
                        crate::decision::IdentityVerdict::Challenge
                    },
                    principal: crate::decision::Principal::Unknown,
                    aal: None,
                    factor: crate::decision::FactorKind::Password,
                    subject: verified
                        .as_ref()
                        .map(|a| crate::decision::Subject::new(a.username.as_bytes())),
                    latency_us: 0,
                    transport: crate::decision::Transport::Local,
                    risk: None,
                });
                if verified.is_none() {
                    decision.refuse(Stage::Identity, Reason::BasicDenied);
                }
            }
            match verified {
                Some(authenticated) => {
                    if let Some(policy) = resource_policy
                        && matches!(
                            policy.principal,
                            crate::resource_policy::PrincipalSource::Basic
                        )
                    {
                        resource_allowed = policy.allows(
                            request.method().as_str(),
                            crate::resource_policy::PrincipalEvidence::Basic(
                                &authenticated.username,
                            ),
                        );
                    }
                    if basic.hide_credentials {
                        request.headers_mut().remove(header::AUTHORIZATION);
                    }
                    if let Some(name) = &basic.identity_header
                        && let (Ok(name), Ok(value)) = (
                            HeaderName::from_bytes(name.as_bytes()),
                            HeaderValue::from_str(&authenticated.username),
                        )
                    {
                        request.headers_mut().remove(&name);
                        request.headers_mut().insert(name.clone(), value.clone());
                        established_identity.push((name, value));
                    }
                    for (name, value) in authenticated.identity_headers {
                        request.headers_mut().remove(&name);
                        if let Some(value) = value {
                            request.headers_mut().insert(name.clone(), value.clone());
                            established_identity.push((name, value));
                        }
                    }
                }
                None => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    let mut denied = response(401, "authentication required");
                    let challenge = format!("Basic realm=\"{}\", charset=\"UTF-8\"", basic.realm);
                    denied.headers_mut().insert(
                        "www-authenticate",
                        HeaderValue::from_str(&challenge)
                            .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
                    );
                    return Ok(denied);
                }
            }
        }

        // A request transform may buffer or stream the client body before the
        // upstream send loop starts. Guard the original body as soon as all
        // gateway authenticators have established their lease.
        if let Some(lease) = &auth_route_lease
            && !request.body().is_end_stream()
        {
            let body = std::mem::replace(request.body_mut(), full_body(Bytes::new()));
            *request.body_mut() =
                AuthResponseBody::new(body, lease.clone(), self.metrics.clone()).boxed_unsync();
        }

        let mut native_auth_context = None;
        let mut native_preliminary_identity = None;
        if let Some(auth) = &runtime.route.auth {
            if auth
                .request_headers
                .iter()
                .any(|name| has_duplicate_header(request.headers(), name))
            {
                return Ok(response(
                    StatusCode::BAD_REQUEST.as_u16(),
                    "ambiguous duplicate authorization header",
                ));
            }
            // A client must never supply identity headers reserved for the auth service.
            for name in &auth.response_headers {
                request.headers_mut().remove(name);
            }
            let native_authorization = runtime
                .native_resource
                .as_ref()
                .and_then(|binding| binding.observed_authentication())
                .map(|(class, issuer)| NativeAuthorization {
                    class,
                    issuer,
                    route_id: &runtime.route.id,
                    canonical_path: canonical_resource_path.as_deref(),
                });
            if runtime.native_resource.is_some() {
                native_auth_context =
                    match auth_request_headers(auth, &runtime.auth_static_headers, &request, &edge)
                    {
                        Ok(mut headers) => {
                            if native_authorization
                                .is_some_and(|scope| scope.apply(&mut headers).is_err())
                            {
                                decision.refuse(Stage::Identity, Reason::NativeContextUnavailable);
                                return Ok(response(
                                    503,
                                    "native Human ingress context unavailable",
                                ));
                            }
                            Some(headers)
                        }
                        Err(_) => {
                            decision.refuse(Stage::Identity, Reason::NativeContextUnavailable);
                            return Ok(response(503, "native authentication context unavailable"));
                        }
                    };
            }
            let auth_started = decision.clock();
            // Sumunjang's evidence of this request, when the route sends Hopae a risk context.
            let risk_evidence = if auth.risk_context && self.risk_context.is_some() {
                guard_evidence.as_ref().and_then(|e| e.network().cloned())
            } else {
                None
            };
            if auth.risk_context
                && let Some(settings) = &self.risk_context
                && let Some(e) = &risk_evidence
            {
                risk_level = Some(settings.level(e));
            }
            let authorization = tokio::select! {
                biased;
                retired = auth_retired(auth_route_lease.as_ref()) => {
                    retired.record(&self.metrics);
                    decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                    return Ok(response(503, "route authorization retired"));
                }
                outcome = self.authorize(auth, &runtime.auth_static_headers, runtime.auth_native.as_ref(), native_authorization, &mut request, &edge, risk_evidence.as_ref()) => outcome,
            };
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            if decision.active() {
                use crate::decision::IdentityVerdict as V;
                let (verdict, principal, aal, subject) = match &authorization {
                    AuthOutcome::Allow(headers, _, _, _, typed) => {
                        let mut kinds = headers.get_all("x-hopae-principal-kind").iter();
                        let kind = kinds.next().filter(|_| kinds.next().is_none());
                        let identity = typed
                            .as_ref()
                            .map(|(subject, aal)| (subject.as_str(), *aal))
                            .or_else(|| crate::pumgye::identity(headers));
                        (
                            V::Authenticated,
                            crate::decision::Principal::parse(kind.map(HeaderValue::as_bytes)),
                            identity.map(|(_, aal)| aal),
                            identity.map(|(subject, _)| {
                                crate::decision::Subject::new(subject.as_bytes())
                            }),
                        )
                    }
                    AuthOutcome::Deny(401) | AuthOutcome::Forward(_) => (
                        V::Challenge,
                        crate::decision::Principal::Unknown,
                        None,
                        None,
                    ),
                    AuthOutcome::Deny(status) if *status >= 500 => (
                        V::Unavailable,
                        crate::decision::Principal::Unknown,
                        None,
                        None,
                    ),
                    AuthOutcome::Deny(_) => {
                        (V::Denied, crate::decision::Principal::Unknown, None, None)
                    }
                };
                decision.identity(crate::decision::Identity {
                    authority: crate::decision::IdentityAuthority::Hopae,
                    verdict,
                    principal,
                    aal,
                    factor: crate::decision::FactorKind::None,
                    subject,
                    latency_us: crate::decision::elapsed_us(auth_started),
                    transport: if runtime.auth_native.is_some() {
                        crate::decision::Transport::Hop1
                    } else {
                        crate::decision::Transport::Http
                    },
                    risk: risk_level,
                });
                match &authorization {
                    AuthOutcome::Allow(..) => {}
                    AuthOutcome::Forward(_) => {
                        decision.refuse(Stage::Identity, Reason::AuthenticationRedirect)
                    }
                    AuthOutcome::Deny(401) => {
                        decision.refuse(Stage::Identity, Reason::AuthenticationRequired)
                    }
                    AuthOutcome::Deny(status) if *status >= 500 => {
                        decision.refuse(Stage::Identity, Reason::AuthenticationUnavailable)
                    }
                    AuthOutcome::Deny(_) => {
                        decision.refuse(Stage::Identity, Reason::AuthenticationDenied)
                    }
                }
            }
            match authorization {
                AuthOutcome::Allow(
                    headers,
                    cookies,
                    service_scope,
                    evidence_expires,
                    typed_identity,
                ) => {
                    let workload_preliminary = runtime
                        .native_resource
                        .as_ref()
                        .and_then(|binding| binding.observed_class())
                        == Some(crate::native_observed::AuthenticationClass::Workload);
                    let human_preliminary = runtime
                        .native_resource
                        .as_ref()
                        .is_some_and(|b| b.human_mode());
                    if let Some(expiry) = evidence_expires {
                        let lease = auth_route_lease.get_or_insert_with(Default::default);
                        match expiry {
                            MachineLease::Fixed(deadline) => lease.hopae_expires = Some(deadline),
                            MachineLease::Renewing(renewal) => lease.hopae_renewal = Some(renewal),
                        }
                        if !request.body().is_end_stream() {
                            let body =
                                std::mem::replace(request.body_mut(), full_body(Bytes::new()));
                            *request.body_mut() =
                                AuthResponseBody::new(body, lease.clone(), self.metrics.clone())
                                    .boxed_unsync();
                        }
                    }
                    if let Some(service_scope) = service_scope {
                        if resource_policy.is_none_or(|policy| {
                            policy.pumgye_service() != Some(service_scope.as_str())
                        }) {
                            decision.refuse(Stage::Authorization, Reason::ServiceScopeMismatch);
                            return Ok(response(
                                403,
                                "service identity requires an enforced Pumgye permission gate",
                            ));
                        }
                        consumed_service_credential = true;
                        request.headers_mut().remove(header::AUTHORIZATION);
                    }
                    if let Some(policy) = resource_policy
                        && matches!(
                            policy.principal,
                            crate::resource_policy::PrincipalSource::External { .. }
                        )
                    {
                        let authz_started = decision.clock();
                        resource_allowed = if let Some(gate) = &policy.pumgye_resource {
                            let identity = typed_identity
                                .as_ref()
                                .map(|(subject, aal)| (subject.as_str(), *aal))
                                .or_else(|| crate::pumgye::identity(&headers));
                            let evidence = match &self.guard {
                                Some(guard) => match guard_evidence
                                    .take()
                                    .and_then(|proof| proof.current(guard, edge.client_ip))
                                {
                                    Some(evidence) => evidence,
                                    None => guard.authorization_evidence(edge.client_ip).await,
                                },
                                None => pumgye_core::GuardEvidence::Unavailable,
                            };
                            if snapshot.config.pumgye_authority.is_some() {
                                match (snapshot.pumgye_remote.as_ref(), identity) {
                                    (Some(remote), Some((subject, aal))) => {
                                        match if human_preliminary {
                                            remote
                                                .authorize_human_resource_traced(
                                                    gate,
                                                    request.method().as_str(),
                                                    subject,
                                                    edge.client_ip,
                                                    aal,
                                                    evidence,
                                                )
                                                .await
                                        } else if workload_preliminary {
                                            remote
                                                .authorize_workload_resource_traced(
                                                    gate,
                                                    request.method().as_str(),
                                                    subject,
                                                    edge.client_ip,
                                                    aal,
                                                    evidence,
                                                )
                                                .await
                                        } else {
                                            remote
                                                .authorize_resource_traced(
                                                    gate,
                                                    request.method().as_str(),
                                                    subject,
                                                    edge.client_ip,
                                                    aal,
                                                    evidence,
                                                )
                                                .await
                                        } {
                                            Ok(decided) => {
                                                decision.authorization(
                                                    decided.decision,
                                                    decided.revision,
                                                    authz_started,
                                                    remote.decision_transport(),
                                                );
                                                if let Some(revision) = decided.allowed_revision() {
                                                    auth_route_lease
                                                        .get_or_insert_with(Default::default)
                                                        .pumgye_remote =
                                                        Some((remote.clone(), revision));
                                                    true
                                                } else {
                                                    false
                                                }
                                            }
                                            Err(_) if policy.enforce => {
                                                decision.authorization(
                                                    crate::decision::Authorization::Unavailable,
                                                    None,
                                                    authz_started,
                                                    remote.decision_transport(),
                                                );
                                                decision.refuse(
                                                    Stage::Authorization,
                                                    Reason::Pumgye(
                                                        crate::decision::Authorization::Unavailable,
                                                    ),
                                                );
                                                return Ok(response(
                                                    503,
                                                    "Pumgye authority unavailable",
                                                ));
                                            }
                                            Err(_) => false,
                                        }
                                    }
                                    (None, _) if policy.enforce => {
                                        decision.refuse(
                                            Stage::Authorization,
                                            Reason::Pumgye(
                                                crate::decision::Authorization::Unavailable,
                                            ),
                                        );
                                        return Ok(response(503, "Pumgye authority unavailable"));
                                    }
                                    _ => false,
                                }
                            } else if workload_preliminary || human_preliminary {
                                return Ok(response(
                                    503,
                                    "native resource authority requires typed remote decision",
                                ));
                            } else {
                                match (
                                    snapshot.pumgye.as_ref(),
                                    identity,
                                    gate.actions.get(request.method().as_str()),
                                ) {
                                    (Some(compiled), Some((subject, aal)), Some(action)) => {
                                        let decided = compiled.evaluate_scoped_resource(
                                            &gate.service_id,
                                            &gate.resource,
                                            action,
                                            subject,
                                            edge.client_ip,
                                            aal,
                                            evidence,
                                        );
                                        decision.authorization(
                                            crate::decision::Authorization::from_resource(decided),
                                            None,
                                            authz_started,
                                            crate::decision::Transport::Local,
                                        );
                                        decided
                                            == pumgye_core::ResourceDecision::Decided(
                                                pumgye_core::Decision::Allow,
                                            )
                                    }
                                    _ => false,
                                }
                            }
                        } else if let Some(gate) = &policy.pumgye {
                            let identity = crate::pumgye::identity(&headers);
                            let evidence = match &self.guard {
                                Some(guard) => match guard_evidence
                                    .take()
                                    .and_then(|proof| proof.current(guard, edge.client_ip))
                                {
                                    Some(evidence) => evidence,
                                    None => guard.authorization_evidence(edge.client_ip).await,
                                },
                                None => pumgye_core::GuardEvidence::Unavailable,
                            };
                            if snapshot.config.pumgye_authority.is_some() {
                                match (snapshot.pumgye_remote.as_ref(), identity) {
                                    (Some(remote), Some((subject, aal))) => match remote
                                        .authorize_traced(
                                            gate,
                                            request.method().as_str(),
                                            subject,
                                            edge.client_ip,
                                            aal,
                                            evidence,
                                        )
                                        .await
                                    {
                                        Ok(decided) => {
                                            decision.authorization(
                                                decided.decision,
                                                decided.revision,
                                                authz_started,
                                                remote.decision_transport(),
                                            );
                                            match decided.allowed_revision() {
                                                Some(revision) => {
                                                    if policy.enforce {
                                                        auth_route_lease
                                                            .get_or_insert_with(Default::default)
                                                            .pumgye_remote =
                                                            Some((remote.clone(), revision));
                                                    }
                                                    true
                                                }
                                                None => false,
                                            }
                                        }
                                        Err(_) if policy.enforce => {
                                            decision.authorization(
                                                crate::decision::Authorization::Unavailable,
                                                None,
                                                authz_started,
                                                remote.decision_transport(),
                                            );
                                            decision.refuse(
                                                Stage::Authorization,
                                                Reason::Pumgye(
                                                    crate::decision::Authorization::Unavailable,
                                                ),
                                            );
                                            return Ok(response(
                                                503,
                                                "Pumgye authority unavailable",
                                            ));
                                        }
                                        Err(_) => false,
                                    },
                                    (None, _) if policy.enforce => {
                                        decision.refuse(
                                            Stage::Authorization,
                                            Reason::Pumgye(
                                                crate::decision::Authorization::Unavailable,
                                            ),
                                        );
                                        return Ok(response(503, "Pumgye authority unavailable"));
                                    }
                                    _ => false,
                                }
                            } else {
                                match (
                                    snapshot.pumgye.as_ref(),
                                    identity,
                                    gate.permissions.get(request.method().as_str()),
                                ) {
                                    (Some(compiled), Some((subject, aal)), Some(permissions)) => {
                                        let denied = permissions
                                            .iter()
                                            .map(|permission| {
                                                compiled.evaluate(
                                                    &gate.service_id,
                                                    subject,
                                                    edge.client_ip,
                                                    permission,
                                                    &gate.information_class,
                                                    aal,
                                                    evidence,
                                                )
                                            })
                                            .find(|d| *d != pumgye_core::Decision::Allow);
                                        decision.authorization(
                                            denied.map_or(
                                                crate::decision::Authorization::Allow,
                                                crate::decision::Authorization::from_decision,
                                            ),
                                            None,
                                            authz_started,
                                            crate::decision::Transport::Local,
                                        );
                                        denied.is_none()
                                    }
                                    _ => false,
                                }
                            }
                        } else {
                            policy.allows(
                                request.method().as_str(),
                                crate::resource_policy::PrincipalEvidence::External(&headers),
                            )
                        };
                    }
                    for (name, value) in headers.iter() {
                        request.headers_mut().insert(name.clone(), value.clone());
                        established_identity.push((name.clone(), value.clone()));
                    }
                    native_preliminary_identity = typed_identity;
                    auth_cookies = cookies;
                }
                AuthOutcome::Deny(status) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    return Ok(response(status, "authorization refused"));
                }
                AuthOutcome::Forward(mut forwarded) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    if let Some(denied) =
                        retired_auth_response(auth_route_lease.as_ref(), &self.metrics)
                    {
                        return Ok(denied);
                    }
                    if let Some(lease) = &auth_route_lease {
                        let body = std::mem::replace(forwarded.body_mut(), full_body(Bytes::new()));
                        *forwarded.body_mut() =
                            AuthResponseBody::new(body, lease.clone(), self.metrics.clone())
                                .boxed_unsync();
                    }
                    return Ok(*forwarded);
                }
            }
        }

        if runtime
            .route
            .jwt_auth
            .as_ref()
            .is_some_and(|jwt| jwt.hide_credentials)
        {
            request.headers_mut().remove(header::AUTHORIZATION);
        }
        if !resource_allowed {
            self.metrics.errors.fetch_add(1, Ordering::Relaxed);
            match decision.authorization_decision() {
                Some(denied) if denied != crate::decision::Authorization::Allow => {
                    decision.refuse(Stage::Authorization, Reason::Pumgye(denied));
                }
                Some(_) => decision.refuse(Stage::Authorization, Reason::ResourcePolicyDenied),
                None if resource_policy.is_some_and(|p| p.has_pumgye()) => {
                    decision.refuse(Stage::Authorization, Reason::PumgyeIdentityMissing);
                }
                None => decision.refuse(Stage::Authorization, Reason::ResourcePolicyDenied),
            }
            return Ok(response(403, "resource permission denied"));
        }
        let Some(mut index) = self.select_http_backend(&runtime) else {
            decision.refuse(Stage::Enforcement, Reason::UpstreamUnavailable);
            return Ok(self.failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "all backends are unavailable",
            ));
        };
        let mut backend = runtime.route.backends[index].address().to_owned();

        if let Some(script) = &runtime.route.lua {
            // The policy API exposes one value per header name while the
            // upstream receives every field. A request that repeats a header
            // the script could read is therefore ambiguous: reject it, except
            // `cookie`, whose fields are joined into the single value RFC 9113
            // prescribes so the policy and the upstream see the same thing.
            if collapse_duplicate_policy_headers(request.headers_mut()).is_err() {
                return Ok(response(
                    StatusCode::BAD_REQUEST.as_u16(),
                    "ambiguous duplicate header",
                ));
            }
            let mut visible_headers = request.headers().clone();
            strip_hop_by_hop(&mut visible_headers);
            strip_forwarding_headers(&mut visible_headers);
            let input = PolicyInput {
                geoip: geoip.clone(),
                script: script.clone(),
                method: request.method().as_str().to_owned(),
                path: request.uri().path().to_owned(),
                headers: policy_headers(&visible_headers),
            };
            let evaluation = tokio::select! {
                biased;
                retired = auth_retired(auth_route_lease.as_ref()) => {
                    retired.record(&self.metrics);
                    decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                    return Ok(response(503, "route authorization retired"));
                }
                result = self.policy.evaluate(input) => result,
            };
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            match evaluation {
                Ok(decision) => {
                    if let Some(status) = decision.reject {
                        let status = StatusCode::from_u16(status)
                            .ok()
                            .filter(|s| s.is_client_error() || s.is_server_error())
                            .unwrap_or(StatusCode::FORBIDDEN);
                        return Ok(response(status.as_u16(), "request rejected by policy"));
                    }
                    if decision.backend.is_some() || decision.member_id.is_some() {
                        // Resolve only within the captured route snapshot. Member IDs are
                        // not addresses and may never fall back to address matching.
                        let chosen_index = runtime.route.backends.iter().position(|candidate| {
                            if let Some(id) = decision.member_id.as_deref() {
                                decision.backend.is_none() && candidate.id() == Some(id)
                            } else {
                                decision.backend.as_deref() == Some(candidate.address())
                            }
                        });
                        let Some(chosen_index) = chosen_index else {
                            self.metrics.policy_errors.fetch_add(1, Ordering::Relaxed);
                            return Ok(self.failure(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "policy selected an unknown or ambiguous backend",
                            ));
                        };
                        index = chosen_index;
                        backend = runtime.route.backends[index].address().to_owned();
                        policy_pinned_backend = true;
                    }
                    let protected = runtime
                        .route
                        .auth
                        .as_ref()
                        .map(|auth| auth.response_headers.as_slice())
                        .unwrap_or(&[]);
                    let basic_identity = runtime
                        .route
                        .basic_auth
                        .as_ref()
                        .and_then(|basic| basic.identity_header.as_deref());
                    if let Err(()) = apply_policy_headers(
                        request.headers_mut(),
                        decision.headers,
                        protected,
                        basic_identity,
                        auth_reserved,
                    ) {
                        self.metrics.policy_errors.fetch_add(1, Ordering::Relaxed);
                        return Ok(self.failure(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "policy returned an invalid header mutation",
                        ));
                    }
                }
                Err(error) => {
                    self.metrics.policy_errors.fetch_add(1, Ordering::Relaxed);
                    if error.is::<crate::policy::WorkerCapacityUnavailable>() {
                        self.metrics
                            .policy_capacity_rejections
                            .fetch_add(1, Ordering::Relaxed);
                        return Ok(self.failure(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "policy worker capacity exhausted",
                        ));
                    }
                    return Ok(
                        self.failure(StatusCode::SERVICE_UNAVAILABLE, "policy evaluation failed")
                    );
                }
            }
        }

        if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
            decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
            return Ok(denied);
        }

        // Explicitly protected routes check gateway authentication and any
        // configured Lua policy before honoring a cache-only request. Their
        // cache is ineligible, so no origin content follows this shortcut.
        if only_if_cached {
            return Ok(response(504, "only-if-cached cannot be satisfied"));
        }

        transform_request_no_transform |= crate::transform_body::no_transform(request.headers());
        transform_request_preconditions |= [
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
            header::IF_UNMODIFIED_SINCE,
        ]
        .iter()
        .any(|name| request.headers().contains_key(name));
        transform_request_range |= request.headers().contains_key(header::RANGE)
            || request.headers().contains_key(header::IF_RANGE);
        transform_request_partial |= request.headers().contains_key(header::CONTENT_RANGE);
        if transforms {
            if request.method() == Method::CONNECT
                || request.headers().contains_key(header::UPGRADE)
            {
                return Ok(response(
                    400,
                    "body transforms do not support tunnels or upgrades",
                ));
            }
            if transform_request_no_transform
                && (runtime.request_transform.is_some() || !conditional_response)
            {
                return Ok(response(400, "body transform conflicts with no-transform"));
            }
            if runtime.route.response_transform.is_some() {
                if transform_request_range {
                    return Ok(response(
                        416,
                        "ranges are unsupported for transformed representations",
                    ));
                }
                // Preconditions refer to the original representation.
                if !conditional_response && transform_request_preconditions {
                    return Ok(response(
                        412,
                        "preconditions are unsupported for transformed representations",
                    ));
                }
            }
            if runtime.request_transform.is_some() && transform_request_partial {
                return Ok(response(
                    400,
                    "partial request bodies cannot be transformed",
                ));
            }
        }

        let transform_budget = if transforms {
            match self.transformations.clone().try_acquire_owned() {
                Ok(permit) => Some(Arc::new(permit)),
                Err(_) => {
                    self.metrics
                        .rejected_requests
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(response(503, "body transformation capacity exhausted"));
                }
            }
        } else {
            None
        };
        if let Some(config) = &runtime.request_transform {
            crate::request_blocks::invalidate_body_cache(&mut request);
            if !crate::transform_body::identity_encoding(request.headers()) {
                return Ok(response(
                    415,
                    "encoded request transformation is unsupported",
                ));
            }
            let (mut parts, body) = request.into_parts();
            crate::transform_body::rewrite_headers(&mut parts.headers, config);
            // Config validation rejects a transform naming an identity header;
            // re-assert regardless so the authenticated identity always wins.
            reassert_identity_headers(&mut parts.headers, &established_identity, auth_reserved);
            let transformed = tokio::select! {
                biased;
                retired = auth_retired(auth_route_lease.as_ref()) => {
                    retired.record(&self.metrics);
                    decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                    return Ok(response(503, "route authorization retired"));
                }
                result = crate::transform_body::transform_with_geoip(
                body,
                config.clone(),
                self.policy.clone(),
                "request",
                geoip.clone(),
                transform_budget.clone().expect("transform budget"),
                self.metrics.clone(),
                ) => result,
            };
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            match transformed {
                Ok(body) => request = Request::from_parts(parts, body),
                Err(error) => {
                    return Ok(response(
                        error.status(true),
                        "request body transformation failed",
                    ));
                }
            }
        }
        transform_request_no_transform |= crate::transform_body::no_transform(request.headers());
        transform_request_preconditions |= [
            header::IF_MATCH,
            header::IF_NONE_MATCH,
            header::IF_MODIFIED_SINCE,
            header::IF_UNMODIFIED_SINCE,
        ]
        .iter()
        .any(|name| request.headers().contains_key(name));
        transform_request_range |= request.headers().contains_key(header::RANGE)
            || request.headers().contains_key(header::IF_RANGE);
        transform_request_partial |= request.headers().contains_key(header::CONTENT_RANGE);
        if transforms {
            if transform_request_no_transform
                && (runtime.request_transform.is_some() || !conditional_response)
            {
                return Ok(response(400, "body transform conflicts with no-transform"));
            }
            if runtime.request_transform.is_some() && transform_request_partial {
                return Ok(response(
                    400,
                    "partial request bodies cannot be transformed",
                ));
            }
            if runtime.response_transform.is_some() && transform_request_range {
                return Ok(response(
                    416,
                    "ranges are unsupported for transformed representations",
                ));
            }
            if runtime.response_transform.is_some()
                && !conditional_response
                && transform_request_preconditions
            {
                return Ok(response(
                    412,
                    "preconditions are unsupported for transformed representations",
                ));
            }
        }
        if (runtime.request_transform.is_some() || runtime.route.lua.is_some())
            && !snapshot.settings.request_blocks.is_empty()
        {
            request = match crate::request_blocks::check(
                &snapshot.settings.request_blocks,
                request,
                edge.forwarded_host.as_ref().and_then(|h| h.to_str().ok()),
                &self.request_inspectors,
                &self.request_spools,
            )
            .await
            {
                Ok(request) => request,
                Err(status) => {
                    decision.refuse(Stage::Enforcement, Reason::RequestBlocked);
                    crate::security_events::record("request_blocked", edge.client_ip, status, None);
                    return Ok(security_denied(status));
                }
            };
        }
        if runtime.route.response_transform.is_some() {
            request.headers_mut().insert(
                header::ACCEPT_ENCODING,
                HeaderValue::from_static("identity"),
            );
        }
        let response_has_body = request.method() != Method::HEAD;

        let mut docker_target = if backend.starts_with("docker://") {
            let Some(discovery) = self.discovery.load_full() else {
                return Ok(self.failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Docker discovery is unavailable",
                ));
            };
            let Some(target) =
                discovery.resolve_with_epoch(&backend, crate::discovery::Protocol::Http)
            else {
                return Ok(self.failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Docker backend is unavailable",
                ));
            };
            if !runtime.balancer.observe_epoch(index, target.epoch) {
                return Ok(self.failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Docker endpoint generation changed",
                ));
            }
            Some((backend.clone(), target, discovery))
        } else {
            None
        };
        let available = match &docker_target {
            Some((_, target, _)) => runtime.balancer.available_for(index, target.epoch),
            None => runtime.balancer.available(index),
        };
        if !available {
            return Ok(self.failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "selected backend is unavailable",
            ));
        }
        let lease = match &docker_target {
            Some((_, target, _)) => runtime.balancer.acquire_for(index, target.epoch),
            None => runtime.balancer.acquire(index),
        };
        let Some(lease) = lease else {
            return Ok(self.failure(
                StatusCode::SERVICE_UNAVAILABLE,
                "selected backend admission refused",
            ));
        };
        let mut backend_lease = Some(lease);
        if let Some((_, target, _)) = &docker_target {
            backend = target.endpoint.clone();
        }
        let websocket = valid_websocket_request(&request);
        let downstream_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
        let original_host = request.headers().get(header::HOST).cloned().or_else(|| {
            request
                .uri()
                .authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
        });
        strip_standard_hop_by_hop(request.headers_mut());
        strip_forwarding_headers(request.headers_mut());
        if websocket {
            request
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            request
                .headers_mut()
                .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        }
        set_forwarding_headers(
            request.headers_mut(),
            peer.ip(),
            edge.proto,
            edge.forwarded_host.as_ref(),
            edge.forwarded_port,
        );
        // Identity established by the authorization service or a policy may
        // live under `x-forwarded-user`-style names that the forwarding pass
        // above just cleared; the authenticated values always win.
        reassert_identity_headers(request.headers_mut(), &established_identity, auth_reserved);
        // Last header mutation before dispatch: after authorization, Lua,
        // request transforms, forwarding headers and identity reassertion,
        // and before retry headers are captured. Nothing below may add Cookie.
        let strip_cookies = runtime.route.effective_strip_cookies();
        if !strip_cookies.is_empty() {
            strip_request_cookies(request.headers_mut(), &strip_cookies);
        }
        if consumed_service_credential {
            // The API credential was consumed by the trusted native authenticator.
            // Strip it after all transforms so it cannot become an upstream credential.
            request.headers_mut().remove(header::AUTHORIZATION);
        }
        *request.version_mut() = Version::HTTP_11;
        // Regenerate HTTP/1 framing for an unknown-length body now that the
        // incoming Transfer-Encoding is gone. Without an explicit header the
        // client encoder assumes a GET/HEAD body is empty and silently drops
        // it, so the upstream would see a different request than the client
        // sent. An explicit `chunked` is honored for every method; a body of
        // exactly known size gets a Content-Length from the encoder instead.
        if request.method() != Method::CONNECT
            && !request.body().is_end_stream()
            && request.body().size_hint().exact().is_none()
            && !request.headers().contains_key(header::CONTENT_LENGTH)
        {
            request.headers_mut().insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        }

        let custom_outbound = docker_target.is_some()
            || runtime.route.upstream != Default::default()
            || runtime.route.upstream_host.is_some()
            || runtime.route.preserve_host;
        let host_override: Option<String> = runtime.route.upstream_host.clone().or_else(|| {
            runtime
                .route
                .preserve_host
                .then(|| {
                    original_host
                        .as_ref()
                        .and_then(|h| h.to_str().ok())
                        .map(str::to_owned)
                })
                .flatten()
        });
        // A request is safe to replay to another backend only if it carries no
        // body and no side-effecting semantics, and is not being transformed or
        // upgraded. This never replays a request that may have taken effect.
        let retryable = !websocket
            && !policy_pinned_backend
            && runtime.route.request_transform.is_none()
            && matches!(
                *request.method(),
                Method::GET | Method::HEAD | Method::OPTIONS | Method::DELETE
            )
            && request.body().size_hint().upper() == Some(0);
        let max_attempts = if retryable {
            1 + runtime.route.retries as usize
        } else {
            1
        };
        let header_timeout = runtime
            .route
            .upstream_timeout_ms
            .map(Duration::from_millis)
            .or(snapshot.settings.upstream_timeout)
            .unwrap_or(self.default_upstream_timeout);
        let cache_request_ms = if cache_fill.is_some() {
            crate::cache::now_ms()
        } else {
            0
        };
        // Template used to rebuild the request on a retry (retryable requests
        // are bodyless, so an empty body is a faithful replay).
        let method = request.method().clone();
        let version = request.version();
        let client_pq = request.uri().clone();
        request
            .extensions_mut()
            .remove::<Arc<crate::metrics::ConnectionLease>>();
        let base_headers = request.headers().clone();
        let (parts, first_body) = request.into_parts();
        let mut first_request = Some(Request::from_parts(parts, first_body));
        let mut attempt = 0usize;
        let upstream = loop {
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            attempt += 1;
            let uri = match build_upstream_uri(&backend, &client_pq, host_override.as_deref()) {
                Ok(uri) => uri,
                Err((code, message)) => return Ok(response(code, message)),
            };
            let client = if custom_outbound
                && !runtime
                    .native_resource
                    .as_ref()
                    .is_some_and(|binding| binding.observed_mode())
            {
                let client = match &docker_target {
                    Some((configured, target, discovery)) => self.outbound.client_for_epoch(
                        &runtime,
                        configured,
                        target,
                        Some(discovery.clone()),
                        snapshot.upstream_tls.get(&runtime.route.id),
                    ),
                    None => self.outbound.client(
                        &runtime,
                        &backend,
                        snapshot.upstream_tls.get(&runtime.route.id),
                    ),
                };
                match client {
                    Ok(client) => Some(client),
                    Err(_) => {
                        return Ok(self.failure(
                            StatusCode::BAD_GATEWAY,
                            "upstream transport configuration failed",
                        ));
                    }
                }
            } else {
                None
            };
            let mut outgoing = match first_request.take() {
                Some(mut request) => {
                    *request.uri_mut() = uri.clone();
                    // hyper-util synthesizes Host from the URI for HTTP/1.
                    // HTTP/2 uses :authority; forwarding a regular Host as
                    // well makes some origins reject the request as ambiguous.
                    request.headers_mut().remove(header::HOST);
                    request
                }
                None => {
                    let mut request = Request::builder()
                        .method(method.clone())
                        .uri(uri.clone())
                        .version(version)
                        .body(full_body(Bytes::new()))
                        .expect("rebuilt retry request is valid");
                    *request.headers_mut() = base_headers.clone();
                    request.headers_mut().remove(header::HOST);
                    request
                }
            };
            let mut native_observation = None;
            if let Some(binding) = &runtime.native_resource {
                let (Some(hopae), Some(authority), Some(context)) = (
                    runtime.auth_native.as_ref(),
                    snapshot.pumgye_remote.as_ref(),
                    native_auth_context.as_ref(),
                ) else {
                    decision.refuse(Stage::Authorization, Reason::NativeUnavailable);
                    return Ok(response(503, "native resource authority unavailable"));
                };
                let mut context = context.clone();
                if !binding.human_mode() {
                    for (name, value) in forward_auth_context(&outgoing, &edge) {
                        let Ok(value) = HeaderValue::from_str(&value) else {
                            return Ok(response(400, "native request context refused"));
                        };
                        context.insert(HeaderName::from_static(name), value);
                    }
                    for (name, value) in &runtime.auth_static_headers {
                        context.insert(name.clone(), value.clone());
                    }
                }
                binding.strip_human_credentials(outgoing.headers_mut());
                let selected_origin: Uri = match docker_target
                    .as_ref()
                    .map_or(backend.as_str(), |(_, target, _)| target.endpoint.as_str())
                    .parse()
                {
                    Ok(uri) => uri,
                    Err(_) => return Ok(response(503, "native selected origin invalid")),
                };
                let prepared = tokio::select! {
                    biased;
                    retired = auth_retired(auth_route_lease.as_ref()) => {
                        retired.record(&self.metrics);
                        decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                        return Ok(response(503, "route authorization retired"));
                    }
                    result = binding.prepare_for_origin(outgoing, self.native_bodies.clone(),&selected_origin) => match result {
                        Ok(prepared) => prepared,
                        Err(crate::projection_entity::Refused::TooLarge) => return Ok(response(413, "native entity too large")),
                        Err(crate::projection_entity::Refused::Length | crate::projection_entity::Refused::Trailers | crate::projection_entity::Refused::Target) => return Ok(response(400, "native entity refused")),
                        Err(_) => return Ok(response(503, "native entity unavailable")),
                    }
                };
                let route_owner =
                    match self
                        .native_routes
                        .capture(&snapshot, &runtime, &prepared, edge.client_ip)
                    {
                        Ok(owner) => owner,
                        Err(_) => return Ok(response(503, "native route owner unavailable")),
                    };
                let route_reference = self.route_owner_queries.then(|| route_owner.wire());
                let observation = tokio::select! {
                    biased;
                    retired = auth_retired(auth_route_lease.as_ref()) => {
                        retired.record(&self.metrics);
                        decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                        return Ok(response(503, "route authorization retired"));
                    }
                    result = binding.observe_after_preliminary(&prepared, &context, hopae, authority, edge.client_ip, route_reference.as_ref(), native_preliminary_identity.as_ref().map(|(subject, aal)| (subject.as_str(), *aal))) => match result {
                        Ok(observation) => observation,
                        Err(error) if error.is::<crate::projection_permit::Denied>() => {
                            decision.refuse(Stage::Authorization, Reason::NativePermissionDenied);
                            return Ok(response(403, "native resource permission denied"));
                        }
                        Err(_) => {
                            decision.refuse(Stage::Authorization, Reason::NativeUnavailable);
                            return Ok(response(503, "native resource authority unavailable"));
                        }
                    }
                };
                if !observation.allowed() {
                    decision.refuse(Stage::Authorization, Reason::NativePermissionDenied);
                    return Ok(response(403, "native resource permission denied"));
                }
                let (dispatch, seal) = prepared.into_dispatch_sealed();
                outgoing = dispatch;
                outgoing.headers_mut().remove(header::AUTHORIZATION);
                outgoing.headers_mut().remove("x-hopae-subject");
                if observation
                    .install_credential(outgoing.headers_mut())
                    .is_err()
                {
                    return Ok(response(503, "native credential expired"));
                }
                if let Some(seal) = seal {
                    let Some(slot) = observation.projected_slot() else {
                        return Ok(response(503, "Human projection slot unavailable"));
                    };
                    if seal.check(&outgoing, slot).is_err() {
                        return Ok(response(503, "Human final headers changed"));
                    }
                }
                native_observation = Some((
                    Arc::new(observation),
                    authority.clone(),
                    Arc::new(route_owner),
                ));
            }
            // Raw request bodies already carry the guard installed before
            // external auth/Lua/transform buffering. A transformed body is a
            // new stream and needs its own final output guard.
            if runtime.request_transform.is_some()
                && let Some(lease) = &auth_route_lease
                && !outgoing.body().is_end_stream()
            {
                outgoing = outgoing.map(|body| {
                    AuthResponseBody::new(body, lease.clone(), self.metrics.clone()).boxed_unsync()
                });
            }
            if let Some((configured, target, discovery)) = &docker_target
                && (discovery
                    .resolve_with_epoch(configured, crate::discovery::Protocol::Http)
                    .as_ref()
                    != Some(target)
                    || !runtime.balancer.available_for(index, target.epoch))
            {
                return Ok(self.failure(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Docker endpoint changed before request admission",
                ));
            }
            {
                let current = self.active.load_full();
                if request_policy_fence
                    .as_ref()
                    .is_some_and(|f| !f.current(&current.settings.request_blocks))
                    || public_admission
                        .as_ref()
                        .is_some_and(|e| !e.current(&current))
                {
                    return Ok(security_denied(503));
                }
            }
            if native_observation
                .as_ref()
                .is_some_and(|(observation, authority, route_owner)| {
                    !route_owner.current_for(edge.client_ip)
                        || !observation.local_fences_hold(authority)
                })
            {
                return Ok(response(503, "native resource observation retired"));
            }
            // Observed credentials belong to one operation. The native gate is
            // carried to the actual transport writes, including detached Hyper
            // driver tasks and rustls buffered ciphertext. No pool may retain it.
            let mut dispatch_timeout = header_timeout;
            let gated_client =
                if let Some((observation, authority, route_owner)) = &native_observation {
                    if let Some(remaining) = observation.remaining_dispatch() {
                        let Ok(remaining) = remaining else {
                            return Ok(response(503, "native dispatch expired"));
                        };
                        dispatch_timeout = dispatch_timeout.min(remaining);
                        let observation = observation.clone();
                        let authority = authority.clone();
                        let route_owner = route_owner.clone();
                        let ip = edge.client_ip;
                        let gate: crate::http_outbound::DispatchGate = Arc::new(move || {
                            route_owner.current_for(ip) && observation.local_fences_hold(&authority)
                        });
                        let result = match &docker_target {
                            Some((configured, target, discovery)) => self.outbound.gated_client(
                                &runtime,
                                configured,
                                &target.endpoint,
                                target.epoch,
                                Some(discovery.clone()),
                                snapshot.upstream_tls.get(&runtime.route.id),
                                gate,
                            ),
                            None => self.outbound.gated_client(
                                &runtime,
                                &backend,
                                &backend,
                                0,
                                None,
                                snapshot.upstream_tls.get(&runtime.route.id),
                                gate,
                            ),
                        };
                        match result {
                            Ok(client) => Some(client),
                            Err(_) => {
                                return Ok(response(503, "native dispatch transport unavailable"));
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };
            let send = async {
                if let Some(client) = &gated_client {
                    return client.request(outgoing).await;
                }
                match &client {
                    Some(client) => client.request(outgoing).await,
                    None => self.client.request(outgoing).await,
                }
            };
            let sent = tokio::select! {
                biased;
                retired = auth_retired(auth_route_lease.as_ref()) => {
                    retired.record(&self.metrics);
                    decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                    return Ok(response(503, "route authorization retired"));
                }
                result = timeout(dispatch_timeout, send) => result,
            };
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            match sent {
                Ok(Ok(response)) => {
                    decision.forwarded();
                    break response;
                }
                Ok(Err(error)) => {
                    if let Some(lease) = &backend_lease {
                        lease.record_transport_failure();
                    }
                    // Retry to a freshly selected (healthy) backend for a safely
                    // replayable request, and only when the failure proves the
                    // request was never transmitted: a connection-establishment
                    // error. A backend that accepted the connection and then
                    // dropped it may already have executed the request (a
                    // DELETE is idempotent, not side-effect free), so that is
                    // never replayed. Docker refs are not re-resolved here.
                    if retryable
                        && error.is_connect()
                        && attempt < max_attempts
                        && let Some(next) = self.select_http_backend(&runtime)
                    {
                        let candidate = runtime.route.backends[next].address().to_owned();
                        if !candidate.starts_with("docker://")
                            && let Some(lease) = runtime.balancer.acquire(next)
                        {
                            backend = candidate;
                            index = next;
                            docker_target = None;
                            backend_lease = Some(lease);
                            continue;
                        }
                    }
                    decision.refuse(Stage::Enforcement, Reason::UpstreamUnavailable);
                    return Ok(self.failure(StatusCode::BAD_GATEWAY, "upstream request failed"));
                }
                Err(_) => {
                    if let Some(lease) = &backend_lease {
                        lease.record_timeout();
                    }
                    decision.refuse(Stage::Enforcement, Reason::UpstreamUnavailable);
                    return Ok(self.failure(
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream response header timed out",
                    ));
                }
            }
        };
        let mut upstream = upstream;
        if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
            decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
            return Ok(denied);
        }

        let cache_header_ms = if cache_fill.is_some() {
            crate::cache::now_ms()
        } else {
            0
        };
        let cache_origin_ttl = if cache_fill.is_some() {
            runtime
                .route
                .cache
                .as_ref()
                .and_then(|settings| {
                    crate::cache_policy::response_ttl(
                        upstream.headers(),
                        upstream.status(),
                        settings,
                    )
                })
                .map(|(ttl, age)| {
                    (
                        ttl.saturating_sub(cache_header_ms.saturating_sub(cache_request_ms)),
                        age.saturating_add(
                            cache_header_ms
                                .saturating_sub(cache_request_ms)
                                .div_ceil(1000),
                        ),
                    )
                })
        } else {
            None
        };
        if cache_origin_ttl.is_none() {
            cache_fill = None;
        }
        if let Some(lease) = &backend_lease {
            lease.record_http_status(upstream.status().as_u16());
        }
        let response_is_websocket = websocket && valid_websocket_response(&upstream);
        if upstream.status() == StatusCode::SWITCHING_PROTOCOLS && !response_is_websocket {
            return Ok(self.failure(
                StatusCode::BAD_GATEWAY,
                "invalid or unsolicited upstream upgrade",
            ));
        }
        let upstream_upgrade = response_is_websocket.then(|| hyper::upgrade::on(&mut upstream));
        // Transformation eligibility belongs to the original representation;
        // hop-by-hop nominations and configured removals cannot erase it.
        let origin_transform_identity =
            crate::transform_body::identity_encoding(upstream.headers());
        let origin_transform_no_transform = crate::transform_body::no_transform(upstream.headers());
        let origin_transform_partial = upstream.status() == StatusCode::PARTIAL_CONTENT
            || upstream.headers().contains_key(header::CONTENT_RANGE);
        strip_hop_by_hop(upstream.headers_mut());
        // Streaming-safe response header rules (global removals + per-route
        // set/remove), applied to the head before the body is streamed.
        apply_response_header_rules(
            upstream.headers_mut(),
            snapshot
                .settings
                .remove_response_headers
                .as_deref()
                .map(Vec::as_slice)
                .unwrap_or(&self.remove_response_headers),
            &runtime.route.response_set_headers,
            &runtime.route.response_remove_headers,
        );
        for cookie in &auth_cookies {
            upstream
                .headers_mut()
                .append(header::SET_COOKIE, cookie.clone());
        }
        if response_is_websocket {
            upstream
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            upstream
                .headers_mut()
                .insert(header::UPGRADE, HeaderValue::from_static("websocket"));
        }

        if let (Some(downstream), Some(upstream)) = (downstream_upgrade, upstream_upgrade) {
            if let Some(denied) = retired_auth_response(auth_route_lease.as_ref(), &self.metrics) {
                decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                return Ok(denied);
            }
            // Register admission before checking closed. Shutdown must either
            // see this token or prevent this new tunnel from being spawned.
            let admission = self.tunnels.token();
            if self.tunnels.is_closed() {
                return Ok(response(503, "server is draining"));
            }
            let cancel = self.shutdown.clone();
            let tunnel_backend = backend_lease.clone();
            let tunnel_route = route_permit.clone();
            let tunnel_idle = self.tunnel_idle;
            let tunnel_auth = auth_route_lease.clone();
            let tunnel_metrics = self.metrics.clone();
            self.tunnels.spawn(async move {
                let _backend_lease = tunnel_backend;
                let _route_permit = tunnel_route;
                let _admission = admission;
                let _connection_lease = connection_lease;
                let upgraded = tokio::select! {
                    biased;
                    _ = cancel.cancelled() => return,
                    retired = auth_retired(tunnel_auth.as_ref()) => {
                        retired.record(&tunnel_metrics);
                        return;
                    },
                    upgraded = async { tokio::try_join!(downstream, upstream) } => upgraded,
                };
                if let Ok((downstream, upstream)) = upgraded {
                    // The listener's idle watchdog ended when hyper handed this
                    // socket over, so the tunnel keeps its own: every byte in
                    // either direction crosses the downstream side.
                    let (mut downstream, idle) =
                        crate::idle::IdleIo::new(TokioIo::new(downstream), tunnel_idle);
                    let mut upstream = TokioIo::new(upstream);
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => {}
                        retired = auth_retired(tunnel_auth.as_ref()) => {
                            retired.record(&tunnel_metrics);
                        }
                        _ = idle.expired() => {}
                        _ = copy_bidirectional(&mut downstream, &mut upstream) => {}
                    }
                }
            });
        }

        let (parts, body) = upstream.into_parts();
        let mut response = Response::from_parts(parts, boxed_incoming(body));
        if let Some(config) = &runtime.response_transform {
            if config.when_prefix.is_some()
                && (origin_transform_partial
                    || response.status() == StatusCode::PARTIAL_CONTENT
                    || response.headers().contains_key(header::CONTENT_RANGE))
            {
                return Ok(self.failure(
                    StatusCode::BAD_GATEWAY,
                    "partial representation cannot be inspected",
                ));
            }
            let mut selected = config.when_prefix.is_none();
            let inspection_started = std::time::Instant::now();
            if config.when_prefix.is_some()
                && response_has_body
                && !response.status().is_informational()
                && !matches!(response.status().as_u16(), 204 | 205 | 304)
            {
                if !origin_transform_identity
                    || !crate::transform_body::identity_encoding(response.headers())
                {
                    return Ok(self.failure(
                        StatusCode::BAD_GATEWAY,
                        "upstream representation cannot be inspected",
                    ));
                }
                let (parts, body) = response.into_parts();
                let probe = tokio::select! {
                    biased;
                    retired=auth_retired(auth_route_lease.as_ref())=>{retired.record(&self.metrics);return Ok(crate::proxy::response(503,"route authorization retired"));}
                    result=crate::transform_body::probe_prefix(body,config,transform_budget.clone().expect("transform budget"))=>result,
                };
                match probe {
                    Ok((body, matched)) => {
                        response = Response::from_parts(parts, body);
                        selected = matched;
                    }
                    Err(error) => {
                        return Ok(self.failure(
                            StatusCode::from_u16(error.status(false)).expect("static status"),
                            "response body inspection failed",
                        ));
                    }
                }
                if selected && transform_request_no_transform {
                    return Ok(crate::proxy::response(
                        400,
                        "body transform conflicts with no-transform",
                    ));
                }
                if selected && transform_request_preconditions {
                    return Ok(crate::proxy::response(
                        412,
                        "preconditions are unsupported for transformed representations",
                    ));
                }
            }
            if selected
                && response_has_body
                && !response.status().is_informational()
                && response.status() != StatusCode::NO_CONTENT
                && response.status() != StatusCode::NOT_MODIFIED
                && response.status() != StatusCode::RESET_CONTENT
            {
                if !origin_transform_identity
                    || !crate::transform_body::identity_encoding(response.headers())
                    || origin_transform_no_transform
                    || crate::transform_body::no_transform(response.headers())
                    || origin_transform_partial
                    || response.status() == StatusCode::PARTIAL_CONTENT
                    || response.headers().contains_key(header::CONTENT_RANGE)
                {
                    return Ok(self.failure(
                        StatusCode::BAD_GATEWAY,
                        "upstream representation cannot be transformed",
                    ));
                }
                let (mut parts, body) = response.into_parts();
                crate::transform_body::rewrite_headers(&mut parts.headers, config);
                let transform_config = if config.when_prefix.is_some() {
                    let mut remaining = (**config).clone();
                    let elapsed = inspection_started
                        .elapsed()
                        .as_millis()
                        .min(u64::MAX as u128) as u64;
                    if elapsed >= remaining.timeout_ms {
                        return Ok(self.failure(
                            StatusCode::GATEWAY_TIMEOUT,
                            "response body inspection timed out",
                        ));
                    }
                    remaining.timeout_ms -= elapsed;
                    Arc::new(remaining)
                } else {
                    config.clone()
                };
                let transformed = tokio::select! {
                    biased;
                    retired = auth_retired(auth_route_lease.as_ref()) => {
                        retired.record(&self.metrics);
                        decision.refuse(Stage::Enforcement, Reason::AuthorizationRetired);
                        return Ok(crate::proxy::response(503, "route authorization retired"));
                    }
                    result = crate::transform_body::transform_with_geoip(
                    body,
                    transform_config,
                    self.policy.clone(),
                    "response",
                    geoip.clone(),
                    transform_budget.clone().expect("transform budget"),
                    self.metrics.clone(),
                    ) => result,
                };
                if let Some(denied) =
                    retired_auth_response(auth_route_lease.as_ref(), &self.metrics)
                {
                    return Ok(denied);
                }
                match transformed {
                    Ok(body) => response = Response::from_parts(parts, body),
                    Err(error) => {
                        return Ok(self.failure(
                            StatusCode::from_u16(error.status(false)).expect("static status"),
                            "response body transformation failed",
                        ));
                    }
                }
            } else if selected {
                crate::transform_body::rewrite_headers(response.headers_mut(), config);
            }
        }
        if let (Some(fill), Some((origin_ttl, origin_age)), Some(settings)) =
            (cache_fill, cache_origin_ttl, runtime.route.cache.as_ref())
            && let Some((final_ttl, final_age)) =
                crate::cache_policy::response_ttl(response.headers(), response.status(), settings)
        {
            response = crate::cache::capture(
                response,
                fill,
                origin_ttl.min(final_ttl),
                origin_age.max(final_age),
                cache_header_ms,
            );
        }
        if let Some(lease) = backend_lease {
            response.extensions_mut().insert(lease);
        }
        if let Some(permit) = route_permit {
            response.extensions_mut().insert(permit);
        }
        if let Some(lease) = auth_route_lease {
            response = response.map(|body| {
                AuthResponseBody::new(body, lease, self.metrics.clone()).boxed_unsync()
            });
        }
        Ok(response)
    }

    pub async fn shutdown(&self, grace: Duration) {
        self.tunnels.close();
        if timeout(grace, self.tunnels.wait()).await.is_err() {
            self.shutdown.cancel();
            let _ = timeout(Duration::from_secs(1), self.tunnels.wait()).await;
        }
        self.shutdown.cancel();
    }

    fn failure(&self, status: StatusCode, text: &str) -> Response<Body> {
        self.metrics.errors.fetch_add(1, Ordering::Relaxed);
        response(status.as_u16(), text)
    }
}

fn canonical_domain_redirect(
    request: &Request<Body>,
    edge: &EdgeContext,
    canonical_path: &str,
    policy: &crate::config::CanonicalDomain,
) -> Option<Response<Body>> {
    if !policy.enabled
        || !policy
            .methods
            .iter()
            .any(|method| method == request.method().as_str())
        || !policy
            .path_prefixes
            .iter()
            .any(|prefix| canonical_prefix_matches(prefix, canonical_path))
        || policy
            .exclude_path_prefixes
            .iter()
            .any(|prefix| canonical_prefix_matches(prefix, canonical_path))
    {
        return None;
    }
    let current = edge
        .forwarded_host
        .as_ref()?
        .to_str()
        .ok()?
        .parse::<hyper::http::uri::Authority>()
        .ok()?;
    if current.host().eq_ignore_ascii_case(&policy.host) {
        return None;
    }
    let scheme = match policy.scheme {
        crate::config::CanonicalScheme::Http => "http",
        crate::config::CanonicalScheme::Https => "https",
    };
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let location = HeaderValue::from_str(&format!("{scheme}://{}{path}", policy.host)).ok()?;
    let mut redirect = response(policy.status, "redirecting to canonical domain");
    redirect.headers_mut().insert(header::LOCATION, location);
    redirect
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    redirect.headers_mut().insert(
        HeaderName::from_static("x-hangang-canonical-redirect"),
        HeaderValue::from_static("true"),
    );
    Some(redirect)
}

fn canonical_prefix_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || (path.starts_with(prefix)
            && (prefix.ends_with('/') || path.as_bytes().get(prefix.len()) == Some(&b'/')))
}

#[derive(Debug)]
enum InspectError {
    TooLarge,
    Timeout,
    Invalid,
}

async fn inspect_json_body(
    request: Request<Body>,
) -> Result<(Request<Body>, serde_json::Value), InspectError> {
    let (parts, body) = request.into_parts();
    if parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_INSPECT_BODY as u64)
    {
        return Err(InspectError::TooLarge);
    }
    let collected = timeout(
        BODY_READ_TIMEOUT,
        Limited::new(body, MAX_INSPECT_BODY).collect(),
    )
    .await
    .map_err(|_| InspectError::Timeout)?
    .map_err(|error| {
        if error.is::<http_body_util::LengthLimitError>() {
            InspectError::TooLarge
        } else {
            InspectError::Invalid
        }
    })?;
    let bytes = collected.to_bytes();
    let json = serde_json::from_slice(&bytes).map_err(|_| InspectError::Invalid)?;
    Ok((Request::from_parts(parts, full_body(bytes)), json))
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("Bearer")
        && !token.is_empty()
        && !token.bytes().any(|byte| byte.is_ascii_whitespace()))
    .then_some(token)
}

#[cfg(test)]
fn basic_match<B>(
    route: &HttpRoute,
    request: &Request<B>,
    host_regex: Option<&regex::Regex>,
) -> bool {
    basic_match_path(route, request, host_regex, request.uri().path())
}

fn basic_match_path<B>(
    route: &HttpRoute,
    request: &Request<B>,
    host_regex: Option<&regex::Regex>,
    path: &str,
) -> bool {
    if !crate::resource_guard::listener_matches(route, request) {
        return false;
    }
    let constrained_host = route.host.is_some() || !route.hosts.is_empty() || host_regex.is_some();
    if (constrained_host
        && !crate::resource_guard::host_matches(
            route,
            host_regex,
            crate::resource_guard::request_host(request).as_deref(),
        ))
        || !crate::resource_guard::path_matches(route, path)
    {
        return false;
    }
    route.headers.iter().all(|(name, value)| {
        request
            .headers()
            .get(name)
            .is_some_and(|actual| actual.as_bytes() == value.as_bytes())
    })
}

fn json_match(route: &HttpRoute, value: &serde_json::Value) -> bool {
    route
        .json
        .iter()
        .all(|(pointer, expected)| value.pointer(pointer) == Some(expected))
}

fn policy_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_owned(), v.to_owned()))
        })
        .collect()
}

fn apply_policy_headers(
    headers: &mut HeaderMap,
    mutations: BTreeMap<String, String>,
    protected: &[String],
    basic_identity: Option<&str>,
    auth_reserved: &[HeaderName],
) -> Result<(), ()> {
    for (name, value) in mutations {
        let name: HeaderName = name.parse().map_err(|_| ())?;
        // A policy must not rewrite framing/forwarding/credential headers, nor
        // the identity headers an external authorization service established for
        // this request (its `response_headers`).
        if sensitive_mutation(&name)
            || protected
                .iter()
                .any(|p| p.eq_ignore_ascii_case(name.as_str()))
            || basic_identity.is_some_and(|p| p.eq_ignore_ascii_case(name.as_str()))
            || auth_reserved.contains(&name)
        {
            return Err(());
        }
        let value: HeaderValue = value.parse().map_err(|_| ())?;
        headers.insert(name, value);
    }
    Ok(())
}

fn sensitive_mutation(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "x-real-ip"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
            | "forwarded"
            | "authorization"
            | "cookie"
    ) || name.as_str().starts_with("x-forwarded-")
        || name.as_str().starts_with("sec-websocket-")
}

fn connection_tokens(headers: &HeaderMap) -> HashSet<HeaderName> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|v| v.as_bytes().split(|b| *b == b','))
        .filter_map(|v| std::str::from_utf8(v).ok())
        .filter_map(|v| v.trim().parse().ok())
        .collect()
}

fn has_duplicate_header(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(name).iter().nth(1).is_some()
}

/// The fixed hop-by-hop header set (RFC 7230 §6.1 plus proxy-specific ones).
const STANDARD_HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_standard_hop_by_hop(name: &HeaderName) -> bool {
    STANDARD_HOP_BY_HOP.contains(&name.as_str())
}

/// True if any path segment is a `.` or `..` dot segment, considering
/// percent-encoded dots (`%2e`/`%2E`) that a backend would decode before
/// normalizing. Segment boundaries are the raw `/`, a raw backslash, and the
/// percent-encoded forms of both (`%2f`/`%2F`, `%5c`/`%5C`): a backend that
/// decodes the separator before resolving `..` would otherwise turn
/// `/public/%2e%2e%2fadmin` into `/admin` after it matched the `/public`
/// route. Only these escapes are decoded so other escapes stay opaque.
fn path_has_dot_segment(path: &str) -> bool {
    let normalized = path
        .replace("%2f", "/")
        .replace("%2F", "/")
        .replace("%5c", "\\")
        .replace("%5C", "\\");
    normalized.split(['/', '\\']).any(|segment| {
        let decoded = segment.replace("%2e", ".").replace("%2E", ".");
        decoded == "." || decoded == ".."
    })
}

/// Validate and canonicalize the request's Content-Length fields. Every value
/// must be a pure decimal (RFC 9110 `1*DIGIT`, no list syntax) and all values
/// must agree; accepted duplicates collapse to one canonical field so the raw
/// duplicates are never forwarded. Anything else is an error.
fn canonicalize_content_length(headers: &mut HeaderMap) -> Result<(), ()> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(first) = values.next() else {
        return Ok(());
    };
    let length = parse_content_length(first).ok_or(())?;
    let mut duplicated = false;
    for value in values {
        if parse_content_length(value) != Some(length) {
            return Err(());
        }
        duplicated = true;
    }
    if duplicated || first.as_bytes() != length.to_string().as_bytes() {
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    Ok(())
}

fn parse_content_length(value: &HeaderValue) -> Option<u64> {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Before a Lua policy runs, make every header it could read unambiguous. The
/// policy API returns one value per name, while the upstream receives every
/// field, so a repeated application header could satisfy a policy check with
/// one value while the upstream acts on another. Repeated `cookie` fields are
/// joined with `; ` (RFC 9113 §8.2.3) so both sides see the same single value;
/// any other repeated header that is neither hop-by-hop nor a regenerated
/// forwarding header is rejected.
fn collapse_duplicate_policy_headers(headers: &mut HeaderMap) -> Result<(), ()> {
    join_cookie_headers(headers)?;
    for name in headers.keys() {
        if has_duplicate_header(headers, name.as_str())
            && !is_standard_hop_by_hop(name)
            && !is_forwarding_identity_header(name)
        {
            return Err(());
        }
    }
    Ok(())
}

fn is_cookie_token_byte(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.'
        | b'^' | b'_' | b'`' | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

/// True when `name` occurs in `bytes` delimited on both sides by a non-token
/// byte (or an end). Deliberately over-approximate: it is the fail-safe check.
fn contains_cookie_name(bytes: &[u8], name: &[u8]) -> bool {
    if name.is_empty() || bytes.len() < name.len() {
        return false;
    }
    (0..=bytes.len() - name.len()).any(|at| {
        &bytes[at..at + name.len()] == name
            && (at == 0 || !is_cookie_token_byte(bytes[at - 1]))
            && bytes
                .get(at + name.len())
                .is_none_or(|b| !is_cookie_token_byte(*b))
    })
}

/// Split on `;` outside double quotes. `None` when a quote is left open.
fn split_cookie_pairs(value: &[u8]) -> Option<Vec<&[u8]>> {
    let mut pairs = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut i = 0;
    while i < value.len() {
        match value[i] {
            b'\\' if quoted => i += 1,
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                pairs.push(&value[start..i]);
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if quoted {
        return None;
    }
    pairs.push(&value[start.min(value.len())..]);
    Some(pairs)
}

/// Remove every cookie pair whose name exactly equals one of `names` from all
/// Cookie fields. Pairs are split on `;` outside quoted values; the other
/// pairs keep their bytes and order and are rejoined with `; `. If nothing
/// remains, or the result could still carry a listed cookie (an unbalanced
/// quote, or a listed name still present at a token boundary such as in
/// `a=1 name=v`), the whole header is dropped rather than risk forwarding
/// part of a removed cookie or corrupting another one.
fn strip_request_cookies(headers: &mut HeaderMap, names: &[String]) {
    if !headers.contains_key(header::COOKIE) {
        return;
    }
    let mut kept: Vec<u8> = Vec::new();
    let mut sensitive = false;
    let mut clean = true;
    for value in headers.get_all(header::COOKIE) {
        sensitive |= value.is_sensitive();
        let Some(pairs) = split_cookie_pairs(value.as_bytes()) else {
            clean = false;
            break;
        };
        for pair in pairs {
            let pair = pair.trim_ascii();
            if pair.is_empty() {
                continue;
            }
            let name = pair
                .iter()
                .position(|b| *b == b'=')
                .map_or(pair, |at| pair[..at].trim_ascii());
            if names.iter().any(|n| n.as_bytes() == name) {
                continue;
            }
            if !kept.is_empty() {
                kept.extend_from_slice(b"; ");
            }
            kept.extend_from_slice(pair);
        }
    }
    clean = clean
        && !names
            .iter()
            .any(|n| contains_cookie_name(&kept, n.as_bytes()));
    headers.remove(header::COOKIE);
    if !clean || kept.is_empty() {
        return;
    }
    if let Ok(mut value) = HeaderValue::from_bytes(&kept) {
        value.set_sensitive(sensitive);
        headers.insert(header::COOKIE, value);
    }
}

/// RFC 9113 section 8.2.3: join Cookie fields with `; ` before exposing
/// them to a generic application or HTTP/1 peer. Do not apply list joining
/// to Set-Cookie or any other header. Preserve byte order and sensitivity.
fn join_cookie_headers(headers: &mut HeaderMap) -> Result<(), ()> {
    let mut values = headers.get_all(header::COOKIE).iter();
    let (Some(first), Some(second)) = (values.next(), values.next()) else {
        return Ok(());
    };
    // The ingress parser already enforces its header budget. Each removed
    // Cookie field includes more framing/name overhead than the two-byte
    // separator added here (HTTP/2 also accounts for 32 bytes per field).
    // Thus this representation cannot exceed the admitted header budget.
    let capacity = headers
        .get_all(header::COOKIE)
        .iter()
        .try_fold(0_usize, |size, value| {
            size.checked_add(value.as_bytes().len())?.checked_add(2)
        })
        .and_then(|size| size.checked_sub(2))
        .ok_or(())?;
    let mut joined = Vec::new();
    joined.try_reserve_exact(capacity).map_err(|_| ())?;
    joined.extend_from_slice(first.as_bytes());
    let mut sensitive = first.is_sensitive();
    for value in std::iter::once(second).chain(values) {
        joined.extend_from_slice(b"; ");
        joined.extend_from_slice(value.as_bytes());
        sensitive |= value.is_sensitive();
    }
    let mut value = HeaderValue::from_bytes(&joined).map_err(|_| ())?;
    value.set_sensitive(sensitive);
    headers.insert(header::COOKIE, value);
    Ok(())
}

/// Re-insert identity headers established by authentication, replacing any
/// value a later header rewrite may have set for the same name.
fn reassert_identity_headers(
    headers: &mut HeaderMap,
    identity: &[(HeaderName, HeaderValue)],
    auth_reserved: &[HeaderName],
) {
    for name in auth_reserved {
        headers.remove(name);
    }
    for (name, _) in identity {
        headers.remove(name);
    }
    for (name, value) in identity {
        headers.insert(name.clone(), value.clone());
    }
}

/// Remove only the fixed hop-by-hop set, WITHOUT consulting a `Connection`
/// header's token list. Used on the outgoing upstream request after gateway
/// headers have been injected, so that a client-supplied `Connection: <name>`
/// cannot delete an auth/policy/transform-injected header (the client-declared
/// tokens are handled earlier by `drop_client_connection_marked_headers`).
fn strip_standard_hop_by_hop(headers: &mut HeaderMap) {
    for name in STANDARD_HOP_BY_HOP {
        headers.remove(name);
    }
}

/// Remove the arbitrary headers a client named in its `Connection` header,
/// except the standard hop-by-hop names (which are stripped/renegotiated
/// separately and include `upgrade` needed for WebSocket detection). Run this
/// on the incoming request BEFORE any gateway header injection.
fn drop_client_connection_marked_headers(headers: &mut HeaderMap) {
    for name in connection_tokens(headers) {
        if !is_standard_hop_by_hop(&name) {
            headers.remove(&name);
        }
    }
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    for name in connection_tokens(headers) {
        headers.remove(name);
    }
    strip_standard_hop_by_hop(headers);
}

fn strip_forwarding_headers(headers: &mut HeaderMap) {
    let names: Vec<_> = headers
        .keys()
        .filter(|name| {
            matches!(name.as_str(), "forwarded" | "x-real-ip")
                || name.as_str().starts_with("x-forwarded-")
        })
        .cloned()
        .collect();
    for name in names {
        headers.remove(name);
    }
}

fn is_forwarding_identity_header(name: &HeaderName) -> bool {
    // `host` is included: a client must not be able to hide an invalid or
    // spoofed Host from validation by nominating it as hop-by-hop.
    matches!(name.as_str(), "forwarded" | "x-real-ip" | "host")
        || name.as_str().starts_with("x-forwarded-")
}

fn set_forwarding_headers(
    headers: &mut HeaderMap,
    client_ip: std::net::IpAddr,
    proto: &str,
    host: Option<&HeaderValue>,
    port: u16,
) {
    if let Ok(value) = HeaderValue::from_str(&client_ip.to_string()) {
        headers.insert(HeaderName::from_static("x-real-ip"), value.clone());
        headers.insert(HeaderName::from_static("x-forwarded-for"), value);
    }
    if let Ok(value) = HeaderValue::from_str(proto) {
        headers.insert(HeaderName::from_static("x-forwarded-proto"), value);
    }
    if let Some(host) = host {
        headers.insert(HeaderName::from_static("x-forwarded-host"), host.clone());
    }
    if port != 0
        && let Ok(value) = HeaderValue::from_str(&port.to_string())
    {
        headers.insert(HeaderName::from_static("x-forwarded-port"), value);
    }
}

/// Request context sent to an external authorization service, in the order
/// the headers are inserted. `x-original-uri`/`x-forwarded-uri` are always
/// origin-form (path and query), independent of the client's HTTP version.
/// Trusted native response metadata only; actual SDK/H0 proof remains mandatory.
fn native_human_policy_identity<'a>(headers: &'a HeaderMap, issuer: &str) -> Option<(&'a str, u8)> {
    let unique = |name: &str| {
        let mut values = headers.get_all(name).iter();
        let first = values.next()?;
        if values.next().is_some() {
            None
        } else {
            first.to_str().ok()
        }
    };
    if unique("x-hopae-human-policy-issuer")? != issuer {
        return None;
    }
    let subject = unique("x-hopae-human-policy-subject")?;
    pumgye_core::HumanSubject::parse(subject).ok()?;
    let mut kinds = headers.get_all("x-hopae-principal-kind").iter();
    if kinds.next().is_some_and(|v| v.as_bytes() != b"human") || kinds.next().is_some() {
        return None;
    }
    let aal = match unique("x-hopae-aal")? {
        "1" => 1,
        "2" => 2,
        _ => return None,
    };
    Some((subject, aal))
}
fn auth_request_headers(
    auth: &crate::config::ExternalAuth,
    static_headers: &[(HeaderName, HeaderValue)],
    original: &Request<Body>,
    edge: &EdgeContext,
) -> Result<HeaderMap, u16> {
    let mut headers = HeaderMap::new();
    for name in &auth.request_headers {
        for value in original.headers().get_all(name) {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| 503u16)?,
                value.clone(),
            );
        }
    }
    // Generated request context always wins over anything a client
    // sent under the same name (the copy above used `append`; these
    // use `insert`). Values come from the trusted-proxy resolution,
    // so behind a trusted load balancer the service sees the real
    // client, scheme and host. `x-original-*` names are kept for
    // existing deployments; `x-forwarded-*`, `x-real-ip` and
    // `x-original-url` are the set most authorization services expect.
    for (name, value) in forward_auth_context(original, edge) {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(&value).map_err(|_| 503u16)?,
        );
    }
    // Configured static headers are applied last with `insert`, so a
    // client copy of the same name can never reach the service.
    for (name, value) in static_headers {
        headers.insert(name.clone(), value.clone());
    }
    Ok(headers)
}

fn forward_auth_context(
    original: &Request<Body>,
    edge: &EdgeContext,
) -> Vec<(&'static str, String)> {
    let method = original.method().as_str().to_owned();
    let uri = original
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| "/".to_owned());
    let client_ip = edge.client_ip.to_string();
    let host = edge
        .forwarded_host
        .as_ref()
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut context = vec![
        ("x-original-method", method.clone()),
        ("x-original-uri", uri.clone()),
        ("x-original-client-ip", client_ip.clone()),
        ("x-forwarded-method", method),
        ("x-forwarded-uri", uri.clone()),
        ("x-forwarded-proto", edge.proto.to_owned()),
        ("x-forwarded-port", edge.forwarded_port.to_string()),
        ("x-forwarded-for", client_ip.clone()),
        ("x-real-ip", client_ip),
    ];
    if let Some(host) = host {
        let default_port = matches!(
            (edge.proto, edge.forwarded_port),
            ("http", 80) | ("https", 443)
        );
        let authority = if default_port || host_has_port(&host) {
            host.clone()
        } else {
            format!("{host}:{}", edge.forwarded_port)
        };
        context.push(("x-forwarded-host", host));
        context.push((
            "x-original-url",
            format!("{}://{authority}{uri}", edge.proto),
        ));
    }
    context
}

/// Select only unambiguous request authority metadata for response policies.
/// Routing keeps its existing rules; this guard must not use trusted forwarding
/// to reconcile a conflicting raw Host and URI :authority.
fn response_security_authority(
    headers: &HeaderMap,
    uri: &Uri,
    transport_tls: bool,
) -> Option<hyper::http::uri::Authority> {
    let mut hosts = headers.get_all(header::HOST).iter();
    let host = match hosts.next() {
        Some(value) => {
            if hosts.next().is_some() || !valid_authority(value) {
                return None;
            }
            Some(
                value
                    .to_str()
                    .ok()?
                    .parse::<hyper::http::uri::Authority>()
                    .ok()?,
            )
        }
        None => None,
    };
    let authority = match uri.authority() {
        Some(value) => {
            if !valid_authority(&HeaderValue::from_str(value.as_str()).ok()?) {
                return None;
            }
            Some(value.clone())
        }
        None => None,
    };
    if let (Some(host), Some(authority)) = (&host, &authority) {
        let default_port = if transport_tls { 443 } else { 80 };
        if !host
            .host()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(authority.host().trim_end_matches('.'))
            || host.port_u16().unwrap_or(default_port)
                != authority.port_u16().unwrap_or(default_port)
        {
            return None;
        }
    }
    host.or(authority)
}

/// A Host / X-Forwarded-Host value that is a well-formed authority (host with
/// optional port, no userinfo, no path/query/fragment characters).
fn valid_authority(value: &HeaderValue) -> bool {
    let Ok(text) = value.to_str() else {
        return false;
    };
    let Ok(authority) = text.parse::<hyper::http::uri::Authority>() else {
        return false;
    };
    if authority.host().is_empty() || text.contains('@') || authority.as_str() != text {
        return false;
    }
    // `Authority` checks delimiters only: the port must be decimal (and not
    // empty), and a bracketed host must be an IPv6 literal.
    let host = authority.host();
    if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        if inner.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
    } else if host.contains([':', '%', '[', ']']) {
        return false;
    }
    match text.len() > host.len() {
        true => {
            let port = &text[host.len()..];
            port.strip_prefix(':').is_some_and(|digits| {
                !digits.is_empty()
                    && digits.len() <= 5
                    && digits.bytes().all(|b| b.is_ascii_digit())
                    && digits.parse::<u16>().is_ok()
            })
        }
        false => true,
    }
}

/// Whether a Host-style authority already carries an explicit port
/// (`example.com:8443`, `[::1]:8443`), so a forwarded port is not appended twice.
fn host_has_port(host: &str) -> bool {
    match host.rsplit_once(':') {
        Some((head, port)) => {
            !port.is_empty()
                && port.bytes().all(|b| b.is_ascii_digit())
                && (!head.contains(':') || (host.starts_with('[') && head.ends_with(']')))
        }
        None => false,
    }
}

struct EdgeContext {
    client_ip: std::net::IpAddr,
    proto: &'static str,
    forwarded_host: Option<HeaderValue>,
    forwarded_port: u16,
    explicit_forwarded_port: Option<u16>,
}

impl Proxy {
    fn resolve_edge(
        &self,
        request: &Request<Incoming>,
        peer: SocketAddr,
        trusted_proxies: &[ipnet::IpNet],
    ) -> Result<EdgeContext, crate::trusted_proxy::InvalidForwardedHeader> {
        let transport = request
            .extensions()
            .get::<crate::tls::TransportInfo>()
            .copied()
            .unwrap_or_default();
        let headers = request.headers();
        // RFC 7230 §5.4: more than one Host field is a 400.
        if headers.get_all(header::HOST).iter().count() > 1 {
            return Err(crate::trusted_proxy::InvalidForwardedHeader);
        }
        let client_host = headers.get(header::HOST).cloned().or_else(|| {
            request
                .uri()
                .authority()
                .and_then(|a| HeaderValue::from_str(a.as_str()).ok())
        });
        // The host becomes URL text (auth context `x-original-url`, HTTPS
        // redirects, `X-Forwarded-Host`); only a well-formed authority may.
        // A raw `Host: app.test/public#` would otherwise let the client
        // choose the path structure an authorization service sees.
        if client_host
            .as_ref()
            .is_some_and(|host| !valid_authority(host))
        {
            return Err(crate::trusted_proxy::InvalidForwardedHeader);
        }
        let trusted = !trusted_proxies.is_empty()
            && crate::trusted_proxy::is_trusted(peer.ip(), trusted_proxies);
        if !trusted {
            let proto = if transport.tls { "https" } else { "http" };
            return Ok(EdgeContext {
                client_ip: peer.ip(),
                proto,
                forwarded_host: client_host,
                forwarded_port: default_forwarded_port(proto, transport.local_port),
                explicit_forwarded_port: None,
            });
        }
        let client_ip =
            crate::trusted_proxy::client_ip_from_forwarded(peer.ip(), headers, trusted_proxies)?;
        let proto = crate::trusted_proxy::forwarded_proto(headers, transport.tls);
        let mut forwarded_hosts = headers.get_all("x-forwarded-host").iter();
        let forwarded_host = forwarded_hosts.next().cloned().or(client_host);
        if forwarded_hosts.next().is_some() {
            return Err(crate::trusted_proxy::InvalidForwardedHeader);
        }
        if forwarded_host
            .as_ref()
            .is_some_and(|host| !valid_authority(host))
        {
            return Err(crate::trusted_proxy::InvalidForwardedHeader);
        }
        let mut forwarded_ports = headers.get_all("x-forwarded-port").iter();
        let forwarded_port_value = forwarded_ports.next();
        let forwarded_port_explicit = forwarded_port_value.is_some();
        let forwarded_port = match forwarded_port_value {
            Some(value) => {
                if forwarded_ports.next().is_some() {
                    return Err(crate::trusted_proxy::InvalidForwardedHeader);
                }
                let value = value
                    .to_str()
                    .map_err(|_| crate::trusted_proxy::InvalidForwardedHeader)?;
                if value.is_empty()
                    || value.len() > 5
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(crate::trusted_proxy::InvalidForwardedHeader);
                }
                value
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or(crate::trusted_proxy::InvalidForwardedHeader)?
            }
            None => default_forwarded_port(proto, transport.local_port),
        };
        Ok(EdgeContext {
            client_ip,
            proto,
            forwarded_host,
            forwarded_port,
            explicit_forwarded_port: forwarded_port_explicit.then_some(forwarded_port),
        })
    }
}

fn apply_response_header_rules(
    headers: &mut HeaderMap,
    global_remove: &[HeaderName],
    set: &BTreeMap<String, String>,
    remove: &[String],
) {
    for name in global_remove {
        headers.remove(name);
    }
    for name in remove {
        if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&name);
        }
    }
    for (name, value) in set {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            // Config validation already rejects framing/hop-by-hop names; guard
            // again so a rule can never corrupt message framing.
            if !is_standard_hop_by_hop(&name)
                && !matches!(
                    name.as_str(),
                    "content-length" | "content-encoding" | "content-range"
                )
            {
                headers.insert(name, value);
            }
        }
    }
}

fn default_forwarded_port(proto: &str, local_port: u16) -> u16 {
    if local_port != 0 {
        local_port
    } else if proto == "https" {
        443
    } else {
        80
    }
}

fn valid_websocket_request<B>(request: &Request<B>) -> bool {
    request.method() == Method::GET
        && request.version() == Version::HTTP_11
        && header_has_token(request.headers(), header::CONNECTION, "upgrade")
        && request
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        && request
            .headers()
            .get("sec-websocket-key")
            .is_some_and(|v| valid_base64_shape(v, 24, 2))
        && request
            .headers()
            .get("sec-websocket-version")
            .is_some_and(|v| v == "13")
}

fn valid_websocket_response<B>(response: &Response<B>) -> bool {
    response.status() == StatusCode::SWITCHING_PROTOCOLS
        && response.version() == Version::HTTP_11
        && header_has_token(response.headers(), header::CONNECTION, "upgrade")
        && response
            .headers()
            .get(header::UPGRADE)
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
        && response
            .headers()
            .get("sec-websocket-accept")
            .is_some_and(|v| valid_base64_shape(v, 28, 1))
}

fn valid_base64_shape(value: &HeaderValue, encoded_len: usize, padding: usize) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == encoded_len
        && bytes[..encoded_len - padding]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/'))
        && bytes[encoded_len - padding..].iter().all(|b| *b == b'=')
}

fn header_has_token(headers: &HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// Build the upstream URI for a backend, applying an optional Host/authority
/// override. Errors are returned as ready-to-send responses.
fn build_upstream_uri(
    backend: &str,
    client_uri: &Uri,
    host_override: Option<&str>,
) -> Result<Uri, (u16, &'static str)> {
    let mut uri = upstream_uri(backend, client_uri)
        .map_err(|()| (StatusCode::BAD_GATEWAY.as_u16(), "invalid upstream URI"))?;
    if let Some(host) = host_override {
        let authority = host
            .parse::<hyper::http::uri::Authority>()
            .map_err(|_| (400, "invalid upstream Host"))?;
        let mut parts = uri.into_parts();
        parts.authority = Some(authority);
        uri = Uri::from_parts(parts).map_err(|_| (400, "invalid upstream Host"))?;
    }
    Ok(uri)
}

fn upstream_uri(backend: &str, original: &Uri) -> Result<Uri, ()> {
    let base: Uri = backend.parse().map_err(|_| ())?;
    let scheme = base.scheme_str().ok_or(())?;
    let authority = base.authority().ok_or(())?;
    let base_path = base.path().trim_end_matches('/');
    let request_path = original.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let path = if base_path.is_empty() {
        request_path.to_owned()
    } else {
        format!(
            "{base_path}{}",
            if request_path.starts_with('/') {
                request_path.to_owned()
            } else {
                format!("/{request_path}")
            }
        )
    };
    format!("{scheme}://{authority}{path}")
        .parse()
        .map_err(|_| ())
}

/// Only initial request headers participate in routing, policy, authentication,
/// and forwarding sanitation. Do not let uninspected late fields restore a
/// stripped identity or present a different application-header view to an h2
/// origin. Trailer declarations are already removed before upstream dispatch;
/// response trailers retain their existing behavior.
struct RequestDataBody {
    body: Incoming,
}

impl hyper::body::Body for RequestDataBody {
    type Data = Bytes;
    type Error = BodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
        loop {
            match std::pin::Pin::new(&mut self.body).poll_frame(cx) {
                std::task::Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                std::task::Poll::Ready(Some(Err(error))) => {
                    return std::task::Poll::Ready(Some(Err(BodyError(Box::new(error)))));
                }
                std::task::Poll::Ready(Some(Ok(frame))) => {
                    return std::task::Poll::Ready(Some(Ok(frame)));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(None),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

fn boxed_incoming(body: Incoming) -> Body {
    body.map_err(|error| BodyError(Box::new(error)))
        .boxed_unsync()
}

pub(crate) fn full_body(bytes: Bytes) -> Body {
    Full::new(bytes)
        .map_err(|never| -> BodyError { match never {} })
        .boxed_unsync()
}

pub fn response(status: u16, text: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(Bytes::copy_from_slice(text.as_bytes())))
        .expect("static response is valid")
}

pub fn retain_request_permit(
    mut response: Response<Body>,
    permit: tokio::sync::OwnedSemaphorePermit,
) -> Response<Body> {
    let backend = response
        .extensions_mut()
        .remove::<crate::balance::BackendLease>();
    let route = response
        .extensions_mut()
        .remove::<crate::admission::Lease>();
    response.map(|body| {
        RequestBody {
            body,
            _permit: permit,
            _backend: backend,
            _route: route,
        }
        .boxed_unsync()
    })
}

// Keep admission charged while a streaming response is alive, including slow readers.
struct RequestBody {
    body: Body,
    _permit: tokio::sync::OwnedSemaphorePermit,
    _backend: Option<crate::balance::BackendLease>,
    _route: Option<crate::admission::Lease>,
}
impl hyper::body::Body for RequestBody {
    type Data = Bytes;
    type Error = BodyError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, BodyError>>> {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn native_human_trusted_ingress_overwrites_duplicates_and_requires_canonical_path() {
        use super::NativeAuthorization;
        use crate::native_observed::AuthenticationClass;
        let mut headers = hyper::HeaderMap::new();
        for name in [
            "x-hopae-contract",
            "x-hangang-route-id",
            "x-hangang-canonical-path",
        ] {
            headers.append(name, "client-spoof".parse().unwrap());
            headers.append(name, "configured-spoof".parse().unwrap());
        }
        NativeAuthorization {
            class: AuthenticationClass::Human,
            issuer: "native-human",
            route_id: "actual-route",
            canonical_path: Some("/actual"),
        }
        .apply(&mut headers)
        .unwrap();
        for (name, value) in [
            ("x-hopae-contract", "1"),
            ("x-hangang-route-id", "actual-route"),
            ("x-hangang-canonical-path", "/actual"),
        ] {
            assert_eq!(headers.get_all(name).iter().count(), 1);
            assert_eq!(headers[name], value);
        }
        assert_eq!(
            NativeAuthorization {
                class: AuthenticationClass::Human,
                issuer: "native-human",
                route_id: "actual-route",
                canonical_path: None
            }
            .apply(&mut headers),
            Err(503)
        );
        for class in [AuthenticationClass::Service, AuthenticationClass::Workload] {
            let mut untouched = hyper::HeaderMap::new();
            untouched.insert("x-hangang-route-id", "legacy-value".parse().unwrap());
            let before = untouched.clone();
            NativeAuthorization {
                class,
                issuer: "issuer",
                route_id: "actual-route",
                canonical_path: None,
            }
            .apply(&mut untouched)
            .unwrap();
            assert_eq!(untouched, before);
        }
    }

    #[test]
    fn native_human_policy_metadata_requires_pinned_unique_canonical_subject() {
        use hyper::{HeaderMap, header::HeaderValue};
        let subject = format!("human1:{}", "a".repeat(64));
        let good = || {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-hopae-human-policy-subject",
                HeaderValue::from_str(&subject).unwrap(),
            );
            headers.insert(
                "x-hopae-human-policy-issuer",
                HeaderValue::from_static("native-human"),
            );
            headers.insert("x-hopae-aal", HeaderValue::from_static("2"));
            headers
        };
        assert_eq!(
            super::native_human_policy_identity(&good(), "native-human"),
            Some((subject.as_str(), 2))
        );
        assert!(super::native_human_policy_identity(&good(), "other-issuer").is_none());
        for (name, value) in [
            ("x-hopae-human-policy-subject", "u_legacy"),
            ("x-hopae-aal", "0"),
            ("x-hopae-aal", "3"),
            ("x-hopae-principal-kind", "service"),
            ("x-hopae-principal-kind", "workload"),
        ] {
            let mut headers = good();
            headers.insert(name, HeaderValue::from_static(value));
            assert!(super::native_human_policy_identity(&headers, "native-human").is_none());
        }
        for name in [
            "x-hopae-human-policy-subject",
            "x-hopae-human-policy-issuer",
            "x-hopae-aal",
        ] {
            let mut headers = good();
            let value = headers[name].clone();
            headers.append(name, value);
            assert!(super::native_human_policy_identity(&headers, "native-human").is_none());
            let mut headers = good();
            headers.remove(name);
            assert!(super::native_human_policy_identity(&headers, "native-human").is_none());
        }
        let mut headers = good();
        headers.append("x-hopae-principal-kind", HeaderValue::from_static("human"));
        assert!(super::native_human_policy_identity(&headers, "native-human").is_some());
        headers.append("x-hopae-principal-kind", HeaderValue::from_static("human"));
        assert!(super::native_human_policy_identity(&headers, "native-human").is_none());
    }
    #[test]
    fn sacho_security_response_authority_checks_both_sources_without_trusting_scheme() {
        use hyper::header::HeaderValue;
        use hyper::{HeaderMap, Uri};
        let authority = |hosts: &[&str], uri: &str, tls| {
            let mut headers = HeaderMap::new();
            for host in hosts {
                headers.append("host", HeaderValue::from_str(host).unwrap());
            }
            super::response_security_authority(&headers, &uri.parse::<Uri>().unwrap(), tls)
                .map(|authority| authority.to_string())
        };
        assert_eq!(
            authority(&[], "https://sacho.example.test/x", true).as_deref(),
            Some("sacho.example.test")
        );
        assert!(
            authority(
                &["other.example.test"],
                "https://sacho.example.test/x",
                true
            )
            .is_none()
        );
        assert!(authority(&["sacho.example.test", "sacho.example.test"], "/x", true).is_none());
        assert!(authority(&[], "https://user@sacho.example.test/x", true).is_none());
        assert!(authority(&[], "https://sacho.example.test:bad/x", true).is_none());
        assert!(
            authority(
                &["sacho.example.test:80"],
                "http://sacho.example.test/x",
                true
            )
            .is_none(),
            "URI scheme must not choose a plaintext default for actual TLS"
        );
        assert!(
            authority(
                &["sacho.example.test:443"],
                "http://sacho.example.test/x",
                true
            )
            .is_some()
        );
        assert!(
            authority(
                &["SACHO.EXAMPLE.TEST."],
                "https://sacho.example.test:443/x",
                true
            )
            .is_some()
        );
    }

    #[test]
    fn receipt_binding_uses_actual_backend_composition_and_final_entity() {
        let original: Uri = "/rewritten/orders?x=%2F&x=2".parse().unwrap();
        let outgoing = build_upstream_uri(
            "https://backend.example.test/api/",
            &original,
            Some("selected.example.test:8443"),
        )
        .unwrap();
        assert_eq!(
            outgoing.path_and_query().unwrap().as_str(),
            "/api/rewritten/orders?x=%2F&x=2"
        );
        let mut request = Request::builder()
            .method("POST")
            .uri(outgoing)
            .body(Bytes::from_static(b"transformed entity"))
            .unwrap();
        let bound =
            crate::projection_binding::digest_upstream("orders", "orders-api", &request).unwrap();
        let origin = Request::builder()
            .method("POST")
            .uri("/api/rewritten/orders?x=%2F&x=2")
            .body(Bytes::from_static(b"transformed entity"))
            .unwrap();
        assert_eq!(
            bound,
            crate::projection_binding::digest("orders", "orders-api", &origin).unwrap()
        );
        let before_backend = Request::builder()
            .method("POST")
            .uri(original)
            .body(Bytes::from_static(b"transformed entity"))
            .unwrap();
        assert_ne!(
            bound,
            crate::projection_binding::digest("orders", "orders-api", &before_backend).unwrap()
        );
        *request.body_mut() = Bytes::new();
        assert_ne!(
            bound,
            crate::projection_binding::digest_upstream("orders", "orders-api", &request).unwrap()
        );
        for target in [
            "/api/orders",
            "ftp://backend.example.test/api/orders",
            "https://user@backend.example.test/api/orders",
            "https://backend.example.test//api/orders",
            "https://backend.example.test/api%zz",
        ] {
            *request.uri_mut() = target.parse().unwrap();
            assert!(
                crate::projection_binding::digest_upstream("orders", "orders-api", &request)
                    .is_err()
            );
        }
    }

    fn renewal_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in [
            ("x-forwarded-user", "s_fixture"),
            ("x-hopae-principal-kind", "workload"),
            ("x-hopae-aal", "0"),
            ("x-hopae-service-id", "fixture"),
            ("x-hopae-evidence-ttl-ms", "300"),
        ] {
            headers.insert(name, HeaderValue::from_static(value));
        }
        headers
    }
    #[tokio::test]
    async fn renewal_quota_expiry_and_inflight_cancellation_are_fail_closed() {
        let occupied = RENEWAL_SLOTS.try_acquire_many(4096).unwrap();
        let client = Arc::new(crate::hopae_native::Client::new(
            "127.0.0.1:9".parse::<pumgye_client::Endpoint>().unwrap(),
            1,
            HeaderValue::from_static("owned-key"),
        ));
        assert!(
            Renewal::start(
                client,
                HeaderMap::new(),
                &renewal_headers(),
                std::time::Instant::now()
            )
            .is_none()
        );
        drop(occupied);
        let expired = Renewal {
            expires: std::sync::Mutex::new(std::time::Instant::now()),
            failed: std::sync::atomic::AtomicBool::new(false),
            task: std::sync::Mutex::new(None),
            _slot: RENEWAL_SLOTS.try_acquire().unwrap(),
        };
        assert!(!expired.current());
        *expired.expires.lock().unwrap() = std::time::Instant::now() + Duration::from_secs(1);
        assert!(
            !expired.current(),
            "an observed expiration must never revive"
        );
        drop(expired);
        for drop_during_io in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = Arc::new(crate::hopae_native::Client::new(
                listener.local_addr().unwrap(),
                1,
                HeaderValue::from_static("owned-key"),
            ));
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut head = [0; 16];
                socket.read_exact(&mut head).await.unwrap();
                let (id, len) = crate::hopae_wire::parse_header(head).unwrap();
                assert_eq!(id, 0);
                let mut body = vec![0; len];
                socket.read_exact(&mut body).await.unwrap();
                socket
                    .write_all(&crate::hopae_wire::frame_header(0, 1).unwrap())
                    .await
                    .unwrap();
                socket.write_all(&[1]).await.unwrap();
                socket.read_exact(&mut head).await.unwrap();
                let (_, len) = crate::hopae_wire::parse_header(head).unwrap();
                let mut body = vec![0; len];
                socket.read_exact(&mut body).await.unwrap();
                started_tx.send(()).unwrap();
                // No renewal reply: dropping or exhausting the lease must cancel I/O.
                let mut byte = [0; 1];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(1), socket.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            });
            let lease = Renewal::start(
                client,
                HeaderMap::new(),
                &renewal_headers(),
                std::time::Instant::now(),
            )
            .unwrap();
            tokio::time::timeout(Duration::from_secs(1), started_rx)
                .await
                .unwrap()
                .unwrap();
            if !drop_during_io {
                tokio::time::sleep(Duration::from_millis(350)).await;
                assert!(
                    !lease.current(),
                    "late or missing response cannot extend a lease"
                );
            }
            drop(lease);
            peer.await.unwrap();
            assert_eq!(RENEWAL_SLOTS.available_permits(), 4096);
        }
    }

    #[tokio::test]
    async fn native_route_fences_exact_snapshot_even_with_an_identical_revision() {
        let original = Arc::new(Snapshot::new(crate::config::Config::default()).unwrap());
        let active = Arc::new(ArcSwap::from(original.clone()));
        let lease = AuthRouteLease {
            native_snapshot: Some((active.clone(), original.clone())),
            ..Default::default()
        };
        assert!(!lease.retirement().any());
        // Equal public configuration and revision are insufficient to preserve
        // a request across fresh native owner activation.
        let replacement = Arc::new(Snapshot::new(original.config.clone()).unwrap());
        assert_eq!(replacement.config.revision, original.config.revision);
        active.store(replacement);
        assert!(lease.retirement().native_route && lease.retirement().any());
        let metrics = Metrics::default();
        assert_eq!(
            retired_auth_response(Some(&lease), &metrics)
                .unwrap()
                .status(),
            503
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), lease.revoked())
                .await
                .unwrap()
                .native_route
        );
    }

    #[tokio::test]
    async fn native_route_retirement_stops_an_already_prepared_body() {
        use http_body_util::BodyExt;
        let original = Arc::new(Snapshot::new(crate::config::Config::default()).unwrap());
        let active = Arc::new(ArcSwap::from(original.clone()));
        let lease = AuthRouteLease {
            native_snapshot: Some((active.clone(), original.clone())),
            ..Default::default()
        };
        let mut body = AuthResponseBody::new(
            full_body(Bytes::from_static(b"owned final entity")),
            lease,
            Arc::new(Metrics::default()),
        );
        active.store(Arc::new(Snapshot::new(original.config.clone()).unwrap()));
        assert!(body.frame().await.unwrap().is_err());
    }

    #[test]
    fn native_evidence_ttl_is_bounded_unique_and_consumes_exchange_time() {
        let mut headers = HeaderMap::new();
        let started = std::time::Instant::now();
        let legacy = native_evidence_expiry(&headers, started).unwrap();
        assert_eq!(legacy, started + Duration::from_millis(1000));
        headers.insert("x-hopae-evidence-ttl-ms", HeaderValue::from_static("400"));
        assert_eq!(
            native_evidence_expiry(&headers, started).unwrap(),
            started + Duration::from_millis(400)
        );
        for value in ["0", "1001", "-1", "+1", " 1", "1.0", "18446744073709551616"] {
            headers.insert(
                "x-hopae-evidence-ttl-ms",
                HeaderValue::from_str(value).unwrap(),
            );
            assert!(native_evidence_expiry(&headers, started).is_none());
        }
        headers.insert("x-hopae-evidence-ttl-ms", HeaderValue::from_static("1"));
        assert!(native_evidence_expiry(&headers, started - Duration::from_millis(5)).is_none());
        headers.append("x-hopae-evidence-ttl-ms", HeaderValue::from_static("1"));
        assert!(native_evidence_expiry(&headers, started).is_none());
        let lease = AuthRouteLease {
            hopae_expires: Some(std::time::Instant::now()),
            ..Default::default()
        };
        assert!(lease.retirement().hopae && lease.retirement().any());
    }

    #[test]
    fn strip_request_cookies_parser_is_quote_aware_and_fails_safe() {
        let names = vec!["s".to_owned()];
        let run = |input: &'static str| {
            let mut headers = HeaderMap::new();
            headers.append(header::COOKIE, HeaderValue::from_static(input));
            strip_request_cookies(&mut headers, &names);
            headers
                .get(header::COOKIE)
                .map(|v| v.to_str().unwrap().to_owned())
        };
        assert_eq!(run("s=\"p;q\"; a=1").as_deref(), Some("a=1"));
        assert_eq!(run("a=\"x;y\"; s=1").as_deref(), Some("a=\"x;y\""));
        assert_eq!(run("a=1 s=2; b=3"), None);
        assert_eq!(run("a=1\ts=2"), None);
        assert_eq!(run("a=\"x; s=2"), None);
        assert_eq!(run("a=\"s=1;\"; s=2"), None);
        assert_eq!(
            run("s2=1; ss=2; a_s=3").as_deref(),
            Some("s2=1; ss=2; a_s=3")
        );
    }

    #[test]
    fn strip_request_cookies_keeps_order_and_removes_empty_header() {
        let names = vec!["s".to_owned()];
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("a=1; s=x"));
        headers.append(header::COOKIE, HeaderValue::from_static("bare; s; c=3"));
        strip_request_cookies(&mut headers, &names);
        assert_eq!(headers.get_all(header::COOKIE).iter().count(), 1);
        assert_eq!(headers[header::COOKIE], "a=1; bare; c=3");
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("s=x; s=y"));
        strip_request_cookies(&mut headers, &names);
        assert!(!headers.contains_key(header::COOKIE));
    }

    use super::*;
    use ipnet::IpNet;

    fn canonical_policy() -> crate::config::CanonicalDomain {
        crate::config::CanonicalDomain {
            enabled: true,
            host: "example.test".into(),
            scheme: crate::config::CanonicalScheme::Https,
            status: 302,
            path_prefixes: vec!["/wp-login.php".into(), "/wp-admin".into()],
            exclude_path_prefixes: vec!["/wp-admin/admin-ajax.php".into()],
            methods: vec!["GET".into(), "HEAD".into()],
        }
    }

    #[test]
    fn canonical_redirect_uses_static_target_and_raw_path_query() {
        let request = Request::builder()
            .uri("/wp-login.php/%2fkeep?redirect_to=https%3A%2F%2Fevil.test%2Fx&x=1&x=2")
            .body(full_body(Bytes::new()))
            .unwrap();
        // This is the effective host after trusted-proxy resolution; it may
        // select the alias, but it can never become destination URL text.
        let edge = EdgeContext {
            explicit_forwarded_port: None,
            client_ip: "192.0.2.1".parse().unwrap(),
            proto: "http",
            forwarded_host: Some(HeaderValue::from_static("www.example.test:8443")),
            forwarded_port: 8443,
        };
        let response = canonical_domain_redirect(
            &request,
            &edge,
            "/wp-login.php/%2fkeep",
            &canonical_policy(),
        )
        .unwrap();
        assert_eq!(response.status(), 302);
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://example.test/wp-login.php/%2fkeep?redirect_to=https%3A%2F%2Fevil.test%2Fx&x=1&x=2"
        );
    }

    #[test]
    fn canonical_redirect_exclusions_methods_boundaries_and_loop_guard() {
        let policy = canonical_policy();
        let edge = EdgeContext {
            explicit_forwarded_port: None,
            client_ip: "192.0.2.1".parse().unwrap(),
            proto: "https",
            forwarded_host: Some(HeaderValue::from_static("www.example.test")),
            forwarded_port: 443,
        };
        let request = |method, path| {
            Request::builder()
                .method(method)
                .uri(path)
                .body(full_body(Bytes::new()))
                .unwrap()
        };
        assert!(
            canonical_domain_redirect(
                &request(Method::GET, "/wp-admin"),
                &edge,
                "/wp-admin",
                &policy
            )
            .is_some()
        );
        assert!(
            canonical_domain_redirect(
                &request(Method::GET, "/wp-admin/tools"),
                &edge,
                "/wp-admin/tools",
                &policy
            )
            .is_some()
        );
        assert!(
            canonical_domain_redirect(
                &request(Method::GET, "/wp-adminx"),
                &edge,
                "/wp-adminx",
                &policy
            )
            .is_none()
        );
        assert!(
            canonical_domain_redirect(
                &request(Method::GET, "/wp-admin/admin-ajax.php/x"),
                &edge,
                "/wp-admin/admin-ajax.php/x",
                &policy
            )
            .is_none()
        );
        assert!(
            canonical_domain_redirect(
                &request(Method::POST, "/wp-login.php"),
                &edge,
                "/wp-login.php",
                &policy
            )
            .is_none()
        );
        let canonical = EdgeContext {
            forwarded_host: Some(HeaderValue::from_static("EXAMPLE.test:443")),
            ..edge
        };
        assert!(
            canonical_domain_redirect(
                &request(Method::GET, "/wp-login.php"),
                &canonical,
                "/wp-login.php",
                &policy
            )
            .is_none()
        );
    }

    #[test]
    fn authority_validation_is_strict() {
        let ok = [
            "app.test",
            "app.test:8443",
            "[::1]",
            "[::1]:8443",
            "10.0.0.1:80",
            "a.b.c.",
        ];
        for host in ok {
            assert!(valid_authority(&HeaderValue::from_static(host)), "{host}");
        }
        let bad = [
            "",
            "app.test:",
            "app.test:abc",
            "app.test:70000",
            "app.test:8080:1",
            "[not-an-ip]",
            "[::1",
            "::1",
            "user@app.test",
            "app.test/x",
            "app.test?x",
            "app.test#x",
            "app%2etest",
            "app.test:8080/",
            " app.test",
            "x[garbage]",
            "x]y",
            "[::1]x",
        ];
        for host in bad {
            let value = HeaderValue::from_str(host).unwrap();
            assert!(!valid_authority(&value), "{host}");
        }
    }

    #[test]
    fn forward_auth_context_is_origin_form_and_edge_resolved() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://ignored.example/p/a%20b?q=1")
            .body(full_body(Bytes::new()))
            .unwrap();
        let edge = EdgeContext {
            explicit_forwarded_port: None,
            client_ip: "203.0.113.9".parse().unwrap(),
            proto: "https",
            forwarded_host: Some(HeaderValue::from_static("app.example")),
            forwarded_port: 8443,
        };
        let context: std::collections::HashMap<_, _> =
            forward_auth_context(&request, &edge).into_iter().collect();
        assert_eq!(context["x-original-method"], "POST");
        assert_eq!(context["x-forwarded-method"], "POST");
        assert_eq!(context["x-original-uri"], "/p/a%20b?q=1");
        assert_eq!(context["x-forwarded-uri"], "/p/a%20b?q=1");
        assert_eq!(context["x-original-client-ip"], "203.0.113.9");
        assert_eq!(context["x-forwarded-for"], "203.0.113.9");
        assert_eq!(context["x-real-ip"], "203.0.113.9");
        assert_eq!(context["x-forwarded-proto"], "https");
        assert_eq!(context["x-forwarded-port"], "8443");
        assert_eq!(context["x-forwarded-host"], "app.example");
        assert_eq!(
            context["x-original-url"],
            "https://app.example:8443/p/a%20b?q=1"
        );

        let default_port = EdgeContext {
            forwarded_port: 443,
            forwarded_host: Some(HeaderValue::from_static("[::1]:9443")),
            ..edge
        };
        let context: std::collections::HashMap<_, _> =
            forward_auth_context(&request, &default_port)
                .into_iter()
                .collect();
        assert_eq!(context["x-original-url"], "https://[::1]:9443/p/a%20b?q=1");
        let no_host = EdgeContext {
            forwarded_host: None,
            ..default_port
        };
        let context: std::collections::HashMap<_, _> = forward_auth_context(&request, &no_host)
            .into_iter()
            .collect();
        assert!(!context.contains_key("x-original-url"));
        assert!(!context.contains_key("x-forwarded-host"));
        assert!(host_has_port("example.com:8443"));
        assert!(host_has_port("[::1]:8443"));
        assert!(!host_has_port("example.com"));
        assert!(!host_has_port("[::1]"));
        assert!(!host_has_port("::1"));
        assert!(!host_has_port("example.com:"));
    }

    fn route() -> HttpRoute {
        HttpRoute {
            listener_ids: Vec::new(),
            access_mode: Default::default(),
            resource_policy: None,
            language_policy: None,
            country_policy: None,
            jwt_auth: None,
            workload_auth: None,
            enabled: true,
            upstream: Default::default(),
            priority: 0,
            host_regex: None,
            upstream_host: None,
            preserve_host: false,
            id: "test".into(),
            host: None,
            hosts: Vec::new(),
            acme_http01: None,
            canonical_domain: None,
            path_prefix: None,
            path_match: Default::default(),
            path_case: None,
            strip_request_cookies: Vec::new(),
            max_requests: None,
            upstream_timeout_ms: None,
            retries: 0,
            require_tls: false,
            https_redirect_code: None,
            cache: None,
            headers: BTreeMap::new(),
            json: BTreeMap::new(),
            backends: vec!["http://127.0.0.1:8080".into()],
            deny_cidrs: Vec::<IpNet>::new(),
            lua: None,
            request_transform: None,
            response_transform: None,
            auth: None,
            basic_auth: None,
            balance: Default::default(),
            response_set_headers: std::collections::BTreeMap::new(),
            response_remove_headers: Vec::new(),
        }
    }

    #[test]
    fn policy_header_mutations_respect_protected_and_credential_names() {
        // A plain application header is allowed.
        let mut headers = HeaderMap::new();
        let mutations = BTreeMap::from([("x-plugin".to_owned(), "ok".to_owned())]);
        assert!(apply_policy_headers(&mut headers, mutations, &[], None, &[]).is_ok());
        assert_eq!(headers["x-plugin"], "ok");

        // Credential/framing headers are rejected outright.
        for blocked in ["authorization", "cookie", "host", "x-forwarded-for"] {
            let mut headers = HeaderMap::new();
            let mutations = BTreeMap::from([(blocked.to_owned(), "x".to_owned())]);
            assert!(
                apply_policy_headers(&mut headers, mutations, &[], None, &[]).is_err(),
                "{blocked} must be rejected"
            );
        }

        // An auth-established identity header (its response_headers) cannot be
        // overridden by a policy, case-insensitively.
        let mut headers = HeaderMap::new();
        let mutations = BTreeMap::from([("X-User".to_owned(), "attacker".to_owned())]);
        assert!(
            apply_policy_headers(
                &mut headers,
                mutations.clone(),
                &["x-user".to_owned()],
                None,
                &[]
            )
            .is_err()
        );
        assert!(
            apply_policy_headers(&mut headers, mutations, &[], Some("x-user"), &[]).is_err(),
            "native Basic identity header must be protected from policy mutation"
        );
        let reserved = [HeaderName::from_static("x-anonymous-consumer")];
        let mutations = BTreeMap::from([("x-anonymous-consumer".to_owned(), "forged".to_owned())]);
        assert!(apply_policy_headers(&mut headers, mutations, &[], None, &reserved).is_err());
    }

    #[test]
    fn dot_segments_are_detected_raw_and_percent_encoded() {
        assert!(path_has_dot_segment("/public/../admin"));
        assert!(path_has_dot_segment("/a/.."));
        assert!(path_has_dot_segment("/a/."));
        assert!(path_has_dot_segment("/public/%2e%2e/admin"));
        assert!(path_has_dot_segment("/public/%2E./admin"));
        assert!(path_has_dot_segment("/public/.%2e/admin"));
        assert!(path_has_dot_segment("/%2e%2e"));
        // Not dot segments: normal paths, embedded dots, and a bare prefix.
        assert!(!path_has_dot_segment("/public/admin"));
        assert!(!path_has_dot_segment("/apix"));
        assert!(!path_has_dot_segment("/a/b.c/d"));
        assert!(!path_has_dot_segment("/..bar/x"));
        assert!(!path_has_dot_segment("/file%2ename"));
        assert!(!path_has_dot_segment("/"));
    }

    #[test]
    fn encoded_and_backslash_separators_do_not_hide_dot_segments() {
        // A backend that decodes `%2f`/`%5c` before resolving `..` would turn
        // each of these into `/admin` after the `/public` prefix matched.
        for path in [
            "/public/%2e%2e%2fadmin",
            "/public/%2E%2E%2Fadmin",
            "/public%2f..%2fadmin",
            "/public/%2f..%2fadmin",
            "/public%2F..%2Fadmin",
            "/public%5c..%5cadmin",
            "/public/%5C..%5Cadmin",
            "/public/..%5cadmin",
            "/public/%2e%2e%5Cadmin",
            "/public/\\..\\admin",
            "/public\\..\\admin",
            "/public/..\\admin",
            "/public/.%2fadmin",
            "/public/.%5Cadmin",
        ] {
            assert!(path_has_dot_segment(path), "{path} must be rejected");
        }
        // Encoded separators without a dot segment stay opaque data.
        for path in [
            "/public/a%2fb",
            "/public/a%5Cb",
            "/public/%2f",
            "/public/..a%2fb",
            "/public/%2e%2ea%2fb",
        ] {
            assert!(!path_has_dot_segment(path), "{path} must be allowed");
        }
    }

    #[test]
    fn content_length_is_canonicalized_and_conflicts_are_rejected() {
        // No header: nothing to do.
        let mut headers = HeaderMap::new();
        assert!(canonicalize_content_length(&mut headers).is_ok());
        assert!(!headers.contains_key(header::CONTENT_LENGTH));

        // One valid value is kept as-is.
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert!(canonicalize_content_length(&mut headers).is_ok());
        assert_eq!(headers.get_all(header::CONTENT_LENGTH).iter().count(), 1);
        assert_eq!(headers[header::CONTENT_LENGTH], "4");

        // Identical duplicates collapse to a single canonical field.
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.append(header::CONTENT_LENGTH, HeaderValue::from_static("04"));
        assert!(canonicalize_content_length(&mut headers).is_ok());
        assert_eq!(headers.get_all(header::CONTENT_LENGTH).iter().count(), 1);
        assert_eq!(headers[header::CONTENT_LENGTH], "4");

        // Conflicting, non-numeric, list-syntax, signed, empty or oversized
        // values are all rejected rather than forwarded.
        for values in [
            vec!["4", "1"],
            vec!["4", "abc"],
            vec!["abc"],
            vec!["4, 4"],
            vec!["+4"],
            vec!["-1"],
            vec![""],
            vec!["99999999999999999999"],
            vec!["4", "4", "5"],
        ] {
            let mut headers = HeaderMap::new();
            for value in &values {
                headers.append(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(value).unwrap(),
                );
            }
            assert!(
                canonicalize_content_length(&mut headers).is_err(),
                "{values:?} must be rejected"
            );
        }
    }

    #[test]
    fn cookie_join_preserves_bytes_sensitivity_and_other_fields() {
        let mut headers = HeaderMap::new();
        join_cookie_headers(&mut headers).unwrap();
        assert!(!headers.contains_key(header::COOKIE));
        let mut first = HeaderValue::from_bytes(b"a=\xff").unwrap();
        first.set_sensitive(true);
        headers.append(header::COOKIE, first);
        join_cookie_headers(&mut headers).unwrap();
        assert!(headers[header::COOKIE].is_sensitive());
        headers.append(header::COOKIE, HeaderValue::from_static("b=2; c=3"));
        headers.append(header::SET_COOKIE, HeaderValue::from_static("x=1; Path=/"));
        headers.append(header::SET_COOKIE, HeaderValue::from_static("y=2; Path=/"));
        headers.append("x-application", HeaderValue::from_static("first"));
        headers.append("x-application", HeaderValue::from_static("second"));
        join_cookie_headers(&mut headers).unwrap();
        assert_eq!(headers[header::COOKIE].as_bytes(), b"a=\xff; b=2; c=3");
        assert!(headers[header::COOKIE].is_sensitive());
        assert_eq!(headers.get_all(header::SET_COOKIE).iter().count(), 2);
        assert_eq!(headers.get_all("x-application").iter().count(), 2);
        join_cookie_headers(&mut headers).unwrap();
        assert_eq!(headers[header::COOKIE].as_bytes(), b"a=\xff; b=2; c=3");
    }

    #[test]
    fn policy_duplicate_headers_are_rejected_except_joined_cookies() {
        // A repeated application header is ambiguous for a scalar policy API.
        let mut headers = HeaderMap::new();
        headers.append("x-scope", HeaderValue::from_static("private"));
        headers.append("x-scope", HeaderValue::from_static("public"));
        assert!(collapse_duplicate_policy_headers(&mut headers).is_err());

        // Single-valued headers, repeated hop-by-hop headers and repeated
        // forwarding headers (stripped from the policy view, regenerated for
        // the upstream) are not ambiguous.
        let mut headers = HeaderMap::new();
        headers.append("x-scope", HeaderValue::from_static("public"));
        headers.append(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        headers.append(header::CONNECTION, HeaderValue::from_static("upgrade"));
        headers.append("x-forwarded-for", HeaderValue::from_static("1.1.1.1"));
        headers.append("x-forwarded-for", HeaderValue::from_static("2.2.2.2"));
        assert!(collapse_duplicate_policy_headers(&mut headers).is_ok());
        assert_eq!(headers.get_all(header::CONNECTION).iter().count(), 2);

        // Repeated cookie fields are joined (RFC 9113 §8.2.3) into the one
        // value both the policy and the upstream will see.
        let mut headers = HeaderMap::new();
        headers.append(header::COOKIE, HeaderValue::from_static("a=1"));
        headers.append(header::COOKIE, HeaderValue::from_static("b=2"));
        headers.append(header::COOKIE, HeaderValue::from_static("c=3"));
        assert!(collapse_duplicate_policy_headers(&mut headers).is_ok());
        assert_eq!(headers.get_all(header::COOKIE).iter().count(), 1);
        assert_eq!(headers[header::COOKIE], "a=1; b=2; c=3");
    }

    #[test]
    fn reassert_identity_headers_restores_authenticated_value() {
        let identity = vec![(
            HeaderName::from_static("x-user"),
            HeaderValue::from_static("alice"),
        )];
        let mut headers = HeaderMap::new();
        headers.insert("x-user", HeaderValue::from_static("admin"));
        headers.append("x-user", HeaderValue::from_static("root"));
        reassert_identity_headers(&mut headers, &identity, &[]);
        assert_eq!(headers.get_all("x-user").iter().count(), 1);
        assert_eq!(headers["x-user"], "alice");
        // A removed identity header is restored as well.
        headers.remove("x-user");
        reassert_identity_headers(&mut headers, &identity, &[]);
        assert_eq!(headers["x-user"], "alice");
        // A credential's explicit null mapping is a protected absence.
        headers.insert("x-anonymous-consumer", HeaderValue::from_static("forged"));
        reassert_identity_headers(
            &mut headers,
            &identity,
            &[HeaderName::from_static("x-anonymous-consumer")],
        );
        assert!(!headers.contains_key("x-anonymous-consumer"));
    }

    #[test]
    fn matcher_checks_host_path_and_headers() {
        let mut route = route();
        route.host = Some("example.com".into());
        route.path_prefix = Some("/api".into());
        route.headers.insert("x-mode".into(), "blue".into());
        let request = Request::builder()
            .uri("/api/v1")
            .header("host", "EXAMPLE.com:8080")
            .header("x-mode", "blue")
            .body(())
            .unwrap();
        assert!(basic_match(&route, &request, None));
        let request = Request::builder()
            .uri("/other")
            .header("host", "example.com")
            .header("x-mode", "blue")
            .body(())
            .unwrap();
        assert!(!basic_match(&route, &request, None));
    }

    #[test]
    fn ingress_path_boundaries_and_single_label_wildcards() {
        let mut route = route();
        route.host = Some("*.example.test".into());
        route.path_prefix = Some("/foo/".into());
        route.path_match = crate::config::PathMatch::SegmentPrefix;
        for (host, path, expected) in [
            ("a.example.test", "/foo", true),
            ("A.EXAMPLE.test", "/foo/", true),
            ("a.example.test", "/foo/bar", true),
            ("a.example.test", "/foobar", false),
            ("a.b.example.test", "/foo", false),
            ("example.test", "/foo", false),
        ] {
            let request = Request::builder()
                .uri(path)
                .header("host", host)
                .body(())
                .unwrap();
            assert_eq!(
                basic_match(&route, &request, None),
                expected,
                "{host}{path}"
            );
        }
        route.host = None;
        route.path_match = crate::config::PathMatch::Exact;
        for (path, expected) in [("/foo/", true), ("/foo", false), ("/foo/bar", false)] {
            assert_eq!(
                basic_match(
                    &route,
                    &Request::builder().uri(path).body(()).unwrap(),
                    None
                ),
                expected
            );
        }
    }

    #[test]
    fn legacy_proxy_headers_cannot_spoof_peer_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("proxy-connection", HeaderValue::from_static("keep-alive"));
        headers.insert("x-real-ip", HeaderValue::from_static("203.0.113.99"));
        strip_hop_by_hop(&mut headers);
        strip_forwarding_headers(&mut headers);
        assert!(!headers.contains_key("proxy-connection"));
        assert!(!headers.contains_key("x-real-ip"));
        set_forwarding_headers(&mut headers, "127.0.0.1".parse().unwrap(), "http", None, 80);
        assert_eq!(headers["x-real-ip"], "127.0.0.1");
        for name in ["proxy-connection", "x-real-ip"] {
            assert!(sensitive_mutation(&HeaderName::from_static(name)));
        }
    }

    #[test]
    fn json_uses_rfc6901_pointers() {
        let mut route = route();
        route
            .json
            .insert("/nested/a~1b".into(), serde_json::json!(7));
        assert!(json_match(&route, &serde_json::json!({"nested":{"a/b":7}})));
        assert!(!json_match(
            &route,
            &serde_json::json!({"nested":{"a/b":8}})
        ));
    }

    #[tokio::test]
    async fn json_inspection_restores_body() {
        let bytes = Bytes::from_static(br#"{"name":"hangang"}"#);
        let request = Request::builder()
            .header(header::CONTENT_LENGTH, bytes.len())
            .body(full_body(bytes.clone()))
            .unwrap();
        let (request, json) = inspect_json_body(request).await.unwrap();
        assert_eq!(json.pointer("/name"), Some(&serde_json::json!("hangang")));
        assert_eq!(
            request.into_body().collect().await.unwrap().to_bytes(),
            bytes
        );
    }

    #[test]
    fn strips_connection_nominated_and_spoofed_forwarding_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONNECTION,
            HeaderValue::from_static("keep-alive, x-secret"),
        );
        headers.insert("x-secret", HeaderValue::from_static("remove-me"));
        headers.insert("forwarded", HeaderValue::from_static("for=attacker"));
        headers.insert("x-forwarded-for", HeaderValue::from_static("attacker"));
        strip_hop_by_hop(&mut headers);
        strip_forwarding_headers(&mut headers);
        set_forwarding_headers(
            &mut headers,
            "192.0.2.10".parse().unwrap(),
            "http",
            None,
            80,
        );
        assert!(!headers.contains_key("x-secret"));
        assert!(!headers.contains_key("forwarded"));
        assert_eq!(headers["x-forwarded-for"], "192.0.2.10");
    }

    #[test]
    fn rejects_sensitive_policy_mutations() {
        for name in [
            "host",
            "connection",
            "content-length",
            "forwarded",
            "x-forwarded-for",
            "sec-websocket-key",
        ] {
            assert!(sensitive_mutation(&name.parse().unwrap()), "{name}");
        }
        assert!(!sensitive_mutation(&"x-plugin-result".parse().unwrap()));
    }

    #[test]
    fn builds_upstream_uri_with_original_query() {
        let uri = upstream_uri("http://127.0.0.1:8080/base", &"/v1?q=1".parse().unwrap()).unwrap();
        assert_eq!(uri, "http://127.0.0.1:8080/base/v1?q=1");
    }

    #[test]
    fn websocket_validation_is_strict() {
        let request = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .header(header::CONNECTION, "keep-alive, Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==") // gitleaks:allow -- protocol/test fixture
            .body(())
            .unwrap();
        assert!(valid_websocket_request(&request));
        let request = Request::builder().method(Method::POST).body(()).unwrap();
        assert!(!valid_websocket_request(&request));
    }
}
