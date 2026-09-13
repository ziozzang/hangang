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
    pub(crate) fn from_error(error: impl Error + Send + Sync + 'static) -> Self {
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
impl From<http_body_util::LengthLimitError> for BodyError {
    fn from(error: http_body_util::LengthLimitError) -> Self {
        Self(Box::new(error))
    }
}

pub type Body = http_body_util::combinators::UnsyncBoxBody<Bytes, BodyError>;

/// Result of an external authorization call.
enum AuthOutcome {
    /// 2xx: forward the request, injecting these copied response headers.
    /// The second value carries `Set-Cookie` fields from the authorization
    /// response (session refresh) to append to the final client response when
    /// `forward_response` is enabled.
    Allow(HeaderMap, Vec<HeaderValue>),
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

#[derive(Clone)]
pub struct Proxy {
    active: Arc<ArcSwap<Snapshot>>,
    policy: Arc<PolicyPool>,
    metrics: Arc<Metrics>,
    traffic: Option<Arc<crate::traffic::TrafficHistory>>,
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    outbound: Arc<crate::http_outbound::Pools>,
    requests: Arc<tokio::sync::Semaphore>,
    inspections: Arc<tokio::sync::Semaphore>,
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
    peer_ip: IpAddr,
    peer_port: u16,
    client_ip: IpAddr,
    method: String,
    path: String,
    route_id: Option<String>,
    protocol: &'static str,
    tls: bool,
    started: std::time::Instant,
}

impl TrafficContext {
    fn new(request: &Request<Incoming>, peer: SocketAddr) -> Self {
        Self {
            peer_ip: peer.ip(),
            peer_port: peer.port(),
            client_ip: peer.ip(),
            method: request.method().as_str().chars().take(16).collect(),
            path: request.uri().path().chars().take(256).collect(),
            route_id: None,
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

    fn record(&self, history: &crate::traffic::TrafficHistory, status: u16) {
        history.record(crate::traffic::TrafficInput {
            peer_ip: self.peer_ip,
            peer_port: self.peer_port,
            client_ip: self.client_ip,
            method: &self.method,
            path: &self.path,
            route_id: self.route_id.as_deref(),
            status,
            response_head_ms: self.started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            protocol: self.protocol,
            tls: self.tls,
        });
    }
}

impl Drop for ShutdownGuard {
    fn drop(&mut self) {
        self.0.cancel();
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
        Self {
            active,
            policy,
            metrics,
            traffic: None,
            client,
            outbound,
            requests: Arc::new(tokio::sync::Semaphore::new(4096)),
            inspections: Arc::new(tokio::sync::Semaphore::new(32)),
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

    async fn authorize(
        &self,
        auth: &crate::config::ExternalAuth,
        original: &mut Request<Body>,
        edge: &EdgeContext,
    ) -> AuthOutcome {
        let operation = async move {
            let mut request = Request::builder()
                .method(Method::GET)
                .uri(&auth.url)
                .body(full_body(Bytes::new()))
                .map_err(|_| 503u16)?;
            for name in &auth.request_headers {
                for value in original.headers().get_all(name) {
                    request.headers_mut().append(
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
                request.headers_mut().insert(
                    HeaderName::from_static(name),
                    HeaderValue::from_str(&value).map_err(|_| 503u16)?,
                );
            }
            let response = self.client.request(request).await.map_err(|_| 503u16)?;
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
                return Ok(AuthOutcome::Allow(headers, cookies));
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

    pub async fn handle(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Result<Response<Body>, Infallible> {
        // Canonicalize the peer address so an IPv4-mapped IPv6 address
        // (`::ffff:a.b.c.d`, produced by a dual-stack `[::]` listener for an
        // IPv4 client) is compared and forwarded as the real IPv4 address.
        // Without this, `deny_cidrs` with IPv4 ranges never matches and the
        // forwarded X-Forwarded-For / X-Real-IP / x-original-client-ip carry
        // the mapped form.
        let peer = SocketAddr::new(peer.ip().to_canonical(), peer.port());
        let mut traffic = self
            .traffic
            .as_ref()
            .map(|_| TrafficContext::new(&request, peer));
        // Unauthenticated health probe for external load balancers. Answered
        // before route matching and before acquiring a request permit, so it
        // stays responsive under data-plane saturation. Reports 503 while
        // draining or before the control plane is ready, so a balancer can
        // deregister the instance instead of sending it traffic.
        // One snapshot per request, captured before the health check so the
        // probe decision, routing and the document's settings all come from
        // the same activation.
        let snapshot = self.active.load_full();
        let health_path = snapshot
            .settings
            .health_path
            .clone()
            .or_else(|| self.health_path.clone());
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
                if let (Some(history), Some(context)) = (&self.traffic, &traffic) {
                    context.record(history, 503);
                }
                return Ok(response(503, "request capacity exhausted"));
            }
        };
        // Capture access-log fields before the request is consumed.
        let access = self.access_log.then(|| {
            let host = request
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| request.uri().authority().map(|a| a.as_str()))
                .unwrap_or("")
                .to_owned();
            let path = request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .to_owned();
            (
                request.method().clone(),
                host,
                path,
                std::time::Instant::now(),
            )
        });
        let response = self
            .handle_inner(request, peer, snapshot, traffic.as_mut())
            .await?;
        if let (Some(history), Some(context)) = (&self.traffic, &traffic) {
            context.record(history, response.status().as_u16());
        }
        if let Some((method, host, path, started)) = access {
            tracing::info!(
                target: "hangang::access",
                client = %peer.ip(),
                method = %method,
                host = %host,
                path = %path,
                status = response.status().as_u16(),
                latency_ms = started.elapsed().as_millis() as u64,
                "request"
            );
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
    ) -> Result<Response<Body>, Infallible> {
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
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
        // The terminal marker has meaning only on a response from the
        // configured authorization service, never as a client request field.
        request.headers_mut().remove("x-hangang-auth-terminal");
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
        let trusted_proxies: &[ipnet::IpNet] = snapshot
            .settings
            .trusted_proxy_cidrs
            .as_deref()
            .map(Vec::as_slice)
            .unwrap_or(&self.trusted_proxies);
        let edge = match self.resolve_edge(&request, peer, trusted_proxies) {
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
        let peer = SocketAddr::new(edge.client_ip, peer.port());
        let connection_lease = request
            .extensions()
            .get::<Arc<crate::metrics::ConnectionLease>>()
            .cloned();
        // Replacing the body preserves request extensions, including OnUpgrade.
        let (parts, body) = request.into_parts();
        let mut request = Request::from_parts(parts, boxed_incoming(body));

        let mut inspected = None;
        let mut selected: Option<Arc<HttpRuntime>> = None;
        for runtime in &snapshot.http {
            if !runtime.route.enabled
                || !basic_match(&runtime.route, &request, runtime.host_regex.as_ref())
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
            context.route_id = Some(runtime.route.id.chars().take(128).collect());
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

        // Cache access follows route admission and IP policy. Sensitive/dynamic
        // policy routes bypass entirely; hits must not depend on origin health.
        let mut cache_fill = None;
        let only_if_cached = crate::cache_policy::only_if_cached(request.headers());
        if only_if_cached && runtime.route.access_mode != crate::config::AccessMode::Protected {
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

        // Identity headers established by authentication on this request. They
        // are re-asserted after the request transform so a later header rewrite
        // cannot replace the authenticated identity the upstream relies on.
        let mut established_identity: Vec<(HeaderName, HeaderValue)> = Vec::new();
        // Includes compatibility identity names whose authenticated value is
        // null: those names must remain absent all the way to the origin.
        let basic_reserved = runtime
            .basic_auth
            .as_ref()
            .map(|prepared| prepared.reserved_headers())
            .unwrap_or(&[]);
        // Session cookies issued by the authorization service on a 2xx.
        let mut auth_cookies: Vec<HeaderValue> = Vec::new();
        // A policy-selected backend is an authorization/routing decision. A
        // later connection retry must not replace it with a balancer-selected
        // backend the policy never approved.
        let mut policy_pinned_backend = false;
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
            match verified {
                Some(authenticated) => {
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
            match self.authorize(auth, &mut request, &edge).await {
                AuthOutcome::Allow(headers, cookies) => {
                    for (name, value) in headers.iter() {
                        request.headers_mut().insert(name.clone(), value.clone());
                        established_identity.push((name.clone(), value.clone()));
                    }
                    auth_cookies = cookies;
                }
                AuthOutcome::Deny(status) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    return Ok(response(status, "authorization refused"));
                }
                AuthOutcome::Forward(forwarded) => {
                    self.metrics.errors.fetch_add(1, Ordering::Relaxed);
                    return Ok(*forwarded);
                }
            }
        }

        let Some(mut index) = self.select_http_backend(&runtime) else {
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
                script: script.clone(),
                method: request.method().as_str().to_owned(),
                path: request.uri().path().to_owned(),
                headers: policy_headers(&visible_headers),
            };
            match self.policy.evaluate(input).await {
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
                        basic_reserved,
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

        // Explicitly protected routes check gateway authentication and any
        // configured Lua policy before honoring a cache-only request. Their
        // cache is ineligible, so no origin content follows this shortcut.
        if only_if_cached {
            return Ok(response(504, "only-if-cached cannot be satisfied"));
        }

        if transforms {
            if request.method() == Method::CONNECT
                || request.headers().contains_key(header::UPGRADE)
            {
                return Ok(response(
                    400,
                    "body transforms do not support tunnels or upgrades",
                ));
            }
            if crate::transform_body::no_transform(request.headers()) {
                return Ok(response(400, "body transform conflicts with no-transform"));
            }
            if runtime.route.response_transform.is_some() {
                if request.headers().contains_key(header::RANGE)
                    || request.headers().contains_key(header::IF_RANGE)
                {
                    return Ok(response(
                        416,
                        "ranges are unsupported for transformed representations",
                    ));
                }
                // Preconditions refer to the original representation, not the configured output.
                if [
                    header::IF_MATCH,
                    header::IF_NONE_MATCH,
                    header::IF_MODIFIED_SINCE,
                    header::IF_UNMODIFIED_SINCE,
                ]
                .iter()
                .any(|name| request.headers().contains_key(name))
                {
                    return Ok(response(
                        412,
                        "preconditions are unsupported for transformed representations",
                    ));
                }
            }
            if runtime.request_transform.is_some()
                && request.headers().contains_key(header::CONTENT_RANGE)
            {
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
            reassert_identity_headers(&mut parts.headers, &established_identity, basic_reserved);
            match crate::transform_body::transform(
                body,
                config.clone(),
                self.policy.clone(),
                "request",
                transform_budget.clone().expect("transform budget"),
                self.metrics.clone(),
            )
            .await
            {
                Ok(body) => request = Request::from_parts(parts, body),
                Err(error) => {
                    return Ok(response(
                        error.status(true),
                        "request body transformation failed",
                    ));
                }
            }
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
        reassert_identity_headers(request.headers_mut(), &established_identity, basic_reserved);
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
            attempt += 1;
            let uri = match build_upstream_uri(&backend, &client_pq, host_override.as_deref()) {
                Ok(uri) => uri,
                Err((code, message)) => return Ok(response(code, message)),
            };
            let client = if custom_outbound {
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
            let outgoing = match first_request.take() {
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
            let send = async {
                match &client {
                    Some(client) => client.request(outgoing).await,
                    None => self.client.request(outgoing).await,
                }
            };
            match timeout(header_timeout, send).await {
                Ok(Ok(response)) => break response,
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
                    return Ok(self.failure(StatusCode::BAD_GATEWAY, "upstream request failed"));
                }
                Err(_) => {
                    if let Some(lease) = &backend_lease {
                        lease.record_timeout();
                    }
                    return Ok(self.failure(
                        StatusCode::GATEWAY_TIMEOUT,
                        "upstream response header timed out",
                    ));
                }
            }
        };
        let mut upstream = upstream;

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
            self.tunnels.spawn(async move {
                let _backend_lease = tunnel_backend;
                let _route_permit = tunnel_route;
                let _admission = admission;
                let _connection_lease = connection_lease;
                let upgraded = tokio::select! {
                    _ = cancel.cancelled() => return,
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
                        _ = cancel.cancelled() => {}
                        _ = idle.expired() => {}
                        _ = copy_bidirectional(&mut downstream, &mut upstream) => {}
                    }
                }
            });
        }

        let (parts, body) = upstream.into_parts();
        let mut response = Response::from_parts(parts, boxed_incoming(body));
        if let Some(config) = &runtime.response_transform {
            if response_has_body
                && !response.status().is_informational()
                && response.status() != StatusCode::NO_CONTENT
                && response.status() != StatusCode::NOT_MODIFIED
                && response.status() != StatusCode::RESET_CONTENT
            {
                if !crate::transform_body::identity_encoding(response.headers())
                    || crate::transform_body::no_transform(response.headers())
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
                match crate::transform_body::transform(
                    body,
                    config.clone(),
                    self.policy.clone(),
                    "response",
                    transform_budget.clone().expect("transform budget"),
                    self.metrics.clone(),
                )
                .await
                {
                    Ok(body) => response = Response::from_parts(parts, body),
                    Err(error) => {
                        return Ok(self.failure(
                            StatusCode::from_u16(error.status(false)).expect("static status"),
                            "response body transformation failed",
                        ));
                    }
                }
            } else {
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

fn basic_match<B>(
    route: &HttpRoute,
    request: &Request<B>,
    host_regex: Option<&regex::Regex>,
) -> bool {
    let actual = if route.host.is_some() || !route.hosts.is_empty() || host_regex.is_some() {
        request
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<hyper::http::uri::Authority>().ok())
            .map(|a| a.host().to_owned())
            .or_else(|| request.uri().authority().map(|a| a.host().to_owned()))
    } else {
        None
    };
    if let Some(expected) = &route.host
        && !actual
            .as_deref()
            .is_some_and(|host| crate::host_match::matches(expected, host))
    {
        return false;
    }
    if !route.hosts.is_empty()
        && !actual.as_deref().is_some_and(|host| {
            route
                .hosts
                .iter()
                .any(|pattern| crate::host_match::matches(pattern, host))
        })
    {
        return false;
    }
    if let Some(regex) = host_regex
        && !actual
            .as_deref()
            .is_some_and(|host| host.len() <= 253 && host.is_ascii() && regex.is_match(host))
    {
        return false;
    }
    if let Some(prefix) = &route.path_prefix {
        let path = request.uri().path();
        let matches = match route.path_match {
            crate::config::PathMatch::Prefix => path.starts_with(prefix),
            crate::config::PathMatch::Exact => path == prefix,
            crate::config::PathMatch::SegmentPrefix => {
                let base = prefix.trim_end_matches('/');
                base.is_empty()
                    || path == base
                    || path
                        .strip_prefix(base)
                        .is_some_and(|tail| tail.starts_with('/'))
            }
        };
        if !matches {
            return false;
        }
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
    basic_reserved: &[HeaderName],
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
            || basic_reserved.contains(&name)
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
    let mut cookies: Option<Vec<u8>> = None;
    for name in headers.keys() {
        let mut values = headers.get_all(name).iter();
        let (Some(first), Some(second)) = (values.next(), values.next()) else {
            continue;
        };
        if is_standard_hop_by_hop(name) || is_forwarding_identity_header(name) {
            continue;
        }
        if *name != header::COOKIE {
            return Err(());
        }
        let mut joined = first.as_bytes().to_vec();
        for value in std::iter::once(second).chain(values) {
            joined.extend_from_slice(b"; ");
            joined.extend_from_slice(value.as_bytes());
        }
        cookies = Some(joined);
    }
    if let Some(joined) = cookies {
        let value = HeaderValue::from_bytes(&joined).map_err(|_| ())?;
        headers.insert(header::COOKIE, value);
    }
    Ok(())
}

/// Re-insert identity headers established by authentication, replacing any
/// value a later header rewrite may have set for the same name.
fn reassert_identity_headers(
    headers: &mut HeaderMap,
    identity: &[(HeaderName, HeaderValue)],
    basic_reserved: &[HeaderName],
) {
    for name in basic_reserved {
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
        let forwarded_port = match forwarded_ports.next() {
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

fn boxed_incoming(body: Incoming) -> Body {
    body.map_err(|error| BodyError(Box::new(error)))
        .boxed_unsync()
}

fn full_body(bytes: Bytes) -> Body {
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
    use super::*;
    use ipnet::IpNet;

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
            access_mode: Default::default(),
            enabled: true,
            upstream: Default::default(),
            priority: 0,
            host_regex: None,
            upstream_host: None,
            preserve_host: false,
            id: "test".into(),
            host: None,
            hosts: Vec::new(),
            path_prefix: None,
            path_match: Default::default(),
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
