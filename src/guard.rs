//! Opt-in native hangang-guard transport and local, expiring admission cache.
//! Query mode awaits bounded remote decisions; snapshot exports never wait for queue capacity.
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const MAX_BODY: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;
const QUEUE: usize = 4096;
const BATCH: usize = 256;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Enforce,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Honeypot,
    Scanner,
    AuthFailure,
    InvalidRequest,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub ip: IpAddr,
    pub kind: Kind,
    pub observed_at: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub network: String,
    pub expires_at: u64,
    pub reason: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub revision: u64,
    pub generated_at: u64,
    pub valid_until: u64,
    pub mode: Mode,
    pub allow: Vec<String>,
    pub blocks: Vec<Block>,
}

#[derive(Default)]
struct Prefixes {
    v4: HashMap<(u8, u32), u64>,
    v6: HashMap<(u8, u128), u64>,
}
fn mask4(n: u32, bits: u8) -> u32 {
    if bits == 0 {
        0
    } else {
        n & (u32::MAX << (32 - bits))
    }
}
fn mask6(n: u128, bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        n & (u128::MAX << (128 - bits))
    }
}
impl Prefixes {
    fn insert(&mut self, network: IpNet, expires: u64) {
        match network {
            IpNet::V4(net) => {
                self.v4
                    .insert((net.prefix_len(), u32::from(net.network())), expires);
            }
            IpNet::V6(net) => {
                self.v6
                    .insert((net.prefix_len(), u128::from(net.network())), expires);
            }
        }
    }
    fn matches(&self, ip: IpAddr, time: u64) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(ip) => (0..=32).any(|bits| {
                self.v4
                    .get(&(bits, mask4(u32::from(ip), bits)))
                    .is_some_and(|end| *end > time)
            }),
            IpAddr::V6(ip) => (0..=128).any(|bits| {
                self.v6
                    .get(&(bits, mask6(u128::from(ip), bits)))
                    .is_some_and(|end| *end > time)
            }),
        }
    }
}
struct Policy {
    revision: u64,
    generated_at: u64,
    valid_until: u64,
    mode: Mode,
    allow: Prefixes,
    blocks: Prefixes,
}
fn canonical(value: &str) -> Result<IpNet> {
    let net: IpNet = value.parse().context("invalid guard network")?;
    ensure!(
        net.addr() == net.network() && net.to_string() == value,
        "guard network must be canonical"
    );
    if let IpNet::V6(v6) = net {
        ensure!(
            v6.addr().to_ipv4_mapped().is_none(),
            "mapped guard networks must use IPv4"
        );
    }
    Ok(net)
}
impl Policy {
    fn compile(snapshot: Snapshot, time: u64) -> Result<Self> {
        ensure!(snapshot.version == 1, "unsupported guard snapshot version");
        ensure!(
            snapshot.generated_at <= time
                && snapshot.valid_until > time
                && snapshot.valid_until > snapshot.generated_at
                && snapshot.valid_until - snapshot.generated_at <= 300,
            "invalid guard snapshot times"
        );
        ensure!(
            snapshot.allow.len() <= MAX_ENTRIES && snapshot.blocks.len() <= MAX_ENTRIES,
            "too many guard networks"
        );
        let mut allow = Prefixes::default();
        let mut blocks = Prefixes::default();
        let mut seen = HashSet::new();
        for text in snapshot.allow {
            let net = canonical(&text)?;
            ensure!(seen.insert(net), "duplicate guard allow network");
            allow.insert(net, u64::MAX);
        }
        seen.clear();
        for block in snapshot.blocks {
            ensure!(block.reason.len() <= 128, "guard reason too long");
            let net = canonical(&block.network)?;
            ensure!(seen.insert(net), "duplicate guard block network");
            blocks.insert(net, block.expires_at);
        }
        Ok(Self {
            revision: snapshot.revision,
            generated_at: snapshot.generated_at,
            valid_until: snapshot.valid_until,
            mode: snapshot.mode,
            allow,
            blocks,
        })
    }
    fn denied(&self, ip: IpAddr, time: u64) -> bool {
        self.mode == Mode::Enforce
            && time < self.valid_until
            && !self.allow.matches(ip, time)
            && self.blocks.matches(ip, time)
    }
}

/// Transport settings contain no credential; token is read from the named environment variable.
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum TransportMode {
    Query,
    Snapshot,
}
#[derive(Clone, Copy, Debug, clap::ValueEnum, PartialEq, Eq)]
pub enum FailureMode {
    Allow,
    Deny,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    version: u32,
    revision: u64,
    action: Action,
    mode: Mode,
    reason: Option<String>,
    ttl_ms: u64,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Action {
    Allow,
    Deny,
}
struct Cached {
    denied: bool,
    expires: std::time::Instant,
}
#[derive(Default)]
struct Cache {
    revision: Option<u64>,
    entries: HashMap<IpAddr, Cached>,
}
pub struct Config {
    pub transport_mode: TransportMode,
    pub failure_mode: FailureMode,
    pub timeout_ms: u64,
    pub cache_ms: u64,
    pub url: String,
    pub source_id: String,
    pub token_env: String,
    pub honeypot_paths: Vec<String>,
    pub scanner_paths: Vec<String>,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=5000).contains(&self.timeout_ms),
            "guard timeout must be 1..5000 ms"
        );
        ensure!(
            self.cache_ms == 0 || (1000..=5000).contains(&self.cache_ms),
            "guard cache must be zero or 1000..5000 ms"
        );
        let url = reqwest::Url::parse(&self.url).context("invalid guard URL")?;
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "guard URL must be an origin without credentials"
        );
        let local = url.host_str().is_some_and(|host| {
            host.trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        });
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && local),
            "guard HTTP requires a literal loopback address; remote guard requires HTTPS"
        );
        ensure!(
            !self.source_id.is_empty()
                && self.source_id.len() <= 64
                && self
                    .source_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "invalid guard source ID"
        );
        ensure!(
            !self.token_env.is_empty(),
            "empty guard token environment name"
        );
        ensure!(
            self.honeypot_paths.len() + self.scanner_paths.len() <= 256,
            "too many guard signal paths"
        );
        let mut seen = HashSet::new();
        for path in self.honeypot_paths.iter().chain(&self.scanner_paths) {
            ensure!(
                path.starts_with('/')
                    && path.len() <= 1024
                    && path.is_ascii()
                    && !path
                        .bytes()
                        .any(|b| b.is_ascii_control() || matches!(b, b'?' | b'#'))
                    && seen.insert(path),
                "invalid or duplicate guard signal path"
            );
        }
        Ok(())
    }
}

pub struct GuardClient {
    transport_mode: TransportMode,
    failure_mode: FailureMode,
    cache_ms: u64,
    cache: Mutex<Cache>,
    http: reqwest::Client,
    base: String,
    source: String,
    auth: reqwest::header::HeaderValue,
    policy: ArcSwapOption<Policy>,
    queue: mpsc::Sender<Event>,
    dropped: AtomicU64,
    query_failures: AtomicU64,
    honeypot_paths: HashSet<String>,
    scanner_paths: HashSet<String>,
}
impl GuardClient {
    pub fn start(config: Config, cancel: CancellationToken) -> Result<Arc<Self>> {
        config.validate()?;
        let token = std::env::var(&config.token_env)
            .context("guard collector token environment variable unavailable")?;
        Self::start_with_token(config, token, cancel)
    }
    fn start_with_token(
        config: Config,
        token: String,
        cancel: CancellationToken,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        ensure!(
            !token.is_empty() && token.len() <= 4096 && token.bytes().all(|b| b.is_ascii_graphic()),
            "invalid guard collector token"
        );
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;
        let (queue, rx) = mpsc::channel(QUEUE);
        let guard = Arc::new(Self {
            transport_mode: config.transport_mode,
            failure_mode: config.failure_mode,
            cache_ms: config.cache_ms,
            cache: Mutex::new(Cache::default()),
            http: client.clone(),
            base: config.url.trim_end_matches('/').into(),
            source: config.source_id.clone(),
            auth: authorization.clone(),
            policy: ArcSwapOption::empty(),
            queue,
            dropped: AtomicU64::new(0),
            query_failures: AtomicU64::new(0),
            honeypot_paths: config.honeypot_paths.into_iter().collect(),
            scanner_paths: config.scanner_paths.into_iter().collect(),
        });
        if config.transport_mode == TransportMode::Snapshot {
            tokio::spawn(Self::worker(
                guard.clone(),
                rx,
                client,
                config.url.trim_end_matches('/').into(),
                config.source_id,
                authorization,
                cancel,
            ));
        }
        Ok(guard)
    }
    /// Native zero-trust admission after trusted-proxy identity resolution.
    pub async fn admit(&self, ip: IpAddr, path: &str) -> bool {
        self.rejection(ip, path).await.is_none()
    }
    /// Explicit denials are 403; unavailable query authority fails closed with 503.
    pub async fn rejection(&self, ip: IpAddr, path: &str) -> Option<u16> {
        let ip = ip.to_canonical();
        if self.transport_mode == TransportMode::Snapshot {
            if self.denied(ip) {
                return Some(403);
            }
            self.observe_path(ip, path);
            return None;
        }
        let kind = self.path_kind(path);
        if kind.is_none() && self.cache_ms > 0 {
            let cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(entry) = cache
                .entries
                .get(&ip)
                .filter(|entry| entry.expires > std::time::Instant::now())
            {
                return entry.denied.then_some(403);
            }
        }
        let query_started = std::time::Instant::now();
        let result: Result<Decision> = async {
            let mut body = serde_json::json!({"source_id": self.source, "ip": ip});
            if let Some(kind) = kind {
                body["kind"] = serde_json::to_value(kind)?;
            }
            let response = self
                .http
                .post(format!("{}/v1/decision", self.base))
                .header(reqwest::header::AUTHORIZATION, self.auth.clone())
                .json(&body)
                .send()
                .await?;
            let body = Self::bounded_body(response).await?;
            let decision: Decision = serde_json::from_slice(&body)?;
            ensure!(
                decision.version == 1
                    && decision
                        .reason
                        .as_ref()
                        .is_none_or(|reason| reason.len() <= 128)
                    && decision.ttl_ms <= 5000,
                "invalid guard decision"
            );
            ensure!(
                !matches!(
                    (decision.mode, decision.action),
                    (Mode::Observe, Action::Deny)
                ),
                "observe decision cannot deny"
            );
            Ok(decision)
        }
        .await;
        match result {
            Ok(decision) => {
                let denied = matches!(decision.action, Action::Deny);
                let mut cache = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if cache.revision != Some(decision.revision) {
                    cache.entries.clear();
                    cache.revision = Some(decision.revision);
                }
                let ttl = self.cache_ms.min(decision.ttl_ms);
                if kind.is_none() && ttl > 0 {
                    if cache.entries.len() >= 10_000 {
                        cache
                            .entries
                            .retain(|_, entry| entry.expires > std::time::Instant::now());
                    }
                    if cache.entries.len() < 10_000 {
                        cache.entries.insert(
                            ip,
                            Cached {
                                denied,
                                expires: query_started + Duration::from_millis(ttl),
                            },
                        );
                    }
                }
                denied.then_some(403)
            }
            Err(_) => {
                let failures = self
                    .query_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if failures.is_power_of_two() {
                    tracing::warn!(query_failures = failures, "guard decision query failed");
                }
                (self.failure_mode == FailureMode::Deny).then_some(503)
            }
        }
    }
    fn path_kind(&self, path: &str) -> Option<Kind> {
        if self.honeypot_paths.contains(path) {
            Some(Kind::Honeypot)
        } else if self.scanner_paths.contains(path) {
            Some(Kind::Scanner)
        } else {
            None
        }
    }
    pub fn denied(&self, ip: IpAddr) -> bool {
        self.policy
            .load()
            .as_ref()
            .is_some_and(|policy| policy.denied(ip, now()))
    }
    /// Only explicitly configured paths create evidence, before any guard rejection.
    pub fn observe_path(&self, ip: IpAddr, path: &str) {
        let kind = self.path_kind(path);
        if let Some(kind) = kind
            && self
                .queue
                .try_send(Event {
                    ip: ip.to_canonical(),
                    kind,
                    observed_at: now(),
                })
                .is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn install(&self, snapshot: Snapshot) -> Result<()> {
        let policy = Policy::compile(snapshot, now())?;
        // Revisions may reset after service restart, but old generated snapshots cannot roll back a live cache.
        if let Some(old) = self.policy.load().as_ref() {
            ensure!(
                policy.generated_at >= old.generated_at,
                "guard snapshot predates current cache"
            );
        }
        self.policy.store(Some(Arc::new(policy)));
        Ok(())
    }
    async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>> {
        ensure!(
            response.status().is_success(),
            "guard returned unsuccessful status"
        );
        ensure!(
            response
                .content_length()
                .is_none_or(|n| n <= MAX_BODY as u64),
            "guard response too large"
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                body.len() + chunk.len() <= MAX_BODY,
                "guard response too large"
            );
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
    async fn worker(
        guard: Arc<Self>,
        mut rx: mpsc::Receiver<Event>,
        client: reqwest::Client,
        base: String,
        source: String,
        auth: reqwest::header::HeaderValue,
        cancel: CancellationToken,
    ) {
        let mut poll = tokio::time::interval(Duration::from_secs(2));
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                _ = poll.tick() => {
                    let result: Result<()> = async {
                        let response = client.get(format!("{base}/v1/snapshot")).header(reqwest::header::AUTHORIZATION, auth.clone()).send().await?;
                        let body = Self::bounded_body(response).await?;
                        guard.install(serde_json::from_slice(&body)?)
                    }.await;
                    match result { Ok(()) => { let policy = guard.policy.load(); tracing::debug!(revision = policy.as_ref().map(|p| p.revision), dropped_events = guard.dropped.load(Ordering::Relaxed), "guard snapshot refreshed"); }, Err(_) => tracing::warn!(dropped_events = guard.dropped.load(Ordering::Relaxed), "guard snapshot refresh failed; retaining cache until expiry") }
                }
                event = rx.recv() => {
                    let Some(event) = event else { break; };
                    let mut events = vec![event];
                    while events.len() < BATCH { match rx.try_recv() { Ok(event) => events.push(event), Err(_) => break } }
                    let count = events.len() as u64;
                    let result: Result<()> = async {
                        let response = client.post(format!("{base}/v1/events")).header(reqwest::header::AUTHORIZATION, auth.clone()).json(&serde_json::json!({"source_id": source, "events": events})).send().await?;
                        Self::bounded_body(response).await?; Ok(())
                    }.await;
                    if result.is_err() { guard.dropped.fetch_add(count, Ordering::Relaxed); tracing::warn!(dropped_events = guard.dropped.load(Ordering::Relaxed), "guard event batch delivery failed"); }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> Snapshot {
        Snapshot {
            version: 1,
            revision: 1,
            generated_at: 100,
            valid_until: 130,
            mode: Mode::Enforce,
            allow: vec!["192.0.2.7/32".into()],
            blocks: vec![
                Block {
                    network: "192.0.2.0/24".into(),
                    expires_at: 120,
                    reason: "test".into(),
                },
                Block {
                    network: "2001:db8::/32".into(),
                    expires_at: 130,
                    reason: "test".into(),
                },
            ],
        }
    }
    #[test]
    fn prefix_allow_expiry_and_mapped_identity() {
        let p = Policy::compile(snapshot(), 100).unwrap();
        assert!(p.denied("::ffff:192.0.2.8".parse().unwrap(), 110));
        assert!(!p.denied("192.0.2.7".parse().unwrap(), 110));
        assert!(!p.denied("192.0.2.8".parse().unwrap(), 120));
        assert!(p.denied("2001:db8::42".parse().unwrap(), 129));
        assert!(!p.denied("2001:db8::42".parse().unwrap(), 130));
    }
    #[test]
    fn observe_does_not_enforce() {
        let mut s = snapshot();
        s.mode = Mode::Observe;
        assert!(
            !Policy::compile(s, 100)
                .unwrap()
                .denied("192.0.2.8".parse().unwrap(), 110)
        );
    }
    #[test]
    fn invalid_snapshot_rejected() {
        let mut s = snapshot();
        s.generated_at = 101;
        assert!(Policy::compile(s, 100).is_err());
        let mut s = snapshot();
        s.blocks[0].network = "192.0.2.1/24".into();
        assert!(Policy::compile(s, 100).is_err());
        let mut s = snapshot();
        s.blocks.push(s.blocks[0].clone());
        assert!(Policy::compile(s, 100).is_err());
        let mut s = snapshot();
        s.valid_until = 401;
        assert!(Policy::compile(s, 100).is_err());
    }
    #[test]
    fn url_boundaries() {
        let mut c = Config {
            transport_mode: TransportMode::Query,
            failure_mode: FailureMode::Deny,
            timeout_ms: 100,
            cache_ms: 0,
            url: "http://127.0.0.1:8090".into(),
            source_id: "hangang".into(),
            token_env: "TOKEN".into(),
            honeypot_paths: vec![],
            scanner_paths: vec![],
        };
        assert!(c.validate().is_ok());
        c.cache_ms = 999;
        assert!(c.validate().is_err());
        c.cache_ms = 5001;
        assert!(c.validate().is_err());
        c.cache_ms = 1000;
        assert!(c.validate().is_ok());
        c.cache_ms = 0;
        c.url = "http://example.com".into();
        assert!(c.validate().is_err());
        c.url = "https://example.com".into();
        assert!(c.validate().is_ok());
        c.url = "https://user:secret@example.com".into();
        assert!(c.validate().is_err());
    }
    #[test]
    fn saturated_export_is_nonblocking() {
        let (queue, mut rx) = mpsc::channel(1);
        let guard = GuardClient {
            transport_mode: TransportMode::Snapshot,
            failure_mode: FailureMode::Deny,
            cache_ms: 0,
            cache: Mutex::new(Cache::default()),
            http: reqwest::Client::new(),
            base: "http://127.0.0.1".into(),
            source: "test".into(),
            auth: reqwest::header::HeaderValue::from_static("Bearer test"),
            policy: ArcSwapOption::empty(),
            queue,
            dropped: AtomicU64::new(0),
            query_failures: AtomicU64::new(0),
            honeypot_paths: HashSet::from(["/trap".into()]),
            scanner_paths: HashSet::new(),
        };
        guard.observe_path("127.0.0.1".parse().unwrap(), "/trap");
        guard.observe_path("127.0.0.1".parse().unwrap(), "/trap");
        guard.observe_path("127.0.0.1".parse().unwrap(), "/ordinary");
        assert_eq!(guard.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(rx.try_recv().unwrap().kind, Kind::Honeypot);
    }
    fn test_config(url: String) -> Config {
        Config {
            transport_mode: TransportMode::Query,
            failure_mode: FailureMode::Deny,
            timeout_ms: 1000,
            cache_ms: 0,
            url,
            source_id: "test".into(),
            token_env: "UNUSED_TEST_TOKEN".into(),
            honeypot_paths: vec!["/trap".into()],
            scanner_paths: vec![],
        }
    }
    async fn decision_server() -> (
        String,
        Arc<Mutex<Vec<serde_json::Value>>>,
        Arc<Mutex<serde_json::Value>>,
        tokio::task::JoinHandle<()>,
    ) {
        use http_body_util::{BodyExt, Full};
        use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let decision = Arc::new(Mutex::new(
            serde_json::json!({"version":1,"revision":1,"action":"allow","mode":"enforce","reason":null,"ttl_ms":5000}),
        ));
        let records = seen.clone();
        let output = decision.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let records = records.clone();
                let output = output.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let records = records.clone();
                        let output = output.clone();
                        async move {
                            assert_eq!(req.uri().path(), "/v1/decision");
                            assert_eq!(req.headers()["authorization"], "Bearer test-token");
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            records
                                .lock()
                                .unwrap()
                                .push(serde_json::from_slice(&body).unwrap());
                            let body = serde_json::to_vec(&*output.lock().unwrap()).unwrap();
                            Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                bytes::Bytes::from(body),
                            )))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (url, seen, decision, task)
    }
    #[tokio::test]
    async fn malformed_snapshot_preserves_last_good_generation() {
        let guard = GuardClient::start_with_token(
            test_config("http://127.0.0.1:1".into()),
            "test-token".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let time = now();
        let mut good = snapshot();
        good.generated_at = time;
        good.valid_until = time + 30;
        for block in &mut good.blocks {
            block.expires_at = time + 30;
        }
        guard.install(good.clone()).unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        assert!(guard.denied(ip));
        let mut invalid = good.clone();
        invalid.generated_at = time + 10;
        assert!(guard.install(invalid).is_err());
        assert!(guard.denied(ip));
        let mut invalid = good.clone();
        invalid.blocks[0].network = "192.0.2.1/24".into();
        assert!(guard.install(invalid).is_err());
        assert!(guard.denied(ip));
        good.mode = Mode::Observe;
        guard.install(good).unwrap();
        assert!(!guard.denied(ip));
    }
    #[tokio::test]
    async fn query_default_has_no_cache_and_typed_paths_skip_optional_cache() {
        let (url, seen, decision, task) = decision_server().await;
        let cancel = CancellationToken::new();
        let guard = GuardClient::start_with_token(
            test_config(url.clone()),
            "test-token".into(),
            cancel.clone(),
        )
        .unwrap();
        let ip = "::ffff:192.0.2.8".parse().unwrap();
        assert!(guard.admit(ip, "/ordinary").await);
        assert!(guard.admit(ip, "/ordinary").await);
        assert_eq!(seen.lock().unwrap().len(), 2);
        assert_eq!(
            seen.lock().unwrap()[0],
            serde_json::json!({"source_id":"test","ip":"192.0.2.8"})
        );
        let mut config = test_config(url);
        config.cache_ms = 5000;
        let guard =
            GuardClient::start_with_token(config, "test-token".into(), cancel.clone()).unwrap();
        assert!(guard.admit(ip, "/ordinary").await);
        assert!(guard.admit(ip, "/ordinary").await);
        assert_eq!(seen.lock().unwrap().len(), 3);
        assert!(guard.admit(ip, "/trap").await);
        assert!(guard.admit(ip, "/trap").await);
        assert_eq!(seen.lock().unwrap().len(), 5);
        assert_eq!(seen.lock().unwrap()[3]["kind"], "honeypot");
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":2,"action":"deny","mode":"enforce","reason":"blocked","ttl_ms":1000});
        assert!(!guard.admit("192.0.2.9".parse().unwrap(), "/ordinary").await);
        assert!(!guard.admit(ip, "/ordinary").await);
        assert_eq!(seen.lock().unwrap().len(), 7);
        cancel.cancel();
        task.abort();
    }
    #[tokio::test]
    async fn malformed_decision_and_connection_failure_follow_configured_failure_policy() {
        let (url, _, decision, task) = decision_server().await;
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":1,"action":"deny","mode":"observe","reason":"invalid","ttl_ms":1000});
        let cancel = CancellationToken::new();
        let mut config = test_config(url.clone());
        let deny =
            GuardClient::start_with_token(config, "test-token".into(), cancel.clone()).unwrap();
        assert!(!deny.admit("127.0.0.1".parse().unwrap(), "/").await);
        config = test_config(url);
        config.failure_mode = FailureMode::Allow;
        let allow =
            GuardClient::start_with_token(config, "test-token".into(), cancel.clone()).unwrap();
        assert!(allow.admit("127.0.0.1".parse().unwrap(), "/").await);
        // Use an unbound port to exercise connection errors without relying on keepalive shutdown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let deny = GuardClient::start_with_token(
            test_config(url.clone()),
            "test-token".into(),
            cancel.clone(),
        )
        .unwrap();
        assert!(!deny.admit("127.0.0.1".parse().unwrap(), "/").await);
        let mut config = test_config(url);
        config.failure_mode = FailureMode::Allow;
        let allow =
            GuardClient::start_with_token(config, "test-token".into(), cancel.clone()).unwrap();
        assert!(allow.admit("127.0.0.1".parse().unwrap(), "/").await);
        cancel.cancel();
        task.abort();
    }
    #[tokio::test]
    async fn native_proxy_queries_verified_ip_and_preserves_route_authentication() {
        use http_body_util::{BodyExt, Full};
        use hyper::{Request, body::Incoming, server::conn::http1, service::service_fn};
        let (url, seen, decision, task) = decision_server().await;
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(test_config(url), "test-token".into(), cancel.clone())
                .unwrap();
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({"revision":1,"http":[{"id":"app","hosts":["app.example"],"path_prefix":"/","backends":["http://127.0.0.1:1"],"access_mode":"protected","basic_auth":{"realm":"app","credentials":[crate::basic_auth::hash_credential("alice", "password").unwrap()]}}]})).unwrap();
        let active = Arc::new(arc_swap::ArcSwap::from_pointee(
            crate::config::Snapshot::new(config).unwrap(),
        ));
        let policy = Arc::new(crate::policy::PolicyPool::new(
            std::env::current_exe().unwrap(),
            1,
        ));
        let proxy = crate::proxy::Proxy::new(
            active,
            policy.clone(),
            Arc::new(crate::metrics::Metrics::default()),
        )
        .with_guard(Some(guard))
        .with_trusted_proxies(vec!["127.0.0.0/8".parse().unwrap()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front = listener.local_addr().unwrap();
        let front_task = tokio::spawn(async move {
            while let Ok((stream, peer)) = listener.accept().await {
                let proxy = proxy.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let proxy = proxy.clone();
                        async move { proxy.handle(request, peer).await }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let client =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http::<Full<bytes::Bytes>>();
        let request = || {
            Request::builder()
                .uri(format!("http://{front}/trap?secret=excluded"))
                .header("host", "app.example")
                .header("x-forwarded-for", "192.0.2.8")
                .body(Full::new(bytes::Bytes::new()))
                .unwrap()
        };
        let response = client.request(request()).await.unwrap();
        assert_eq!(response.status().as_u16(), 401);
        response.into_body().collect().await.unwrap();
        assert_eq!(
            seen.lock().unwrap()[0],
            serde_json::json!({"source_id":"test","ip":"192.0.2.8","kind":"honeypot"})
        );
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":2,"action":"deny","mode":"enforce","reason":"blocked","ttl_ms":1000});
        let response = client.request(request()).await.unwrap();
        assert_eq!(response.status().as_u16(), 403);
        response.into_body().collect().await.unwrap();
        // The same single decision call carries the typed path; no separate event re-export occurs.
        assert_eq!(seen.lock().unwrap().len(), 2);
        cancel.cancel();
        front_task.abort();
        task.abort();
        policy.shutdown().await;
    }
}
