//! Opt-in native hangang-guard transport and local, expiring admission cache.
//! Query mode awaits bounded remote decisions; snapshot exports never wait for queue capacity.
mod grpc;
mod lifetime;
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Semaphore, mpsc},
};
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

const TCP_POOL_SIZE: usize = 64;
const TCP_IDLE_RETIRE: Duration = Duration::from_secs(25);
trait NativeIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> NativeIo for T {}
struct IdleSocket {
    socket: Box<dyn NativeIo>,
    created: std::time::Instant,
    last_used: std::time::Instant,
}
struct TcpPool {
    address: pumgye_client::Endpoint,
    /// Swapped when the client certificate rotates; pooled connections keep
    /// the identity they were opened with.
    tls: ArcSwapOption<(
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )>,
    token: Vec<u8>,
    timeout: Duration,
    slots: Semaphore,
    idle: Mutex<Vec<IdleSocket>>,
    correlation: AtomicU32,
}
impl TcpPool {
    async fn query(&self, ip: IpAddr) -> Result<Decision> {
        tokio::time::timeout(self.timeout, async {
            let _slot = self.slots.acquire().await?;
            let cached = {
                let mut idle = self
                    .idle
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                loop {
                    match idle.pop() {
                        Some(entry)
                            if entry.last_used.elapsed() < TCP_IDLE_RETIRE
                                && entry.created.elapsed() < Duration::from_secs(240) =>
                        {
                            break Some((entry.socket, entry.created));
                        }
                        Some(_) => continue,
                        None => break None,
                    }
                }
            };
            let (mut socket, created) = if let Some(cached) = cached {
                cached
            } else {
                let socket = TcpStream::connect(self.address.as_str()).await?;
                socket.set_nodelay(true)?;
                let tls = self.tls.load_full();
                let mut socket: Box<dyn NativeIo> = if let Some((connector, name)) = tls.as_deref()
                {
                    let stream = connector.connect(name.clone(), socket).await?;
                    ensure!(
                        stream.get_ref().1.alpn_protocol() == Some(b"hgd1".as_slice()),
                        "invalid guard native TLS protocol"
                    );
                    Box::new(stream)
                } else {
                    Box::new(socket)
                };
                socket.write_all(b"HGD1").await?;
                socket
                    .write_all(&(self.token.len() as u16).to_be_bytes())
                    .await?;
                socket.write_all(&self.token).await?;
                let mut ack = [0; 4];
                socket.read_exact(&mut ack).await?;
                ensure!(&ack == b"HGA1", "invalid guard TCP acknowledgement");
                (socket, std::time::Instant::now())
            };
            let correlation = self.correlation.fetch_add(1, Ordering::Relaxed);
            let mut request = [0u8; 24];
            request[0] = 1;
            request[4..8].copy_from_slice(&correlation.to_be_bytes());
            match ip.to_canonical() {
                IpAddr::V4(ip) => {
                    request[1] = 4;
                    request[8..12].copy_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    request[1] = 6;
                    request[8..24].copy_from_slice(&ip.octets());
                }
            }
            socket.write_all(&request).await?;
            let mut frame = [0u8; 24];
            socket.read_exact(&mut frame).await?;
            ensure!(
                frame[0] == 1
                    && frame[1] <= 1
                    && frame[2] <= 1
                    && frame[3] == 0
                    && frame[20..24] == [0; 4]
                    && frame[4..8] == correlation.to_be_bytes(),
                "invalid guard TCP decision frame"
            );
            let revision = u64::from_be_bytes(frame[8..16].try_into().unwrap());
            let ttl_ms = u32::from_be_bytes(frame[16..20].try_into().unwrap()) as u64;
            ensure!(
                ttl_ms <= 5000 && !(frame[1] == 1 && frame[2] == 0),
                "invalid guard TCP decision values"
            );
            let decision = Decision {
                version: 1,
                revision,
                action: if frame[1] == 0 {
                    Action::Allow
                } else {
                    Action::Deny
                },
                mode: if frame[2] == 0 {
                    Mode::Observe
                } else {
                    Mode::Enforce
                },
                reason: None,
                ttl_ms,
            };
            let mut idle = self
                .idle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !self.slots.is_closed() {
                idle.push(IdleSocket {
                    socket,
                    created,
                    last_used: std::time::Instant::now(),
                });
            }
            Ok(decision)
        })
        .await
        .context("guard TCP decision timed out")?
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
/// Native capture retains the original query clock and source owner, including cache hits.
#[derive(Clone)]
pub(crate) struct RequestEvidence {
    authority: Arc<()>,
    ip: IpAddr,
    revision: u64,
    lifetime: Arc<lifetime::Lifetime>,
    ttl_ms: u64,
    value: pumgye_core::GuardEvidence,
}
impl RequestEvidence {
    pub(crate) fn current(
        &self,
        guard: &GuardClient,
        ip: IpAddr,
    ) -> Option<pumgye_core::GuardEvidence> {
        self.remaining(guard, ip).map(|_| self.value)
    }
    fn bound_to(&self, guard: &GuardClient, ip: IpAddr) -> bool {
        !guard.cancel.is_cancelled()
            && Arc::ptr_eq(&self.authority, &guard.owner)
            && self.ip == ip.to_canonical()
            && guard
                .cache
                .lock()
                .map(|cache| cache.revision == Some(self.revision))
                .unwrap_or(false)
    }
    pub(crate) fn remaining(&self, guard: &GuardClient, ip: IpAddr) -> Option<Duration> {
        self.bound_to(guard, ip)
            .then(|| self.lifetime.remaining(self.ttl_ms.min(1000)))
            .flatten()
    }
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
    proof: RequestEvidence,
    ttl_ms: u64,
}
#[derive(Default)]
struct Cache {
    revision: Option<u64>,
    entries: HashMap<IpAddr, Cached>,
}
#[derive(Clone, Debug)]
pub struct NativeTls {
    pub server_name: String,
    pub ca: std::path::PathBuf,
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
}
pub struct Config {
    pub decision_tcp: Option<pumgye_client::Endpoint>,
    pub decision_grpc: bool,
    pub decision_tls: Option<NativeTls>,
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
        ensure!(
            !self.decision_grpc || (self.decision_tcp.is_some() && self.decision_tls.is_some()),
            "guard gRPC requires an endpoint and mTLS"
        );
        if let Some(tls) = &self.decision_tls {
            ensure!(
                self.decision_tcp.is_some(),
                "guard native TLS requires a decision TCP address"
            );
            ensure!(
                rustls::pki_types::ServerName::try_from(tls.server_name.clone()).is_ok(),
                "invalid guard native TLS server name"
            );
            ensure!(
                [&tls.ca, &tls.certificate, &tls.key]
                    .iter()
                    .all(|p| p.is_absolute()),
                "guard native TLS paths must be absolute"
            );
        }
        if let Some(address) = &self.decision_tcp {
            address.validate()?;
            ensure!(
                (address.is_loopback() || self.decision_tls.is_some()),
                "remote guard decision TCP requires mTLS and a nonzero unicast address"
            );
            ensure!(
                self.transport_mode == TransportMode::Query,
                "guard decision TCP requires query mode"
            );
        }
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
    owner: Arc<()>,
    cancel: CancellationToken,
    #[cfg(test)]
    test_clock: Mutex<Option<lifetime::TestClock>>,
    grpc: Option<grpc::Client>,
    tcp: Option<TcpPool>,
    /// Decision mTLS material, polled for rotation.
    decision_tls: Option<NativeTls>,
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
    /// Decision client identity, for certificate rotation polling.
    pub fn tls_material(&self) -> Vec<crate::tls_reload::Material> {
        self.decision_tls
            .iter()
            .map(|tls| crate::tls_reload::Material {
                ca: tls.ca.clone(),
                certificate: tls.certificate.clone(),
                key: tls.key.clone(),
            })
            .collect()
    }
    /// Rebuild the decision clients from the (rotated) files. New
    /// connections present the new identity; open ones are unaffected.
    pub fn reload_tls(&self) -> Result<()> {
        let Some(tls) = &self.decision_tls else {
            return Ok(());
        };
        if let Some(tcp) = &self.tcp {
            let connector = crate::tls::mutual_client(
                &tls.ca,
                &tls.certificate,
                &tls.key,
                &tls.server_name,
                b"hgd1",
            )?;
            tcp.tls.store(Some(Arc::new(connector)));
        }
        if let Some(grpc) = &self.grpc {
            grpc.reload(tls)?;
        }
        Ok(())
    }
    fn start_query(&self) -> Result<lifetime::Lifetime> {
        #[cfg(test)]
        if let Some(clock) = self.test_clock.lock().unwrap().as_ref() {
            return Ok(lifetime::Lifetime::manual(clock.clone()));
        }
        lifetime::Lifetime::start()
    }
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
        if config.decision_tcp.is_some() {
            ensure!(
                (16..=4096).contains(&token.len()),
                "guard TCP token must contain 16..4096 bytes"
            );
        }
        let mut authorization = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))?;
        authorization.set_sensitive(true);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()?;
        let native_tls = config
            .decision_tls
            .as_ref()
            .map(|tls| {
                crate::tls::mutual_client(
                    &tls.ca,
                    &tls.certificate,
                    &tls.key,
                    &tls.server_name,
                    b"hgd1",
                )
            })
            .transpose()?;
        let grpc = config
            .decision_grpc
            .then(|| grpc::Client::new(&config, &token, cancel.clone()))
            .transpose()?;
        let (queue, rx) = mpsc::channel(QUEUE);
        let guard = Arc::new(Self {
            owner: Arc::new(()),
            cancel: cancel.clone(),
            #[cfg(test)]
            test_clock: Mutex::new(None),
            grpc,
            decision_tls: config.decision_tls.clone(),
            tcp: config
                .decision_tcp
                .filter(|_| !config.decision_grpc)
                .map(|address| TcpPool {
                    address,
                    tls: ArcSwapOption::from(native_tls.map(Arc::new)),
                    token: token.into_bytes(),
                    timeout: Duration::from_millis(config.timeout_ms),
                    slots: Semaphore::new(TCP_POOL_SIZE),
                    idle: Mutex::new(Vec::with_capacity(TCP_POOL_SIZE)),
                    correlation: AtomicU32::new(1),
                }),
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
        if guard.tcp.is_some() {
            let weak = Arc::downgrade(&guard);
            let stop = cancel.clone();
            tokio::spawn(async move {
                stop.cancelled().await;
                if let Some(guard) = weak.upgrade()
                    && let Some(pool) = &guard.tcp
                {
                    pool.slots.close();
                    pool.idle
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clear();
                }
            });
        }
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
    /// Fresh authenticated evidence for mandatory Pumgye authorization; never fail open.
    pub async fn authorization_evidence(&self, ip: IpAddr) -> pumgye_core::GuardEvidence {
        self.authorization_capture(ip).await.0
    }
    pub(crate) async fn authorization_capture(
        &self,
        ip: IpAddr,
    ) -> (pumgye_core::GuardEvidence, Option<RequestEvidence>) {
        use pumgye_core::GuardEvidence;
        if self.transport_mode == TransportMode::Snapshot || self.cancel.is_cancelled() {
            return (GuardEvidence::Unavailable, None);
        }
        let started = match self.start_query() {
            Ok(started) => Arc::new(started),
            Err(_) => return (GuardEvidence::Unavailable, None),
        };
        let result: Result<Decision> = async {
            if let Some(client) = &self.grpc {
                return client.query(ip.to_canonical()).await;
            }
            if let Some(pool) = &self.tcp {
                return pool.query(ip.to_canonical()).await;
            }
            let response = self
                .http
                .post(format!("{}/v1/decision", self.base))
                .header(reqwest::header::AUTHORIZATION, self.auth.clone())
                .json(&serde_json::json!({"source_id":self.source,"ip":ip.to_canonical()}))
                .send()
                .await?;
            let body = Self::bounded_body(response).await?;
            let decision: Decision = serde_json::from_slice(&body)?;
            ensure!(
                decision.version == 1 && decision.ttl_ms <= 5000,
                "invalid decision"
            );
            Ok(decision)
        }
        .await;
        let result = result.and_then(|decision| {
            let mut cache = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ensure!(
                cache
                    .revision
                    .is_none_or(|revision| decision.revision >= revision),
                "guard revision rollback"
            );
            if cache.revision != Some(decision.revision) {
                cache.entries.clear();
                cache.revision = Some(decision.revision);
            }
            Ok(decision)
        });
        match result {
            Ok(decision) => {
                let value = match (decision.mode, decision.action) {
                    (Mode::Enforce, Action::Allow) => GuardEvidence::EnforcedAllow,
                    (Mode::Enforce, Action::Deny) => GuardEvidence::Deny,
                    (Mode::Observe, Action::Allow) => GuardEvidence::Observe,
                    _ => return (GuardEvidence::Unavailable, None),
                };
                // TTL zero remains a point-in-time legacy decision, never a
                // reusable capture. Positive evidence ages across the RPC.
                let ttl_ms = decision.ttl_ms.min(1000);
                if self.cancel.is_cancelled() || ttl_ms > 0 && started.remaining(ttl_ms).is_none() {
                    return (GuardEvidence::Unavailable, None);
                }
                let proof = (ttl_ms > 0).then(|| RequestEvidence {
                    authority: self.owner.clone(),
                    ip: ip.to_canonical(),
                    revision: decision.revision,
                    lifetime: started,
                    ttl_ms,
                    value,
                });
                (value, proof)
            }
            Err(_) => (GuardEvidence::Unavailable, None),
        }
    }
    /// Explicit denials are 403; unavailable query authority fails closed with 503.
    pub async fn rejection(&self, ip: IpAddr, path: &str) -> Option<u16> {
        self.admission(ip, path).await.0
    }
    pub(crate) async fn admission(
        &self,
        ip: IpAddr,
        path: &str,
    ) -> (Option<u16>, Option<RequestEvidence>) {
        let ip = ip.to_canonical();
        if self.transport_mode == TransportMode::Snapshot {
            if self.denied(ip) {
                return (Some(403), None);
            }
            self.observe_path(ip, path);
            return (None, None);
        }
        if self.cancel.is_cancelled() {
            return (
                (self.failure_mode == FailureMode::Deny).then_some(503),
                None,
            );
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
                .filter(|entry| entry.proof.lifetime.remaining(entry.ttl_ms).is_some())
            {
                return (
                    entry.denied.then_some(403),
                    (!entry.denied).then(|| {
                        let mut proof = entry.proof.clone();
                        proof.ttl_ms = entry.ttl_ms;
                        proof
                    }),
                );
            }
        }
        let query_started = match self.start_query() {
            Ok(started) => Arc::new(started),
            Err(_) => {
                return (
                    (self.failure_mode == FailureMode::Deny).then_some(503),
                    None,
                );
            }
        };
        let result: Result<Decision> = async {
            if kind.is_none()
                && let Some(client) = &self.grpc
            {
                return client.query(ip).await;
            }
            if kind.is_none()
                && let Some(pool) = &self.tcp
            {
                return pool.query(ip).await;
            }
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
                if cache
                    .revision
                    .is_some_and(|revision| decision.revision < revision)
                {
                    return (
                        (self.failure_mode == FailureMode::Deny).then_some(503),
                        None,
                    );
                }
                if cache.revision != Some(decision.revision) {
                    cache.entries.clear();
                    cache.revision = Some(decision.revision);
                }
                // Age the entire transport exchange from original query start.
                if self.cancel.is_cancelled()
                    || decision.ttl_ms > 0 && query_started.remaining(decision.ttl_ms).is_none()
                {
                    return (
                        (self.failure_mode == FailureMode::Deny).then_some(503),
                        None,
                    );
                }
                let value = if decision.mode == Mode::Enforce {
                    pumgye_core::GuardEvidence::EnforcedAllow
                } else {
                    pumgye_core::GuardEvidence::Observe
                };
                let capture = RequestEvidence {
                    authority: self.owner.clone(),
                    ip,
                    revision: decision.revision,
                    lifetime: query_started,
                    ttl_ms: decision.ttl_ms,
                    value,
                };
                let ttl = self.cache_ms.min(decision.ttl_ms);
                if kind.is_none() && ttl > 0 {
                    if cache.entries.len() >= 10_000 {
                        cache.entries.retain(|_, entry| {
                            entry.proof.lifetime.remaining(entry.ttl_ms).is_some()
                        });
                    }
                    if cache.entries.len() < 10_000 {
                        cache.entries.insert(
                            ip,
                            Cached {
                                denied,
                                proof: capture.clone(),
                                ttl_ms: ttl,
                            },
                        );
                    }
                }
                let proof = (!denied && decision.ttl_ms > 0).then_some(capture);
                (denied.then_some(403), proof)
            }
            Err(_) => {
                let failures = self
                    .query_failures
                    .fetch_add(1, Ordering::Relaxed)
                    .saturating_add(1);
                if failures.is_power_of_two() {
                    tracing::warn!(query_failures = failures, "guard decision query failed");
                }
                (
                    (self.failure_mode == FailureMode::Deny).then_some(503),
                    None,
                )
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
    use std::net::SocketAddr;
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
            decision_tcp: None,
            decision_grpc: false,
            decision_tls: None,
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
        c.decision_grpc = true;
        assert!(c.validate().is_err());
        c.decision_tcp = Some("127.0.0.1:9083".parse().unwrap());
        assert!(c.validate().is_err());
        c.decision_grpc = false;
        c.decision_tcp = None;
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
    fn service_dns_never_authorizes_plaintext_loopback() {
        let mut config = test_config("http://127.0.0.1:8090".into());
        for endpoint in ["localhost:9081", "sumunjang.world.svc:9081"] {
            config.decision_tcp = Some(endpoint.parse().unwrap());
            assert!(config.validate().is_err());
        }
        config.decision_tls = Some(NativeTls {
            server_name: "sumunjang.world.svc".into(),
            ca: "/tls/ca.pem".into(),
            certificate: "/tls/client.pem".into(),
            key: "/tls/client.key".into(),
        });
        assert!(config.validate().is_ok());
    }
    #[test]
    fn saturated_export_is_nonblocking() {
        let (queue, mut rx) = mpsc::channel(1);
        let guard = GuardClient {
            owner: Arc::new(()),
            cancel: CancellationToken::new(),
            #[cfg(test)]
            test_clock: Mutex::new(None),
            grpc: None,
            tcp: None,
            decision_tls: None,
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
            decision_tcp: None,
            decision_grpc: false,
            decision_tls: None,
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
                            assert_eq!(
                                req.headers()["authorization"],
                                "Bearer test-token-0123456789"
                            );
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
            "test-token-0123456789".into(),
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
            "test-token-0123456789".into(),
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
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
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
    async fn known_revision_never_rolls_back_across_admission_and_authorization() {
        let (url, _, decision, task) = decision_server().await;
        let cancel = CancellationToken::new();
        let guard = GuardClient::start_with_token(
            test_config(url),
            "test-token-0123456789".into(),
            cancel.clone(),
        )
        .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":2,"action":"deny","mode":"enforce","reason":"blocked","ttl_ms":1000});
        assert!(!guard.admit(ip, "/ordinary").await);
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":1,"action":"allow","mode":"enforce","reason":null,"ttl_ms":1000});
        assert_eq!(
            guard.authorization_evidence(ip).await,
            pumgye_core::GuardEvidence::Unavailable
        );
        assert_eq!(guard.rejection(ip, "/ordinary").await, Some(503));
        assert_eq!(guard.cache.lock().unwrap().revision, Some(2));
        *decision.lock().unwrap() = serde_json::json!({"version":1,"revision":3,"action":"allow","mode":"enforce","reason":null,"ttl_ms":1000});
        assert_eq!(
            guard.authorization_evidence(ip).await,
            pumgye_core::GuardEvidence::EnforcedAllow
        );
        assert!(guard.admit(ip, "/ordinary").await);
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
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        assert!(!deny.admit("127.0.0.1".parse().unwrap(), "/").await);
        config = test_config(url);
        config.failure_mode = FailureMode::Allow;
        let allow =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        assert!(allow.admit("127.0.0.1".parse().unwrap(), "/").await);
        // Use an unbound port to exercise connection errors without relying on keepalive shutdown.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let deny = GuardClient::start_with_token(
            test_config(url.clone()),
            "test-token-0123456789".into(),
            cancel.clone(),
        )
        .unwrap();
        assert!(!deny.admit("127.0.0.1".parse().unwrap(), "/").await);
        let mut config = test_config(url);
        config.failure_mode = FailureMode::Allow;
        let allow =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
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
        let guard = GuardClient::start_with_token(
            test_config(url),
            "test-token-0123456789".into(),
            cancel.clone(),
        )
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
    struct TestTcp {
        address: SocketAddr,
        connections: Arc<AtomicU64>,
        requests: Arc<Mutex<Vec<[u8; 24]>>>,
        response: Arc<Mutex<[u8; 24]>>,
        delay_ms: Arc<AtomicU64>,
        task: tokio::task::JoinHandle<()>,
    }
    async fn tcp_server() -> TestTcp {
        tcp_server_with_tls(None).await
    }
    #[tokio::test]
    async fn native_mtls_name_ca_and_collector_are_verified_without_http_fallback() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
            KeyPair,
        };
        let temp = tempfile::tempdir().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let server_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["sumunjang.example.test".into()]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = params.signed_by(&server_key, &ca).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = params.signed_by(&client_key, &ca).unwrap();
        std::fs::write(temp.path().join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(temp.path().join("client.pem"), client_cert.pem()).unwrap();
        std::fs::write(temp.path().join("client.key"), client_key.serialize_pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )
            .unwrap();
        server.alpn_protocols = vec![b"hgd1".to_vec()];
        let tcp =
            tcp_server_with_tls(Some(tokio_rustls::TlsAcceptor::from(Arc::new(server)))).await;
        let (url, http_seen, _, http_task) = decision_server().await;
        let settings = NativeTls {
            server_name: "sumunjang.example.test".into(),
            ca: temp.path().join("ca.pem"),
            certificate: temp.path().join("client.pem"),
            key: temp.path().join("client.key"),
        };
        let mut config = test_config(url.clone());
        config.decision_tcp = Some(format!("localhost:{}", tcp.address.port()).parse().unwrap());
        config.decision_tls = Some(settings.clone());
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        assert!(guard.admit(ip, "/ordinary").await);
        assert!(guard.admit(ip, "/ordinary").await);
        assert_eq!(tcp.connections.load(Ordering::Relaxed), 1);
        tcp.response.lock().unwrap()[1] = 1;
        assert_eq!(guard.rejection(ip, "/ordinary").await, Some(403));
        let mut config = test_config(url.clone());
        config.decision_tcp = Some(format!("localhost:{}", tcp.address.port()).parse().unwrap());
        config.decision_tls = Some(NativeTls {
            server_name: "wrong.example.test".into(),
            ..settings.clone()
        });
        let wrong =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        assert_eq!(wrong.rejection(ip, "/ordinary").await, Some(503));
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        std::fs::write(temp.path().join("other.pem"), other.pem()).unwrap();
        let mut config = test_config(url);
        config.decision_tcp = Some(format!("localhost:{}", tcp.address.port()).parse().unwrap());
        config.decision_tls = Some(NativeTls {
            ca: temp.path().join("other.pem"),
            ..settings
        });
        let wrong =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        assert_eq!(wrong.rejection(ip, "/ordinary").await, Some(503));
        assert!(http_seen.lock().unwrap().is_empty());
        cancel.cancel();
        tcp.task.abort();
        http_task.abort();
    }
    async fn tcp_server_with_tls(tls: Option<tokio_rustls::TlsAcceptor>) -> TestTcp {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let mut frame = [0u8; 24];
        frame[0] = 1;
        frame[2] = 1;
        frame[8..16].copy_from_slice(&1u64.to_be_bytes());
        frame[16..20].copy_from_slice(&1000u32.to_be_bytes());
        let response = Arc::new(Mutex::new(frame));
        let delay_ms = Arc::new(AtomicU64::new(0));
        let count = connections.clone();
        let records = requests.clone();
        let output = response.clone();
        let delay = delay_ms.clone();
        let task = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                count.fetch_add(1, Ordering::Relaxed);
                let records = records.clone();
                let output = output.clone();
                let delay = delay.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let mut header = [0u8; 6];
                    socket.set_nodelay(true).unwrap();
                    let mut socket: Box<dyn NativeIo> = if let Some(tls) = tls {
                        let Ok(stream) = tls.accept(socket).await else {
                            return;
                        };
                        Box::new(stream)
                    } else {
                        Box::new(socket)
                    };
                    if socket.read_exact(&mut header).await.is_err() {
                        return;
                    }
                    assert_eq!(&header[..4], b"HGD1");
                    let mut token =
                        vec![0; u16::from_be_bytes(header[4..6].try_into().unwrap()) as usize];
                    socket.read_exact(&mut token).await.unwrap();
                    assert_eq!(token, b"test-token-0123456789");
                    socket.write_all(b"HGA1").await.unwrap();
                    loop {
                        let mut request = [0u8; 24];
                        if socket.read_exact(&mut request).await.is_err() {
                            break;
                        }
                        assert_eq!(request[0], 1);
                        assert_eq!(request[2..4], [0; 2]);
                        records.lock().unwrap().push(request);
                        let mut response = *output.lock().unwrap();
                        response[4..8].copy_from_slice(&request[4..8]);
                        tokio::time::sleep(Duration::from_millis(delay.load(Ordering::Relaxed)))
                            .await;
                        if socket.write_all(&response).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        TestTcp {
            address,
            connections,
            requests,
            response,
            delay_ms,
            task,
        }
    }
    #[tokio::test]
    async fn tcp_persistent_pool_reuses_connections_and_keeps_evidence_on_http() {
        let tcp = tcp_server().await;
        let (url, http_seen, _, http_task) = decision_server().await;
        let mut config = test_config(url);
        config.decision_tcp = Some(tcp.address.into());
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let ip = "::ffff:192.0.2.8".parse().unwrap();
        assert!(guard.admit(ip, "/ordinary").await);
        assert!(guard.admit(ip, "/ordinary").await);
        assert_eq!(tcp.connections.load(Ordering::Relaxed), 1);
        assert_eq!(tcp.requests.lock().unwrap().len(), 2);
        let request = tcp.requests.lock().unwrap()[0];
        assert_eq!(request[1], 4);
        assert_eq!(request[8..12], [192, 0, 2, 8]);
        assert_eq!(request[12..24], [0; 12]);
        assert!(guard.admit(ip, "/trap").await);
        assert_eq!(http_seen.lock().unwrap().len(), 1);
        assert_eq!(tcp.requests.lock().unwrap().len(), 2);
        tcp.response.lock().unwrap()[1] = 1;
        assert_eq!(guard.rejection(ip, "/ordinary").await, Some(403));
        tcp.response.lock().unwrap()[0] = 2;
        assert_eq!(guard.rejection(ip, "/ordinary").await, Some(503));
        assert!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().is_empty());
        tcp.response.lock().unwrap()[0] = 1;
        assert_eq!(guard.rejection(ip, "/ordinary").await, Some(403));
        assert_eq!(tcp.connections.load(Ordering::Relaxed), 2);
        tcp.task.abort();
        http_task.abort();
    }
    #[tokio::test]
    async fn tcp_pool_is_bounded_and_timeout_discards_socket_without_http_fallback() {
        let tcp = tcp_server().await;
        let (url, http_seen, _, http_task) = decision_server().await;
        let mut config = test_config(url.clone());
        config.decision_tcp = Some(tcp.address.into());
        config.timeout_ms = 25;
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        tcp.delay_ms.store(100, Ordering::Relaxed);
        assert_eq!(
            guard.rejection("2001:db8::42".parse().unwrap(), "/").await,
            Some(503)
        );
        assert!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().is_empty());
        assert!(http_seen.lock().unwrap().is_empty());
        assert_eq!(
            guard.tcp.as_ref().unwrap().slots.available_permits(),
            TCP_POOL_SIZE
        );
        let mut config = test_config(url);
        config.decision_tcp = Some(tcp.address.into());
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        tcp.delay_ms.store(2, Ordering::Relaxed);
        let responses = futures_util::future::join_all(
            (0..100).map(|_| guard.rejection("127.0.0.1".parse().unwrap(), "/")),
        )
        .await;
        assert!(responses.iter().any(Option::is_none));
        assert!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().len() <= TCP_POOL_SIZE);
        assert!(tcp.connections.load(Ordering::Relaxed) <= TCP_POOL_SIZE as u64 + 1);
        tcp.task.abort();
        http_task.abort();
    }
    #[tokio::test]
    async fn tcp_optional_cache_uses_decision_ttl_and_signal_bypasses_cache() {
        let tcp = tcp_server().await;
        let (url, http_seen, _, http_task) = decision_server().await;
        let mut config = test_config(url);
        config.decision_tcp = Some(tcp.address.into());
        config.cache_ms = 1000;
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        assert!(guard.admit(ip, "/").await);
        tcp.response.lock().unwrap()[1] = 1;
        assert!(guard.admit(ip, "/").await);
        assert_eq!(tcp.requests.lock().unwrap().len(), 1);
        assert!(guard.admit(ip, "/trap").await);
        assert_eq!(http_seen.lock().unwrap().len(), 1);
        tokio::time::sleep(Duration::from_millis(1010)).await;
        assert_eq!(guard.rejection(ip, "/").await, Some(403));
        tcp.task.abort();
        http_task.abort();
    }
    #[tokio::test]
    async fn tcp_shutdown_closes_idle_pool_and_wakes_waiters() {
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        assert!(guard.admit("127.0.0.1".parse().unwrap(), "/").await);
        assert_eq!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().len(), 1);
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !guard.tcp.as_ref().unwrap().slots.is_closed() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().is_empty());
        assert_eq!(
            guard.rejection("127.0.0.1".parse().unwrap(), "/").await,
            Some(503)
        );
        tcp.task.abort();
    }
    #[tokio::test]
    async fn tcp_idle_socket_is_retired_before_server_idle_timeout() {
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        assert!(guard.admit(ip, "/").await);
        assert_eq!(tcp.connections.load(Ordering::Relaxed), 1);
        {
            let mut idle = guard.tcp.as_ref().unwrap().idle.lock().unwrap();
            assert_eq!(idle.len(), 1);
            idle[0].last_used = std::time::Instant::now() - Duration::from_secs(26);
        }
        assert!(guard.admit(ip, "/").await);
        assert_eq!(tcp.connections.load(Ordering::Relaxed), 2);
        assert_eq!(tcp.requests.lock().unwrap().len(), 2);
        assert_eq!(guard.tcp.as_ref().unwrap().idle.lock().unwrap().len(), 1);
        cancel.cancel();
        tcp.task.abort();
    }
    #[tokio::test]
    async fn original_query_budget_survives_cache_reuse_suspend_and_clock_failure() {
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        config.cache_ms = 5000;
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let clock = Arc::new(Mutex::new(Some(Duration::ZERO)));
        *guard.test_clock.lock().unwrap() = Some(clock.clone());
        let ip = "192.0.2.8".parse().unwrap();
        let (_, first) = guard.admission(ip, "/").await;
        let first = first.unwrap();
        *clock.lock().unwrap() = Some(Duration::from_millis(400));
        let (_, cached) = guard.admission(ip, "/").await;
        let cached = cached.unwrap();
        assert!(Arc::ptr_eq(&first.lifetime, &cached.lifetime));
        assert_eq!(tcp.requests.lock().unwrap().len(), 1);
        assert_eq!(
            cached.remaining(&guard, ip),
            Some(Duration::from_millis(599))
        );
        // Simulated Linux suspend ages BOOTTIME while Tokio's timer does not move.
        *clock.lock().unwrap() = Some(Duration::from_secs(20));
        assert!(first.current(&guard, ip).is_none());
        assert!(cached.remaining(&guard, ip).is_none());
        // A reversed clock cannot resurrect old captures, even with a later valid reading.
        *clock.lock().unwrap() = Some(Duration::from_millis(500));
        assert!(cached.remaining(&guard, ip).is_none());
        *clock.lock().unwrap() = Some(Duration::from_secs(21));
        assert!(cached.remaining(&guard, ip).is_none());
        let clock = Arc::new(Mutex::new(Some(Duration::ZERO)));
        *guard.test_clock.lock().unwrap() = Some(clock.clone());
        let (_, proof) = guard.admission(ip, "/").await;
        let proof = proof.unwrap();
        *clock.lock().unwrap() = None;
        assert!(proof.remaining(&guard, ip).is_none());
        *clock.lock().unwrap() = Some(Duration::ZERO);
        assert!(
            proof.remaining(&guard, ip).is_none(),
            "read failure is irreversible"
        );
        tcp.task.abort();
    }
    #[tokio::test]
    async fn retired_native_owner_cannot_reuse_cache_or_captured_network_evidence() {
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        config.cache_ms = 5000;
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        let (_, proof) = guard.admission(ip, "/").await;
        let proof = proof.unwrap();
        assert!(proof.current(&guard, ip).is_some());
        cancel.cancel();
        assert!(proof.current(&guard, ip).is_none());
        assert_eq!(guard.rejection(ip, "/").await, Some(503));
        assert_eq!(
            guard.authorization_evidence(ip).await,
            pumgye_core::GuardEvidence::Unavailable
        );
        assert_eq!(
            tcp.requests.lock().unwrap().len(),
            1,
            "retirement must not query or reuse the cache"
        );
        tcp.task.abort();
    }
    #[tokio::test]
    async fn transport_wait_consumes_positive_budget_but_zero_ttl_never_creates_capture() {
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        let guard = GuardClient::start_with_token(
            config,
            "test-token-0123456789".into(),
            CancellationToken::new(),
        )
        .unwrap();
        let clock = Arc::new(Mutex::new(Some(Duration::ZERO)));
        *guard.test_clock.lock().unwrap() = Some(clock.clone());
        tcp.delay_ms.store(30, Ordering::Relaxed);
        let ip = "192.0.2.8".parse().unwrap();
        for fresh in [false, true] {
            *clock.lock().unwrap() = Some(Duration::ZERO);
            let before = tcp.requests.lock().unwrap().len();
            let advance = async {
                while tcp.requests.lock().unwrap().len() == before {
                    tokio::task::yield_now().await;
                }
                *clock.lock().unwrap() = Some(Duration::from_secs(2));
            };
            if fresh {
                let ((evidence, capture), ()) =
                    tokio::join!(guard.authorization_capture(ip), advance);
                assert_eq!(evidence, pumgye_core::GuardEvidence::Unavailable);
                assert!(capture.is_none());
            } else {
                let ((rejected, capture), ()) = tokio::join!(guard.admission(ip, "/"), advance);
                assert_eq!(rejected, Some(503));
                assert!(capture.is_none());
            }
        }
        tcp.response.lock().unwrap()[16..20].copy_from_slice(&0u32.to_be_bytes());
        let (rejected, capture) = guard.admission(ip, "/").await;
        assert!(rejected.is_none() && capture.is_none());
        let (evidence, capture) = guard.authorization_capture(ip).await;
        assert_eq!(evidence, pumgye_core::GuardEvidence::EnforcedAllow);
        assert!(capture.is_none());
        assert!(guard.cache.lock().unwrap().entries.is_empty());
        tcp.task.abort();
    }
    #[tokio::test]
    async fn request_evidence_is_bound_to_authority_ip_revision_and_deadline() {
        use pumgye_core::GuardEvidence;
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        let mut other_config = test_config("http://127.0.0.1:1".into());
        other_config.decision_tcp = Some(tcp.address.into());
        let other = GuardClient::start_with_token(
            other_config,
            "test-token-0123456789".into(),
            cancel.clone(),
        )
        .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        let (denied, proof) = guard.admission(ip, "/").await;
        assert!(denied.is_none());
        let proof = proof.unwrap();
        assert_eq!(
            proof.current(&guard, ip),
            Some(GuardEvidence::EnforcedAllow)
        );
        assert_eq!(
            tcp.requests.lock().unwrap().len(),
            1,
            "request evidence reuse must not issue another query"
        );
        assert!(
            proof
                .current(&guard, "192.0.2.9".parse().unwrap())
                .is_none()
        );
        assert!(proof.current(&other, ip).is_none());
        guard.cache.lock().unwrap().revision = Some(proof.revision + 1);
        assert!(proof.current(&guard, ip).is_none());
        guard.cache.lock().unwrap().revision = Some(proof.revision);
        let mut proof = proof;
        proof.ttl_ms = 0;
        assert!(proof.current(&guard, ip).is_none());
        cancel.cancel();
        tcp.task.abort();
    }
    #[tokio::test]
    async fn pumgye_fresh_evidence_ignores_cache_and_fail_open() {
        use pumgye_core::GuardEvidence;
        let tcp = tcp_server().await;
        let mut config = test_config("http://127.0.0.1:1".into());
        config.decision_tcp = Some(tcp.address.into());
        config.cache_ms = 5000;
        config.failure_mode = FailureMode::Allow;
        let cancel = CancellationToken::new();
        let guard =
            GuardClient::start_with_token(config, "test-token-0123456789".into(), cancel.clone())
                .unwrap();
        let ip = "192.0.2.8".parse().unwrap();
        assert_eq!(
            guard.authorization_evidence(ip).await,
            GuardEvidence::EnforcedAllow
        );
        tcp.response.lock().unwrap()[1] = 1;
        assert_eq!(guard.authorization_evidence(ip).await, GuardEvidence::Deny);
        {
            let mut response = tcp.response.lock().unwrap();
            response[1] = 0;
            response[2] = 0;
        }
        assert_eq!(
            guard.authorization_evidence(ip).await,
            GuardEvidence::Observe
        );
        assert_eq!(tcp.requests.lock().unwrap().len(), 3);
        tcp.delay_ms.store(5000, Ordering::Relaxed);
        assert_eq!(
            guard.authorization_evidence(ip).await,
            GuardEvidence::Unavailable
        );
        cancel.cancel();
        tcp.task.abort();
    }
}
