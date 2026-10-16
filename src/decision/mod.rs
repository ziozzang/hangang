//! Decision events (ADR 0019 phase D1): request-path capture, sampling,
//! bounded per-worker rings and the drain to the independent exporter.
//!
//! The request path only writes fixed-size fields into a stack `Capture`.
//! When decision events are off (the default) no `Emitter` exists, every
//! capture method returns immediately and nothing is allocated. When on, a
//! kept event is moved into a preallocated ring slot with `try_push`; a full
//! ring increments a drop counter and never waits. Pseudonymization, sealing,
//! protobuf encoding and I/O happen in the drain task.

pub mod broker;
pub mod drain;
pub mod keys;
pub mod sampling;

use crossbeam_queue::ArrayQueue;
use serde::Deserialize;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub use hangang_decision_event as schema;
use schema::v1;

/// Opaque subject IDs up to this size are carried inline; longer ones are
/// represented by their SHA-256 digest and never sealed.
pub const SUBJECT_INLINE: usize = schema::MAX_SEALED_SUBJECT_PLAINTEXT;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    #[default]
    Off,
    Strict,
    Standard,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Off => "off",
            Profile::Strict => "strict",
            Profile::Standard => "standard",
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    #[serde(default)]
    pub allow_sample_percent: Option<f64>,
    #[serde(default)]
    pub audit_all: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct BucketSettings {
    pub burst: u32,
    pub refill_per_second: f64,
    pub window_seconds: u64,
}

impl Default for BucketSettings {
    fn default() -> Self {
        Self {
            burst: 20,
            refill_per_second: 1.0,
            window_seconds: 60,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct RingSettings {
    pub deny_slots: usize,
    pub allow_slots: usize,
    /// Rings per kind; defaults to the number of available CPUs.
    pub shards: Option<usize>,
}

impl Default for RingSettings {
    fn default() -> Self {
        Self {
            deny_slots: 8192,
            allow_slots: 4096,
            shards: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields, default)]
pub struct BatchSettings {
    pub max_events: usize,
    pub interval_ms: u64,
}

impl Default for BatchSettings {
    fn default() -> Self {
        Self {
            max_events: schema::MAX_BATCH_EVENTS,
            interval_ms: 250,
        }
    }
}

fn default_rotation() -> u64 {
    24
}
fn default_retention() -> u64 {
    8 * 24
}
fn default_allow_percent() -> f64 {
    1.0
}
fn default_audit_classes() -> Vec<String> {
    vec!["restricted".into()]
}
fn default_bucket_slots() -> usize {
    4096
}

/// `--decision-events-config` document. Absent means `off`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub profile: Profile,
    #[serde(default)]
    pub instance: Option<String>,
    #[serde(default)]
    pub exporter_socket: Option<PathBuf>,
    #[serde(default)]
    pub query_socket: Option<PathBuf>,
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub manage_keys: bool,
    #[serde(default = "default_rotation")]
    pub key_rotation_hours: u64,
    /// Epoch keys are destroyed this long after their epoch ends. Set it to
    /// the exporter retention plus one epoch.
    #[serde(default = "default_retention")]
    pub key_retention_hours: u64,
    #[serde(default = "default_allow_percent")]
    pub allow_sample_percent: f64,
    #[serde(default = "default_audit_classes")]
    pub audit_all_classes: Vec<String>,
    #[serde(default)]
    pub routes: BTreeMap<String, RouteRule>,
    #[serde(default)]
    pub deny_bucket: BucketSettings,
    #[serde(default)]
    pub rings: RingSettings,
    #[serde(default)]
    pub batch: BatchSettings,
    #[serde(default = "default_bucket_slots")]
    pub bucket_slots: usize,
}

fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

fn percent_ppm(value: f64) -> anyhow::Result<u32> {
    anyhow::ensure!(
        value.is_finite() && (0.0..=100.0).contains(&value),
        "sample percent must be 0..100"
    );
    Ok((value * 10_000.0).round() as u32)
}

impl Config {
    pub fn from_file(path: &std::path::Path) -> anyhow::Result<Self> {
        let text = std::fs::read(path)?;
        anyhow::ensure!(
            text.len() <= 1024 * 1024,
            "decision events config too large"
        );
        let config: Self = serde_json::from_slice(&text)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        use anyhow::ensure;
        if self.profile == Profile::Off {
            return Ok(());
        }
        ensure!(
            self.exporter_socket.is_some(),
            "decision events require exporter_socket"
        );
        ensure!(self.key_file.is_some(), "decision events require key_file");
        let rotation = self.key_rotation_hours * 3600;
        ensure!(
            (keys::MIN_ROTATION_SECONDS..=keys::MAX_ROTATION_SECONDS).contains(&rotation),
            "key_rotation_hours must be 1..720"
        );
        let retention = self.key_retention_hours * 3600;
        ensure!(
            retention >= rotation && retention <= keys::MAX_RETENTION_SECONDS,
            "key_retention_hours must cover one epoch and at most 90 days plus one epoch"
        );
        percent_ppm(self.allow_sample_percent)?;
        for (id, rule) in &self.routes {
            ensure!(identifier(id, 128), "invalid decision route id");
            if let Some(percent) = rule.allow_sample_percent {
                percent_ppm(percent)?;
            }
        }
        ensure!(self.audit_all_classes.len() <= 64, "too many audit classes");
        ensure!(
            self.audit_all_classes.iter().all(|c| identifier(c, 64)),
            "invalid audit class"
        );
        if let Some(instance) = &self.instance {
            ensure!(identifier(instance, 64), "invalid decision instance name");
        }
        ensure!(
            (1..=65_536).contains(&self.rings.deny_slots)
                && (1..=65_536).contains(&self.rings.allow_slots),
            "ring slots must be 1..65536"
        );
        ensure!(
            self.rings.shards.is_none_or(|s| (1..=256).contains(&s)),
            "ring shards must be 1..256"
        );
        ensure!(
            (1..=schema::MAX_BATCH_EVENTS).contains(&self.batch.max_events)
                && (10..=5000).contains(&self.batch.interval_ms),
            "batch must be 1..512 events and 10..5000 ms"
        );
        let bucket = &self.deny_bucket;
        ensure!(
            (1..=10_000).contains(&bucket.burst)
                && bucket.refill_per_second.is_finite()
                && bucket.refill_per_second > 0.0
                && bucket.refill_per_second <= 10_000.0
                && (1..=3600).contains(&bucket.window_seconds),
            "invalid deny_bucket"
        );
        ensure!(
            (16..=1 << 20).contains(&self.bucket_slots),
            "bucket_slots must be 16..1048576"
        );
        Ok(())
    }
}

/// Stable reason codes emitted by Hangang. Every code is registered in
/// `hangang_decision_event::reasons` with EN/KO messages (contract test).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    NetworkDenied,
    NetworkUnavailable,
    AuthenticationRequired,
    AuthenticationRedirect,
    AuthenticationDenied,
    AuthenticationUnavailable,
    NativeContextUnavailable,
    Pumgye(Authorization),
    PumgyeMethodNotMapped,
    PumgyeIdentityMissing,
    Allowed,
    Redirected,
    IpBanned,
    UrlNotAllowlisted,
    RateLimited,
    RequestBlocked,
    ResourceNamespaceRefused,
    WorkloadDenied,
    JwtDenied,
    BasicDenied,
    ResourcePolicyDenied,
    ServiceScopeMismatch,
    NativePermissionDenied,
    NativeUnavailable,
    AuthorizationRetired,
    RouteAuthorizationUnavailable,
    UpstreamUnavailable,
    Refused,
    Error,
    Suppressed,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::NetworkDenied => "sumunjang.network_denied",
            Reason::NetworkUnavailable => "sumunjang.unavailable",
            Reason::AuthenticationRequired => "hopae.authentication_required",
            Reason::AuthenticationRedirect => "hopae.authentication_redirect",
            Reason::AuthenticationDenied => "hopae.authentication_denied",
            Reason::AuthenticationUnavailable => "hopae.unavailable",
            Reason::NativeContextUnavailable => "hopae.native_context_unavailable",
            Reason::Pumgye(decision) => decision.reason(),
            Reason::PumgyeMethodNotMapped => "pumgye.method_not_mapped",
            Reason::PumgyeIdentityMissing => "pumgye.identity_missing",
            Reason::Allowed => "hangang.allowed",
            Reason::Redirected => "hangang.redirected",
            Reason::IpBanned => "hangang.ip_banned",
            Reason::UrlNotAllowlisted => "hangang.url_not_allowlisted",
            Reason::RateLimited => "hangang.rate_limited",
            Reason::RequestBlocked => "hangang.request_blocked",
            Reason::ResourceNamespaceRefused => "hangang.resource_namespace_refused",
            Reason::WorkloadDenied => "hangang.workload_denied",
            Reason::JwtDenied => "hangang.jwt_denied",
            Reason::BasicDenied => "hangang.basic_denied",
            Reason::ResourcePolicyDenied => "hangang.resource_policy_denied",
            Reason::ServiceScopeMismatch => "hangang.service_scope_mismatch",
            Reason::NativePermissionDenied => "hangang.native_permission_denied",
            Reason::NativeUnavailable => "hangang.native_unavailable",
            Reason::AuthorizationRetired => "hangang.authorization_retired",
            Reason::RouteAuthorizationUnavailable => "hangang.route_authorization_unavailable",
            Reason::UpstreamUnavailable => "hangang.upstream_unavailable",
            Reason::Refused => "hangang.refused",
            Reason::Error => "hangang.error",
            Reason::Suppressed => "hangang.suppressed",
        }
    }

    fn class(self) -> schema::reasons::Class {
        schema::reasons::lookup(self.code())
            .map(|r| r.class)
            .unwrap_or(schema::reasons::Class::Error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Network,
    Identity,
    Authorization,
    Enforcement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkVerdict {
    Allow,
    Deny,
    Observe,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Local,
    Http,
    Hgd1,
    Hop1,
    Ppg1,
    Grpc,
    Snapshot,
}

impl Transport {
    fn wire(self) -> v1::Transport {
        match self {
            Transport::Local => v1::Transport::Local,
            Transport::Http => v1::Transport::Http,
            Transport::Hgd1 => v1::Transport::Hgd1,
            Transport::Hop1 => v1::Transport::Hop1,
            Transport::Ppg1 => v1::Transport::Ppg1,
            Transport::Grpc => v1::Transport::Grpc,
            Transport::Snapshot => v1::Transport::Snapshot,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Network {
    pub verdict: NetworkVerdict,
    pub enforce: bool,
    pub revision: Option<u64>,
    pub latency_us: u32,
    pub transport: Transport,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityAuthority {
    Hopae,
    Hangang,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityVerdict {
    Authenticated,
    Anonymous,
    Challenge,
    Denied,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Principal {
    Unknown,
    Human,
    Service,
    Workload,
}

impl Principal {
    pub fn parse(value: Option<&[u8]>) -> Self {
        match value {
            Some(b"human") => Principal::Human,
            Some(b"service") => Principal::Service,
            Some(b"workload") => Principal::Workload,
            _ => Principal::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactorKind {
    None,
    Password,
    Federated,
    Certificate,
    Bearer,
}

/// Fixed-capacity copy of an opaque subject ID.
#[derive(Clone, Copy)]
pub struct Subject {
    len: u16,
    hashed: bool,
    bytes: [u8; SUBJECT_INLINE],
}

impl Subject {
    pub fn new(value: &[u8]) -> Self {
        let mut bytes = [0u8; SUBJECT_INLINE];
        if value.len() <= SUBJECT_INLINE {
            bytes[..value.len()].copy_from_slice(value);
            Self {
                len: value.len() as u16,
                hashed: false,
                bytes,
            }
        } else {
            use sha2::Digest;
            bytes[..32].copy_from_slice(&sha2::Sha256::digest(value));
            Self {
                len: 32,
                hashed: true,
                bytes,
            }
        }
    }

    /// Bytes fed to the subject pseudonym (raw ID, or `sha256:` + digest for
    /// oversized IDs so forward lookup stays reproducible).
    pub fn pseudonym_input(&self, out: &mut Vec<u8>) {
        if self.hashed {
            out.extend_from_slice(b"sha256:");
        }
        out.extend_from_slice(&self.bytes[..self.len as usize]);
    }

    pub fn sealable(&self) -> Option<&[u8]> {
        (!self.hashed).then(|| &self.bytes[..self.len as usize])
    }
}

impl std::fmt::Debug for Subject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Subject(..)")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Identity {
    pub authority: IdentityAuthority,
    pub verdict: IdentityVerdict,
    pub principal: Principal,
    pub aal: Option<u8>,
    pub factor: FactorKind,
    pub subject: Option<Subject>,
    pub latency_us: u32,
    pub transport: Transport,
}

/// Exact `pumgye_core::Decision` plus resource lookup and transport outcomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authorization {
    Allow,
    UnknownService,
    Guest,
    NetworkGuest,
    PermissionDenied,
    ClassDenied,
    AssuranceDenied,
    GuardDenied,
    GuardUnavailable,
    UnknownResource,
    UnknownAction,
    Unavailable,
    NotMapped,
}

impl Authorization {
    pub fn from_decision(decision: pumgye_core::Decision) -> Self {
        use pumgye_core::Decision as D;
        match decision {
            D::Allow => Self::Allow,
            D::UnknownService => Self::UnknownService,
            D::Guest => Self::Guest,
            D::NetworkGuest => Self::NetworkGuest,
            D::PermissionDenied => Self::PermissionDenied,
            D::ClassDenied => Self::ClassDenied,
            D::AssuranceDenied => Self::AssuranceDenied,
            D::GuardDenied => Self::GuardDenied,
            D::GuardUnavailable => Self::GuardUnavailable,
        }
    }

    pub fn from_resource(decision: pumgye_core::ResourceDecision) -> Self {
        match decision {
            pumgye_core::ResourceDecision::UnknownResource => Self::UnknownResource,
            pumgye_core::ResourceDecision::UnknownAction => Self::UnknownAction,
            pumgye_core::ResourceDecision::Decided(d) => Self::from_decision(d),
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::Allow => "hangang.allowed",
            Self::UnknownService => "pumgye.unknown_service",
            Self::Guest => "pumgye.guest",
            Self::NetworkGuest => "pumgye.network_guest",
            Self::PermissionDenied => "pumgye.permission_denied",
            Self::ClassDenied => "pumgye.class_denied",
            Self::AssuranceDenied => "pumgye.assurance_denied",
            Self::GuardDenied => "pumgye.guard_denied",
            Self::GuardUnavailable => "pumgye.guard_unavailable",
            Self::UnknownResource => "pumgye.unknown_resource",
            Self::UnknownAction => "pumgye.unknown_action",
            Self::Unavailable => "pumgye.unavailable",
            Self::NotMapped => "pumgye.method_not_mapped",
        }
    }

    fn wire(self) -> v1::AuthorizationDecision {
        use v1::AuthorizationDecision as W;
        match self {
            Self::Allow => W::Allow,
            Self::UnknownService => W::UnknownService,
            Self::Guest => W::Guest,
            Self::NetworkGuest => W::NetworkGuest,
            Self::PermissionDenied => W::PermissionDenied,
            Self::ClassDenied => W::ClassDenied,
            Self::AssuranceDenied => W::AssuranceDenied,
            Self::GuardDenied => W::GuardDenied,
            Self::GuardUnavailable => W::GuardUnavailable,
            Self::UnknownResource => W::UnknownResource,
            Self::UnknownAction => W::UnknownAction,
            Self::Unavailable => W::Unavailable,
            Self::NotMapped => W::NotMapped,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AuthorizationStage {
    pub decision: Authorization,
    pub revision: Option<u64>,
    pub latency_us: u32,
    pub transport: Transport,
}

/// Result of a remote Pumgye decision with its exact variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decided {
    pub decision: Authorization,
    pub revision: Option<u64>,
}

impl Decided {
    pub fn allowed_revision(self) -> Option<u64> {
        (self.decision == Authorization::Allow)
            .then_some(self.revision)
            .flatten()
    }
}

fn method_code(method: &hyper::Method) -> &'static str {
    match *method {
        hyper::Method::GET => "GET",
        hyper::Method::HEAD => "HEAD",
        hyper::Method::POST => "POST",
        hyper::Method::PUT => "PUT",
        hyper::Method::PATCH => "PATCH",
        hyper::Method::DELETE => "DELETE",
        hyper::Method::OPTIONS => "OPTIONS",
        hyper::Method::CONNECT => "CONNECT",
        hyper::Method::TRACE => "TRACE",
        _ => "",
    }
}

/// Per-request stage record. Lives on the request's stack; every writer is a
/// no-op unless the capture is active.
pub struct Capture {
    active: bool,
    request_id: u64,
    time_ms: u64,
    method: &'static str,
    client_ip: Option<IpAddr>,
    country: [u8; 2],
    route: Option<Arc<crate::config::HttpRuntime>>,
    protected: bool,
    network: Option<Network>,
    identity: Option<Identity>,
    authorization: Option<AuthorizationStage>,
    refusal: Option<(Stage, Reason)>,
    forwarded: bool,
    hangang_revision: u64,
}

impl Capture {
    /// Inactive capture: the only path taken when decision events are off.
    #[inline]
    pub const fn disabled() -> Self {
        Self {
            active: false,
            request_id: 0,
            time_ms: 0,
            method: "",
            client_ip: None,
            country: [0; 2],
            route: None,
            protected: false,
            network: None,
            identity: None,
            authorization: None,
            refusal: None,
            forwarded: false,
            hangang_revision: 0,
        }
    }

    #[inline]
    pub fn active(&self) -> bool {
        self.active
    }

    pub fn request_id(&self) -> Option<u64> {
        self.active.then_some(self.request_id)
    }

    /// Monotonic start for a stage latency, only when active.
    #[inline]
    pub fn clock(&self) -> Option<Instant> {
        self.active.then(Instant::now)
    }

    #[inline]
    pub fn client(&mut self, ip: IpAddr) {
        if self.active {
            self.client_ip = Some(ip.to_canonical());
        }
    }

    #[inline]
    pub fn country(&mut self, country: Option<&str>) {
        if self.active
            && let Some(code) = country.map(str::as_bytes)
            && code.len() == 2
            && code.iter().all(u8::is_ascii_uppercase)
        {
            self.country = [code[0], code[1]];
        }
    }

    #[inline]
    pub fn route(&mut self, runtime: &Arc<crate::config::HttpRuntime>) {
        if !self.active {
            return;
        }
        let route = &runtime.route;
        self.protected = route.auth.is_some()
            || route.jwt_auth.is_some()
            || route.basic_auth.is_some()
            || route.workload_auth.is_some()
            || runtime.native_resource.is_some()
            || route.resource_policy.as_ref().is_some_and(|p| p.enforce)
            || route.access_mode == crate::config::AccessMode::Protected;
        self.route = Some(runtime.clone());
    }

    #[inline]
    pub fn network(&mut self, network: Network) {
        if self.active {
            self.network = Some(network);
        }
    }

    #[inline]
    pub fn identity(&mut self, identity: Identity) {
        if self.active {
            self.identity = Some(identity);
        }
    }

    #[inline]
    pub fn authorization(
        &mut self,
        decision: Authorization,
        revision: Option<u64>,
        started: Option<Instant>,
        transport: Transport,
    ) {
        if self.active {
            self.authorization = Some(AuthorizationStage {
                decision,
                revision,
                latency_us: elapsed_us(started),
                transport,
            });
        }
    }

    pub fn authorization_decision(&self) -> Option<Authorization> {
        self.authorization.map(|a| a.decision)
    }

    /// Records the deciding refusal; the first one wins.
    #[inline]
    pub fn refuse(&mut self, stage: Stage, reason: Reason) {
        if self.active && self.refusal.is_none() {
            self.refusal = Some((stage, reason));
        }
    }

    #[inline]
    pub fn forwarded(&mut self) {
        if self.active {
            self.forwarded = true;
        }
    }

    /// True when any authority was consulted or the gateway refused for an
    /// access reason: only such requests are decision events.
    fn candidate(&self) -> bool {
        self.protected
            || self.identity.is_some()
            || self.authorization.is_some()
            || self.refusal.is_some()
            || self
                .network
                .is_some_and(|n| n.verdict != NetworkVerdict::Allow)
    }
}

pub fn elapsed_us(started: Option<Instant>) -> u32 {
    started.map_or(0, |s| {
        s.elapsed().as_micros().min(u128::from(u32::MAX)) as u32
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    Allow,
    Deny,
    Challenge,
    Error,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SampleClass {
    Deny,
    Challenge,
    Error,
    Unavailable,
    Allow,
    Audit,
    Suppressed,
}

/// One kept event awaiting the drain.
pub struct Record {
    pub capture: Capture,
    pub outcome: OutcomeKind,
    pub status: u16,
    pub deciding: Stage,
    pub reason: Reason,
    pub class: SampleClass,
    pub rate_ppm: u32,
    pub suppressed: Option<sampling::Summary>,
}

/// Per-shard bounded rings; separate deny and allow rings so an allow flood
/// can never evict denies.
pub struct Rings {
    deny: Box<[ArrayQueue<Record>]>,
    allow: Box<[ArrayQueue<Record>]>,
}

static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);
thread_local! {
    static SHARD: Cell<usize> = const { Cell::new(usize::MAX) };
}

fn shard_index(shards: usize) -> usize {
    SHARD.with(|cell| {
        let mut value = cell.get();
        if value == usize::MAX {
            value = NEXT_SHARD.fetch_add(1, Ordering::Relaxed);
            cell.set(value);
        }
        value % shards
    })
}

impl Rings {
    pub fn new(shards: usize, deny_slots: usize, allow_slots: usize) -> Self {
        Self {
            deny: (0..shards).map(|_| ArrayQueue::new(deny_slots)).collect(),
            allow: (0..shards).map(|_| ArrayQueue::new(allow_slots)).collect(),
        }
    }

    pub fn shards(&self) -> usize {
        self.deny.len()
    }

    /// Never blocks; a record that does not fit is dropped here.
    fn try_push(&self, record: Record) -> bool {
        let deny = record.class != SampleClass::Allow && record.class != SampleClass::Audit;
        let rings = if deny { &self.deny } else { &self.allow };
        rings[shard_index(rings.len())].push(record).is_ok()
    }

    /// Drains up to `max` records, denies first, round-robin over shards.
    pub fn pop_batch(&self, max: usize, out: &mut Vec<Record>) {
        for rings in [&self.deny, &self.allow] {
            let mut progress = true;
            while progress && out.len() < max {
                progress = false;
                for ring in rings.iter() {
                    if out.len() >= max {
                        break;
                    }
                    if let Some(record) = ring.pop() {
                        out.push(record);
                        progress = true;
                    }
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.deny
            .iter()
            .chain(self.allow.iter())
            .map(ArrayQueue::len)
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> (usize, usize) {
        (
            self.deny.iter().map(ArrayQueue::capacity).sum(),
            self.allow.iter().map(ArrayQueue::capacity).sum(),
        )
    }
}

#[derive(Default)]
pub struct Counters {
    pub captured: AtomicU64,
    pub kept_deny: AtomicU64,
    pub kept_allow: AtomicU64,
    pub sampled_out: AtomicU64,
    pub suppressed: AtomicU64,
    pub summaries: AtomicU64,
    pub dropped_ring_deny: AtomicU64,
    pub dropped_ring_allow: AtomicU64,
    pub dropped_exporter: AtomicU64,
    pub dropped_no_key: AtomicU64,
    pub dropped_invalid: AtomicU64,
    pub exported: AtomicU64,
    pub batches: AtomicU64,
    pub export_errors: AtomicU64,
}

pub struct Emitter {
    pub config: Config,
    pub rings: Rings,
    pub buckets: sampling::Buckets,
    pub keys: arc_swap::ArcSwap<keys::KeyRing>,
    pub counters: Counters,
    pub exporter_connected: AtomicBool,
    allow_ppm: u32,
    routes: HashMap<String, (u32, bool)>,
    id_seed: u64,
    id_counter: AtomicU64,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Emitter {
    /// `None` for the `off` profile: nothing is constructed or captured.
    pub fn new(config: Config) -> anyhow::Result<Option<Arc<Self>>> {
        config.validate()?;
        if config.profile == Profile::Off {
            return Ok(None);
        }
        let rotation = config.key_rotation_hours * 3600;
        let keys = keys::KeyRing::load(
            config.key_file.as_deref().expect("validated key file"),
            rotation,
        )?;
        let shards = config.rings.shards.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(usize::from)
                .unwrap_or(4)
                .min(64)
        });
        let mut seed = [0u8; 8];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut seed)
            .map_err(|_| anyhow::anyhow!("secure random unavailable"))?;
        let routes = config
            .routes
            .iter()
            .map(|(id, rule)| {
                let ppm = if rule.audit_all {
                    sampling::PPM
                } else {
                    rule.allow_sample_percent
                        .map(|p| percent_ppm(p).expect("validated"))
                        .unwrap_or_else(|| {
                            percent_ppm(config.allow_sample_percent).expect("validated")
                        })
                };
                (id.clone(), (ppm, rule.audit_all))
            })
            .collect();
        Ok(Some(Arc::new(Self {
            allow_ppm: percent_ppm(config.allow_sample_percent)?,
            rings: Rings::new(shards, config.rings.deny_slots, config.rings.allow_slots),
            buckets: sampling::Buckets::new(
                sampling::BucketConfig {
                    burst: config.deny_bucket.burst,
                    refill_per_second: config.deny_bucket.refill_per_second,
                    window_ms: config.deny_bucket.window_seconds * 1000,
                },
                config.bucket_slots,
            ),
            keys: arc_swap::ArcSwap::from_pointee(keys),
            counters: Counters::default(),
            exporter_connected: AtomicBool::new(false),
            routes,
            id_seed: u64::from_le_bytes(seed),
            id_counter: AtomicU64::new(0),
            config,
        })))
    }

    pub fn profile(&self) -> Profile {
        self.config.profile
    }

    /// Starts an active capture for one request.
    #[inline]
    pub fn capture(&self, method: &hyper::Method, hangang_revision: u64) -> Capture {
        let counter = self.id_counter.fetch_add(1, Ordering::Relaxed);
        Capture {
            active: true,
            request_id: sampling::mix(counter ^ self.id_seed),
            time_ms: now_ms(),
            method: method_code(method),
            hangang_revision,
            ..Capture::disabled()
        }
    }

    fn allow_rate(&self, capture: &Capture) -> (u32, bool) {
        let Some(runtime) = &capture.route else {
            return (self.allow_ppm, false);
        };
        if let Some(rule) = self.routes.get(runtime.route.id.as_str()) {
            return *rule;
        }
        let class = runtime
            .route
            .resource_policy
            .as_ref()
            .and_then(|p| p.pumgye.as_ref())
            .map(|g| g.information_class.as_str());
        if class.is_some_and(|c| self.config.audit_all_classes.iter().any(|a| a == c)) {
            return (sampling::PPM, true);
        }
        (self.allow_ppm, false)
    }

    fn outcome(capture: &Capture, status: u16) -> (OutcomeKind, Stage, Reason) {
        use schema::reasons::Class;
        if let Some((stage, reason)) = capture.refusal {
            let kind = match reason.class() {
                Class::Allow => OutcomeKind::Allow,
                Class::Deny => OutcomeKind::Deny,
                Class::Challenge => OutcomeKind::Challenge,
                Class::Error => OutcomeKind::Error,
                Class::Unavailable => OutcomeKind::Unavailable,
            };
            return (kind, stage, reason);
        }
        if capture.forwarded {
            return (OutcomeKind::Allow, Stage::Enforcement, Reason::Allowed);
        }
        match status {
            300..=399 => (OutcomeKind::Allow, Stage::Enforcement, Reason::Redirected),
            0..=399 => (OutcomeKind::Allow, Stage::Enforcement, Reason::Allowed),
            401 | 403 | 429 => (OutcomeKind::Deny, Stage::Enforcement, Reason::Refused),
            _ => (OutcomeKind::Error, Stage::Enforcement, Reason::Error),
        }
    }

    fn push(&self, record: Record) {
        let deny = record.class != SampleClass::Allow && record.class != SampleClass::Audit;
        let counter = match (self.rings.try_push(record), deny) {
            (true, true) => &self.counters.kept_deny,
            (true, false) => &self.counters.kept_allow,
            (false, true) => &self.counters.dropped_ring_deny,
            (false, false) => &self.counters.dropped_ring_allow,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn summary_record(&self, summary: sampling::Summary) -> Record {
        let mut capture = Capture {
            active: true,
            time_ms: summary.last_ms,
            client_ip: summary.prefix,
            route: summary.route.clone(),
            ..Capture::disabled()
        };
        // A summary has no single request; its ID is derived from the key.
        let counter = self.id_counter.fetch_add(1, Ordering::Relaxed);
        capture.request_id = sampling::mix(counter ^ self.id_seed);
        self.counters.summaries.fetch_add(1, Ordering::Relaxed);
        Record {
            capture,
            outcome: OutcomeKind::Deny,
            status: 0,
            deciding: Stage::Enforcement,
            reason: Reason::Suppressed,
            class: SampleClass::Suppressed,
            rate_ppm: sampling::PPM,
            suppressed: Some(summary),
        }
    }

    /// Request-path completion: sampling, bucket admission and `try_push`.
    /// Never blocks, never performs I/O, allocates nothing.
    #[inline]
    pub fn finish(&self, capture: Capture, status: u16) {
        if !capture.active || !capture.candidate() {
            return;
        }
        self.counters.captured.fetch_add(1, Ordering::Relaxed);
        let (outcome, deciding, reason) = Self::outcome(&capture, status);
        let (class, rate_ppm) = match outcome {
            OutcomeKind::Allow => {
                let (ppm, audit) = self.allow_rate(&capture);
                if !sampling::keep(capture.request_id, ppm) {
                    self.counters.sampled_out.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                (
                    if audit {
                        SampleClass::Audit
                    } else {
                        SampleClass::Allow
                    },
                    ppm,
                )
            }
            other => {
                let class = match other {
                    OutcomeKind::Deny => SampleClass::Deny,
                    OutcomeKind::Challenge => SampleClass::Challenge,
                    OutcomeKind::Error => SampleClass::Error,
                    _ => SampleClass::Unavailable,
                };
                match self
                    .buckets
                    .admit(capture.route.as_ref(), capture.client_ip, capture.time_ms)
                {
                    sampling::Admission::Keep(summary) => {
                        if let Some(summary) = summary {
                            self.push(self.summary_record(summary));
                        }
                        (class, sampling::PPM)
                    }
                    sampling::Admission::Suppress(summary) => {
                        self.counters.suppressed.fetch_add(1, Ordering::Relaxed);
                        if let Some(summary) = summary {
                            self.push(self.summary_record(summary));
                        }
                        return;
                    }
                }
            }
        };
        self.push(Record {
            capture,
            outcome,
            status,
            deciding,
            reason,
            class,
            rate_ppm,
            suppressed: None,
        });
    }

    pub fn status(&self) -> serde_json::Value {
        let c = &self.counters;
        let load = |v: &AtomicU64| v.load(Ordering::Relaxed);
        let keys = self.keys.load();
        let current = keys.epoch_index(now_ms());
        let (deny_slots, allow_slots) = self.rings.capacity();
        serde_json::json!({
            "state": "enabled",
            "profile": self.profile().as_str(),
            "exporter": {"connected": self.exporter_connected.load(Ordering::Relaxed)},
            "rings": {
                "shards": self.rings.shards(),
                "deny_slots": deny_slots,
                "allow_slots": allow_slots,
                "queued": self.rings.len(),
                "record_bytes": std::mem::size_of::<Record>(),
            },
            "sampling": {
                "allow_percent": self.config.allow_sample_percent,
                "audit_all_classes": self.config.audit_all_classes,
                "deny_bucket": {
                    "burst": self.config.deny_bucket.burst,
                    "refill_per_second": self.config.deny_bucket.refill_per_second,
                    "window_seconds": self.config.deny_bucket.window_seconds,
                },
            },
            "keys": {
                "rotation_hours": self.config.key_rotation_hours,
                "retention_hours": self.config.key_retention_hours,
                "managed": self.config.manage_keys,
                "epochs": keys.epochs().count(),
                "current_epoch": keys.label(current),
                "current_key_present": keys.has_epoch(current),
            },
            "counters": {
                "captured": load(&c.captured),
                "kept_deny": load(&c.kept_deny),
                "kept_allow": load(&c.kept_allow),
                "sampled_out": load(&c.sampled_out),
                "suppressed": load(&c.suppressed),
                "summaries": load(&c.summaries),
                "dropped": {
                    "ring_full_deny": load(&c.dropped_ring_deny),
                    "ring_full_allow": load(&c.dropped_ring_allow),
                    "exporter_unavailable": load(&c.dropped_exporter),
                    "no_key": load(&c.dropped_no_key),
                    "invalid": load(&c.dropped_invalid),
                },
                "exported": load(&c.exported),
                "batches": load(&c.batches),
                "export_errors": load(&c.export_errors),
            },
        })
    }

    /// Low-cardinality Prometheus series (no pseudonym in any label).
    pub fn render_metrics(&self, out: &mut String) {
        let c = &self.counters;
        let load = |v: &AtomicU64| v.load(Ordering::Relaxed);
        out.push_str("# HELP hangang_decision_events_dropped_total Decision events dropped before storage.\n# TYPE hangang_decision_events_dropped_total counter\n");
        for (class, reason, value) in [
            ("deny", "ring_full", load(&c.dropped_ring_deny)),
            ("allow", "ring_full", load(&c.dropped_ring_allow)),
            ("any", "exporter_unavailable", load(&c.dropped_exporter)),
            ("any", "no_key", load(&c.dropped_no_key)),
            ("any", "invalid", load(&c.dropped_invalid)),
        ] {
            out.push_str(&format!(
                "hangang_decision_events_dropped_total{{class=\"{class}\",reason=\"{reason}\"}} {value}\n"
            ));
        }
        for (name, help, value) in [
            (
                "captured_total",
                "Protected decisions captured.",
                load(&c.captured),
            ),
            (
                "kept_total{class=\"deny\"}",
                "Decision events kept.",
                load(&c.kept_deny),
            ),
            (
                "kept_total{class=\"allow\"}",
                "Decision events kept.",
                load(&c.kept_allow),
            ),
            (
                "sampled_out_total",
                "Allow decisions not sampled.",
                load(&c.sampled_out),
            ),
            (
                "suppressed_total",
                "Deny decisions suppressed by the token bucket.",
                load(&c.suppressed),
            ),
            (
                "summaries_total",
                "Suppressed summary events.",
                load(&c.summaries),
            ),
            (
                "exported_total",
                "Decision events written to the exporter.",
                load(&c.exported),
            ),
            (
                "export_errors_total",
                "Exporter connection or write failures.",
                load(&c.export_errors),
            ),
        ] {
            let base = name.split('{').next().unwrap_or(name);
            if !name.contains("class=\"allow\"") {
                out.push_str(&format!(
                    "# HELP hangang_decision_events_{base} {help}\n# TYPE hangang_decision_events_{base} counter\n"
                ));
            }
            out.push_str(&format!("hangang_decision_events_{name} {value}\n"));
        }
        out.push_str(&format!(
            "# HELP hangang_decision_events_queued Decision events waiting in rings.\n# TYPE hangang_decision_events_queued gauge\nhangang_decision_events_queued {}\n# HELP hangang_decision_exporter_connected Exporter connection state.\n# TYPE hangang_decision_exporter_connected gauge\nhangang_decision_exporter_connected {}\n",
            self.rings.len(),
            u8::from(self.exporter_connected.load(Ordering::Relaxed))
        ));
    }
}

#[cfg(test)]
mod tests;
