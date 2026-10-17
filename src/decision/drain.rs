//! Drain task: pseudonymizes, seals, encodes and ships kept records to the
//! exporter. Runs off the request path. There is no disk spool and no retry:
//! a batch that cannot be written is counted as dropped.

use super::keys::KeyRing;
use super::{
    Capture, Emitter, FactorKind, IdentityAuthority, IdentityVerdict, NetworkVerdict, OutcomeKind,
    Principal, Profile, Reason, Record, SampleClass, Stage, schema,
};
use prost::Message;
use ring::rand::{SecureRandom, SystemRandom};
use schema::v1::{self, stage_verdict};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixStream;

pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const KEY_CHECK: Duration = Duration::from_secs(10);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dropped {
    NoKey,
    Invalid,
}

pub struct Context<'a> {
    pub keys: &'a KeyRing,
    pub profile: Profile,
    pub instance: &'a str,
    pub build: &'a str,
    pub rng: &'a SystemRandom,
}

fn text(value: &str, valid: impl Fn(&str) -> bool) -> String {
    if valid(value) {
        value.to_owned()
    } else {
        String::new()
    }
}

fn ident(value: &str) -> String {
    text(value, |v| schema::identifier(v, 128))
}

fn route(capture: &Capture) -> v1::Route {
    let mut route = v1::Route {
        method: capture.method.to_owned(),
        ..Default::default()
    };
    let Some(runtime) = &capture.route else {
        return route;
    };
    let config = &runtime.route;
    route.route_id = ident(&config.id);
    route.listener = config
        .listener_ids
        .first()
        .map(|l| ident(l))
        .unwrap_or_default();
    route.host = config
        .host
        .as_deref()
        .or(config.hosts.first().map(String::as_str))
        .map(|h| text(&h.to_ascii_lowercase(), schema::host))
        .unwrap_or_default();
    route.path_template = config
        .path_prefix
        .as_deref()
        .map(|p| text(p, schema::path_template))
        .unwrap_or_default();
    if let Some(policy) = &config.resource_policy {
        if let Some(gate) = &policy.pumgye_resource {
            route.service = ident(&gate.service_id);
            route.resource = ident(&gate.resource);
            route.action = gate
                .actions
                .get(capture.method)
                .map(|a| ident(a))
                .unwrap_or_default();
        } else if let Some(gate) = &policy.pumgye {
            route.service = ident(&gate.service_id);
            route.resource = ident(&policy.resource_id);
            if let Some([permission]) = gate.permissions.get(capture.method).map(Vec::as_slice) {
                route.action = ident(permission);
            }
        } else {
            route.resource = ident(&policy.resource_id);
        }
    }
    route
}

fn information_class(capture: &Capture) -> String {
    capture
        .route
        .as_ref()
        .and_then(|r| r.route.resource_policy.as_ref())
        .and_then(|p| p.pumgye.as_ref())
        .map(|g| text(&g.information_class, |v| schema::identifier(v, 64)))
        .unwrap_or_default()
}

/// Builds and encodes one `hangang.decision.v1` event (≤2 KiB, validated).
pub fn encode(record: &Record, cx: &Context<'_>) -> Result<Vec<u8>, Dropped> {
    let capture = &record.capture;
    let epoch = cx.keys.epoch_index(capture.time_ms);
    if !cx.keys.has_epoch(epoch) {
        return Err(Dropped::NoKey);
    }
    let mut random = [0u8; 10];
    cx.rng.fill(&mut random).map_err(|_| Dropped::Invalid)?;
    let event_id = schema::event_id(capture.time_ms, random);
    let standard = cx.profile == Profile::Standard;
    let mut stages = Vec::with_capacity(4);
    let mut revisions = v1::Revisions {
        hangang: (capture.hangang_revision > 0).then_some(capture.hangang_revision),
        ..Default::default()
    };

    if capture.network.is_some() || capture.client_ip.is_some() {
        let mut stage = v1::NetworkStage::default();
        if let Some(network) = capture.network {
            stage.verdict = match network.verdict {
                NetworkVerdict::Allow => v1::NetworkVerdict::Allow,
                NetworkVerdict::Deny => v1::NetworkVerdict::Deny,
                NetworkVerdict::Observe => v1::NetworkVerdict::Observe,
                NetworkVerdict::Unavailable => v1::NetworkVerdict::Unavailable,
            } as i32;
            stage.mode = if network.enforce {
                v1::GuardMode::Enforce
            } else {
                v1::GuardMode::Observe
            } as i32;
            stage.revision = network.revision;
            stage.latency_us = network.latency_us;
            stage.transport = network.transport.wire() as i32;
            revisions.sumunjang = network.revision;
        }
        if let Some(ip) = capture.client_ip {
            stage.prefix_ref = cx.keys.prefix_ref(epoch, ip).ok_or(Dropped::NoKey)?;
            // A suppressed summary is keyed by prefix only.
            if record.suppressed.is_none() {
                stage.ip_ref = cx.keys.ip_ref(epoch, ip).ok_or(Dropped::NoKey)?;
                if standard {
                    let (bytes, len) = super::keys::ip_bytes(ip);
                    stage.sealed_ip = cx
                        .keys
                        .seal(epoch, &event_id, b"ip", &bytes[..len], cx.rng)
                        .ok_or(Dropped::NoKey)?;
                }
            }
        }
        if capture.country != [0; 2] {
            stage.country = String::from_utf8_lossy(&capture.country).into_owned();
        }
        stages.push(v1::StageVerdict {
            stage: Some(stage_verdict::Stage::Network(stage)),
        });
    }

    if let Some(identity) = capture.identity {
        let mut stage = v1::IdentityStage {
            authority: match identity.authority {
                IdentityAuthority::Hopae => v1::Authority::Hopae,
                IdentityAuthority::Hangang => v1::Authority::Hangang,
            } as i32,
            verdict: match identity.verdict {
                IdentityVerdict::Authenticated => v1::IdentityVerdict::Authenticated,
                IdentityVerdict::Anonymous => v1::IdentityVerdict::Anonymous,
                IdentityVerdict::Challenge => v1::IdentityVerdict::Challenge,
                IdentityVerdict::Denied => v1::IdentityVerdict::Denied,
                IdentityVerdict::Unavailable => v1::IdentityVerdict::Unavailable,
            } as i32,
            principal: match identity.principal {
                Principal::Unknown => v1::PrincipalKind::Unspecified,
                Principal::Human => v1::PrincipalKind::Human,
                Principal::Service => v1::PrincipalKind::Service,
                Principal::Workload => v1::PrincipalKind::Workload,
            } as i32,
            aal: identity.aal.filter(|a| *a <= 3).map(u32::from),
            latency_us: identity.latency_us,
            transport: identity.transport.wire() as i32,
            risk_level: match identity.risk {
                None => v1::RiskLevel::Unspecified,
                Some(crate::risk_context::Level::Low) => v1::RiskLevel::Low,
                Some(crate::risk_context::Level::Elevated) => v1::RiskLevel::Elevated,
                Some(crate::risk_context::Level::High) => v1::RiskLevel::High,
            } as i32,
            ..Default::default()
        };
        let factor = match identity.factor {
            FactorKind::None => None,
            FactorKind::Password => Some(v1::Factor::Password),
            FactorKind::Federated => Some(v1::Factor::Federated),
            FactorKind::Certificate => Some(v1::Factor::Certificate),
            FactorKind::Bearer => Some(v1::Factor::Bearer),
        };
        stage.factors.extend(factor.map(|f| f as i32));
        if let Some(subject) = &identity.subject {
            let mut input = Vec::with_capacity(160);
            subject.pseudonym_input(&mut input);
            stage.subject_ref = cx.keys.subject_ref(epoch, &input).ok_or(Dropped::NoKey)?;
            if standard && let Some(plain) = subject.sealable() {
                stage.sealed_subject = cx
                    .keys
                    .seal(epoch, &event_id, b"sub", plain, cx.rng)
                    .ok_or(Dropped::NoKey)?;
            }
        }
        stages.push(v1::StageVerdict {
            stage: Some(stage_verdict::Stage::Identity(stage)),
        });
    }

    if let Some(authorization) = capture.authorization {
        revisions.pumgye = authorization.revision;
        stages.push(v1::StageVerdict {
            stage: Some(stage_verdict::Stage::Authorization(
                v1::AuthorizationStage {
                    decision: authorization.decision.wire() as i32,
                    information_class: information_class(capture),
                    revision: authorization.revision,
                    latency_us: authorization.latency_us,
                    transport: authorization.transport.wire() as i32,
                    ..Default::default()
                },
            )),
        });
    }

    let action = if capture.forwarded {
        v1::EnforcementAction::Forwarded
    } else if record.reason == Reason::Redirected {
        v1::EnforcementAction::Redirected
    } else if record.outcome == OutcomeKind::Challenge {
        v1::EnforcementAction::Challenged
    } else if record.outcome == OutcomeKind::Allow {
        v1::EnforcementAction::Unspecified
    } else {
        v1::EnforcementAction::Refused
    };
    stages.push(v1::StageVerdict {
        stage: Some(stage_verdict::Stage::Enforcement(v1::EnforcementStage {
            action: action as i32,
            fence: if record.reason == Reason::AuthorizationRetired {
                v1::Fence::StaleOwner
            } else if capture.forwarded {
                v1::Fence::Ok
            } else {
                v1::Fence::Unspecified
            } as i32,
            revision: revisions.hangang,
            upstream_status_class: if capture.forwarded && (100..600).contains(&record.status) {
                u32::from(record.status / 100)
            } else {
                0
            },
            ..Default::default()
        })),
    });

    let event = v1::DecisionEvent {
        schema: schema::SCHEMA.into(),
        event_id: event_id.to_vec(),
        kind: v1::Kind::Enforced as i32,
        request_id: format!("hg-{:016x}", capture.request_id),
        time_unix_ms: capture.time_ms,
        emitter: Some(v1::Emitter {
            component: "hangang".into(),
            instance: cx.instance.to_owned(),
            build: text(cx.build, |v| schema::identifier(v, 32)),
        }),
        route: Some(route(capture)),
        outcome: Some(v1::Outcome {
            result: match record.outcome {
                OutcomeKind::Allow => v1::Result::Allow,
                OutcomeKind::Deny => v1::Result::Deny,
                OutcomeKind::Challenge => v1::Result::Challenge,
                OutcomeKind::Error => v1::Result::Error,
                OutcomeKind::Unavailable => v1::Result::Unavailable,
            } as i32,
            status: u32::from(record.status),
            deciding_stage: match record.deciding {
                Stage::Network => v1::Stage::Network,
                Stage::Identity => v1::Stage::Identity,
                Stage::Authorization => v1::Stage::Authorization,
                Stage::Enforcement => v1::Stage::Enforcement,
            } as i32,
            reason: record.reason.code().to_owned(),
        }),
        stages,
        revisions: Some(revisions),
        sampling: Some(v1::Sampling {
            class: match record.class {
                SampleClass::Deny => v1::SampleClass::Deny,
                SampleClass::Challenge => v1::SampleClass::Challenge,
                SampleClass::Error => v1::SampleClass::Error,
                SampleClass::Unavailable => v1::SampleClass::Unavailable,
                SampleClass::Allow => v1::SampleClass::Allow,
                SampleClass::Audit => v1::SampleClass::Audit,
                SampleClass::Suppressed => v1::SampleClass::Suppressed,
            } as i32,
            rate_ppm: record.rate_ppm,
        }),
        privacy: Some(v1::Privacy {
            profile: match cx.profile {
                Profile::Standard => v1::PrivacyProfile::Standard,
                _ => v1::PrivacyProfile::Strict,
            } as i32,
            key_epoch: cx.keys.label(epoch),
        }),
        suppressed: record.suppressed.as_ref().map(|s| v1::Suppressed {
            count: s.count,
            first_unix_ms: s.first_ms,
            last_unix_ms: s.last_ms,
            window_seconds: (s.window_ms / 1000).max(1) as u32,
        }),
    };
    schema::validate(&event).map_err(|_| Dropped::Invalid)?;
    Ok(event.encode_to_vec())
}

/// Key maintenance (owner) or reload (replica).
pub struct KeyKeeper {
    last_check: Option<Instant>,
    modified: Option<std::time::SystemTime>,
    warned: bool,
}

impl Default for KeyKeeper {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyKeeper {
    pub fn new() -> Self {
        Self {
            last_check: None,
            modified: None,
            warned: false,
        }
    }

    pub fn tick(&mut self, emitter: &Emitter, rng: &SystemRandom, force: bool) {
        if !force && self.last_check.is_some_and(|t| t.elapsed() < KEY_CHECK) {
            return;
        }
        self.last_check = Some(Instant::now());
        let path = emitter.config.key_file.as_deref().expect("validated");
        let rotation = emitter.config.key_rotation_hours * 3600;
        let result: anyhow::Result<()> = (|| {
            if emitter.config.manage_keys {
                let current = emitter.keys.load_full();
                if let Some((next, destroyed)) = current.maintain(
                    super::now_ms(),
                    emitter.config.key_retention_hours * 3_600_000,
                    rng,
                )? {
                    next.store(path)?;
                    emitter.keys.store(Arc::new(next));
                    if !destroyed.is_empty() {
                        tracing::info!(
                            epochs = destroyed.len(),
                            "decision key epochs destroyed (crypto-shredded)"
                        );
                    }
                }
            } else {
                let modified = std::fs::metadata(path).and_then(|m| m.modified()).ok();
                if force || modified != self.modified {
                    let ring = KeyRing::load(path, rotation)?;
                    emitter.keys.store(Arc::new(ring));
                    self.modified = modified;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => self.warned = false,
            Err(error) if !self.warned => {
                self.warned = true;
                tracing::warn!(%error, "decision key maintenance failed; events without a key are dropped");
            }
            Err(_) => {}
        }
    }
}

struct Connection {
    stream: Option<UnixStream>,
    next_attempt: Instant,
    backoff: Duration,
}

impl Connection {
    async fn ensure(&mut self, emitter: &Emitter) -> Option<&mut UnixStream> {
        if self.stream.is_none() && Instant::now() >= self.next_attempt {
            let path = emitter
                .config
                .exporter_socket
                .as_deref()
                .expect("validated");
            match tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(path)).await {
                Ok(Ok(stream)) => {
                    self.stream = Some(stream);
                    self.backoff = Duration::from_millis(500);
                    emitter.exporter_connected.store(true, Ordering::Relaxed);
                }
                _ => {
                    emitter
                        .counters
                        .export_errors
                        .fetch_add(1, Ordering::Relaxed);
                    self.next_attempt = Instant::now() + self.backoff;
                    self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
        self.stream.as_mut()
    }

    fn fail(&mut self, emitter: &Emitter) {
        self.stream = None;
        emitter.exporter_connected.store(false, Ordering::Relaxed);
        emitter
            .counters
            .export_errors
            .fetch_add(1, Ordering::Relaxed);
        self.next_attempt = Instant::now() + self.backoff;
    }
}

/// One drain pass: sweeps bucket summaries and ships every queued record.
pub async fn drain_once(emitter: &Emitter, cx: &Context<'_>, connection: &mut ConnectionState) {
    let now = super::now_ms();
    let mut summaries = Vec::new();
    emitter.buckets.sweep(now, &mut summaries);
    for summary in summaries {
        emitter.push(emitter.summary_record(summary));
    }
    let max = emitter.config.batch.max_events;
    let mut records = Vec::with_capacity(max);
    loop {
        records.clear();
        emitter.rings.pop_batch(max, &mut records);
        if records.is_empty() {
            break;
        }
        let mut encoded = Vec::with_capacity(records.len());
        for record in &records {
            match encode(record, cx) {
                Ok(bytes) => encoded.push(bytes),
                Err(Dropped::NoKey) => {
                    emitter
                        .counters
                        .dropped_no_key
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(Dropped::Invalid) => {
                    emitter
                        .counters
                        .dropped_invalid
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        // Release route references before any I/O.
        records.clear();
        if encoded.is_empty() {
            continue;
        }
        let count = encoded.len() as u64;
        let frame = schema::encode_frame(&encoded);
        let written = connection.write(emitter, &frame).await;
        if written {
            emitter
                .counters
                .exported
                .fetch_add(count, Ordering::Relaxed);
            emitter.counters.batches.fetch_add(1, Ordering::Relaxed);
        } else {
            emitter
                .counters
                .dropped_exporter
                .fetch_add(count, Ordering::Relaxed);
        }
    }
}

/// Exporter connection with bounded backoff.
pub struct ConnectionState(Connection);

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    pub fn new() -> Self {
        Self(Connection {
            stream: None,
            next_attempt: Instant::now(),
            backoff: Duration::from_millis(500),
        })
    }

    async fn write(&mut self, emitter: &Emitter, frame: &[u8]) -> bool {
        let Some(stream) = self.0.ensure(emitter).await else {
            return false;
        };
        match tokio::time::timeout(WRITE_TIMEOUT, stream.write_all(frame)).await {
            Ok(Ok(())) => true,
            _ => {
                self.0.fail(emitter);
                false
            }
        }
    }
}

/// Background drain loop; stops with the gateway.
pub async fn run(
    emitter: Arc<Emitter>,
    build: String,
    cancel: tokio_util::sync::CancellationToken,
) {
    let rng = SystemRandom::new();
    let mut keeper = KeyKeeper::new();
    keeper.tick(&emitter, &rng, true);
    let mut connection = ConnectionState::new();
    let instance = emitter.config.instance.clone().unwrap_or_default();
    let interval = Duration::from_millis(emitter.config.batch.interval_ms);
    loop {
        let stop = tokio::select! {
            _ = cancel.cancelled() => true,
            _ = tokio::time::sleep(interval) => false,
        };
        keeper.tick(&emitter, &rng, false);
        let keys = emitter.keys.load_full();
        let cx = Context {
            keys: &keys,
            profile: emitter.profile(),
            instance: &instance,
            build: &build,
            rng: &rng,
        };
        drain_once(&emitter, &cx, &mut connection).await;
        if stop {
            break;
        }
    }
}
