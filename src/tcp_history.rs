//! Bounded, instance-local metadata for raw TCP connections.
//!
//! Active connections and completed connections have different cursors:
//! completion order can differ arbitrarily from accept order. This store owns
//! only copied, bounded metadata. It never retains a socket, Snapshot, GeoIP
//! database, TLS material, payload, credential, or raw error text.

use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize, Serializer};

use crate::country_observation::Observation;

pub const DEFAULT_RETENTION: Duration = Duration::from_secs(60);
pub const DEFAULT_ACTIVE_CAPACITY: usize = 4096;
pub const DEFAULT_RECENT_CAPACITY: usize = 4096;
const MAX_PAGE: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Accepted,
    Inspecting,
    Authenticating,
    Dialing,
    Forwarding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Eof,
    IdleTimeout,
    Shutdown,
    IdentityRevoked,
    Interrupted,
    NoRoute,
    IpDenied,
    Capacity,
    SniRejected,
    SniTimeout,
    CountryDenied,
    CountryUnavailable,
    MtlsRejected,
    NoBackend,
    MemberUnavailable,
    DialFailed,
    EndpointChanged,
    IoError,
}

/// Bytes successfully written toward each side, at the proxy I/O abstraction.
/// A counting I/O adapter should update this after each successful write,
/// including partial writes; read-ahead bytes not delivered do not count.
#[derive(Default, Debug)]
pub struct ByteCounters {
    upstream: AtomicU64,
    downstream: AtomicU64,
}

impl ByteCounters {
    pub fn add_upstream(&self, bytes: u64) {
        let _ = self
            .upstream
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(bytes))
            });
    }

    pub fn add_downstream(&self, bytes: u64) {
        let _ = self
            .downstream
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                Some(old.saturating_add(bytes))
            });
    }

    fn snapshot(&self) -> (String, String) {
        (
            self.upstream.load(Ordering::Relaxed).to_string(),
            self.downstream.load(Ordering::Relaxed).to_string(),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ActiveRecord {
    #[serde(serialize_with = "decimal")]
    pub connection_id: u64,
    pub started_at_unix_ms: u64,
    pub elapsed_ms: u64,
    pub peer_ip: String,
    pub peer_port: u16,
    pub listen: String,
    pub phase: Phase,
    pub route_id: Option<String>,
    pub member_id: Option<String>,
    pub geoip: Observation,
    pub bytes_upstream: String,
    pub bytes_downstream: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecentRecord {
    #[serde(serialize_with = "decimal")]
    pub event_id: u64,
    #[serde(serialize_with = "decimal")]
    pub connection_id: u64,
    pub started_at_unix_ms: u64,
    pub ended_at_unix_ms: u64,
    pub duration_ms: u64,
    pub peer_ip: String,
    pub peer_port: u16,
    pub listen: String,
    pub phase: Phase,
    pub route_id: Option<String>,
    pub member_id: Option<String>,
    pub geoip: Observation,
    pub bytes_upstream: String,
    pub bytes_downstream: String,
    pub outcome: Outcome,
    #[serde(serialize_with = "optional_decimal")]
    pub policy_revision: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct ActiveBatch {
    pub process_id: String,
    pub server_time_unix_ms: u64,
    pub records: Vec<ActiveRecord>,
    #[serde(serialize_with = "decimal")]
    pub latest_connection_id: u64,
    #[serde(serialize_with = "decimal")]
    pub next_after: u64,
    pub active_tracked: usize,
    pub active_untracked: u64,
    #[serde(serialize_with = "decimal")]
    pub omitted_total: u64,
    pub capacity: usize,
    /// Insertions and removals can occur between page requests.
    pub best_effort: bool,
}

#[derive(Debug, Serialize)]
pub struct RecentBatch {
    pub process_id: String,
    pub server_time_unix_ms: u64,
    pub records: Vec<RecentRecord>,
    #[serde(serialize_with = "optional_decimal")]
    pub oldest_event_id: Option<u64>,
    #[serde(serialize_with = "decimal")]
    pub latest_event_id: u64,
    #[serde(serialize_with = "decimal")]
    pub next_after: u64,
    pub gap: bool,
    #[serde(serialize_with = "decimal")]
    pub dropped_total: u64,
    #[serde(serialize_with = "decimal")]
    pub omitted_total: u64,
    #[serde(serialize_with = "decimal")]
    pub filtered_total: u64,
    pub retention_seconds: u64,
    pub capacity: usize,
}

fn decimal<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&value.to_string())
}

fn optional_decimal<S: Serializer>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(value) => serializer.serialize_some(&value.to_string()),
        None => serializer.serialize_none(),
    }
}

struct ActiveEntry {
    started: Instant,
    started_at_unix_ms: u64,
    peer_ip: String,
    peer_port: u16,
    listen: String,
    phase: Phase,
    route_id: Option<String>,
    member_id: Option<String>,
    geoip: Observation,
    bytes: Arc<ByteCounters>,
}

struct RecentEntry {
    recorded: Instant,
    record: RecentRecord,
}

#[derive(Default)]
struct State {
    active: BTreeMap<u64, ActiveEntry>,
    recent: VecDeque<RecentEntry>,
    latest_connection_id: u64,
    latest_event_id: u64,
    active_untracked: u64,
    omitted_total: u64,
    dropped_total: u64,
    filtered_total: u64,
}

pub struct History {
    state: Mutex<State>,
    retention: Duration,
    active_capacity: usize,
    recent_capacity: usize,
}

impl Default for History {
    fn default() -> Self {
        Self::with_limits(
            DEFAULT_RETENTION,
            DEFAULT_ACTIVE_CAPACITY,
            DEFAULT_RECENT_CAPACITY,
        )
    }
}

impl History {
    pub fn with_limits(
        retention: Duration,
        active_capacity: usize,
        recent_capacity: usize,
    ) -> Self {
        assert!(!retention.is_zero() && active_capacity > 0 && recent_capacity > 0);
        Self {
            state: Mutex::new(State::default()),
            retention,
            active_capacity,
            recent_capacity,
        }
    }

    /// Start a raw TCP observation immediately after a successful accept. A
    /// full history changes no admission decision: the returned guard merely
    /// tracks an omitted connection count until it is dropped.
    pub fn begin(self: &Arc<Self>, peer: SocketAddr, listen: SocketAddr) -> Guard {
        self.begin_inner(peer, listen, None)
    }

    /// Production observations resolve the current policy at completion.
    /// This stores an authority pointer, never an accepted snapshot.
    pub fn begin_with_policy(
        self: &Arc<Self>,
        peer: SocketAddr,
        listen: SocketAddr,
        active: Arc<ArcSwap<crate::config::Snapshot>>,
    ) -> Guard {
        self.begin_inner(peer, listen, Some(active))
    }

    fn begin_inner(
        self: &Arc<Self>,
        peer: SocketAddr,
        listen: SocketAddr,
        policy_source: Option<Arc<ArcSwap<crate::config::Snapshot>>>,
    ) -> Guard {
        let now = Instant::now();
        let started_at_unix_ms = unix_ms();
        let mut state = self.lock();
        let id = state.latest_connection_id.checked_add(1);
        if let Some(id) = id {
            state.latest_connection_id = id;
            if state.active.len() < self.active_capacity {
                state.active.insert(
                    id,
                    ActiveEntry {
                        started: now,
                        started_at_unix_ms,
                        peer_ip: peer.ip().to_canonical().to_string(),
                        peer_port: peer.port(),
                        listen: listen.to_string(),
                        phase: Phase::Accepted,
                        route_id: None,
                        member_id: None,
                        geoip: Observation::default(),
                        bytes: Arc::new(ByteCounters::default()),
                    },
                );
                return Guard {
                    history: self.clone(),
                    id: Some(id),
                    untracked: false,
                    outcome: Outcome::Interrupted,
                    listen,
                    peer_ip: peer.ip().to_canonical(),
                    route_id: None,
                    policy_source,
                };
            }
        }
        state.active_untracked = state.active_untracked.saturating_add(1);
        state.omitted_total = state.omitted_total.saturating_add(1);
        Guard {
            history: self.clone(),
            id: None,
            untracked: true,
            outcome: Outcome::Interrupted,
            listen,
            peer_ip: peer.ip().to_canonical(),
            route_id: None,
            policy_source,
        }
    }

    /// Active pages are sorted by accept ID. They are best-effort snapshots,
    /// not a frozen multi-page inventory. `None` starts from the oldest active
    /// record; `Some(0)` has the same meaning.
    pub fn active(&self, after: Option<u64>, limit: usize) -> ActiveBatch {
        let now = Instant::now();
        let state = self.lock();
        let records = state
            .active
            .iter()
            .filter(|(id, _)| after.is_none_or(|cursor| **id > cursor))
            .take(limit.clamp(1, MAX_PAGE))
            .map(|(id, entry)| {
                let (bytes_upstream, bytes_downstream) = entry.bytes.snapshot();
                ActiveRecord {
                    connection_id: *id,
                    started_at_unix_ms: entry.started_at_unix_ms,
                    elapsed_ms: safe_duration_ms(now.saturating_duration_since(entry.started)),
                    peer_ip: entry.peer_ip.clone(),
                    peer_port: entry.peer_port,
                    listen: entry.listen.clone(),
                    phase: entry.phase,
                    route_id: entry.route_id.clone(),
                    member_id: entry.member_id.clone(),
                    geoip: entry.geoip.clone(),
                    bytes_upstream,
                    bytes_downstream,
                }
            })
            .collect::<Vec<_>>();
        let next_after = records
            .last()
            .map_or(state.latest_connection_id, |record| record.connection_id);
        let server_time_unix_ms = unix_ms().max(
            records
                .iter()
                .map(|record| record.started_at_unix_ms)
                .max()
                .unwrap_or(0),
        );
        ActiveBatch {
            process_id: crate::admin::instance_id().to_owned(),
            server_time_unix_ms,
            records,
            latest_connection_id: state.latest_connection_id,
            next_after,
            active_tracked: state.active.len(),
            active_untracked: state.active_untracked,
            omitted_total: state.omitted_total,
            capacity: self.active_capacity,
            best_effort: true,
        }
    }

    /// Recent pages are sorted by *completion* event ID. With no cursor the
    /// latest page is returned, like HTTP traffic history. A cursor of zero
    /// starts from the oldest retained event.
    pub fn recent(&self, after: Option<u64>, limit: usize) -> RecentBatch {
        let now = Instant::now();
        let mut state = self.lock();
        self.prune(&mut state, now);
        let oldest_event_id = state.recent.front().map(|entry| entry.record.event_id);
        let latest_event_id = state.latest_event_id;
        let gap = after.is_some_and(|cursor| {
            cursor > latest_event_id
                || oldest_event_id.is_some_and(|oldest| cursor < oldest.saturating_sub(1))
                || (oldest_event_id.is_none() && cursor < latest_event_id)
        });
        let limit = limit.clamp(1, MAX_PAGE);
        let records: Vec<RecentRecord> = match after {
            None => state
                .recent
                .iter()
                .rev()
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            Some(cursor) if cursor > latest_event_id => state
                .recent
                .iter()
                .rev()
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            Some(cursor) => state
                .recent
                .iter()
                .filter(|entry| entry.record.event_id > cursor)
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect(),
        };
        let next_after = records
            .last()
            .map_or(latest_event_id, |record: &RecentRecord| record.event_id);
        let server_time_unix_ms = unix_ms().max(
            records
                .iter()
                .map(|record| record.ended_at_unix_ms)
                .max()
                .unwrap_or(0),
        );
        RecentBatch {
            process_id: crate::admin::instance_id().to_owned(),
            server_time_unix_ms,
            records,
            oldest_event_id,
            latest_event_id,
            next_after,
            gap,
            dropped_total: state.dropped_total,
            omitted_total: state.omitted_total,
            filtered_total: state.filtered_total,
            retention_seconds: self.retention.as_secs(),
            capacity: self.recent_capacity,
        }
    }

    pub fn latest_event_id(&self) -> u64 {
        self.lock().latest_event_id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn prune(&self, state: &mut State, now: Instant) {
        while state
            .recent
            .front()
            .is_some_and(|entry| now.saturating_duration_since(entry.recorded) >= self.retention)
        {
            state.recent.pop_front();
            state.dropped_total = state.dropped_total.saturating_add(1);
        }
    }
}

pub struct Guard {
    history: Arc<History>,
    id: Option<u64>,
    untracked: bool,
    outcome: Outcome,
    listen: SocketAddr,
    peer_ip: IpAddr,
    route_id: Option<String>,
    policy_source: Option<Arc<ArcSwap<crate::config::Snapshot>>>,
}

impl Guard {
    pub fn set_phase(&mut self, phase: Phase) {
        self.with_entry(|entry| entry.phase = phase);
    }

    pub fn set_route(&mut self, route: &str) {
        let route = bounded_id(route, 128);
        self.route_id = Some(route.clone());
        self.with_entry(|entry| entry.route_id = Some(route));
    }

    pub fn set_member(&mut self, member: Option<&str>) {
        let member = member.map(|value| bounded_id(value, 64));
        self.with_entry(|entry| entry.member_id = member);
    }

    pub fn set_geoip(&mut self, observation: &Observation) {
        let safe = if observation.validate().is_ok() {
            observation.clone()
        } else {
            Observation::default()
        };
        self.with_entry(|entry| entry.geoip = safe);
    }

    pub fn set_outcome(&mut self, outcome: Outcome) {
        self.outcome = outcome;
    }

    pub fn bytes(&self) -> Option<Arc<ByteCounters>> {
        let id = self.id?;
        self.history
            .lock()
            .active
            .get(&id)
            .map(|entry| entry.bytes.clone())
    }

    fn with_entry(&self, update: impl FnOnce(&mut ActiveEntry)) {
        if let Some(id) = self.id
            && let Some(entry) = self.history.lock().active.get_mut(&id)
        {
            update(entry);
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Resolve one current activation before touching the history lock.
        // A long-lived stream follows the policy at completion, and no old
        // Snapshot/TLS material is retained in the completion record.
        let decision = if !self.untracked {
            self.policy_source.as_ref().map(|source| {
                let snapshot = source.load_full();
                let action = snapshot.settings.tcp_recent_recording.as_ref().map_or(
                    crate::tcp_recording::Action::Record,
                    |policy| {
                        policy.action(crate::tcp_recording::Input {
                            listen: self.listen,
                            peer_ip: self.peer_ip,
                            route_id: self.route_id.as_deref(),
                            route_matched: self.route_id.is_some(),
                            outcome: self.outcome,
                        })
                    },
                );
                (action, snapshot.config.revision)
            })
        } else {
            None
        };
        let mut state = self.history.lock();
        if self.untracked {
            state.active_untracked = state.active_untracked.saturating_sub(1);
            return;
        }
        let Some(id) = self.id else { return };
        let Some(entry) = state.active.remove(&id) else {
            return;
        };
        if decision
            .as_ref()
            .is_some_and(|(action, _)| *action == crate::tcp_recording::Action::Drop)
        {
            state.filtered_total = state.filtered_total.saturating_add(1);
            return;
        }
        let now = Instant::now();
        let ended_at_unix_ms = unix_ms().max(entry.started_at_unix_ms);
        let Some(event_id) = state.latest_event_id.checked_add(1) else {
            // No ID reuse after exhaustion. The active record still exits.
            state.omitted_total = state.omitted_total.saturating_add(1);
            return;
        };
        state.latest_event_id = event_id;
        let (bytes_upstream, bytes_downstream) = entry.bytes.snapshot();
        let record = RecentRecord {
            event_id,
            connection_id: id,
            started_at_unix_ms: entry.started_at_unix_ms,
            ended_at_unix_ms,
            duration_ms: safe_duration_ms(now.saturating_duration_since(entry.started)),
            peer_ip: entry.peer_ip,
            peer_port: entry.peer_port,
            listen: entry.listen,
            phase: entry.phase,
            route_id: entry.route_id,
            member_id: entry.member_id,
            geoip: entry.geoip,
            bytes_upstream,
            bytes_downstream,
            outcome: self.outcome,
            policy_revision: decision.map(|(_, revision)| revision),
        };
        self.history.prune(&mut state, now);
        state.recent.push_back(RecentEntry {
            recorded: now,
            record,
        });
        while state.recent.len() > self.history.recent_capacity {
            state.recent.pop_front();
            state.dropped_total = state.dropped_total.saturating_add(1);
        }
    }
}

fn bounded_id(input: &str, max: usize) -> String {
    input
        .bytes()
        .take(max)
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"._-".contains(&byte) {
                byte as char
            } else {
                '_'
            }
        })
        .collect()
}

fn safe_duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(MAX_SAFE_INTEGER as u128) as u64
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(MAX_SAFE_INTEGER as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{net::IpAddr, sync::Weak};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::from([127, 0, 0, 1]), port)
    }

    fn history(active: usize, recent: usize) -> Arc<History> {
        Arc::new(History::with_limits(
            Duration::from_secs(60),
            active,
            recent,
        ))
    }

    #[test]
    fn completion_cursor_uses_completion_order_not_accept_order() {
        let history = history(4, 4);
        let mut old = history.begin(peer(1000), peer(8000));
        let mut young = history.begin(peer(1001), peer(8000));
        old.set_route("old");
        young.set_route("young");
        young.set_outcome(Outcome::Eof);
        drop(young);
        let first = history.recent(Some(0), 128);
        assert_eq!(first.records.len(), 1);
        assert_eq!(first.records[0].connection_id, 2);
        assert_eq!(first.records[0].event_id, 1);
        assert_eq!(first.records[0].policy_revision, None);
        assert_eq!(first.filtered_total, 0);
        drop(old);
        let second = history.recent(Some(first.next_after), 128);
        assert_eq!(second.records.len(), 1);
        assert_eq!(second.records[0].connection_id, 1);
        assert_eq!(second.records[0].event_id, 2);
        assert_eq!(second.records[0].outcome, Outcome::Interrupted);
    }

    #[test]
    fn active_capacity_omits_metadata_without_changing_connection_lifetime() {
        let history = history(1, 1);
        let first = history.begin(peer(1000), peer(8000));
        let second = history.begin(peer(1001), peer(8000));
        assert!(first.bytes().is_some());
        assert!(second.bytes().is_none());
        let active = history.active(None, 128);
        assert_eq!(active.records.len(), 1);
        assert_eq!(active.active_untracked, 1);
        assert_eq!(active.omitted_total, 1);
        drop(second);
        assert_eq!(history.active(None, 128).active_untracked, 0);
        drop(first);
        assert_eq!(history.recent(None, 128).records.len(), 1);
        assert_eq!(history.recent(None, 128).omitted_total, 1);
        assert_eq!(history.recent(None, 128).filtered_total, 0);
    }

    #[test]
    fn untracked_overflow_does_not_increment_policy_filtered_counter() {
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "revision": 7,
            "settings": {"tcp_recent_recording": {"default_action":"drop","rules":[]}}
        }))
        .unwrap();
        let active = Arc::new(ArcSwap::from_pointee(
            crate::config::Snapshot::new(config).unwrap(),
        ));
        let history = history(1, 4);
        let tracked = history.begin_with_policy(peer(1000), peer(8000), active.clone());
        let untracked = history.begin_with_policy(peer(1001), peer(8000), active);
        assert!(untracked.bytes().is_none());
        drop(untracked);
        assert_eq!(history.recent(None, 128).filtered_total, 0);
        assert_eq!(history.recent(None, 128).omitted_total, 1);
        drop(tracked);
        let batch = history.recent(None, 128);
        assert_eq!(batch.filtered_total, 1);
        assert_eq!(batch.latest_event_id, 0);
        assert!(batch.records.is_empty());
    }

    #[test]
    fn recent_overflow_ttl_and_cursors_report_gaps() {
        let history = history(2, 2);
        for port in 1000..1003 {
            drop(history.begin(peer(port), peer(8000)));
        }
        let batch = history.recent(Some(0), 128);
        assert_eq!(
            batch.records.iter().map(|r| r.event_id).collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert!(batch.gap);
        assert_eq!(batch.dropped_total, 1);
        assert!(history.recent(Some(u64::MAX), 128).gap);
        let expiring = Arc::new(History::with_limits(Duration::from_millis(1), 2, 2));
        drop(expiring.begin(peer(1000), peer(8000)));
        std::thread::sleep(Duration::from_millis(4));
        let expired = expiring.recent(Some(0), 128);
        assert!(expired.records.is_empty());
        assert!(expired.gap);
        assert_eq!(expired.latest_event_id, 1);
    }

    #[test]
    fn metadata_is_bounded_and_does_not_retain_observation_owner() {
        let history = history(1, 1);
        let owner = Arc::new(Observation::default());
        let weak: Weak<Observation> = Arc::downgrade(&owner);
        let mut guard = history.begin(peer(1000), peer(8000));
        guard.set_route(&format!("{}token", "x".repeat(200)));
        guard.set_member(Some("id\n<script>"));
        guard.set_geoip(&owner);
        drop(owner);
        assert!(weak.upgrade().is_none());
        drop(guard);
        let record = &history.recent(None, 128).records[0];
        assert_eq!(record.route_id.as_ref().unwrap().len(), 128);
        assert_eq!(record.member_id.as_deref(), Some("id__script_"));
        assert_eq!(
            record.geoip.state,
            crate::country_observation::State::NotChecked
        );
        let json = serde_json::to_value(record).unwrap();
        assert!(json["event_id"].is_string());
        assert!(json["connection_id"].is_string());
        assert!(json["bytes_upstream"].is_string());
    }

    #[test]
    fn atomic_byte_counters_preserve_partial_progress_and_saturate() {
        let history = history(1, 1);
        let mut guard = history.begin(peer(1000), peer(8000));
        guard.set_phase(Phase::Forwarding);
        let bytes = guard.bytes().unwrap();
        bytes.add_upstream(7);
        bytes.add_downstream(11);
        let active = history.active(None, 128);
        assert_eq!(active.records[0].bytes_upstream, "7");
        assert_eq!(active.records[0].bytes_downstream, "11");
        bytes.add_upstream(u64::MAX);
        guard.set_outcome(Outcome::IoError);
        drop(guard);
        let recent = history.recent(None, 128);
        assert_eq!(recent.records[0].bytes_upstream, u64::MAX.to_string());
        assert_eq!(recent.records[0].bytes_downstream, "11");
        assert_eq!(recent.records[0].outcome, Outcome::IoError);
    }

    #[test]
    fn active_pages_are_sorted_and_best_effort() {
        let history = history(4, 4);
        let guards = (1000..1004)
            .map(|port| history.begin(peer(port), peer(8000)))
            .collect::<Vec<_>>();
        let first = history.active(None, 2);
        assert_eq!(
            first
                .records
                .iter()
                .map(|r| r.connection_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(first.next_after, 2);
        let second = history.active(Some(first.next_after), 2);
        assert_eq!(
            second
                .records
                .iter()
                .map(|r| r.connection_id)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert!(second.best_effort);
        drop(guards);
    }

    #[test]
    fn concurrent_completion_keeps_unique_event_ids_and_bounded_storage() {
        let history = history(32, 8);
        std::thread::scope(|scope| {
            for port in 1000..1032 {
                let history = history.clone();
                scope.spawn(move || {
                    let mut guard = history.begin(peer(port), peer(8000));
                    guard.bytes().unwrap().add_upstream(port.into());
                    guard.set_outcome(Outcome::Eof);
                });
            }
        });
        let recent = history.recent(Some(0), 128);
        assert_eq!(recent.latest_event_id, 32);
        assert_eq!(recent.records.len(), 8);
        assert_eq!(recent.dropped_total, 24);
        assert_eq!(
            recent
                .records
                .iter()
                .map(|r| r.event_id)
                .collect::<Vec<_>>(),
            (25..=32).collect::<Vec<_>>()
        );
        assert_eq!(history.active(None, 128).active_tracked, 0);
    }
}
