//! Short-lived, bounded metadata for completed HTTP response heads.
//!
//! No request or response body, header, cookie, authorization value, or query
//! string enters this store. The admin API must restrict snapshots to admins:
//! even connection IPs and route names can be sensitive operational data.

use serde::Serialize;
use std::{
    collections::VecDeque,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_RETENTION: Duration = Duration::from_secs(60);
pub const DEFAULT_CAPACITY: usize = 4096;
const MAX_SNAPSHOT: usize = 128;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListenerKind {
    Default,
    Public,
    Workload,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct Listener {
    pub kind: ListenerKind,
    pub id: Option<String>,
}

#[derive(Clone, Debug)]
pub enum ListenerInput {
    Default,
    Public(String),
    Workload(String),
    Unknown,
}

impl ListenerInput {
    fn bounded(self) -> Listener {
        match self {
            Self::Default => Listener {
                kind: ListenerKind::Default,
                id: Some("default".into()),
            },
            Self::Public(id) if id != "default" && valid_listener_id(&id, 64, false) => Listener {
                kind: ListenerKind::Public,
                id: Some(id),
            },
            Self::Workload(id) if valid_listener_id(&id, 128, true) => Listener {
                kind: ListenerKind::Workload,
                id: Some(id),
            },
            _ => Listener {
                kind: ListenerKind::Unknown,
                id: None,
            },
        }
    }
}

fn valid_listener_id(id: &str, max: usize, colon: bool) -> bool {
    !id.is_empty()
        && id.len() <= max
        && id.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-')
                || (colon && byte == b':')
        })
}

#[derive(Clone, Debug, Serialize)]
pub struct TrafficRecord {
    pub id: u64,
    /// Configuration revision whose recording policy selected this row.
    pub policy_revision: u64,
    pub timestamp_unix_ms: u64,
    pub peer_ip: String,
    pub peer_port: u16,
    pub client_ip: String,
    pub geoip: crate::country_observation::Observation,
    pub method: String,
    pub path: String,
    pub route_id: Option<String>,
    pub listener: Listener,
    pub status: u16,
    /// Milliseconds from request admission to response headers, not body end.
    pub response_head_ms: u64,
    pub protocol: &'static str,
    pub tls: bool,
}

pub struct TrafficInput<'a> {
    pub peer_ip: IpAddr,
    pub peer_port: u16,
    pub client_ip: IpAddr,
    pub geoip: Option<&'a crate::country_observation::Observation>,
    pub method: &'a str,
    pub path: &'a str,
    pub route_id: Option<&'a str>,
    pub listener: ListenerInput,
    pub status: u16,
    pub response_head_ms: u64,
    pub protocol: &'static str,
    pub tls: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TrafficBatch {
    pub records: Vec<TrafficRecord>,
    /// Server wall-clock time when this snapshot was taken. Consumers can
    /// calculate record age without trusting the browser's wall clock.
    pub server_time_unix_ms: u64,
    pub oldest_id: Option<u64>,
    pub latest_id: u64,
    pub next_after: u64,
    pub gap: bool,
    pub dropped_total: u64,
    /// Response heads omitted by policy; these consume no traffic ID.
    pub filtered_total: u64,
    pub retention_seconds: u64,
}

struct Entry {
    recorded: Instant,
    record: TrafficRecord,
}

#[derive(Default)]
struct State {
    records: VecDeque<Entry>,
    latest_id: u64,
    dropped_total: u64,
    filtered_total: u64,
}

pub struct TrafficHistory {
    state: Mutex<State>,
    retention: Duration,
    capacity: usize,
}

impl Default for TrafficHistory {
    fn default() -> Self {
        Self::with_limits(DEFAULT_RETENTION, DEFAULT_CAPACITY)
    }
}

impl TrafficHistory {
    pub fn with_limits(retention: Duration, capacity: usize) -> Self {
        assert!(!retention.is_zero() && capacity > 0);
        Self {
            state: Mutex::new(State::default()),
            retention,
            capacity,
        }
    }

    /// Records only bounded metadata. Poisoned state is reset; traffic logging
    /// must never make the data plane unavailable.
    pub fn record(&self, input: TrafficInput<'_>) {
        self.record_with_policy_revision(input, 0);
    }

    pub fn record_filtered(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.filtered_total = state.filtered_total.saturating_add(1);
    }

    pub fn record_with_policy_revision(&self, input: TrafficInput<'_>, policy_revision: u64) {
        let now = Instant::now();
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        // Allocate and sanitize before taking the ring lock. The critical
        // section only assigns an ID, prunes, and pushes one bounded entry.
        let mut record = TrafficRecord {
            id: 0,
            policy_revision,
            timestamp_unix_ms,
            peer_ip: input.peer_ip.to_string(),
            peer_port: input.peer_port,
            client_ip: input.client_ip.to_string(),
            // Observations contain only fixed-shape country metadata. Never
            // let an invalid caller insert unbounded strings into the ring.
            geoip: input
                .geoip
                .filter(|value| value.validate().is_ok())
                .cloned()
                .unwrap_or_default(),
            method: bounded_ascii(input.method, 16),
            path: bounded_path(input.path),
            route_id: input.route_id.map(|id| bounded_ascii(id, 128)),
            listener: input.listener.bounded(),
            status: input.status,
            response_head_ms: input.response_head_ms,
            protocol: input.protocol,
            tls: input.tls,
        };
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune(&mut state, now);
        state.latest_id = state.latest_id.saturating_add(1);
        record.id = state.latest_id;
        state.records.push_back(Entry {
            recorded: now,
            record,
        });
        while state.records.len() > self.capacity {
            state.records.pop_front();
            state.dropped_total = state.dropped_total.saturating_add(1);
        }
    }

    pub fn latest_id(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .latest_id
    }

    /// `None` returns the latest records; `Some(id)` returns records newer than
    /// that cursor. `gap` means the caller missed evicted entries or supplied
    /// a cursor from a different, newer process generation.
    pub fn snapshot_since(&self, after: Option<u64>, limit: usize) -> TrafficBatch {
        let now = Instant::now();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.prune(&mut state, now);
        let oldest_id = state.records.front().map(|entry| entry.record.id);
        let latest_id = state.latest_id;
        let gap = after.is_some_and(|cursor| {
            cursor > latest_id
                || oldest_id.is_some_and(|oldest| cursor < oldest.saturating_sub(1))
                || (oldest_id.is_none() && cursor < latest_id)
        });
        let limit = limit.min(MAX_SNAPSHOT);
        let records: Vec<_> = match after {
            None => state
                .records
                .iter()
                .rev()
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            Some(cursor) if cursor > latest_id => state
                .records
                .iter()
                .rev()
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect(),
            Some(cursor) => state
                .records
                .iter()
                .filter(|entry| entry.record.id > cursor)
                .take(limit)
                .map(|entry| entry.record.clone())
                .collect(),
        };
        let next_after = records.last().map_or(latest_id, |record| record.id);
        let server_time_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(u64::MAX as u128) as u64;
        let server_time_unix_ms = server_time_unix_ms.max(
            records
                .iter()
                .map(|record| record.timestamp_unix_ms)
                .max()
                .unwrap_or(0),
        );
        TrafficBatch {
            records,
            server_time_unix_ms,
            oldest_id,
            latest_id,
            next_after,
            gap,
            dropped_total: state.dropped_total,
            filtered_total: state.filtered_total,
            retention_seconds: self.retention.as_secs(),
        }
    }

    fn prune(&self, state: &mut State, now: Instant) {
        while state
            .records
            .front()
            .is_some_and(|entry| now.duration_since(entry.recorded) >= self.retention)
        {
            state.records.pop_front();
            state.dropped_total = state.dropped_total.saturating_add(1);
        }
    }
}

pub(crate) fn bounded_ascii(value: &str, max: usize) -> String {
    value
        .bytes()
        .take(max)
        .map(|byte| {
            if byte.is_ascii_graphic() {
                byte as char
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn bounded_path(value: &str) -> String {
    let path = value.split('?').next().unwrap_or("/");
    if path.is_empty() {
        "/".to_owned()
    } else {
        bounded_ascii(path, 256)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn listener_metadata_is_bounded_and_kind_consistent() {
        let history = TrafficHistory::default();
        for listener in [
            ListenerInput::Default,
            ListenerInput::Public("edge".into()),
            ListenerInput::Workload("private:edge".into()),
            ListenerInput::Public("a".repeat(65)),
            ListenerInput::Public("default".into()),
            ListenerInput::Workload("/private".into()),
            ListenerInput::Unknown,
        ] {
            let mut request = input("/");
            request.listener = listener;
            history.record(request);
        }
        let records = history.snapshot_since(None, 128).records;
        let scopes: Vec<_> = records
            .iter()
            .map(|row| serde_json::to_value(&row.listener).unwrap())
            .collect();
        assert_eq!(
            scopes,
            vec![
                serde_json::json!({"kind":"default","id":"default"}),
                serde_json::json!({"kind":"public","id":"edge"}),
                serde_json::json!({"kind":"workload","id":"private:edge"}),
                serde_json::json!({"kind":"unknown","id":null}),
                serde_json::json!({"kind":"unknown","id":null}),
                serde_json::json!({"kind":"unknown","id":null}),
                serde_json::json!({"kind":"unknown","id":null}),
            ]
        );
    }

    #[test]
    fn clock_rollback_cannot_make_any_returned_record_newer_than_batch_time() {
        let history = TrafficHistory::default();
        history.record(input("/first"));
        history.record(input("/second"));
        let future = history.state.lock().unwrap().records[0]
            .record
            .timestamp_unix_ms
            + 60_000;
        {
            let mut state = history.state.lock().unwrap();
            state.records[0].record.timestamp_unix_ms = future;
            state.records[1].record.timestamp_unix_ms = future - 30_000;
        }
        let batch = history.snapshot_since(None, 128);
        assert_eq!(batch.records.len(), 2);
        assert!(
            batch
                .records
                .iter()
                .all(|record| record.timestamp_unix_ms <= batch.server_time_unix_ms)
        );
    }

    #[test]
    fn malformed_country_metadata_cannot_enter_the_bounded_ring() {
        let history = TrafficHistory::default();
        let observed = crate::country_observation::Observation {
            state: crate::country_observation::State::Known,
            country: Some("x".repeat(100_000)),
            generation_sha256: Some("a".repeat(64)),
            error_code: Some("/private/operator/database.mmdb".into()),
        };
        let mut request = input("/public");
        request.geoip = Some(&observed);
        history.record(request);
        let batch = history.snapshot_since(None, 128);
        assert_eq!(batch.records[0].geoip, Default::default());
        let json = serde_json::to_string(&batch).unwrap();
        assert!(!json.contains("/private"));
        assert!(json.len() < 1024);
    }

    fn input<'a>(path: &'a str) -> TrafficInput<'a> {
        TrafficInput {
            geoip: None,
            peer_ip: "192.0.2.5".parse().unwrap(),
            peer_port: 12345,
            client_ip: "198.51.100.7".parse().unwrap(),
            method: "GET",
            path,
            route_id: Some("api"),
            listener: ListenerInput::Unknown,
            status: 200,
            response_head_ms: 12,
            protocol: "h2",
            tls: true,
        }
    }

    #[test]
    fn bounds_query_strings_capacity_and_cursor_gaps() {
        let history = TrafficHistory::with_limits(Duration::from_secs(60), 3);
        for _ in 0..5 {
            history.record(input("/public?authorization=secret&cookie=private"));
        }
        let batch = history.snapshot_since(None, 128);
        assert_eq!(
            batch
                .records
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(batch.dropped_total, 2);
        assert!(
            batch
                .records
                .iter()
                .all(|record| batch.server_time_unix_ms >= record.timestamp_unix_ms)
        );
        assert!(batch.records.iter().all(|record| record.path == "/public"));
        assert!(!serde_json::to_string(&batch).unwrap().contains("secret"));
        let newer = history.snapshot_since(Some(2), 2);
        assert_eq!(
            newer
                .records
                .iter()
                .map(|record| record.id)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert_eq!(newer.next_after, 4);
        assert!(!newer.gap);
        assert!(history.snapshot_since(Some(1), 2).gap);
        assert!(history.snapshot_since(Some(99), 2).gap);
    }

    #[test]
    fn expiry_and_parallel_writers_stay_bounded() {
        let history = Arc::new(TrafficHistory::with_limits(Duration::from_millis(30), 64));
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let history = history.clone();
                scope.spawn(move || {
                    for _ in 0..200 {
                        history.record(input("/ok"));
                    }
                });
            }
        });
        let batch = history.snapshot_since(None, 128);
        assert!(batch.records.len() <= 64);
        assert_eq!(batch.latest_id, 1600);
        std::thread::sleep(Duration::from_millis(40));
        let expired = history.snapshot_since(Some(0), 128);
        assert!(expired.records.is_empty());
        assert!(expired.gap);
        assert_eq!(expired.next_after, 1600);
        assert_eq!(expired.dropped_total, 1600);
    }

    #[test]
    fn filtered_heads_use_no_id_and_do_not_count_as_evictions() {
        let history = TrafficHistory::default();
        history.record_filtered();
        history.record_filtered();
        let empty = history.snapshot_since(None, 128);
        assert_eq!(empty.latest_id, 0);
        assert_eq!(empty.filtered_total, 2);
        assert_eq!(empty.dropped_total, 0);
        history.record_with_policy_revision(input("/selected"), 42);
        let selected = history.snapshot_since(Some(0), 128);
        assert_eq!(selected.records[0].id, 1);
        assert_eq!(selected.records[0].policy_revision, 42);
        assert_eq!(selected.filtered_total, 2);
    }
}
