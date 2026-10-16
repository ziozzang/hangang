//! Local bounded decision store: SQLite in WAL mode, event-ID uniqueness,
//! hourly partitions and age/byte caps enforced by dropping whole partitions.

use anyhow::{Context, Result, ensure};
use hangang_decision_event::v1::{self, stage_verdict::Stage};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PARTITION_MS: u64 = 3_600_000;
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(7 * 86_400);
pub const HARD_MAX_AGE: Duration = Duration::from_secs(90 * 86_400);
/// Estimated per-row cost of indexed columns beyond the encoded event.
pub const ROW_OVERHEAD: u64 = 384;

/// Traffic and simulation/shadow events never share partitions or counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lane {
    Traffic = 0,
    Simulation = 1,
}

impl Lane {
    pub fn of(kind: i32) -> Self {
        if kind == v1::Kind::Enforced as i32 {
            Lane::Traffic
        } else {
            Lane::Simulation
        }
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_age: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_age: DEFAULT_MAX_AGE,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.max_bytes >= 1024 * 1024, "store byte cap below 1 MiB");
        ensure!(
            self.max_age >= Duration::from_secs(3600) && self.max_age <= HARD_MAX_AGE,
            "store retention must be 1 hour to 90 days"
        );
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct InsertOutcome {
    pub inserted: u64,
    pub duplicates: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Enforced {
    pub partitions_dropped: u64,
    pub rows_dropped: u64,
}

/// Indexed projection of one validated event.
struct Row<'a> {
    event: &'a v1::DecisionEvent,
    body: &'a [u8],
}

pub struct Store {
    conn: Connection,
    path: PathBuf,
    limits: Limits,
}

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS partitions(
  lane INTEGER NOT NULL, part INTEGER NOT NULL, bytes INTEGER NOT NULL,
  rows INTEGER NOT NULL, PRIMARY KEY(lane, part)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS events(
  event_id BLOB PRIMARY KEY,
  lane INTEGER NOT NULL, part INTEGER NOT NULL, time_ms INTEGER NOT NULL,
  kind INTEGER NOT NULL, request_id TEXT NOT NULL,
  result INTEGER NOT NULL, status INTEGER NOT NULL, stage INTEGER NOT NULL,
  reason TEXT NOT NULL,
  route_id TEXT, service TEXT, resource TEXT, action TEXT, method TEXT,
  info_class TEXT, subject_ref TEXT, ip_ref TEXT, prefix_ref TEXT,
  asn INTEGER, country TEXT, principal INTEGER,
  rev_hangang INTEGER, rev_sumunjang INTEGER, rev_hopae INTEGER, rev_pumgye INTEGER,
  sample_class INTEGER NOT NULL, sample_ppm INTEGER NOT NULL,
  suppressed INTEGER NOT NULL, key_epoch TEXT,
  size INTEGER NOT NULL, body BLOB NOT NULL);
CREATE INDEX IF NOT EXISTS ev_time ON events(lane, time_ms, event_id);
CREATE INDEX IF NOT EXISTS ev_part ON events(lane, part);
CREATE INDEX IF NOT EXISTS ev_request ON events(request_id);
CREATE INDEX IF NOT EXISTS ev_subject ON events(subject_ref, time_ms) WHERE subject_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_ip ON events(ip_ref, time_ms) WHERE ip_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_prefix ON events(prefix_ref, time_ms) WHERE prefix_ref IS NOT NULL;
CREATE INDEX IF NOT EXISTS ev_reason ON events(lane, reason, time_ms);
";

fn none_if_empty(value: &str) -> Option<&str> {
    (!value.is_empty()).then_some(value)
}

impl Store {
    pub fn open(path: &Path, limits: Limits) -> Result<Self> {
        limits.validate()?;
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("open decision store {}", path.display()))?;
        // auto_vacuum must precede the first table so dropped partitions
        // return pages to the file system.
        conn.execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")?;
        let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))?;
        ensure!(
            mode.eq_ignore_ascii_case("wal"),
            "decision store requires WAL"
        );
        conn.execute_batch(
            "PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=OFF; PRAGMA busy_timeout=2000;",
        )?;
        conn.execute_batch(SCHEMA)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(Self {
            conn,
            path: path.to_owned(),
            limits,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Inserts validated events; duplicates by `event_id` are ignored so
    /// at-least-once delivery is safe.
    pub fn insert(&mut self, events: &[(v1::DecisionEvent, Vec<u8>)]) -> Result<InsertOutcome> {
        let mut outcome = InsertOutcome::default();
        let tx = self.conn.transaction()?;
        {
            let mut insert = tx.prepare_cached(
                "INSERT OR IGNORE INTO events(event_id, lane, part, time_ms, kind, request_id,
                  result, status, stage, reason, route_id, service, resource, action, method,
                  info_class, subject_ref, ip_ref, prefix_ref, asn, country, principal,
                  rev_hangang, rev_sumunjang, rev_hopae, rev_pumgye, sample_class, sample_ppm,
                  suppressed, key_epoch, size, body)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,
                  ?20,?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32)",
            )?;
            let mut partition = tx.prepare_cached(
                "INSERT INTO partitions(lane, part, bytes, rows) VALUES (?1, ?2, ?3, 1)
                 ON CONFLICT(lane, part) DO UPDATE SET bytes = bytes + ?3, rows = rows + 1",
            )?;
            for (event, body) in events {
                let row = Row { event, body };
                let lane = Lane::of(event.kind) as i64;
                let part = (event.time_unix_ms / PARTITION_MS) as i64;
                let size = body.len() as u64 + ROW_OVERHEAD;
                let changed = row.insert(&mut insert, lane, part, size)?;
                if changed == 0 {
                    outcome.duplicates += 1;
                } else {
                    outcome.inserted += 1;
                    partition.execute(params![lane, part, size as i64])?;
                }
            }
        }
        tx.commit()?;
        Ok(outcome)
    }

    pub fn accounted_bytes(&self) -> Result<u64> {
        let bytes: i64 =
            self.conn
                .query_row("SELECT COALESCE(SUM(bytes), 0) FROM partitions", [], |r| {
                    r.get(0)
                })?;
        Ok(bytes as u64)
    }

    /// Pages in use, excluding the free list.
    pub fn file_bytes(&self) -> Result<u64> {
        let pages: i64 = self.conn.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free: i64 = self
            .conn
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let size: i64 = self.conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(((pages - free).max(0) * size) as u64)
    }

    pub fn used_bytes(&self) -> Result<u64> {
        Ok(self.accounted_bytes()?.max(self.file_bytes()?))
    }

    fn oldest(&self) -> Result<Option<(i64, i64)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT lane, part FROM partitions ORDER BY part ASC, lane DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    fn drop_partition(&mut self, lane: i64, part: i64) -> Result<u64> {
        let tx = self.conn.transaction()?;
        let rows = tx.execute(
            "DELETE FROM events WHERE lane = ?1 AND part = ?2",
            params![lane, part],
        )?;
        tx.execute(
            "DELETE FROM partitions WHERE lane = ?1 AND part = ?2",
            params![lane, part],
        )?;
        tx.commit()?;
        Ok(rows as u64)
    }

    /// Drops whole partitions, oldest first, until both caps hold.
    pub fn enforce(&mut self, now_ms: u64) -> Result<Enforced> {
        let mut result = Enforced::default();
        let age_floor = now_ms.saturating_sub(self.limits.max_age.as_millis() as u64);
        loop {
            let Some((lane, part)) = self.oldest()? else {
                break;
            };
            let partition_end = (part as u64 + 1) * PARTITION_MS;
            let expired = partition_end <= age_floor;
            let over = self.used_bytes()? > self.limits.max_bytes;
            if !expired && !over {
                break;
            }
            result.rows_dropped += self.drop_partition(lane, part)?;
            result.partitions_dropped += 1;
        }
        if result.partitions_dropped > 0 {
            self.conn.execute_batch("PRAGMA incremental_vacuum;")?;
        }
        Ok(result)
    }

    pub fn status(&self) -> Result<serde_json::Value> {
        let (rows, partitions, oldest, newest): (i64, i64, Option<i64>, Option<i64>) =
            self.conn.query_row(
                "SELECT COALESCE(SUM(rows),0), COUNT(*), MIN(part), MAX(part) FROM partitions",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
        let newest_event: Option<i64> =
            self.conn
                .query_row("SELECT MAX(time_ms) FROM events WHERE lane = 0", [], |r| {
                    r.get(0)
                })?;
        Ok(serde_json::json!({
            "rows": rows,
            "partitions": partitions,
            "oldest_partition_start_ms": oldest.map(|p| p as u64 * PARTITION_MS),
            "newest_partition_start_ms": newest.map(|p| p as u64 * PARTITION_MS),
            "newest_event_ms": newest_event,
            "accounted_bytes": self.accounted_bytes()?,
            "file_bytes": self.file_bytes()?,
            "max_bytes": self.limits.max_bytes,
            "max_age_seconds": self.limits.max_age.as_secs(),
        }))
    }

    /// Read-only connection for the query service (WAL readers never block
    /// the writer).
    pub fn reader(path: &Path) -> Result<Connection> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA query_only=ON; PRAGMA busy_timeout=1000;")?;
        Ok(conn)
    }
}

impl Row<'_> {
    fn insert(
        &self,
        statement: &mut rusqlite::CachedStatement<'_>,
        lane: i64,
        part: i64,
        size: u64,
    ) -> Result<usize> {
        let e = self.event;
        let route = e.route.clone().unwrap_or_default();
        let outcome = e.outcome.clone().unwrap_or_default();
        let revisions = e.revisions.unwrap_or_default();
        let sampling = e.sampling.unwrap_or_default();
        let mut info_class = None;
        let mut subject_ref = None;
        let mut ip_ref = None;
        let mut prefix_ref = None;
        let mut asn = None;
        let mut country = None;
        let mut principal = None;
        for stage in &e.stages {
            match &stage.stage {
                Some(Stage::Network(n)) => {
                    ip_ref = none_if_empty(&n.ip_ref);
                    prefix_ref = none_if_empty(&n.prefix_ref);
                    asn = n.asn;
                    country = none_if_empty(&n.country);
                }
                Some(Stage::Identity(i)) => {
                    subject_ref = none_if_empty(&i.subject_ref);
                    principal = Some(i.principal);
                }
                Some(Stage::Authorization(a)) => {
                    info_class = none_if_empty(&a.information_class);
                }
                _ => {}
            }
        }
        let rev = |v: Option<u64>| v.map(|v| v.min(i64::MAX as u64) as i64);
        Ok(statement.execute(params![
            e.event_id,
            lane,
            part,
            e.time_unix_ms as i64,
            e.kind,
            e.request_id,
            outcome.result,
            outcome.status,
            outcome.deciding_stage,
            outcome.reason,
            none_if_empty(&route.route_id),
            none_if_empty(&route.service),
            none_if_empty(&route.resource),
            none_if_empty(&route.action),
            none_if_empty(&route.method),
            info_class,
            subject_ref,
            ip_ref,
            prefix_ref,
            asn,
            country,
            principal,
            rev(revisions.hangang),
            rev(revisions.sumunjang),
            rev(revisions.hopae),
            rev(revisions.pumgye),
            sampling.class,
            sampling.rate_ppm,
            e.suppressed
                .map_or(0, |s| s.count.min(i64::MAX as u64) as i64),
            e.privacy.as_ref().and_then(|p| none_if_empty(&p.key_epoch)),
            size as i64,
            self.body,
        ])?)
    }
}
