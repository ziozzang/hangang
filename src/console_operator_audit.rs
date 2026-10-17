//! The console operator audit store: SSO sign-ins with the operator's
//! assurance, step-up refusals, changes, and break-glass local sign-ins and
//! changes, kept in a bounded table (a ring: at most `max_records` rows, none
//! older than the retention) separate from the authority's account audit, and
//! read by administrators through `GET /v1/console/operator-audit` (the
//! unified audit view's "console operators" source).
use anyhow::{Context, Result, ensure};
use std::sync::Mutex;

pub struct Store {
    conn: Mutex<rusqlite::Connection>,
    max_records: i64,
    retention_ms: i64,
}

/// The default bound: 10 000 records, 90 days.
pub const DEFAULT_MAX_RECORDS: i64 = 10_000;
pub const DEFAULT_RETENTION_DAYS: i64 = 90;
/// A record (as stored) is at most this many bytes of JSON.
const MAX_RECORD: usize = 4096;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

impl Store {
    /// Open the store: a SQLite file (created 0600, never through a symlink)
    /// or, without a path, in memory (lost on restart).
    pub fn open(
        path: Option<&std::path::Path>,
        max_records: i64,
        retention_days: i64,
    ) -> Result<Self> {
        ensure!(
            (100..=1_000_000).contains(&max_records),
            "operator audit max records must be 100 to 1000000"
        );
        ensure!(
            (1..=3650).contains(&retention_days),
            "operator audit retention must be 1 to 3650 days"
        );
        let conn = match path {
            Some(p) => {
                use std::os::unix::fs::OpenOptionsExt;
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(p)
                    .with_context(|| format!("operator audit store {}", p.display()))?;
                rusqlite::Connection::open(p)?
            }
            None => rusqlite::Connection::open_in_memory()?,
        };
        conn.execute_batch(
            "PRAGMA busy_timeout = 2000;
             CREATE TABLE IF NOT EXISTS console_operator_audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 time_unix_ms INTEGER NOT NULL,
                 event TEXT NOT NULL,
                 record TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS console_operator_audit_time
                 ON console_operator_audit (time_unix_ms);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            max_records,
            retention_ms: retention_days * 86_400_000,
        })
    }

    /// Append a record (`event` names it; `time_unix_ms` is set) and prune
    /// past the bound. Returns the stored JSON line.
    pub fn record(&self, mut value: serde_json::Value) -> Result<String> {
        let now = now_ms();
        value["time_unix_ms"] = now.into();
        let event = value["event"]
            .as_str()
            .unwrap_or("console.unknown")
            .to_owned();
        let mut line = value.to_string();
        if line.len() > MAX_RECORD {
            // Keep it valid JSON: the event and time, marked truncated.
            line = serde_json::json!({"event": event, "time_unix_ms": now, "truncated": true})
                .to_string();
        }
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        conn.execute(
            "INSERT INTO console_operator_audit (time_unix_ms, event, record) VALUES (?1, ?2, ?3)",
            rusqlite::params![now, event, line],
        )?;
        let id = conn.last_insert_rowid();
        conn.execute(
            "DELETE FROM console_operator_audit WHERE id <= ?1 OR time_unix_ms < ?2",
            rusqlite::params![id - self.max_records, now - self.retention_ms],
        )?;
        Ok(line)
    }

    /// Newest first, `limit` (1 to 500) records with an id below `before`.
    /// Returns the records (each with its `id`) and the cursor for the next
    /// page, if any.
    pub fn list(
        &self,
        before: Option<i64>,
        limit: usize,
    ) -> Result<(Vec<serde_json::Value>, Option<i64>)> {
        let limit = limit.clamp(1, 500);
        let conn = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        let mut statement = conn.prepare(
            "SELECT id, record FROM console_operator_audit WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = statement
            .query_map(
                rusqlite::params![before.unwrap_or(i64::MAX), limit as i64 + 1],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let more = rows.len() > limit;
        let records: Vec<serde_json::Value> = rows
            .into_iter()
            .take(limit)
            .map(|(id, line)| {
                let mut v: serde_json::Value =
                    serde_json::from_str(&line).unwrap_or_else(|_| serde_json::json!({}));
                v["id"] = id.into();
                v
            })
            .collect();
        let next = if more {
            records.last().and_then(|r| r["id"].as_i64())
        } else {
            None
        };
        Ok((records, next))
    }

    #[cfg(test)]
    fn backdate(&self, id: i64, ms: i64) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE console_operator_audit SET time_unix_ms = ?2 WHERE id = ?1",
            rusqlite::params![id, ms],
        )
        .unwrap();
    }
}

/// `before=<id>&limit=<n>` (both optional; limit default 100).
pub fn query(query: Option<&str>) -> Result<(Option<i64>, usize)> {
    let (mut before, mut limit) = (None, 100usize);
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        match pair.split_once('=') {
            Some(("before", v)) => before = Some(v.parse().context("before")?),
            Some(("limit", v)) => {
                limit = v.parse().context("limit")?;
                ensure!((1..=500).contains(&limit), "limit must be 1 to 500");
            }
            _ => anyhow::bail!("unknown parameter"),
        }
    }
    Ok((before, limit))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_is_a_bounded_ring_with_retention() {
        let store = Store::open(None, 100, 1).unwrap();
        for i in 0..130 {
            store
                .record(serde_json::json!({"event": "console.change", "n": i}))
                .unwrap();
        }
        let (page, next) = store.list(None, 500).unwrap();
        assert_eq!(page.len(), 100, "at most max_records kept");
        assert_eq!(page[0]["n"], 129, "newest first");
        assert_eq!(page[99]["n"], 30);
        assert_eq!(next, None);
        // Paging by id.
        let (first, next) = store.list(None, 40).unwrap();
        assert_eq!(first.len(), 40);
        let (second, _) = store.list(next, 40).unwrap();
        assert_eq!(second[0]["n"], 89);
        // Retention: a record older than a day goes at the next insert.
        let oldest = page[99]["id"].as_i64().unwrap();
        store.backdate(oldest, now_ms() - 2 * 86_400_000);
        store
            .record(serde_json::json!({"event": "console.sso_login"}))
            .unwrap();
        let (page, _) = store.list(None, 500).unwrap();
        assert!(page.iter().all(|r| r["id"].as_i64() != Some(oldest)));
        assert!(page[0]["time_unix_ms"].as_i64().unwrap() > 0);
        // Oversized records are kept as a truncation marker.
        let big = "x".repeat(MAX_RECORD);
        store
            .record(serde_json::json!({"event": "console.change", "path": big}))
            .unwrap();
        let (page, _) = store.list(None, 1).unwrap();
        assert_eq!(page[0]["truncated"], true);
        assert_eq!(page[0]["event"], "console.change");
    }

    #[test]
    fn bounds_and_queries_are_checked() {
        assert!(Store::open(None, 10, 90).is_err());
        assert!(Store::open(None, 10_000, 0).is_err());
        assert_eq!(query(None).unwrap(), (None, 100));
        assert_eq!(query(Some("before=7&limit=20")).unwrap(), (Some(7), 20));
        assert!(query(Some("limit=0")).is_err());
        assert!(query(Some("limit=501")).is_err());
        assert!(query(Some("before=x")).is_err());
        assert!(query(Some("other=1")).is_err());
    }

    #[test]
    fn a_file_store_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        Store::open(Some(&path), 100, 90)
            .unwrap()
            .record(serde_json::json!({"event": "console.break_glass_login"}))
            .unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let (page, _) = Store::open(Some(&path), 100, 90)
            .unwrap()
            .list(None, 10)
            .unwrap();
        assert_eq!(page[0]["event"], "console.break_glass_login");
    }
}
