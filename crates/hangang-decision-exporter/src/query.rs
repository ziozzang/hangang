//! Read-only decision query service (ADR 0019 "Console APIs enabled").
//!
//! Every request is bounded: ≤200 rows per page, ≤31-day window, a 3 s
//! deadline and cursor pagination. Pseudonymous filters arrive already
//! computed by the Hangang broker; this service holds no key.

use crate::store::{Lane, Store};
use anyhow::Result;
use hangang_decision_event as schema;
use rusqlite::types::Value as Sql;
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

pub const MAX_PAGE: usize = 200;
pub const DEFAULT_PAGE: usize = 50;
pub const MAX_WINDOW_MS: u64 = 31 * 86_400_000;
pub const DEFAULT_WINDOW_MS: u64 = 86_400_000;
pub const DEADLINE: Duration = Duration::from_secs(3);
pub const MAX_REFS: usize = 1024;
pub const MAX_QUERY_BYTES: usize = 64 * 1024;
const FACET_LIMIT: usize = 20;
const MAX_BUCKETS: u64 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadRequest(pub &'static str);

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Filters {
    pub from_ms: u64,
    pub to_ms: u64,
    pub limit: usize,
    pub ascending: bool,
    pub cursor: Option<(u64, [u8; 16])>,
    pub lane: Option<Lane>,
    pub results: Vec<i32>,
    pub stages: Vec<i32>,
    pub reasons: Vec<String>,
    pub routes: Vec<String>,
    pub services: Vec<String>,
    pub resources: Vec<String>,
    pub classes: Vec<String>,
    pub subject_refs: Vec<String>,
    pub ip_refs: Vec<String>,
    pub prefix_refs: Vec<String>,
    pub asns: Vec<u32>,
    pub countries: Vec<String>,
    pub principals: Vec<i32>,
    pub pumgye_revisions: Vec<u64>,
    pub bucket_ms: Option<u64>,
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let hex = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                index += 3;
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

pub fn parse_pairs(query: Option<&str>) -> Result<Vec<(String, String)>, BadRequest> {
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return Ok(Vec::new());
    };
    if query.len() > MAX_QUERY_BYTES {
        return Err(BadRequest("query too long"));
    }
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            Ok((
                percent_decode(key).ok_or(BadRequest("query encoding"))?,
                percent_decode(value).ok_or(BadRequest("query encoding"))?,
            ))
        })
        .collect()
}

fn ident(value: &str) -> Result<String, BadRequest> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)))
    .then(|| value.to_owned())
    .ok_or(BadRequest("invalid identifier filter"))
}

fn enum_value(value: &str, names: &[&str]) -> Result<i32, BadRequest> {
    names
        .iter()
        .position(|name| *name == value)
        .map(|index| index as i32 + 1)
        .ok_or(BadRequest("invalid enum filter"))
}

const RESULTS: &[&str] = &["allow", "deny", "challenge", "error", "unavailable"];
const STAGES: &[&str] = &["network", "identity", "authorization", "enforcement"];
const PRINCIPALS: &[&str] = &["human", "service", "workload"];

pub fn encode_cursor(time_ms: u64, id: &[u8]) -> String {
    let mut out = format!("{time_ms:016x}");
    for byte in id {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_cursor(value: &str) -> Result<(u64, [u8; 16]), BadRequest> {
    if value.len() != 48 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BadRequest("invalid cursor"));
    }
    let time = u64::from_str_radix(&value[..16], 16).map_err(|_| BadRequest("invalid cursor"))?;
    let mut id = [0u8; 16];
    for (index, slot) in id.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[16 + index * 2..18 + index * 2], 16)
            .map_err(|_| BadRequest("invalid cursor"))?;
    }
    Ok((time, id))
}

impl Filters {
    pub fn parse(query: Option<&str>, now_ms: u64) -> Result<Self, BadRequest> {
        let mut filters = Filters {
            limit: DEFAULT_PAGE,
            lane: Some(Lane::Traffic),
            ..Default::default()
        };
        let mut from = None;
        let mut to = None;
        let mut refs = 0usize;
        for (key, value) in parse_pairs(query)? {
            match key.as_str() {
                "from" => from = Some(value.parse().map_err(|_| BadRequest("invalid from"))?),
                "to" => to = Some(value.parse().map_err(|_| BadRequest("invalid to"))?),
                "limit" => {
                    filters.limit = value
                        .parse::<usize>()
                        .ok()
                        .filter(|l| (1..=MAX_PAGE).contains(l))
                        .ok_or(BadRequest("limit must be 1..200"))?;
                }
                "order" => {
                    filters.ascending = match value.as_str() {
                        "asc" => true,
                        "desc" => false,
                        _ => return Err(BadRequest("order must be asc or desc")),
                    }
                }
                "cursor" => filters.cursor = Some(decode_cursor(&value)?),
                "kind" => {
                    filters.lane = match value.as_str() {
                        "enforced" => Some(Lane::Traffic),
                        "simulation" => Some(Lane::Simulation),
                        _ => return Err(BadRequest("kind must be enforced or simulation")),
                    }
                }
                "outcome" => filters.results.push(enum_value(&value, RESULTS)?),
                "stage" => filters.stages.push(enum_value(&value, STAGES)?),
                "principal" => filters.principals.push(enum_value(&value, PRINCIPALS)?),
                "reason" => {
                    if !schema::valid_reason(&value) {
                        return Err(BadRequest("invalid reason"));
                    }
                    filters.reasons.push(value);
                }
                "route" => filters.routes.push(ident(&value)?),
                "service" => filters.services.push(ident(&value)?),
                "resource" => filters.resources.push(ident(&value)?),
                "class" => filters.classes.push(ident(&value)?),
                "subject_ref" | "ip_ref" | "prefix_ref" => {
                    let prefix = match key.as_str() {
                        "subject_ref" => schema::SUBJECT_REF,
                        "ip_ref" => schema::IP_REF,
                        _ => schema::PREFIX_REF,
                    };
                    if !schema::is_pseudonym(prefix, &value) {
                        return Err(BadRequest("invalid pseudonymous reference"));
                    }
                    refs += 1;
                    match key.as_str() {
                        "subject_ref" => filters.subject_refs.push(value),
                        "ip_ref" => filters.ip_refs.push(value),
                        _ => filters.prefix_refs.push(value),
                    }
                }
                "asn" => filters
                    .asns
                    .push(value.parse().map_err(|_| BadRequest("invalid asn"))?),
                "country" => {
                    if value.len() != 2 || !value.bytes().all(|b| b.is_ascii_uppercase()) {
                        return Err(BadRequest("invalid country"));
                    }
                    filters.countries.push(value);
                }
                "pumgye_revision" => filters.pumgye_revisions.push(
                    value
                        .parse()
                        .map_err(|_| BadRequest("invalid pumgye_revision"))?,
                ),
                "bucket" => {
                    let seconds: u64 = value.parse().map_err(|_| BadRequest("invalid bucket"))?;
                    if !(60..=86_400).contains(&seconds) {
                        return Err(BadRequest("bucket must be 60..86400 seconds"));
                    }
                    filters.bucket_ms = Some(seconds * 1000);
                }
                _ => return Err(BadRequest("unknown filter")),
            }
            if refs > MAX_REFS {
                return Err(BadRequest("too many references"));
            }
        }
        let others = [
            filters.results.len(),
            filters.stages.len(),
            filters.reasons.len(),
            filters.routes.len(),
            filters.services.len(),
            filters.resources.len(),
            filters.classes.len(),
            filters.asns.len(),
            filters.countries.len(),
            filters.principals.len(),
            filters.pumgye_revisions.len(),
        ];
        if others.iter().any(|n| *n > 32) {
            return Err(BadRequest("too many values for one filter"));
        }
        let to: u64 = to.unwrap_or(now_ms);
        let from: u64 = from.unwrap_or_else(|| to.saturating_sub(DEFAULT_WINDOW_MS));
        if from > to {
            return Err(BadRequest("from must not exceed to"));
        }
        if to - from > MAX_WINDOW_MS {
            return Err(BadRequest("window exceeds 31 days"));
        }
        filters.from_ms = from;
        filters.to_ms = to;
        Ok(filters)
    }

    fn clause(&self, sql: &mut String, args: &mut Vec<Sql>) {
        sql.push_str(" WHERE time_ms >= ? AND time_ms <= ?");
        args.push(Sql::Integer(self.from_ms as i64));
        args.push(Sql::Integer(self.to_ms as i64));
        if let Some(lane) = self.lane {
            sql.push_str(" AND lane = ?");
            args.push(Sql::Integer(lane as i64));
        }
        fn any<T: Clone>(
            sql: &mut String,
            args: &mut Vec<Sql>,
            column: &str,
            values: &[T],
            f: impl Fn(T) -> Sql,
        ) {
            if values.is_empty() {
                return;
            }
            sql.push_str(" AND ");
            sql.push_str(column);
            sql.push_str(" IN (");
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    sql.push(',');
                }
                sql.push('?');
                args.push(f(value.clone()));
            }
            sql.push(')');
        }
        let int = |v: i32| Sql::Integer(i64::from(v));
        let text = Sql::Text;
        any(sql, args, "result", &self.results, int);
        any(sql, args, "stage", &self.stages, int);
        any(sql, args, "principal", &self.principals, int);
        any(sql, args, "reason", &self.reasons, text);
        any(sql, args, "route_id", &self.routes, text);
        any(sql, args, "service", &self.services, text);
        any(sql, args, "resource", &self.resources, text);
        any(sql, args, "info_class", &self.classes, text);
        any(sql, args, "subject_ref", &self.subject_refs, text);
        any(sql, args, "ip_ref", &self.ip_refs, text);
        any(sql, args, "prefix_ref", &self.prefix_refs, text);
        any(sql, args, "country", &self.countries, text);
        any(sql, args, "asn", &self.asns, |v| Sql::Integer(i64::from(v)));
        any(sql, args, "rev_pumgye", &self.pumgye_revisions, |v| {
            Sql::Integer(v.min(i64::MAX as u64) as i64)
        });
    }
}

/// Runs `work` on a read-only connection with the query deadline enforced by
/// SQLite interruption.
pub async fn with_reader<T: Send + 'static>(
    path: &Path,
    work: impl FnOnce(&rusqlite::Connection) -> Result<T> + Send + 'static,
) -> Result<T> {
    let path = path.to_owned();
    let (handle_tx, handle_rx) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || {
        let conn = Store::reader(&path)?;
        let _ = handle_tx.send(conn.get_interrupt_handle());
        work(&conn)
    });
    let interrupt = handle_rx.await.ok();
    match tokio::time::timeout(DEADLINE, task).await {
        Ok(joined) => joined?,
        Err(_) => {
            if let Some(handle) = interrupt {
                handle.interrupt();
            }
            anyhow::bail!("query deadline exceeded")
        }
    }
}

fn event_json(body: &[u8], ppm: i64) -> Option<Value> {
    let event = schema::decode(body).ok()?;
    let mut value = schema::to_json(&event);
    if ppm > 0 && ppm < 1_000_000 {
        value["estimate_weight"] = json!(1_000_000.0 / ppm as f64);
    }
    Some(value)
}

pub fn list(conn: &rusqlite::Connection, filters: &Filters) -> Result<Value> {
    let mut sql = String::from("SELECT time_ms, event_id, body, sample_ppm FROM events");
    let mut args = Vec::new();
    filters.clause(&mut sql, &mut args);
    if let Some((time, id)) = filters.cursor {
        let op = if filters.ascending { '>' } else { '<' };
        sql.push_str(&format!(
            " AND (time_ms {op} ? OR (time_ms = ? AND event_id {op} ?))"
        ));
        args.push(Sql::Integer(time as i64));
        args.push(Sql::Integer(time as i64));
        args.push(Sql::Blob(id.to_vec()));
    }
    let order = if filters.ascending { "ASC" } else { "DESC" };
    sql.push_str(&format!(
        " ORDER BY time_ms {order}, event_id {order} LIMIT ?"
    ));
    args.push(Sql::Integer(filters.limit as i64 + 1));
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(args))?;
    let mut items = Vec::new();
    let mut last = None;
    let mut more = false;
    while let Some(row) = rows.next()? {
        if items.len() == filters.limit {
            more = true;
            break;
        }
        let time: i64 = row.get(0)?;
        let id: Vec<u8> = row.get(1)?;
        let body: Vec<u8> = row.get(2)?;
        let ppm: i64 = row.get(3)?;
        if let Some(value) = event_json(&body, ppm) {
            items.push(value);
        }
        last = Some((time as u64, id));
    }
    Ok(json!({
        "state": "enabled",
        "window": {"from_ms": filters.from_ms, "to_ms": filters.to_ms},
        "items": items,
        "next_cursor": if more { last.map(|(t, id)| encode_cursor(t, &id)) } else { None },
    }))
}

pub fn facets(conn: &rusqlite::Connection, filters: &Filters) -> Result<Value> {
    let mut out = serde_json::Map::new();
    for (name, column) in [
        ("outcome", "result"),
        ("stage", "stage"),
        ("reason", "reason"),
        ("route", "route_id"),
        ("service", "service"),
        ("class", "info_class"),
        ("country", "country"),
        ("asn", "asn"),
        ("sampled", "sample_class"),
    ] {
        let mut sql = format!(
            "SELECT {column}, COUNT(*), SUM(CASE WHEN suppressed > 0 THEN suppressed WHEN sample_ppm > 0 THEN 1000000.0 / sample_ppm ELSE 1 END) FROM events"
        );
        let mut args = Vec::new();
        filters.clause(&mut sql, &mut args);
        sql.push_str(&format!(
            " AND {column} IS NOT NULL GROUP BY {column} ORDER BY COUNT(*) DESC LIMIT {FACET_LIMIT}"
        ));
        let mut statement = conn.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(args))?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            let value: Value = match column {
                "result" => Value::String(schema::result_text(row.get(0)?)),
                "stage" => Value::String(schema::stage_text(row.get(0)?)),
                "sample_class" => Value::String(schema::sample_class_text(row.get(0)?)),
                "asn" => Value::from(row.get::<_, i64>(0)?),
                _ => Value::String(row.get(0)?),
            };
            let count: i64 = row.get(1)?;
            let estimate: f64 = row.get(2)?;
            values.push(json!({
                "value": value,
                "events": count,
                "estimated_requests": estimate.round() as i64,
                "estimate": (estimate - count as f64).abs() > f64::EPSILON,
            }));
        }
        out.insert(name.into(), Value::Array(values));
    }
    Ok(json!({
        "state": "enabled",
        "window": {"from_ms": filters.from_ms, "to_ms": filters.to_ms},
        "facets": out,
        "note": "allow counts are estimates derived from the sample rate; Prometheus counters are authoritative",
    }))
}

pub fn timeseries(conn: &rusqlite::Connection, filters: &Filters) -> Result<Value> {
    let span = filters.to_ms.saturating_sub(filters.from_ms).max(1);
    let bucket = filters
        .bucket_ms
        .unwrap_or_else(|| {
            [60_000u64, 300_000, 3_600_000, 86_400_000]
                .into_iter()
                .find(|b| span / b <= 500)
                .unwrap_or(86_400_000)
        })
        .max(span.div_ceil(MAX_BUCKETS));
    let mut sql = String::from(
        "SELECT (time_ms / ?) * ?, result, COUNT(*), SUM(CASE WHEN suppressed > 0 THEN suppressed WHEN sample_ppm > 0 THEN 1000000.0 / sample_ppm ELSE 1 END) FROM events",
    );
    let mut args = vec![Sql::Integer(bucket as i64), Sql::Integer(bucket as i64)];
    filters.clause(&mut sql, &mut args);
    sql.push_str(" GROUP BY 1, 2 ORDER BY 1 ASC");
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(args))?;
    let mut points = Vec::new();
    while let Some(row) = rows.next()? {
        let start: i64 = row.get(0)?;
        let result: i32 = row.get(1)?;
        let events: i64 = row.get(2)?;
        let estimate: f64 = row.get(3)?;
        points.push(json!({
            "start_ms": start,
            "outcome": schema::result_text(result),
            "events": events,
            "estimated_requests": estimate.round() as i64,
        }));
    }
    Ok(json!({
        "state": "enabled",
        "window": {"from_ms": filters.from_ms, "to_ms": filters.to_ms},
        "bucket_seconds": bucket / 1000,
        "points": points,
    }))
}

pub fn valid_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

/// All events of one request (retries, simulations) in time order.
pub fn request(conn: &rusqlite::Connection, request_id: &str) -> Result<Value> {
    let mut statement = conn.prepare(
        "SELECT body, sample_ppm FROM events WHERE request_id = ? ORDER BY time_ms ASC, event_id ASC LIMIT 64",
    )?;
    let mut rows = statement.query([request_id])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        let body: Vec<u8> = row.get(0)?;
        let ppm: i64 = row.get(1)?;
        if let Some(value) = event_json(&body, ppm) {
            events.push(value);
        }
    }
    Ok(json!({"state": "enabled", "request_id": request_id, "events": events}))
}
