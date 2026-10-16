//! Administration broker for the decision query service (ADR 0019/0020).
//!
//! The exporter holds no key. Forward lookup by user or address is computed
//! here: the raw subject or address is converted into the pseudonyms of every
//! retained key epoch overlapping the query window and never forwarded.
//! Destroyed epochs cannot be searched (crypto-shredding).

use super::{Emitter, Subject, keys::KeyRing, schema};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use std::sync::Arc;
use std::time::Duration;

pub const EXPORTER_TIMEOUT: Duration = Duration::from_secs(4);
pub const MAX_REPLY_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_BYTES: usize = 16 * 1024;
const MAX_FORWARD_EPOCHS: u64 = 1024;
/// Matches nothing: used when no retained epoch can express a lookup.
const NO_MATCH: &str = "0000000000000000";

pub struct Reply {
    pub status: u16,
    pub body: serde_json::Value,
}

fn reply(status: u16, body: serde_json::Value) -> Reply {
    Reply { status, body }
}

fn problem(status: u16, detail: &str) -> Reply {
    reply(
        status,
        serde_json::json!({"status": status, "detail": detail}),
    )
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

fn percent_encode(value: &str, out: &mut String) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
}

/// Epoch indexes overlapping the query window that still have a key.
fn window_epochs(keys: &KeyRing, from_ms: u64, to_ms: u64) -> Vec<u64> {
    let first = keys.epoch_index(from_ms);
    let last = keys.epoch_index(to_ms).min(first + MAX_FORWARD_EPOCHS);
    keys.epochs()
        .filter(|e| *e >= first && *e <= last)
        .collect()
}

/// Rewrites console filters for the exporter. Returns the forwarded query.
pub fn translate(query: Option<&str>, keys: &KeyRing, now_ms: u64) -> Result<String, &'static str> {
    let query = query.unwrap_or("");
    if query.len() > MAX_QUERY_BYTES {
        return Err("query too long");
    }
    let mut pairs = Vec::new();
    let mut from = None;
    let mut to = None;
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key).ok_or("query encoding")?;
        let value = percent_decode(value).ok_or("query encoding")?;
        match key.as_str() {
            "from" => from = Some(value.parse::<u64>().map_err(|_| "invalid from")?),
            "to" => to = Some(value.parse::<u64>().map_err(|_| "invalid to")?),
            _ => {}
        }
        pairs.push((key, value));
    }
    let to_ms = to.unwrap_or(now_ms);
    let from_ms = from.unwrap_or_else(|| to_ms.saturating_sub(86_400_000));
    if from_ms > to_ms {
        return Err("from must not exceed to");
    }
    let epochs = window_epochs(keys, from_ms, to_ms);
    let mut out = String::new();
    let mut push = |key: &str, value: &str| {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(key);
        out.push('=');
        percent_encode(value, &mut out);
    };
    let mut forward_lookups = 0usize;
    for (key, value) in &pairs {
        match key.as_str() {
            "subject" | "ip" | "prefix" => {
                forward_lookups += 1;
                if forward_lookups > 8 {
                    return Err("too many forward lookups");
                }
                let mut refs = Vec::with_capacity(epochs.len());
                match key.as_str() {
                    "subject" => {
                        if value.is_empty() || value.len() > 1024 {
                            return Err("invalid subject");
                        }
                        let mut input = Vec::new();
                        Subject::new(value.as_bytes()).pseudonym_input(&mut input);
                        for epoch in &epochs {
                            refs.extend(keys.subject_ref(*epoch, &input));
                        }
                    }
                    "ip" => {
                        let ip: std::net::IpAddr = value.parse().map_err(|_| "invalid ip")?;
                        for epoch in &epochs {
                            refs.extend(keys.ip_ref(*epoch, ip));
                        }
                    }
                    _ => {
                        let ip: std::net::IpAddr = value
                            .split('/')
                            .next()
                            .unwrap_or_default()
                            .parse()
                            .map_err(|_| "invalid prefix")?;
                        for epoch in &epochs {
                            refs.extend(keys.prefix_ref(*epoch, ip));
                        }
                    }
                }
                let name = match key.as_str() {
                    "subject" => "subject_ref",
                    "ip" => "ip_ref",
                    _ => "prefix_ref",
                };
                let prefix = match key.as_str() {
                    "subject" => schema::SUBJECT_REF,
                    "ip" => schema::IP_REF,
                    _ => schema::PREFIX_REF,
                };
                if refs.is_empty() {
                    push(name, &format!("{prefix}~{NO_MATCH}"));
                }
                for value in refs {
                    push(name, &value);
                }
            }
            _ => push(key, value),
        }
    }
    if from.is_none() {
        push("from", &from_ms.to_string());
    }
    if to.is_none() {
        push("to", &to_ms.to_string());
    }
    Ok(out)
}

/// GET against the exporter's query socket with a bounded reply.
pub async fn exporter_get(socket: &std::path::Path, path_and_query: &str) -> Result<Reply, ()> {
    let exchange = async {
        let stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|_| ())?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .map_err(|_| ())?;
        let driver = tokio::spawn(connection);
        let request = hyper::Request::get(path_and_query)
            .header(hyper::header::HOST, "decision-exporter")
            .body(Empty::<Bytes>::new())
            .map_err(|_| ())?;
        let response = sender.send_request(request).await.map_err(|_| ())?;
        let status = response.status().as_u16();
        let body = Limited::new(response.into_body(), MAX_REPLY_BYTES)
            .collect()
            .await
            .map_err(|_| ())?
            .to_bytes();
        driver.abort();
        let body = serde_json::from_slice(&body).map_err(|_| ())?;
        Ok(reply(status, body))
    };
    tokio::time::timeout(EXPORTER_TIMEOUT, exchange)
        .await
        .map_err(|_| ())?
}

fn disabled() -> Reply {
    reply(
        200,
        serde_json::json!({
            "state": "disabled",
            "profile": "off",
            "detail": "decision events are disabled; simulation remains available through live explain",
        }),
    )
}

fn unavailable() -> Reply {
    problem(503, "decision exporter unavailable")
}

/// Handles `/v1/observability/*` after the caller enforced the
/// administrator role. Only GET is served.
pub async fn handle(emitter: Option<&Arc<Emitter>>, path: &str, query: Option<&str>) -> Reply {
    let Some(emitter) = emitter else {
        return match path {
            "/v1/observability/status"
            | "/v1/observability/decisions"
            | "/v1/observability/decisions/facets"
            | "/v1/observability/decisions/timeseries" => disabled(),
            p if p.starts_with("/v1/observability/requests/") => disabled(),
            _ => problem(404, "unknown observability operation"),
        };
    };
    let socket = emitter.config.query_socket.clone();
    match path {
        "/v1/observability/status" => {
            if query.is_some() {
                return problem(400, "query parameters unsupported");
            }
            let mut status = emitter.status();
            status["store"] = match &socket {
                Some(socket) => match exporter_get(socket, "/v1/status").await {
                    Ok(reply) if reply.status == 200 => reply.body,
                    _ => serde_json::json!({"state": "unavailable"}),
                },
                None => serde_json::json!({"state": "not_configured"}),
            };
            reply(200, status)
        }
        "/v1/observability/decisions"
        | "/v1/observability/decisions/facets"
        | "/v1/observability/decisions/timeseries" => {
            let Some(socket) = socket else {
                return problem(503, "decision query service is not configured");
            };
            let keys = emitter.keys.load_full();
            let forwarded = match translate(query, &keys, super::now_ms()) {
                Ok(forwarded) => forwarded,
                Err(detail) => return problem(400, detail),
            };
            let target = format!(
                "/v1{}?{forwarded}",
                path.strip_prefix("/v1/observability")
                    .expect("matched prefix")
            );
            let mut result = exporter_get(&socket, &target)
                .await
                .unwrap_or_else(|()| unavailable());
            if result.status == 200 {
                result.body["profile"] = serde_json::json!(emitter.profile().as_str());
            }
            result
        }
        _ => match path.strip_prefix("/v1/observability/requests/") {
            Some(id)
                if !id.is_empty()
                    && id.len() <= 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)) =>
            {
                if query.is_some() {
                    return problem(400, "query parameters unsupported");
                }
                let Some(socket) = socket else {
                    return problem(503, "decision query service is not configured");
                };
                exporter_get(&socket, &format!("/v1/requests/{id}"))
                    .await
                    .unwrap_or_else(|()| unavailable())
            }
            Some(_) => problem(400, "invalid request_id"),
            None => problem(404, "unknown observability operation"),
        },
    }
}
