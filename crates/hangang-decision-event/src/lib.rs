//! `hangang.decision.v1`: bounded access-decision events (ADR 0019).
//!
//! This crate owns the wire schema, the length-delimited batch framing, the
//! validation applied by every receiver, the stable reason-code registry and
//! the JSON projection served to the console. It owns no policy, no key and no
//! storage: pseudonymization and sealing happen in the emitter, retention in the
//! exporter.

pub mod reasons;

#[allow(clippy::all, clippy::pedantic)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/hangang.decision.v1.rs"));
}

use prost::Message;
use serde_json::{Map, Value, json};
use v1::{
    Authority, AuthorizationDecision, DecisionEvent, EnforcementAction, Factor, Fence, GuardMode,
    IdentityVerdict, Kind, NetworkVerdict, PrincipalKind, PrivacyProfile, SampleClass, Stage,
    Transport, stage_verdict,
};

pub const SCHEMA: &str = "hangang.decision.v1";
/// Encoded size cap of one event.
pub const MAX_EVENT_BYTES: usize = 2048;
pub const MAX_RULES: usize = 8;
pub const MAX_ROLES: usize = 8;
pub const MAX_FACTORS: usize = 6;
pub const MAX_OBLIGATIONS: usize = 8;
pub const MAX_STAGES: usize = 4;
/// Events per transport batch.
pub const MAX_BATCH_EVENTS: usize = 512;
/// Upper bound of one batch frame payload (events plus their varint prefixes).
pub const MAX_FRAME_BYTES: usize = MAX_BATCH_EVENTS * (MAX_EVENT_BYTES + 3);
/// Opaque Hopae subject IDs larger than this are never sealed.
pub const MAX_SEALED_SUBJECT_PLAINTEXT: usize = 128;
/// 12-byte nonce + plaintext + 16-byte tag.
pub const SEAL_OVERHEAD: usize = 28;

/// Pseudonym type prefixes; domain separation is applied by the emitter.
pub const IP_REF: &str = "ip";
pub const PREFIX_REF: &str = "pfx";
pub const SUBJECT_REF: &str = "sub";
pub const SESSION_REF: &str = "ses";
/// 80-bit truncated HMAC in Crockford base32.
pub const REF_CHARS: usize = 16;

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid decision event: {}", self.0)
    }
}
impl std::error::Error for Invalid {}

/// Crockford base32 without padding, most significant bits first.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(CROCKFORD[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(CROCKFORD[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `prefix~BASE32` of the first 80 bits of a keyed digest.
pub fn pseudonym(prefix: &str, digest: &[u8]) -> String {
    let mut out = String::with_capacity(prefix.len() + 1 + REF_CHARS);
    out.push_str(prefix);
    out.push('~');
    out.push_str(&base32(&digest[..10]));
    out
}

pub fn is_pseudonym(prefix: &str, value: &str) -> bool {
    value
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_prefix('~'))
        .is_some_and(|body| body.len() == REF_CHARS && body.bytes().all(|b| CROCKFORD.contains(&b)))
}

/// 26-character ULID text of a 16-byte event ID.
pub fn event_id_text(id: &[u8]) -> Option<String> {
    let id: [u8; 16] = id.try_into().ok()?;
    let value = u128::from_be_bytes(id);
    let mut out = [0u8; 26];
    for (index, slot) in out.iter_mut().enumerate() {
        let shift = 125 - index * 5;
        *slot = CROCKFORD[((value >> shift) & 31) as usize];
    }
    Some(String::from_utf8(out.to_vec()).expect("ASCII"))
}

pub fn parse_event_id(text: &str) -> Option<[u8; 16]> {
    if text.len() != 26 {
        return None;
    }
    let mut value = 0u128;
    for (index, byte) in text.bytes().enumerate() {
        let digit = CROCKFORD
            .iter()
            .position(|c| *c == byte.to_ascii_uppercase())? as u128;
        if index == 0 && digit > 7 {
            return None;
        }
        value = (value << 5) | digit;
    }
    Some(value.to_be_bytes())
}

/// Builds a sortable 128-bit ID from milliseconds and 80 caller-supplied random bits.
pub fn event_id(unix_ms: u64, random: [u8; 10]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..6].copy_from_slice(&unix_ms.to_be_bytes()[2..]);
    id[6..].copy_from_slice(&random);
    id
}

/// RFC 3339 UTC with millisecond precision.
pub fn rfc3339_ms(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let millis = unix_ms % 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to proleptic Gregorian (Howard Hinnant's algorithm).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Identifier fields: `[A-Za-z0-9_.:-]`, bounded, never an IP literal.
pub fn identifier(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        && value.parse::<std::net::IpAddr>().is_err()
}

fn optional_identifier(value: &str, max: usize) -> bool {
    value.is_empty() || identifier(value, max)
}

/// Configured route host (lowercase DNS name or wildcard), never an IP literal.
pub fn host(value: &str) -> bool {
    value.is_empty()
        || (value.len() <= 253
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-.*".contains(&b))
            && value.parse::<std::net::IpAddr>().is_err())
}

/// Configured route template; no query, encoding or parameters.
pub fn path_template(value: &str) -> bool {
    value.is_empty()
        || (value.starts_with('/')
            && value.len() <= 256
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-._~{}*".contains(&b)))
}

fn method(value: &str) -> bool {
    value.is_empty() || (value.len() <= 16 && value.bytes().all(|b| b.is_ascii_uppercase()))
}

pub fn valid_reason(code: &str) -> bool {
    let Some((namespace, name)) = code.split_once('.') else {
        return false;
    };
    matches!(namespace, "sumunjang" | "hopae" | "pumgye" | "hangang")
        && !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn reference(prefix: &str, value: &str) -> bool {
    value.is_empty() || is_pseudonym(prefix, value)
}

fn list(values: &[String], max: usize, item: usize) -> bool {
    values.len() <= max && values.iter().all(|v| identifier(v, item))
}

fn stage_rank(stage: &stage_verdict::Stage) -> u8 {
    match stage {
        stage_verdict::Stage::Network(_) => 1,
        stage_verdict::Stage::Identity(_) => 2,
        stage_verdict::Stage::Authorization(_) => 3,
        stage_verdict::Stage::Enforcement(_) => 4,
    }
}

/// Receiver-side validation. Unknown enum values are accepted (forward
/// compatibility) and projected as `unspecified`; everything that could carry
/// free text, raw addresses, e-mail or a request path is rejected.
pub fn validate(event: &DecisionEvent) -> Result<(), Invalid> {
    if event.encoded_len() > MAX_EVENT_BYTES {
        return Err(Invalid("event exceeds 2 KiB"));
    }
    if event.schema != SCHEMA {
        return Err(Invalid("schema"));
    }
    if event.event_id.len() != 16 {
        return Err(Invalid("event_id"));
    }
    if !identifier(&event.request_id, 64) {
        return Err(Invalid("request_id"));
    }
    if event.time_unix_ms == 0 || event.time_unix_ms >= 1 << 48 {
        return Err(Invalid("time"));
    }
    let id_ms = u64::from_be_bytes([
        0,
        0,
        event.event_id[0],
        event.event_id[1],
        event.event_id[2],
        event.event_id[3],
        event.event_id[4],
        event.event_id[5],
    ]);
    if id_ms.abs_diff(event.time_unix_ms) > 86_400_000 {
        return Err(Invalid("event_id time"));
    }
    let emitter = event.emitter.as_ref().ok_or(Invalid("emitter"))?;
    if !identifier(&emitter.component, 32)
        || !optional_identifier(&emitter.instance, 64)
        || !optional_identifier(&emitter.build, 32)
    {
        return Err(Invalid("emitter"));
    }
    if let Some(route) = &event.route
        && (!optional_identifier(&route.listener, 128)
            || !host(&route.host)
            || !optional_identifier(&route.route_id, 128)
            || !path_template(&route.path_template)
            || !method(&route.method)
            || !optional_identifier(&route.service, 128)
            || !optional_identifier(&route.resource, 128)
            || !optional_identifier(&route.action, 128))
    {
        return Err(Invalid("route"));
    }
    let outcome = event.outcome.as_ref().ok_or(Invalid("outcome"))?;
    if !valid_reason(&outcome.reason) || outcome.status > 999 {
        return Err(Invalid("outcome"));
    }
    let profile = event
        .privacy
        .as_ref()
        .map(|p| PrivacyProfile::try_from(p.profile).unwrap_or(PrivacyProfile::Unspecified))
        .unwrap_or(PrivacyProfile::Unspecified);
    if let Some(privacy) = &event.privacy
        && (privacy.key_epoch.len() > 32
            || !privacy
                .key_epoch
                .bytes()
                .all(|b| b.is_ascii_digit() || b"-:TZ".contains(&b)))
    {
        return Err(Invalid("privacy"));
    }
    let sealed_allowed = profile == PrivacyProfile::Standard;
    if event.stages.len() > MAX_STAGES {
        return Err(Invalid("too many stages"));
    }
    let mut last = 0;
    for stage in &event.stages {
        let stage = stage.stage.as_ref().ok_or(Invalid("empty stage"))?;
        let rank = stage_rank(stage);
        if rank <= last {
            return Err(Invalid("stage order"));
        }
        last = rank;
        match stage {
            stage_verdict::Stage::Network(network) => {
                if !list(&network.rules, MAX_RULES, 64)
                    || !reference(IP_REF, &network.ip_ref)
                    || !reference(PREFIX_REF, &network.prefix_ref)
                    || !(network.country.is_empty()
                        || (network.country.len() == 2
                            && network.country.bytes().all(|b| b.is_ascii_uppercase())))
                    || (!network.sealed_ip.is_empty()
                        && (!sealed_allowed || network.sealed_ip.len() > SEAL_OVERHEAD + 16))
                {
                    return Err(Invalid("network stage"));
                }
            }
            stage_verdict::Stage::Identity(identity) => {
                if !reference(SUBJECT_REF, &identity.subject_ref)
                    || !reference(SESSION_REF, &identity.session_ref)
                    || !optional_identifier(&identity.provider, 64)
                    || identity.factors.len() > MAX_FACTORS
                    || identity.aal.is_some_and(|aal| aal > 3)
                    || (!identity.sealed_subject.is_empty()
                        && (!sealed_allowed
                            || identity.sealed_subject.len()
                                > SEAL_OVERHEAD + MAX_SEALED_SUBJECT_PLAINTEXT))
                {
                    return Err(Invalid("identity stage"));
                }
            }
            stage_verdict::Stage::Authorization(authorization) => {
                if !list(&authorization.roles, MAX_ROLES, 64)
                    || !optional_identifier(&authorization.information_class, 64)
                    || authorization.required_aal.is_some_and(|aal| aal > 3)
                    || authorization.permit_digest.len() > 16
                    || !authorization
                        .permit_digest
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                {
                    return Err(Invalid("authorization stage"));
                }
            }
            stage_verdict::Stage::Enforcement(enforcement) => {
                if !list(&enforcement.obligations, MAX_OBLIGATIONS, 64)
                    || enforcement.upstream_status_class > 5
                {
                    return Err(Invalid("enforcement stage"));
                }
            }
        }
    }
    if let Some(sampling) = &event.sampling
        && sampling.rate_ppm > 1_000_000
    {
        return Err(Invalid("sampling"));
    }
    if let Some(suppressed) = &event.suppressed
        && (suppressed.count == 0
            || suppressed.first_unix_ms > suppressed.last_unix_ms
            || suppressed.window_seconds == 0)
    {
        return Err(Invalid("suppressed"));
    }
    Ok(())
}

/// Bounded decode of one event followed by validation.
pub fn decode(bytes: &[u8]) -> Result<DecisionEvent, Invalid> {
    if bytes.len() > MAX_EVENT_BYTES {
        return Err(Invalid("event exceeds 2 KiB"));
    }
    let event = DecisionEvent::decode(bytes).map_err(|_| Invalid("protobuf"))?;
    validate(&event)?;
    Ok(event)
}

/// Frame: 4-byte big-endian payload length, then length-delimited events.
pub fn encode_frame(events: &[Vec<u8>]) -> Vec<u8> {
    let payload: usize = events
        .iter()
        .map(|e| prost::length_delimiter_len(e.len()) + e.len())
        .sum();
    let mut out = Vec::with_capacity(4 + payload);
    out.extend_from_slice(&(payload as u32).to_be_bytes());
    for event in events {
        prost::encode_length_delimiter(event.len(), &mut out).expect("vector grows");
        out.extend_from_slice(event);
    }
    out
}

/// Splits a frame payload into encoded events without copying.
pub fn split_payload(mut payload: &[u8]) -> Result<Vec<&[u8]>, Invalid> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(Invalid("frame too large"));
    }
    let mut events = Vec::new();
    while !payload.is_empty() {
        if events.len() == MAX_BATCH_EVENTS {
            return Err(Invalid("too many events in batch"));
        }
        let len = prost::decode_length_delimiter(&mut payload).map_err(|_| Invalid("framing"))?;
        if len > MAX_EVENT_BYTES || len > payload.len() {
            return Err(Invalid("framing"));
        }
        events.push(&payload[..len]);
        payload = &payload[len..];
    }
    Ok(events)
}

fn snake(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, ch) in name.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

macro_rules! enum_text {
    ($ty:ty, $value:expr) => {
        match <$ty>::try_from($value) {
            Ok(<$ty>::Unspecified) | Err(_) => "unspecified".to_owned(),
            Ok(v) => snake(&format!("{v:?}")),
        }
    };
}

pub fn result_text(value: i32) -> String {
    enum_text!(v1::Result, value)
}
pub fn stage_text(value: i32) -> String {
    enum_text!(Stage, value)
}
pub fn kind_text(value: i32) -> String {
    enum_text!(Kind, value)
}
pub fn principal_text(value: i32) -> String {
    enum_text!(PrincipalKind, value)
}
pub fn sample_class_text(value: i32) -> String {
    enum_text!(SampleClass, value)
}
/// Exact `pumgye_core::Decision` variant spelling for authorization stages.
pub fn authorization_text(value: i32) -> String {
    match AuthorizationDecision::try_from(value) {
        Ok(AuthorizationDecision::Unspecified) | Err(_) => "Unspecified".to_owned(),
        Ok(v) => format!("{v:?}"),
    }
}

fn optional<T: Into<Value>>(value: Option<T>) -> Value {
    value.map_or(Value::Null, Into::into)
}

fn strings(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::String).collect())
}

fn nonempty(value: &str) -> Value {
    if value.is_empty() {
        Value::Null
    } else {
        Value::String(value.to_owned())
    }
}

/// Console projection. Sealed values are never projected; only their presence
/// is reported so a privileged reveal operation can be offered.
pub fn to_json(event: &DecisionEvent) -> Value {
    let mut stages = Vec::with_capacity(event.stages.len());
    for stage in &event.stages {
        let Some(stage) = &stage.stage else { continue };
        stages.push(match stage {
            stage_verdict::Stage::Network(n) => json!({
                "stage": "network",
                "authority": "sumunjang",
                "verdict": enum_text!(NetworkVerdict, n.verdict),
                "mode": enum_text!(GuardMode, n.mode),
                "rules": strings(&n.rules),
                "rules_truncated": n.rules_truncated,
                "revision": optional(n.revision),
                "latency_us": n.latency_us,
                "transport": enum_text!(Transport, n.transport),
                "client": {
                    "ip_ref": nonempty(&n.ip_ref),
                    "prefix_ref": nonempty(&n.prefix_ref),
                    "asn": optional(n.asn),
                    "country": nonempty(&n.country),
                    "sealed": !n.sealed_ip.is_empty(),
                },
            }),
            stage_verdict::Stage::Identity(i) => json!({
                "stage": "identity",
                "authority": enum_text!(Authority, i.authority),
                "verdict": enum_text!(IdentityVerdict, i.verdict),
                "subject_ref": nonempty(&i.subject_ref),
                "subject_sealed": !i.sealed_subject.is_empty(),
                "principal": enum_text!(PrincipalKind, i.principal),
                "provider": nonempty(&i.provider),
                "aal": optional(i.aal),
                "factors": Value::Array(i.factors.iter().map(|f| Value::String(enum_text!(Factor, *f))).collect()),
                "factors_truncated": i.factors_truncated,
                "session_ref": nonempty(&i.session_ref),
                "generation": optional(i.generation),
                "latency_us": i.latency_us,
                "transport": enum_text!(Transport, i.transport),
            }),
            stage_verdict::Stage::Authorization(a) => json!({
                "stage": "authorization",
                "authority": "pumgye",
                "decision": authorization_text(a.decision),
                "roles": strings(&a.roles),
                "roles_truncated": a.roles_truncated,
                "information_class": nonempty(&a.information_class),
                "required_aal": optional(a.required_aal),
                "revision": optional(a.revision),
                "permit": nonempty(&a.permit_digest),
                "latency_us": a.latency_us,
                "transport": enum_text!(Transport, a.transport),
            }),
            stage_verdict::Stage::Enforcement(e) => json!({
                "stage": "enforcement",
                "authority": "hangang",
                "action": enum_text!(EnforcementAction, e.action),
                "obligations": strings(&e.obligations),
                "obligations_truncated": e.obligations_truncated,
                "fence": enum_text!(Fence, e.fence),
                "revision": optional(e.revision),
                "upstream_status_class": if e.upstream_status_class == 0 { Value::Null } else { Value::from(e.upstream_status_class) },
            }),
        });
    }
    let mut out = Map::new();
    out.insert("schema".into(), Value::String(event.schema.clone()));
    out.insert("event_id".into(), optional(event_id_text(&event.event_id)));
    out.insert("kind".into(), Value::String(kind_text(event.kind)));
    out.insert("request_id".into(), Value::String(event.request_id.clone()));
    out.insert("time".into(), Value::String(rfc3339_ms(event.time_unix_ms)));
    if let Some(e) = &event.emitter {
        out.insert(
            "emitter".into(),
            json!({"component": e.component, "instance": nonempty(&e.instance), "build": nonempty(&e.build)}),
        );
    }
    if let Some(r) = &event.route {
        out.insert(
            "route".into(),
            json!({
                "listener": nonempty(&r.listener), "host": nonempty(&r.host),
                "route_id": nonempty(&r.route_id), "path_template": nonempty(&r.path_template),
                "method": nonempty(&r.method), "service": nonempty(&r.service),
                "resource": nonempty(&r.resource), "action": nonempty(&r.action),
            }),
        );
    }
    if let Some(o) = &event.outcome {
        out.insert(
            "outcome".into(),
            json!({
                "result": result_text(o.result), "status": o.status,
                "deciding_stage": stage_text(o.deciding_stage), "reason": o.reason,
                "message_key": reasons::message_key(&o.reason),
            }),
        );
    }
    out.insert("stages".into(), Value::Array(stages));
    let revisions = event.revisions.unwrap_or_default();
    let mut vector = Map::new();
    for (name, value) in [
        ("hangang", revisions.hangang),
        ("sumunjang", revisions.sumunjang),
        ("hopae", revisions.hopae),
        ("pumgye", revisions.pumgye),
        ("catalog", revisions.catalog),
    ] {
        if let Some(value) = value {
            vector.insert(name.into(), Value::from(value));
        }
    }
    out.insert("revisions".into(), Value::Object(vector));
    if let Some(s) = &event.sampling {
        out.insert(
            "sampling".into(),
            json!({"class": sample_class_text(s.class), "rate": f64::from(s.rate_ppm) / 1_000_000.0}),
        );
    }
    if let Some(p) = &event.privacy {
        out.insert(
            "privacy".into(),
            json!({"profile": enum_text!(PrivacyProfile, p.profile), "key_epoch": nonempty(&p.key_epoch)}),
        );
    }
    if let Some(s) = &event.suppressed {
        out.insert(
            "suppressed".into(),
            json!({"count": s.count, "first": rfc3339_ms(s.first_unix_ms), "last": rfc3339_ms(s.last_unix_ms), "window_seconds": s.window_seconds}),
        );
    }
    Value::Object(out)
}

/// Removes sealed values. Every sink other than the local store receives
/// only this projection.
pub fn without_sealed(mut event: DecisionEvent) -> DecisionEvent {
    for stage in &mut event.stages {
        match &mut stage.stage {
            Some(stage_verdict::Stage::Network(n)) => n.sealed_ip.clear(),
            Some(stage_verdict::Stage::Identity(i)) => i.sealed_subject.clear(),
            _ => {}
        }
    }
    event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_and_ulid_round_trip() {
        assert_eq!(base32(&[0xff; 10]).len(), REF_CHARS);
        let id = event_id(1_760_605_964_512, [7; 10]);
        let text = event_id_text(&id).unwrap();
        assert_eq!(text.len(), 26);
        assert_eq!(parse_event_id(&text), Some(id));
        assert!(parse_event_id("8ZZZZZZZZZZZZZZZZZZZZZZZZZ").is_none());
        // Sortable by time.
        let later = event_id_text(&event_id(1_760_605_964_513, [0; 10])).unwrap();
        assert!(later > text);
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_760_605_964_512), "2025-10-16T09:12:44.512Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
    }
}
