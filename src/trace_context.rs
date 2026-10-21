//! W3C Trace Context (`traceparent`) propagation without a span exporter.
//!
//! A valid `traceparent` from a trusted proxy is kept unchanged together with
//! its `tracestate`. Anything else (an untrusted peer, a missing, repeated or
//! malformed header) is replaced by a freshly generated, unsampled context, and
//! a stale `tracestate` is removed with it. The normalized request headers then
//! reach the upstream and the external authorization service.

use hyper::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};

pub const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");
pub const TRACESTATE: HeaderName = HeaderName::from_static("tracestate");

/// Trace ID of a version-00 `traceparent`, or `None` when it is malformed.
/// Only lowercase hex is accepted; all-zero trace or parent IDs are invalid.
pub fn trace_id(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    if bytes.len() != 55 || bytes[2] != b'-' || bytes[35] != b'-' || bytes[52] != b'-' {
        return None;
    }
    let lower_hex = |part: &str| part.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    let (version, trace, parent, flags) =
        (&value[..2], &value[3..35], &value[36..52], &value[53..]);
    if version != "00"
        || ![version, trace, parent, flags].into_iter().all(lower_hex)
        || trace.bytes().all(|b| b == b'0')
        || parent.bytes().all(|b| b == b'0')
    {
        return None;
    }
    Some(trace)
}

/// Nonzero random bits from the system CSPRNG. If the CSPRNG is unavailable,
/// a process-unique counter mixed with the clock keeps IDs distinct; these
/// IDs correlate logs and never authorize anything.
pub(crate) fn random_u128() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static FALLBACK: AtomicU64 = AtomicU64::new(1);
    // Building a provider allocates its suite lists; keep only the RNG.
    static RANDOM: std::sync::LazyLock<&'static dyn rustls::crypto::SecureRandom> =
        std::sync::LazyLock::new(|| rustls::crypto::ring::default_provider().secure_random);
    let mut bytes = [0u8; 16];
    let value = match RANDOM.fill(&mut bytes) {
        Ok(()) => u128::from_be_bytes(bytes),
        Err(_) => {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            (nanos << 64) ^ u128::from(FALLBACK.fetch_add(1, Ordering::Relaxed))
        }
    };
    value.max(1)
}

/// A new unsampled version-00 context with random trace and parent IDs.
pub fn generate() -> String {
    let trace = random_u128();
    let parent = (random_u128() as u64).max(1);
    format!("00-{trace:032x}-{parent:016x}-00")
}

/// Normalize the request's trace context and return its trace ID.
pub fn normalize(headers: &mut HeaderMap, trusted_peer: bool) -> String {
    if trusted_peer {
        let mut values = headers.get_all(&TRACEPARENT).iter();
        if let (Some(value), None) = (values.next(), values.next())
            && let Some(trace) = value.to_str().ok().and_then(trace_id)
        {
            return trace.to_owned();
        }
    }
    headers.remove(&TRACEPARENT);
    headers.remove(&TRACESTATE);
    let generated = generate();
    let trace = generated[3..35].to_owned();
    headers.insert(
        TRACEPARENT,
        HeaderValue::from_str(&generated).expect("generated traceparent is ASCII"),
    );
    trace
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    #[test]
    fn accepts_only_well_formed_version_00_contexts() {
        assert_eq!(trace_id(VALID), Some("4bf92f3577b34da6a3ce929d0e0e4736"));
        for invalid in [
            "",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7",
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0g",
            "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-",
        ] {
            assert_eq!(trace_id(invalid), None, "{invalid:?}");
        }
    }

    #[test]
    fn generated_contexts_are_valid_unsampled_and_distinct() {
        let first = generate();
        let second = generate();
        assert!(trace_id(&first).is_some(), "{first}");
        assert!(first.ends_with("-00"));
        assert_ne!(first, second);
    }

    #[test]
    fn trusted_valid_context_and_state_are_kept() {
        let mut headers = HeaderMap::new();
        headers.insert(TRACEPARENT, HeaderValue::from_static(VALID));
        headers.insert(TRACESTATE, HeaderValue::from_static("vendor=opaque"));
        assert_eq!(
            normalize(&mut headers, true),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(headers[&TRACEPARENT], VALID);
        assert_eq!(headers[&TRACESTATE], "vendor=opaque");
    }

    #[test]
    fn untrusted_malformed_or_repeated_contexts_are_replaced() {
        let cases: [(&[&str], bool); 4] = [
            (&[VALID], false),
            (&["00-not-a-context"], true),
            (&[VALID, VALID], true),
            (&[], true),
        ];
        for (values, trusted) in cases {
            let mut headers = HeaderMap::new();
            for value in values {
                headers.append(TRACEPARENT, HeaderValue::from_str(value).unwrap());
            }
            headers.insert(TRACESTATE, HeaderValue::from_static("vendor=stale"));
            let trace = normalize(&mut headers, trusted);
            assert_ne!(trace, "4bf92f3577b34da6a3ce929d0e0e4736");
            assert_eq!(headers.get_all(&TRACEPARENT).iter().count(), 1);
            let value = headers[&TRACEPARENT].to_str().unwrap();
            assert_eq!(trace_id(value), Some(trace.as_str()));
            assert!(!headers.contains_key(&TRACESTATE));
        }
    }
}
