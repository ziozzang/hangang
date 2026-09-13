//! Bounded, label-local hostname glob matching for routing.

use anyhow::{Context, Result, ensure};
use std::net::IpAddr;

const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;
const MAX_REGEX_SOURCE_BYTES: usize = 1024;
const MAX_REGEX_COMPILED_BYTES: usize = 64 * 1024;

/// Compile a route hostname regex with whole-host ASCII case-insensitive
/// semantics and strict resource bounds. Rust's regex syntax is finite-state;
/// look-around and backreferences are rejected by the parser.
pub fn compile_regex(source: &str) -> Result<regex::Regex> {
    ensure!(!source.is_empty(), "host regex source must not be empty");
    ensure!(
        source.len() <= MAX_REGEX_SOURCE_BYTES,
        "host regex source exceeds 1024 bytes"
    );
    // Compile the source on its own first. This prevents unmatched grouping
    // syntax from escaping the non-capturing group added for whole-host
    // anchoring (for example, `foo)|(?:.*`).
    regex_builder(source)
        .build()
        .context("invalid or too-complex host regex")?;
    regex_builder(&format!(r"\A(?:{source})\z"))
        .build()
        .context("invalid or too-complex host regex")
}

fn regex_builder(source: &str) -> regex::RegexBuilder {
    let mut builder = regex::RegexBuilder::new(source);
    builder
        .case_insensitive(true)
        .unicode(false)
        .size_limit(MAX_REGEX_COMPILED_BYTES)
        .dfa_size_limit(MAX_REGEX_COMPILED_BYTES)
        .nest_limit(32);
    builder
}

pub fn is_glob(pattern: &str) -> bool {
    pattern.bytes().any(|byte| matches!(byte, b'*' | b'?'))
}

pub fn validate_pattern(pattern: &str) -> Result<()> {
    ensure!(!pattern.is_empty(), "host pattern must not be empty");
    ensure!(
        pattern.len() <= MAX_HOST_BYTES,
        "host pattern exceeds 253 bytes"
    );
    ensure!(pattern.is_ascii(), "host pattern must be ASCII");
    if !is_glob(pattern) && parse_ip(pattern).is_some() {
        return Ok(());
    }
    ensure!(
        valid_labels(pattern, true),
        "invalid host pattern; each label must contain 1..63 DNS characters, '*' or '?'"
    );
    Ok(())
}

/// Match a complete hostname. Wildcards consume bytes only within their label:
/// `*` consumes zero or more and `?` consumes exactly one. Inputs are ASCII
/// case-insensitive, and invalid or oversized hostnames never match.
pub fn matches(pattern: &str, host: &str) -> bool {
    if pattern.is_empty() || host.is_empty() || !pattern.is_ascii() || !host.is_ascii() {
        return false;
    }

    if !is_glob(pattern) {
        if let Some(expected) = parse_ip(pattern) {
            return parse_ip(host).is_some_and(|actual| actual == expected);
        }
        // Exact HTTP matching historically accepted authorities up to 255
        // bytes, including a trailing root dot. Keep that behavior while glob
        // and regex matching use strict DNS bounds.
        return pattern.len() <= 255 && host.len() <= 255 && pattern.eq_ignore_ascii_case(host);
    }
    if pattern.len() > MAX_HOST_BYTES || host.len() > MAX_HOST_BYTES {
        return false;
    }
    if !valid_labels(pattern, true) || !valid_labels(host, false) {
        return false;
    }

    let mut patterns = pattern.split('.');
    let mut hosts = host.split('.');
    loop {
        match (patterns.next(), hosts.next()) {
            (Some(pattern), Some(host)) if match_label(pattern.as_bytes(), host.as_bytes()) => {}
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value
        .parse()
        .ok()
        .or_else(|| value.strip_prefix('[')?.strip_suffix(']')?.parse().ok())
}

fn valid_labels(value: &str, wildcards: bool) -> bool {
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_BYTES
            && label.as_bytes().first() != Some(&b'-')
            && label.as_bytes().last() != Some(&b'-')
            && label.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || byte == b'-'
                    || (wildcards && matches!(byte, b'*' | b'?'))
            })
    })
}

/// A small NFA encoded in one stack integer. Transition masks are built in one
/// pattern pass, then each host byte advances all active states with bitwise
/// operations. Consecutive stars are collapsed so epsilon closure is one step.
fn match_label(pattern: &[u8], host: &[u8]) -> bool {
    let mut compact = [0_u8; MAX_LABEL_BYTES];
    let mut length = 0_usize;
    for &byte in pattern {
        if byte == b'*' && length > 0 && compact[length - 1] == b'*' {
            continue;
        }
        compact[length] = byte;
        length += 1;
    }

    // 26 letters, 10 digits and '-'. Pattern validation guarantees that no
    // other literal reaches this function.
    let mut literals = [0_u64; 37];
    let mut questions = 0_u64;
    let mut stars = 0_u64;
    for (index, &byte) in compact[..length].iter().enumerate() {
        let bit = 1_u64 << index;
        match byte {
            b'*' => stars |= bit,
            b'?' => questions |= bit,
            literal => literals[character_index(literal)] |= bit,
        }
    }

    let close = |states: u64| states | ((states & stars) << 1);
    let mut states = close(1);
    for &actual in host {
        let advancing = states & (questions | literals[character_index(actual)]);
        let consuming_stars = states & stars;
        states = close((advancing << 1) | consuming_stars);
        if states == 0 {
            return false;
        }
    }
    close(states) & (1_u64 << length) != 0
}

fn character_index(byte: u8) -> usize {
    match byte.to_ascii_lowercase() {
        b'a'..=b'z' => usize::from(byte.to_ascii_lowercase() - b'a'),
        b'0'..=b'9' => 26 + usize::from(byte - b'0'),
        b'-' => 36,
        _ => unreachable!("host character was validated"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_local_globs_are_anchored_and_case_insensitive() {
        for (pattern, host, expected) in [
            ("*.foo.com", "a.foo.com", true),
            ("*.foo.com", "A.FOO.COM", true),
            ("*.foo.com", "foo.com", false),
            ("*.foo.com", "a.b.foo.com", false),
            ("f??.bar.com", "foo.bar.com", true),
            ("f??.bar.com", "fooo.bar.com", false),
            ("a*b.example", "ab.example", true),
            ("a*b.example", "axyzb.example", true),
            ("a*b.example", "axyz.example", false),
            ("?.example", "x.example", true),
            ("?.example", "xy.example", false),
        ] {
            assert_eq!(matches(pattern, host), expected, "{pattern} / {host}");
        }
    }

    #[test]
    fn exact_ip_and_localhost_matching_is_preserved() {
        assert!(matches("localhost", "LOCALHOST"));
        assert!(matches("127.0.0.1", "127.0.0.1"));
        assert!(matches("::1", "[::1]"));
        assert!(matches("2001:db8::1", "[2001:0DB8:0:0:0:0:0:1]"));
        assert!(!matches("127.0.0.1", "127.0.0.2"));
        assert!(matches("example.com.", "EXAMPLE.COM."));
        let legacy_max = format!("{}.", "a".repeat(254));
        assert_eq!(legacy_max.len(), 255);
        assert!(matches(&legacy_max, &legacy_max));
    }

    #[test]
    fn rejects_invalid_and_oversized_patterns_or_hosts() {
        for invalid in [
            "",
            ".example.com",
            "example..com",
            "-bad.example",
            "bad-.example",
            "bad/example",
            "bad_name.example",
            "éxample.com",
        ] {
            assert!(validate_pattern(invalid).is_err(), "{invalid:?}");
            assert!(!matches(invalid, "bad.example"), "{invalid:?}");
        }
        let long_label = "a".repeat(64);
        assert!(validate_pattern(&format!("{long_label}.example")).is_err());
        assert!(!matches("*.example", &format!("{long_label}.example")));
        let long_host = ["a"; 128].join(".");
        assert!(long_host.len() > MAX_HOST_BYTES);
        assert!(!matches("*", &long_host));
    }

    #[test]
    fn many_wildcards_have_bounded_nonrecursive_matching() {
        let pattern = format!("{}z.example", "*?".repeat(31));
        assert_eq!(pattern.split('.').next().unwrap().len(), 63);
        assert!(validate_pattern(&pattern).is_ok());
        assert!(matches(&pattern, &format!("{}z.example", "a".repeat(31))));
        assert!(!matches(&pattern, &format!("{}y.example", "a".repeat(31))));
        assert!(is_glob(&pattern));
        assert!(!is_glob("exact.example"));
    }

    #[test]
    fn regexes_are_ascii_case_insensitive_and_whole_host_anchored() {
        let regex = compile_regex(r"api-[0-9]+\.example\.com").unwrap();
        assert!(regex.is_match("API-42.EXAMPLE.COM"));
        assert!(!regex.is_match("xapi-42.example.com"));
        assert!(!regex.is_match("api-42.example.com.evil"));
        assert!(!regex.is_match("api-xy.example.com"));
    }

    #[test]
    fn regex_compile_rejects_unsupported_or_excessive_sources() {
        assert!(compile_regex("").is_err());
        assert!(compile_regex("(?=example)example").is_err());
        assert!(compile_regex(r"(example)\1").is_err());
        assert!(compile_regex(r"foo)|(?:.*").is_err());
        assert!(compile_regex(&"a".repeat(MAX_REGEX_SOURCE_BYTES + 1)).is_err());
        assert!(compile_regex(&format!("{}a{}", "(".repeat(40), ")".repeat(40))).is_err());
        assert!(compile_regex(r"(?:[a-z]{63}\.){120}[a-z]{63}").is_err());
    }
}
