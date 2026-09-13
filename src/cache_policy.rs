//! Conservative HTTP cache eligibility, keying, and freshness policy.

use anyhow::{Result, ensure};
use hyper::{
    Method, Request, StatusCode,
    body::Body,
    header::{self, HeaderMap, HeaderName},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, time::SystemTime};

const MAX_KEY_HEADER_BYTES: usize = 64 * 1024;
const MAX_TTL_SECONDS: u64 = 86_400;

fn default_ttl_seconds() -> u64 {
    30
}

fn default_max_ttl_seconds() -> u64 {
    300
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteCache {
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    #[serde(default = "default_max_ttl_seconds")]
    pub max_ttl_seconds: u64,
}

impl Default for RouteCache {
    fn default() -> Self {
        Self {
            ttl_seconds: default_ttl_seconds(),
            max_ttl_seconds: default_max_ttl_seconds(),
        }
    }
}

impl RouteCache {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.ttl_seconds >= 1
                && self.ttl_seconds <= self.max_ttl_seconds
                && self.max_ttl_seconds <= MAX_TTL_SECONDS,
            "cache TTL must satisfy 1 <= ttl_seconds <= max_ttl_seconds <= 86400"
        );
        Ok(())
    }
}

/// Returns whether a route can produce one deterministic, shareable representation.
pub fn route_eligible(route: &crate::config::HttpRoute) -> bool {
    route.cache.is_some()
        && route.access_mode != crate::config::AccessMode::Protected
        && route.auth.is_none()
        && route.basic_auth.is_none()
        && route.lua.is_none()
        && route.json.is_empty()
        && route.request_transform.is_none()
        && route.response_transform.as_ref().is_none_or(|transform| {
            transform.mode == crate::transform::TransformMode::Buffered && transform.lua.is_none()
        })
}

/// `only-if-cached` needs a 504 on a miss rather than ordinary cache bypass.
pub fn only_if_cached(headers: &HeaderMap) -> bool {
    headers.get_all(header::CACHE_CONTROL).iter().any(|value| {
        value.as_bytes().split(|byte| *byte == b',').any(|part| {
            let name = part.split(|byte| *byte == b'=').next().unwrap_or(part);
            trim_ascii(name).eq_ignore_ascii_case(b"only-if-cached")
        })
    })
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

/// Request directives and personalized or conditional inputs bypass the shared cache.
pub fn request_eligible<B: Body>(request: &Request<B>) -> bool {
    if request.method() != Method::GET
        || !(request.body().is_end_stream() || request.body().size_hint().upper() == Some(0))
        || request.headers().contains_key(header::CACHE_CONTROL)
        || request.headers().contains_key(header::PRAGMA)
    {
        return false;
    }

    let blocked = [
        header::AUTHORIZATION,
        header::PROXY_AUTHORIZATION,
        header::COOKIE,
        header::RANGE,
        header::CONTENT_RANGE,
        header::UPGRADE,
    ];
    !blocked
        .iter()
        .any(|name| request.headers().contains_key(name))
        && !request
            .headers()
            .keys()
            .any(|name| name.as_str().starts_with("if-"))
}

/// Builds a collision-resistant key from the final upstream request.
///
/// Header names are sorted, repeated values retain wire order, and every component is
/// length-prefixed. Hop-by-hop fields are excluded; all other final request headers are keyed.
///
/// `epoch` is the runtime fence token (`CacheRuntime::epoch`). Only its
/// configuration generation namespaces the key: a fleet-wide invalidation
/// changes every key on every instance and survives restarts, so a route
/// rolled back to an earlier form after an invalidation cannot reach entries
/// stored before it. The local purge counter is deliberately left out; it is
/// not persisted, so keying by it would strand every entry written after a
/// local purge once the process restarts.
pub fn key<B>(
    request: &Request<B>,
    route_fingerprint: &str,
    backend: &str,
    epoch: u64,
) -> Option<String> {
    if request.method() != Method::GET {
        return None;
    }

    // Count framing too, so many empty values cannot evade the aggregate limit.
    let mut header_bytes = 0_usize;
    for name in request.headers().keys() {
        for value in request.headers().get_all(name) {
            header_bytes = header_bytes
                .checked_add(name.as_str().len())?
                .checked_add(value.as_bytes().len())?
                .checked_add(2)?;
            if header_bytes > MAX_KEY_HEADER_BYTES {
                return None;
            }
        }
    }

    let excluded = hop_by_hop_names(request.headers());
    let mut names = Vec::new();
    for name in request.headers().keys() {
        if excluded.contains(name) || names.iter().any(|seen: &&str| *seen == name.as_str()) {
            continue;
        }
        names.push(name.as_str());
    }
    names.sort_unstable();

    let mut hash = Sha256::new();
    framed(&mut hash, b"hangang-cache-key-v2");
    framed(&mut hash, &crate::cache::generation_of(epoch).to_be_bytes());
    framed(&mut hash, request.method().as_str().as_bytes());
    framed(
        &mut hash,
        request.uri().scheme_str().unwrap_or_default().as_bytes(),
    );
    framed(
        &mut hash,
        &[u8::from(
            request
                .extensions()
                .get::<crate::tls::TransportInfo>()
                .is_some_and(|transport| transport.tls),
        )],
    );
    framed(
        &mut hash,
        request
            .uri()
            .authority()
            .map(|authority| authority.as_str())
            .unwrap_or_default()
            .as_bytes(),
    );
    framed(
        &mut hash,
        request
            .uri()
            .path_and_query()
            .map(|value| value.as_str())
            .unwrap_or("/")
            .as_bytes(),
    );
    framed(&mut hash, route_fingerprint.as_bytes());
    framed(&mut hash, backend.as_bytes());
    for name in names {
        framed(&mut hash, name.as_bytes());
        let values = request.headers().get_all(name);
        framed(&mut hash, &(values.iter().count() as u64).to_be_bytes());
        for value in values {
            framed(&mut hash, value.as_bytes());
        }
    }
    let digest = hash.finalize();
    Some(format!("{digest:x}"))
}

fn framed(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn hop_by_hop_names(headers: &HeaderMap) -> HashSet<HeaderName> {
    let mut names = HashSet::from([
        header::CONNECTION,
        HeaderName::from_static("keep-alive"),
        HeaderName::from_static("proxy-connection"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ]);
    for value in headers.get_all(header::CONNECTION) {
        if let Ok(value) = value.to_str() {
            for token in value.split(',') {
                if let Ok(name) = token.trim().parse() {
                    names.insert(name);
                }
            }
        }
    }
    names
}

/// Returns the remaining freshness lifetime in milliseconds and the initial age in seconds.
pub fn response_ttl(
    headers: &HeaderMap,
    status: StatusCode,
    route: &RouteCache,
) -> Option<(u64, u64)> {
    if status != StatusCode::OK
        || headers.contains_key(header::SET_COOKIE)
        || headers.contains_key(header::CONTENT_RANGE)
        || headers.contains_key(header::TRAILER)
        || unsupported_content_type(headers)
        || vary_star_or_invalid(headers)
    {
        return None;
    }
    route.validate().ok()?;

    let directives = cache_directives(headers)?;
    let mut seen = HashSet::new();
    let mut max_age = None;
    let mut shared_max_age = None;
    for (name, value) in directives {
        if !seen.insert(name.clone()) {
            return None;
        }
        match name.as_str() {
            "no-store" | "private" | "no-cache" => return None,
            "max-age" => max_age = Some(delta_seconds(value.as_deref())?),
            "s-maxage" => shared_max_age = Some(delta_seconds(value.as_deref())?),
            "public" | "must-revalidate" | "proxy-revalidate" | "no-transform" => {
                if value.is_some() {
                    return None;
                }
            }
            // Unknown extensions can override ordinary cache behavior. Bypass rather than guess.
            _ => return None,
        }
    }

    let now = SystemTime::now();
    let date = one_http_date(headers, header::DATE)?;
    let age_value = one_delta_header(headers, header::AGE)?.unwrap_or(0);
    let apparent_age = date
        .and_then(|date| now.duration_since(date).ok())
        .map(|age| {
            age.as_secs()
                .saturating_add(u64::from(age.subsec_nanos() != 0))
        })
        .unwrap_or(0);
    let initial_age = age_value.max(apparent_age);

    let lifetime = if let Some(seconds) = shared_max_age.or(max_age) {
        seconds
    } else if let Some(expires) = one_http_date(headers, header::EXPIRES)? {
        let base = date.unwrap_or(now);
        expires.duration_since(base).ok()?.as_secs()
    } else {
        route.ttl_seconds
    }
    .min(route.max_ttl_seconds);
    let remaining = lifetime.checked_sub(initial_age)?;
    (remaining > 0).then_some((remaining.checked_mul(1000)?, initial_age))
}

fn unsupported_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .is_none_or(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn vary_star_or_invalid(headers: &HeaderMap) -> bool {
    headers.get_all(header::VARY).iter().any(|value| {
        let Ok(value) = value.to_str() else {
            return true;
        };
        value.split(',').any(|name| {
            let name = name.trim();
            name == "*" || name.is_empty() || name.parse::<HeaderName>().is_err()
        })
    })
}

fn one_http_date(headers: &HeaderMap, name: HeaderName) -> Option<Option<SystemTime>> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return None;
    }
    match value {
        None => Some(None),
        Some(value) => Some(Some(httpdate::parse_http_date(value.to_str().ok()?).ok()?)),
    }
}

fn one_delta_header(headers: &HeaderMap, name: HeaderName) -> Option<Option<u64>> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return None;
    }
    match value {
        None => Some(None),
        Some(value) => Some(Some(value.to_str().ok()?.trim().parse().ok()?)),
    }
}

fn delta_seconds(value: Option<&str>) -> Option<u64> {
    let value = value?;
    let value = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn cache_directives(headers: &HeaderMap) -> Option<Vec<(String, Option<String>)>> {
    let mut directives = Vec::new();
    for value in headers.get_all(header::CACHE_CONTROL) {
        let value = value.to_str().ok()?;
        for directive in split_directives(value)? {
            let (name, argument) = directive
                .split_once('=')
                .map_or((directive, None), |(name, value)| {
                    (name, Some(value.trim()))
                });
            let name = name.trim();
            if name.is_empty() || name.parse::<HeaderName>().is_err() {
                return None;
            }
            directives.push((name.to_ascii_lowercase(), argument.map(str::to_owned)));
        }
    }
    Some(directives)
}

fn split_directives(value: &str) -> Option<Vec<&str>> {
    let mut values = Vec::new();
    let mut start = 0;
    let mut quoted = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if escaped {
            escaped = false;
        } else if quoted && character == '\\' {
            escaped = true;
        } else if character == '"' {
            quoted = !quoted;
        } else if !quoted && character == ',' {
            values.push(value[start..index].trim());
            start = index + 1;
        }
    }
    if quoted || escaped {
        return None;
    }
    values.push(value[start..].trim());
    Some(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{Empty, Full};
    use serde_json::json;
    use std::time::Duration;

    fn route() -> crate::config::HttpRoute {
        serde_json::from_value(json!({
            "id": "cache",
            "backends": ["http://127.0.0.1:8080"],
            "cache": {}
        }))
        .unwrap()
    }

    #[test]
    fn route_cache_defaults_and_bounds_are_strict() {
        assert_eq!(RouteCache::default().ttl_seconds, 30);
        assert_eq!(RouteCache::default().max_ttl_seconds, 300);
        for (ttl, maximum, valid) in [
            (0, 300, false),
            (1, 1, true),
            (301, 300, false),
            (86_400, 86_400, true),
            (1, 86_401, false),
        ] {
            assert_eq!(
                RouteCache {
                    ttl_seconds: ttl,
                    max_ttl_seconds: maximum,
                }
                .validate()
                .is_ok(),
                valid
            );
        }
        assert!(serde_json::from_value::<RouteCache>(json!({"unknown": 1})).is_err());
    }

    #[test]
    fn declared_protected_route_cannot_become_cache_eligible() {
        let mut route = route();
        assert!(route_eligible(&route));
        route.access_mode = crate::config::AccessMode::Protected;
        assert!(!route_eligible(&route));
    }

    #[test]
    fn route_gating_accepts_only_deterministic_native_response_transforms() {
        let mut route = route();
        assert!(route_eligible(&route));
        route.response_transform = Some(
            serde_json::from_value(json!({"operations":[{"op":"replace","from":"a","to":"b"}]}))
                .unwrap(),
        );
        assert!(route_eligible(&route));
        route.response_transform.as_mut().unwrap().lua = Some("return hangang.body()".into());
        assert!(!route_eligible(&route));
        route.response_transform.as_mut().unwrap().lua = None;
        route.response_transform.as_mut().unwrap().mode = crate::transform::TransformMode::Lines;
        assert!(!route_eligible(&route));
        route.response_transform = None;
        route.lua = Some("return nil".into());
        assert!(!route_eligible(&route));
        route.lua = None;
        route.json.insert("/tenant".into(), json!("a"));
        assert!(!route_eligible(&route));
        route.json.clear();
        route.auth = Some(serde_json::from_value(json!({"url":"http://127.0.0.1:9000"})).unwrap());
        assert!(!route_eligible(&route));
        route.auth = None;
        route.cache = None;
        assert!(!route_eligible(&route));
    }

    #[test]
    fn requests_require_bodyless_plain_gets_and_bypass_directives() {
        let eligible = Request::builder()
            .method("GET")
            .uri("/items?a=1")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(request_eligible(&eligible));
        for (name, value) in [
            ("authorization", "secret"),
            ("proxy-authorization", "secret"),
            ("cookie", "session=x"),
            ("range", "bytes=0-1"),
            ("content-range", "bytes 0-1/2"),
            ("if-none-match", "x"),
            ("upgrade", "websocket"),
            ("cache-control", "max-age=60"),
            ("pragma", "no-cache"),
        ] {
            let request = Request::builder()
                .method("GET")
                .header(name, value)
                .body(Empty::<Bytes>::new())
                .unwrap();
            assert!(!request_eligible(&request), "{name}");
        }
        let request = Request::builder()
            .method("POST")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(!request_eligible(&request));
        let request = Request::builder()
            .method("GET")
            .body(Full::new(Bytes::from_static(b"x")))
            .unwrap();
        assert!(!request_eligible(&request));
        let headers = HeaderMap::from_iter([(
            header::CACHE_CONTROL,
            "max-age=0, ONLY-IF-CACHED".parse().unwrap(),
        )]);
        assert!(only_if_cached(&headers));
        let malformed = HeaderMap::from_iter([(
            header::CACHE_CONTROL,
            "only-if-cached, extension=\"unterminated".parse().unwrap(),
        )]);
        assert!(only_if_cached(&malformed));
    }

    fn keyed_request(order: bool) -> Request<Empty<Bytes>> {
        let mut request = Request::builder()
            .uri("https://upstream.test/path?x=%2f")
            .body(Empty::new())
            .unwrap();
        request.extensions_mut().insert(crate::tls::TransportInfo {
            tls: true,
            local_port: 443,
        });
        if order {
            request.headers_mut().append("x-b", "2".parse().unwrap());
            request.headers_mut().append("x-a", "1".parse().unwrap());
        } else {
            request.headers_mut().append("x-a", "1".parse().unwrap());
            request.headers_mut().append("x-b", "2".parse().unwrap());
        }
        request.headers_mut().append("x-a", "3".parse().unwrap());
        request
    }

    #[test]
    fn keys_are_stable_and_include_ordered_values_uri_tls_route_and_partition() {
        let first = keyed_request(true);
        let second = keyed_request(false);
        let baseline = key(&first, "route", "backend", 7).unwrap();
        assert_eq!(baseline, key(&second, "route", "backend", 7).unwrap());

        let mut reversed = keyed_request(false);
        reversed.headers_mut().remove("x-a");
        reversed.headers_mut().append("x-a", "3".parse().unwrap());
        reversed.headers_mut().append("x-a", "1".parse().unwrap());
        assert_ne!(baseline, key(&reversed, "route", "backend", 7).unwrap());
        assert_ne!(baseline, key(&first, "other", "backend", 7).unwrap());
        assert_ne!(baseline, key(&first, "route", "other", 7).unwrap());
        // The fence token's local purge counter (low 32 bits) stays out of
        // persisted keys so entries written after a purge survive a restart;
        // its configuration generation (high 32 bits) namespaces every key.
        assert_eq!(baseline, key(&first, "route", "backend", 8).unwrap());
        assert_eq!(
            baseline,
            key(&first, "route", "backend", u32::MAX as u64).unwrap()
        );
        assert_ne!(baseline, key(&first, "route", "backend", 1 << 32).unwrap());
        assert_eq!(
            key(&first, "route", "backend", 1 << 32).unwrap(),
            key(&first, "route", "backend", (1 << 32) | 7).unwrap()
        );
        assert_ne!(
            key(&first, "route", "backend", 1 << 32).unwrap(),
            key(&first, "route", "backend", 2 << 32).unwrap()
        );
        let mut plain = keyed_request(false);
        plain.extensions_mut().remove::<crate::tls::TransportInfo>();
        assert_ne!(baseline, key(&plain, "route", "backend", 7).unwrap());
        let mut other_query = keyed_request(false);
        *other_query.uri_mut() = "https://upstream.test/path?x=/".parse().unwrap();
        assert_ne!(baseline, key(&other_query, "route", "backend", 7).unwrap());
        *other_query.method_mut() = Method::HEAD;
        assert!(key(&other_query, "route", "backend", 7).is_none());
    }

    #[test]
    fn key_ignores_hop_fields_and_caps_end_to_end_headers() {
        let mut request = keyed_request(false);
        let baseline = key(&request, "route", "backend", 1).unwrap();
        request
            .headers_mut()
            .insert(header::CONNECTION, "x-hop".parse().unwrap());
        request
            .headers_mut()
            .insert("x-hop", "ignored".parse().unwrap());
        assert_eq!(baseline, key(&request, "route", "backend", 1).unwrap());
        request.headers_mut().insert(
            "x-large",
            hyper::header::HeaderValue::from_bytes(&vec![b'x'; MAX_KEY_HEADER_BYTES]).unwrap(),
        );
        assert!(key(&request, "route", "backend", 1).is_none());
    }

    #[test]
    fn response_freshness_obeys_shared_precedence_age_and_route_cap() {
        let route = RouteCache {
            ttl_seconds: 30,
            max_ttl_seconds: 100,
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CACHE_CONTROL,
            "public, max-age=80, s-maxage=70, must-revalidate"
                .parse()
                .unwrap(),
        );
        headers.insert(header::AGE, "20".parse().unwrap());
        assert_eq!(
            response_ttl(&headers, StatusCode::OK, &route),
            Some((50_000, 20))
        );
        headers.insert(header::CACHE_CONTROL, "max-age=500".parse().unwrap());
        assert_eq!(
            response_ttl(&headers, StatusCode::OK, &route),
            Some((80_000, 20))
        );
    }

    #[test]
    fn expires_and_date_contribute_lifetime_and_initial_age() {
        let now = SystemTime::now();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::DATE,
            httpdate::fmt_http_date(now - Duration::from_secs(10))
                .parse()
                .unwrap(),
        );
        headers.insert(
            header::EXPIRES,
            httpdate::fmt_http_date(now + Duration::from_secs(50))
                .parse()
                .unwrap(),
        );
        let (remaining, initial) =
            response_ttl(&headers, StatusCode::OK, &RouteCache::default()).unwrap();
        assert!((9..=11).contains(&initial));
        assert!((49_000..=51_000).contains(&remaining));
    }

    #[test]
    fn response_vetoes_and_malformed_freshness_are_not_cached() {
        for (name, value) in [
            ("set-cookie", "x=1"),
            ("content-range", "bytes 0-1/2"),
            ("trailer", "digest"),
            ("content-type", "text/event-stream; charset=utf-8"),
            ("vary", "*"),
            ("vary", "bad header"),
            ("cache-control", "private, max-age=30"),
            ("cache-control", "unknown=1"),
            ("cache-control", "max-age=bad"),
        ] {
            let headers = HeaderMap::from_iter([(name.parse().unwrap(), value.parse().unwrap())]);
            assert!(
                response_ttl(&headers, StatusCode::OK, &RouteCache::default()).is_none(),
                "{name}: {value}"
            );
        }
        let mut duplicate = HeaderMap::new();
        duplicate.append(header::CACHE_CONTROL, "max-age=30".parse().unwrap());
        duplicate.append(header::CACHE_CONTROL, "max-age=40".parse().unwrap());
        assert!(response_ttl(&duplicate, StatusCode::OK, &RouteCache::default()).is_none());
        let mut duplicate_date = HeaderMap::new();
        duplicate_date.append(
            header::DATE,
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        duplicate_date.append(
            header::DATE,
            "Sun, 06 Nov 1994 08:49:38 GMT".parse().unwrap(),
        );
        assert!(response_ttl(&duplicate_date, StatusCode::OK, &RouteCache::default()).is_none());
        let mut duplicate_content_type = HeaderMap::new();
        duplicate_content_type.append(header::CONTENT_TYPE, "application/json".parse().unwrap());
        duplicate_content_type.append(header::CONTENT_TYPE, "text/event-stream".parse().unwrap());
        assert!(
            response_ttl(
                &duplicate_content_type,
                StatusCode::OK,
                &RouteCache::default()
            )
            .is_none()
        );
        let valid_vary = HeaderMap::from_iter([(
            header::VARY,
            "accept-encoding, accept-language".parse().unwrap(),
        )]);
        assert!(response_ttl(&valid_vary, StatusCode::OK, &RouteCache::default()).is_some());
        assert!(
            response_ttl(
                &HeaderMap::new(),
                StatusCode::CREATED,
                &RouteCache::default()
            )
            .is_none()
        );
    }
}
