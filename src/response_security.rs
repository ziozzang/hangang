//! Explicit domain response policies applied at the final downstream boundary.
use anyhow::{Result, ensure};
use http_body_util::BodyExt;
use hyper::{
    Response,
    header::{HeaderName, HeaderValue, LOCATION},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ALLOWED: &[&str] = &[
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "x-frame-options",
    "content-security-policy",
    "content-security-policy-report-only",
    "permissions-policy",
];
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub hosts: Vec<String>,
    #[serde(default)]
    pub upgrade_same_host_redirect: bool,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}
#[derive(Debug)]
pub struct Compiled {
    hosts: Vec<String>,
    upgrade: bool,
    headers: Vec<(HeaderName, HeaderValue)>,
}
pub fn validate(rules: &[Rule]) -> Result<()> {
    prepare(rules).map(|_| ())
}
pub fn prepare(rules: &[Rule]) -> Result<Vec<Compiled>> {
    ensure!(
        rules.len() <= 128,
        "response security allows at most128 rules"
    );
    let mut total = 0usize;
    let mut result = Vec::new();
    for rule in rules {
        ensure!(
            !rule.hosts.is_empty() && rule.hosts.len() <= 16,
            "response security requires1..16 hosts"
        );
        let mut hosts = std::collections::HashSet::new();
        for host in &rule.hosts {
            crate::host_match::validate_pattern(host)?;
            ensure!(
                hosts.insert(host.to_ascii_lowercase()),
                "duplicate response security host"
            );
            total += host.len();
        }
        ensure!(rule.headers.len() <= 7, "too many security headers");
        let mut headers = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (name, value) in &rule.headers {
            let name = HeaderName::from_bytes(name.as_bytes())?;
            ensure!(
                ALLOWED.contains(&name.as_str()),
                "unsupported security header"
            );
            ensure!(seen.insert(name.clone()), "duplicate security header");
            ensure!(
                value.len() <= 4096 && !value.bytes().any(|b| b < 32 || b == 127),
                "invalid security header value"
            );
            let parsed = HeaderValue::from_str(value)?;
            total += name.as_str().len() + value.len();
            headers.push((name, parsed));
        }
        result.push(Compiled {
            hosts: rule.hosts.clone(),
            upgrade: rule.upgrade_same_host_redirect,
            headers,
        });
    }
    ensure!(total <= 32 * 1024, "response security exceeds32KiB");
    Ok(result)
}
#[derive(Debug, Clone)]
pub(crate) struct Context {
    pub authority: hyper::http::uri::Authority,
    pub https: bool,
    pub explicit_port: Option<u16>,
}
fn upgrade(value: &HeaderValue, context: &Context) -> Result<Option<HeaderValue>> {
    let raw = value.to_str()?;
    ensure!(
        raw.len() <= 8192 && !raw.bytes().any(|b| b <= 32 || b == 127 || b == b'\\'),
        "malformed redirect"
    );
    // Relative locations are preserved; validate absolute HTTP(S) using the URI
    // grammar rather than browser URL normalization of dot paths/backslashes.
    let scheme_end = raw.find(':').filter(|&colon| {
        raw.find(['/', '?', '#'])
            .is_none_or(|delimiter| colon < delimiter)
    });
    let Some(scheme_end) = scheme_end else {
        return Ok(None);
    };
    let scheme = &raw[..scheme_end];
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return Ok(None);
    }
    ensure!(
        raw[scheme_end + 1..].starts_with("//"),
        "malformed HTTP redirect"
    );
    let start = raw.find("://").unwrap() + 3;
    let end = raw[start..]
        .find(['/', '?', '#'])
        .map(|p| start + p)
        .unwrap_or(raw.len());
    let scheme = &raw[..start - 3];
    let authority: hyper::http::uri::Authority = raw[start..end].parse()?;
    ensure!(
        !authority.as_str().contains('@'),
        "redirect credentials prohibited"
    );
    ensure!(
        authority.port().is_none() || authority.port_u16().is_some_and(|p| p > 0),
        "invalid redirect port"
    );
    let parsed = reqwest::Url::parse(raw)?;
    ensure!(
        parsed.host_str().is_some() && parsed.username().is_empty() && parsed.password().is_none(),
        "malformed redirect authority"
    );
    if !scheme.eq_ignore_ascii_case("http")
        || !authority
            .host()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(context.authority.host().trim_end_matches('.'))
        || authority.port_u16().is_some_and(|p| p != 80)
    {
        return Ok(None);
    }
    let port = context
        .authority
        .port_u16()
        .or(context.explicit_port)
        .unwrap_or(443);
    let host = context.authority.host();
    let target = if port == 443 {
        host.to_owned()
    } else {
        format!("{host}:{port}")
    };
    Ok(Some(HeaderValue::from_str(&format!(
        "https://{target}{}",
        &raw[end..]
    ))?))
}
pub(crate) fn apply(
    mut response: Response<crate::proxy::Body>,
    rules: &[Compiled],
    context: Option<Context>,
) -> Response<crate::proxy::Body> {
    let Some(context) = context else {
        return response;
    };
    let selected: Vec<_> = rules
        .iter()
        .filter(|r| {
            r.hosts.iter().any(|h| {
                crate::host_match::matches(h, context.authority.host().trim_end_matches('.'))
            })
        })
        .collect();
    if selected.is_empty() {
        return response;
    }
    if context.https && selected.iter().any(|r| r.upgrade) && response.status().is_redirection() {
        let all: Vec<_> = response.headers().get_all(LOCATION).iter().collect();
        let upgraded = if all.len() > 1 {
            Err(anyhow::anyhow!("ambiguous location"))
        } else if let Some(value) = all.first() {
            upgrade(value, &context)
        } else {
            Ok(None)
        };
        match upgraded {
            Ok(Some(value)) => {
                response.headers_mut().insert(LOCATION, value);
            }
            Ok(None) => {}
            Err(_) => {
                response = Response::builder()
                    .status(502)
                    .header("cache-control", "no-store")
                    .body(
                        http_body_util::Full::new(bytes::Bytes::from_static(b"bad gateway"))
                            .map_err(|e| match e {})
                            .boxed_unsync(),
                    )
                    .unwrap();
            }
        }
    }
    let mut protected = std::collections::HashSet::new();
    for rule in selected {
        for (name, value) in &rule.headers {
            protected.insert(name.clone());
            if name.as_str() != "strict-transport-security" || context.https {
                response.headers_mut().insert(name.clone(), value.clone());
            } else {
                response.headers_mut().remove(name);
            }
        }
    }
    protected.insert(LOCATION);
    let declared: Option<Vec<_>> = response
        .headers()
        .get_all(hyper::header::TRAILER)
        .iter()
        .map(|value| value.to_str().ok())
        .collect();
    let declared = declared.and_then(|values| {
        values
            .into_iter()
            .flat_map(|value| value.split(','))
            .map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
            .collect::<Option<Vec<_>>>()
    });
    response.headers_mut().remove(hyper::header::TRAILER);
    if let Some(names) = declared {
        let names = names
            .into_iter()
            .filter(|name| !protected.contains(name))
            .map(|name| name.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        if !names.is_empty()
            && let Ok(value) = HeaderValue::from_str(&names)
        {
            response.headers_mut().insert(hyper::header::TRAILER, value);
        }
    }
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        body.map_frame(move |frame| match frame.into_trailers() {
            Ok(mut trailers) => {
                for name in &protected {
                    trailers.remove(name);
                }
                hyper::body::Frame::trailers(trailers)
            }
            Err(frame) => frame,
        })
        .boxed_unsync(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn context(authority: &str) -> Context {
        Context {
            authority: authority.parse().unwrap(),
            https: true,
            explicit_port: None,
        }
    }
    #[test]
    fn redirects_preserve_suffix_and_bind_verified_authority_ports() {
        let ctx = context("example.test:8443");
        for (raw, expected) in [
            (
                "http://EXAMPLE.test:80/a/../b?q=%2F#frag",
                Some("https://example.test:8443/a/../b?q=%2F#frag"),
            ),
            ("http://example.test:8080/x", None),
            ("http://external.test/x", None),
            ("/relative", None),
            ("/login?next=http://example.test/path", None),
            ("relative#https://example.test", None),
            ("mailto:test@example.test", None),
            ("//external.test/x", None),
        ] {
            let actual = upgrade(&HeaderValue::from_str(raw).unwrap(), &ctx).unwrap();
            assert_eq!(actual.as_ref().map(|v| v.to_str().unwrap()), expected);
        }
        for raw in [
            "http://user@example.test/x",
            "http://example.test:bad/x",
            "http://example.test\\@evil.test/x",
        ] {
            assert!(upgrade(&HeaderValue::from_str(raw).unwrap(), &ctx).is_err());
        }
        let mut ctx = context("example.test");
        ctx.explicit_port = Some(9443);
        assert_eq!(
            upgrade(&HeaderValue::from_static("http://example.test/x"), &ctx)
                .unwrap()
                .unwrap(),
            "https://example.test:9443/x"
        );
    }
    #[test]
    fn validation_rejects_framing_and_header_aliases() {
        for headers in [
            serde_json::json!({"location":"https://evil.test"}),
            serde_json::json!({"X-Frame-Options":"DENY","x-frame-options":"SAMEORIGIN"}),
            serde_json::json!({"referrer-policy":"no-referrer\r\nLocation: evil"}),
        ] {
            let rule: Rule = serde_json::from_value(
                serde_json::json!({"hosts":["example.test"],"headers":headers}),
            )
            .unwrap();
            assert!(validate(&[rule]).is_err());
        }
    }
    #[test]
    fn matching_profiles_support_domain_specific_values_and_ordered_overrides() {
        let rules=prepare(&[
            serde_json::from_value(serde_json::json!({"hosts":["*.test"],"headers":{"content-security-policy":"default-src 'none'"}})).unwrap(),
            serde_json::from_value(serde_json::json!({"hosts":["example.test"],"headers":{"content-security-policy":"default-src 'self'"}})).unwrap(),
            serde_json::from_value(serde_json::json!({"hosts":["other.test"],"headers":{"content-security-policy":"default-src https://other.test"}})).unwrap(),
        ]).unwrap();
        let body = http_body_util::Full::new(bytes::Bytes::new())
            .map_err(|e| match e {})
            .boxed_unsync();
        let response = apply(Response::new(body), &rules, Some(context("example.test")));
        assert_eq!(
            response.headers()["content-security-policy"],
            "default-src 'self'"
        );
    }
    #[tokio::test]
    async fn final_headers_and_trailer_filter_cover_replacement_errors() {
        let rules=prepare(&[serde_json::from_value(serde_json::json!({"hosts":["example.test"],"upgrade_same_host_redirect":true,"headers":{"x-frame-options":"DENY","strict-transport-security":"max-age=600"}})).unwrap()]).unwrap();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert(
            "location",
            HeaderValue::from_static("http://example.test/bypass"),
        );
        trailers.insert("x-frame-options", HeaderValue::from_static("SAMEORIGIN"));
        trailers.insert("x-ordinary", HeaderValue::from_static("retained"));
        let body = http_body_util::StreamBody::new(futures_util::stream::iter([Ok::<
            _,
            crate::proxy::BodyError,
        >(
            hyper::body::Frame::trailers(trailers),
        )]))
        .boxed_unsync();
        let response = apply(Response::new(body), &rules, Some(context("example.test")));
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        let collected = response.into_body().collect().await.unwrap();
        let trailers = collected.trailers().unwrap();
        assert!(!trailers.contains_key("location"));
        assert!(!trailers.contains_key("x-frame-options"));
        assert_eq!(trailers["x-ordinary"], "retained");
        let mut response = Response::new(
            http_body_util::Full::new(bytes::Bytes::new())
                .map_err(|e| match e {})
                .boxed_unsync(),
        );
        *response.status_mut() = hyper::StatusCode::FOUND;
        response
            .headers_mut()
            .append(LOCATION, HeaderValue::from_static("http://example.test/a"));
        response
            .headers_mut()
            .append(LOCATION, HeaderValue::from_static("http://example.test/b"));
        let response = apply(response, &rules, Some(context("example.test")));
        assert_eq!(response.status(), 502);
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}
