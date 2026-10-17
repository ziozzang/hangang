//! Request filters of an HTTP route: header modification, redirects and URL
//! rewrites (the Gateway API `RequestHeaderModifier`, `RequestRedirect` and
//! `URLRewrite` filters, also usable in hand-written configuration).
use anyhow::{Result, ensure};
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_ENTRIES: usize = 32;

/// Header names a route may never set, add or remove on the request sent
/// upstream: hop-by-hop and framing headers, the forwarding context the
/// gateway writes, and identity headers produced by authentication.
fn reserved_request_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "host"
            | "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "content-length"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-forwarded-host"
            | "x-forwarded-port"
            | "x-forwarded-user"
            | "x-forwarded-email"
            | "x-forwarded-groups"
            | "x-real-ip"
    ) || name.starts_with("x-hangang-")
        || name.starts_with("x-hopae-")
        || name.starts_with("x-pumgye-")
        || name.starts_with("x-guard-")
        || name.starts_with(':')
}

fn valid_value(value: &str) -> bool {
    value.len() <= 4096
        && value
            .bytes()
            .all(|b| b == b'\t' || (b >= 0x20 && b != 0x7f))
}

/// Set, add and remove request headers before the request is sent upstream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderModifier {
    /// Replace (or create) these headers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
    /// Append a value to these headers.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub add: BTreeMap<String, String>,
    /// Remove these headers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}
impl HeaderModifier {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.set.len() <= MAX_ENTRIES
                && self.add.len() <= MAX_ENTRIES
                && self.remove.len() <= MAX_ENTRIES,
            "request_headers allows at most 32 entries per operation"
        );
        for name in self
            .set
            .keys()
            .chain(self.add.keys())
            .chain(self.remove.iter())
        {
            ensure!(
                HeaderName::from_bytes(name.as_bytes()).is_ok(),
                "request_headers: invalid header name {name:?}"
            );
            ensure!(
                !reserved_request_header(name),
                "request_headers may not change the reserved header {name}"
            );
        }
        for value in self.set.values().chain(self.add.values()) {
            ensure!(
                valid_value(value),
                "request_headers value contains control characters or exceeds 4 KiB"
            );
        }
        Ok(())
    }
    /// Gateway API order: set, then add, then remove.
    pub fn apply(&self, headers: &mut HeaderMap) {
        for (name, value) in &self.set {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
        for (name, value) in &self.add {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.append(name, value);
            }
        }
        for name in &self.remove {
            if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(name);
            }
        }
    }
}

/// How a redirect or rewrite changes the path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum PathModifier {
    /// Replace the whole path.
    Full(String),
    /// Replace the route's matched `path_prefix` and keep the rest.
    Prefix(String),
}
impl PathModifier {
    fn validate(&self) -> Result<()> {
        let value = match self {
            Self::Full(value) | Self::Prefix(value) => value,
        };
        ensure!(
            value.starts_with('/')
                && value.len() <= 1024
                && value
                    .bytes()
                    .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#'),
            "path modifier must be an absolute path without query or fragment"
        );
        Ok(())
    }
    /// The new path for `path` matched by a route with `prefix`.
    pub fn apply(&self, prefix: Option<&str>, path: &str) -> String {
        match self {
            Self::Full(value) => value.clone(),
            Self::Prefix(value) => {
                let matched = prefix.unwrap_or("/").trim_end_matches('/');
                let rest = path.get(matched.len()..).unwrap_or("");
                let rest = rest.trim_start_matches('/');
                let base = value.trim_end_matches('/');
                match (base.is_empty(), rest.is_empty()) {
                    (true, true) => "/".into(),
                    (true, false) => format!("/{rest}"),
                    (false, true) => {
                        // Keep a trailing slash the client sent after the prefix.
                        if path.len() > matched.len() && path.ends_with('/') {
                            format!("{base}/")
                        } else {
                            base.into()
                        }
                    }
                    (false, false) => format!("{base}/{rest}"),
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedirectScheme {
    Http,
    Https,
}

/// Answer the request with a redirect instead of proxying it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRedirect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<RedirectScheme>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathModifier>,
    #[serde(default = "default_status")]
    pub status_code: u16,
}
fn default_status() -> u16 {
    302
}
impl RouteRedirect {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.status_code, 301 | 302 | 303 | 307 | 308),
            "redirect status_code must be 301, 302, 303, 307 or 308"
        );
        if let Some(host) = &self.hostname {
            ensure!(valid_hostname(host), "invalid redirect hostname");
        }
        ensure!(self.port != Some(0), "redirect port must not be 0");
        if let Some(path) = &self.path {
            path.validate()?;
        }
        Ok(())
    }
    /// The `Location` for a request (`scheme`/`host`/`port` as the client
    /// addressed the gateway, `path` and `query` from the request).
    pub fn location(
        &self,
        scheme: &str,
        host: &str,
        port: Option<u16>,
        prefix: Option<&str>,
        path: &str,
        query: Option<&str>,
    ) -> String {
        let scheme = match self.scheme {
            Some(RedirectScheme::Http) => "http",
            Some(RedirectScheme::Https) => "https",
            None => scheme,
        };
        let host = self.hostname.as_deref().unwrap_or(host);
        // Gateway API: without an explicit port, a changed scheme uses its
        // well-known port; otherwise the request's port is kept.
        let port = match (self.port, self.scheme) {
            (Some(port), _) => Some(port),
            (None, Some(_)) => None,
            (None, None) => port,
        };
        let port = port.filter(|p| !matches!((scheme, p), ("http", 80) | ("https", 443)));
        let path = self
            .path
            .as_ref()
            .map_or_else(|| path.to_owned(), |modifier| modifier.apply(prefix, path));
        let mut location = format!("{scheme}://{host}");
        if let Some(port) = port {
            location.push_str(&format!(":{port}"));
        }
        location.push_str(&path);
        if let Some(query) = query.filter(|q| !q.is_empty()) {
            location.push('?');
            location.push_str(query);
        }
        location
    }
}

/// Rewrite the request before it is sent upstream.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRewrite {
    /// Host header (and authority) sent upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathModifier>,
}
impl RouteRewrite {
    pub fn validate(&self) -> Result<()> {
        if let Some(host) = &self.hostname {
            ensure!(valid_hostname(host), "invalid rewrite hostname");
        }
        if let Some(path) = &self.path {
            path.validate()?;
        }
        Ok(())
    }
}

/// Method and query parameter conditions of a route.
pub fn validate_matches(methods: &[String], query: &BTreeMap<String, String>) -> Result<()> {
    ensure!(methods.len() <= 16, "at most 16 methods");
    for method in methods {
        ensure!(
            (1..=32).contains(&method.len()) && method.bytes().all(|b| b.is_ascii_uppercase()),
            "invalid method {method:?}"
        );
    }
    ensure!(query.len() <= 16, "at most 16 query conditions");
    for (name, value) in query {
        ensure!(
            !name.is_empty() && name.len() <= 256 && valid_value(value),
            "invalid query condition"
        );
    }
    Ok(())
}

/// Whether the request's query has `name` with exactly `value` (first
/// occurrence, percent-decoded).
pub fn query_matches(query: Option<&str>, conditions: &BTreeMap<String, String>) -> bool {
    if conditions.is_empty() {
        return true;
    }
    let Ok(mut url) = reqwest::Url::parse("http://query.invalid/") else {
        return false;
    };
    url.set_query(query);
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    conditions.iter().all(|(name, value)| {
        pairs
            .iter()
            .find(|(k, _)| k == name)
            .is_some_and(|(_, v)| v == value)
    })
}

fn valid_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_replacement_follows_gateway_api_examples() {
        let p = PathModifier::Prefix("/xyz".into());
        assert_eq!(p.apply(Some("/foo"), "/foo/bar"), "/xyz/bar");
        assert_eq!(p.apply(Some("/foo"), "/foo"), "/xyz");
        assert_eq!(p.apply(Some("/foo"), "/foo/"), "/xyz/");
        assert_eq!(p.apply(Some("/foo/"), "/foo/bar"), "/xyz/bar");
        let root = PathModifier::Prefix("/".into());
        assert_eq!(root.apply(Some("/foo"), "/foo/bar"), "/bar");
        assert_eq!(root.apply(Some("/foo"), "/foo"), "/");
        let into_root = PathModifier::Prefix("/xyz".into());
        assert_eq!(into_root.apply(Some("/"), "/bar"), "/xyz/bar");
        assert_eq!(
            PathModifier::Full("/one".into()).apply(Some("/foo"), "/foo/x"),
            "/one"
        );
    }

    #[test]
    fn redirect_location_keeps_or_changes_scheme_host_port_and_path() {
        let r = RouteRedirect {
            scheme: Some(RedirectScheme::Https),
            hostname: None,
            port: None,
            path: None,
            status_code: 301,
        };
        assert_eq!(
            r.location(
                "http",
                "a.example.test",
                Some(8080),
                None,
                "/x",
                Some("q=1")
            ),
            "https://a.example.test/x?q=1"
        );
        let r = RouteRedirect {
            scheme: None,
            hostname: Some("b.example.test".into()),
            port: Some(8443),
            path: Some(PathModifier::Prefix("/new".into())),
            status_code: 302,
        };
        assert_eq!(
            r.location(
                "https",
                "a.example.test",
                None,
                Some("/old"),
                "/old/p",
                None
            ),
            "https://b.example.test:8443/new/p"
        );
        let keep = RouteRedirect {
            scheme: None,
            hostname: None,
            port: None,
            path: None,
            status_code: 302,
        };
        assert_eq!(
            keep.location("http", "a.example.test", Some(8080), None, "/", None),
            "http://a.example.test:8080/"
        );
        assert!(
            RouteRedirect {
                status_code: 200,
                ..keep.clone()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn header_modifier_orders_operations_and_refuses_reserved_names() {
        let modifier = HeaderModifier {
            set: BTreeMap::from([("x-set".into(), "one".into())]),
            add: BTreeMap::from([("x-add".into(), "two".into())]),
            remove: vec!["x-gone".into()],
        };
        modifier.validate().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-set", HeaderValue::from_static("old"));
        headers.insert("x-add", HeaderValue::from_static("first"));
        headers.insert("x-gone", HeaderValue::from_static("x"));
        modifier.apply(&mut headers);
        assert_eq!(headers["x-set"], "one");
        assert_eq!(headers.get_all("x-add").iter().count(), 2);
        assert!(headers.get("x-gone").is_none());
        for name in [
            "host",
            "X-Forwarded-User",
            "x-hopae-session",
            "x-hangang-reason",
            "connection",
        ] {
            let bad = HeaderModifier {
                set: BTreeMap::from([(name.into(), "v".into())]),
                ..Default::default()
            };
            assert!(bad.validate().is_err(), "{name}");
        }
    }

    #[test]
    fn query_conditions_match_exactly_on_the_first_value() {
        let conditions = BTreeMap::from([("animal".to_owned(), "whale".to_owned())]);
        assert!(query_matches(Some("animal=whale&x=1"), &conditions));
        assert!(!query_matches(
            Some("animal=dolphin&animal=whale"),
            &conditions
        ));
        assert!(!query_matches(None, &conditions));
        assert!(query_matches(Some("animal=wh%61le"), &conditions));
    }
}
