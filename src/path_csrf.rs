//! Explicit URL CSRF profiles using browser origin metadata and verified edge authority.
use anyhow::{Result, ensure};
use hyper::{Request, header};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};

fn yes() -> bool {
    true
}
fn default_methods() -> Vec<String> {
    ["POST", "PUT", "PATCH", "DELETE"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub include_subpaths: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_origins: Vec<String>,
    #[serde(default = "yes")]
    pub allow_same_origin: bool,
    #[serde(default)]
    pub allow_missing_origin: bool,
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

fn parse_url(raw: &str, root_only: bool) -> Result<Origin> {
    ensure!(
        !raw.is_empty()
            && raw.len() <= 2048
            && !raw.bytes().any(|b| b <= 32 || b == 127 || b == b'\\'),
        "origin URL must be bounded and contain no whitespace, backslashes or controls"
    );
    if root_only {
        let start = raw
            .find("://")
            .ok_or_else(|| anyhow::anyhow!("origin needs an HTTP(S) authority"))?
            + 3;
        let tail = &raw[start..];
        let suffix = tail
            .find(['/', '?', '#'])
            .map(|index| &tail[index..])
            .unwrap_or("");
        ensure!(
            suffix.is_empty() || suffix == "/",
            "origin must contain no path, query or fragment"
        );
    }
    let url = reqwest::Url::parse(raw)?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "origin must use HTTP(S) without credentials, fragments or opaque origins"
    );
    ensure!(
        !url.host_str().unwrap().contains(['*', '?']),
        "origin cannot use hostname wildcards"
    );
    if root_only {
        ensure!(
            url.path() == "/" && url.query().is_none(),
            "allowed origin must be a root URL without query"
        );
    }
    Ok(Origin {
        scheme: url.scheme().to_owned(),
        host: url.host_str().unwrap().to_owned(),
        port: url.port_or_known_default().unwrap(),
    })
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(rules.len() <= 128, "path CSRF allows at most128 rules");
    crate::path_blocks::validate(
        &rules
            .iter()
            .map(|rule| crate::path_blocks::Rule {
                path: rule.path.clone(),
                hosts: rule.hosts.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    let mut text = 0usize;
    for (index, rule) in rules.iter().enumerate() {
        ensure!(!rules[..index].contains(rule), "duplicate path CSRF rule");
        ensure!(
            rule.allow_same_origin || !rule.allow_origins.is_empty(),
            "CSRF requires same-origin admission or explicit allowed origins"
        );
        ensure!(
            rule.allow_origins.len() <= 128,
            "CSRF allows at most128 origins per rule"
        );
        ensure!(
            !rule.methods.is_empty() && rule.methods.len() <= 8,
            "CSRF methods must contain1..8 values"
        );
        let mut methods = HashSet::new();
        for method in &rule.methods {
            ensure!(
                matches!(
                    method.as_str(),
                    "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "TRACE"
                ) && methods.insert(method),
                "CSRF methods must be distinct supported uppercase methods"
            );
        }
        let mut origins = HashSet::new();
        for origin in &rule.allow_origins {
            ensure!(
                origins.insert(parse_url(origin, true)?),
                "duplicate normalized CSRF origin"
            );
        }
        text = text.saturating_add(rule.path.len());
        for value in rule
            .hosts
            .iter()
            .chain(rule.allow_origins.iter())
            .chain(rule.methods.iter())
        {
            text = text.saturating_add(value.len());
        }
        ensure!(text <= 32 * 1024, "path CSRF exceeds32KiB combined text");
    }
    Ok(())
}

#[derive(Debug)]
pub struct Compiled {
    selector: crate::path_blocks::Rule,
    include_subpaths: bool,
    methods: HashSet<String>,
    allowed: HashSet<Origin>,
    same: bool,
    missing: bool,
}

pub(crate) fn prepare(rules: &[Rule]) -> Result<Vec<Arc<Compiled>>> {
    validate(rules)?;
    rules
        .iter()
        .map(|rule| {
            Ok(Arc::new(Compiled {
                selector: crate::path_blocks::Rule {
                    path: rule.path.clone(),
                    hosts: rule.hosts.clone(),
                },
                include_subpaths: rule.include_subpaths,
                methods: rule.methods.iter().cloned().collect(),
                allowed: rule
                    .allow_origins
                    .iter()
                    .map(|value| parse_url(value, true))
                    .collect::<Result<_>>()?,
                same: rule.allow_same_origin,
                missing: rule.allow_missing_origin,
            }))
        })
        .collect()
}

enum Source {
    Missing,
    Opaque,
    Origin(Origin),
}

fn source<B>(request: &Request<B>) -> Result<Source, u16> {
    for name in [header::ORIGIN, header::REFERER] {
        if request.headers().get_all(name).iter().count() > 1 {
            return Err(400);
        }
    }
    let referer = request
        .headers()
        .get(header::REFERER)
        .map(|value| parse_url(value.to_str().map_err(|_| 400u16)?, false).map_err(|_| 400u16))
        .transpose()?;
    if let Some(value) = request.headers().get(header::ORIGIN) {
        let raw = value.to_str().map_err(|_| 400u16)?;
        if raw == "null" {
            return Ok(Source::Opaque);
        }
        return parse_url(raw, true).map(Source::Origin).map_err(|_| 400u16);
    }
    Ok(referer.map(Source::Origin).unwrap_or(Source::Missing))
}

pub(crate) fn check<B>(
    compiled: &[Arc<Compiled>],
    request: &Request<B>,
    verified_host: Option<&str>,
    verified_scheme: &str,
    verified_explicit_port: Option<u16>,
) -> Result<(), u16> {
    let mut observed = None;
    let mut destination = None;
    for rule in compiled {
        if !rule
            .methods
            .iter()
            .any(|method| method.eq_ignore_ascii_case(request.method().as_str()))
            || !crate::path_blocks::selector_matches(
                &rule.selector,
                request,
                verified_host,
                rule.include_subpaths,
            )?
        {
            continue;
        }
        let origin = match &observed {
            Some(value) => value,
            None => observed.insert(source(request)?),
        };
        match origin {
            Source::Missing if rule.missing => continue,
            Source::Missing | Source::Opaque => return Err(403),
            Source::Origin(origin) => {
                if rule.allowed.contains(origin) {
                    continue;
                }
                if rule.same {
                    if destination.is_none() {
                        let mut authority = verified_host
                            .map(str::to_owned)
                            .or_else(|| {
                                request
                                    .headers()
                                    .get(header::HOST)
                                    .and_then(|host| host.to_str().ok())
                                    .map(str::to_owned)
                            })
                            .or_else(|| {
                                request
                                    .uri()
                                    .authority()
                                    .map(|host| host.as_str().to_owned())
                            })
                            .ok_or(400u16)?;
                        if let Some(port) = verified_explicit_port {
                            if port == 0 {
                                return Err(400);
                            }
                            let parsed: hyper::http::uri::Authority =
                                authority.parse().map_err(|_| 400u16)?;
                            if parsed.port_u16().is_none() {
                                authority = format!("{authority}:{port}");
                            }
                        }
                        destination = Some(
                            parse_url(&format!("{verified_scheme}://{authority}"), true)
                                .map_err(|_| 400u16)?,
                        );
                    }
                    if destination.as_ref() == Some(origin) {
                        continue;
                    }
                }
                return Err(403);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn check<B>(
        compiled: &[Arc<Compiled>],
        request: &Request<B>,
        host: Option<&str>,
        scheme: &str,
    ) -> Result<(), u16> {
        super::check(compiled, request, host, scheme, None)
    }
    fn rule() -> Rule {
        serde_json::from_value(serde_json::json!({"path":"/login"})).unwrap()
    }
    fn request(method: &str, path: &str, origin: Option<&str>) -> Request<()> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("host", "app.example");
        if let Some(origin) = origin {
            builder = builder.header("origin", origin);
        }
        builder.body(()).unwrap()
    }
    #[test]
    fn strict_validation_and_normalized_origin_duplicates() {
        validate(&[rule()]).unwrap();
        for origin in [
            "*",
            "https://*.internal.example",
            "null",
            "file:///tmp/x",
            "https://user:password@app.example",
            "https://app.example/path",
            "https://app.example/.",
            "https://app.example/%2e",
            "https://app.example/?secret=x",
            "https://app.example/#x",
            " https://app.example",
        ] {
            let mut bad = rule();
            bad.allow_origins = vec![origin.into()];
            assert!(validate(&[bad]).is_err(), "{origin}");
        }
        let mut duplicate = rule();
        duplicate.allow_origins = vec![
            "https://APP.EXAMPLE:443/".into(),
            "https://app.example".into(),
        ];
        assert!(validate(&[duplicate]).is_err());
        for methods in [
            vec![],
            vec!["post".into()],
            vec!["CONNECT".into()],
            vec!["POST".into(), "POST".into()],
        ] {
            let mut bad = rule();
            bad.methods = methods;
            assert!(validate(&[bad]).is_err());
        }
        assert!(validate(&[rule(), rule()]).is_err());
    }
    #[test]
    fn origin_referer_and_missing_are_fail_closed_only_on_selected_methods_and_urls() {
        let rules = prepare(&[rule()]).unwrap();
        for (origin, status) in [
            (Some("http://APP.EXAMPLE:80/"), Ok(())),
            (Some("https://app.example"), Err(403)),
            (Some("http://other.example"), Err(403)),
            (Some("null"), Err(403)),
            (None, Err(403)),
            (Some("http://app.example/path"), Err(400)),
        ] {
            assert_eq!(
                check(
                    &rules,
                    &request("POST", "/log%69n?ignored=1", origin),
                    None,
                    "http"
                ),
                status
            );
        }
        assert_eq!(
            check(&rules, &request("GET", "/login", None), None, "http"),
            Ok(())
        );
        assert_eq!(
            check(
                &rules,
                &request("POST", "/login/image.png", None),
                None,
                "http"
            ),
            Ok(())
        );
        let mut referred = request("POST", "/login", None);
        referred.headers_mut().insert(
            header::REFERER,
            "http://app.example/form?private=x".parse().unwrap(),
        );
        assert_eq!(check(&rules, &referred, None, "http"), Ok(()));
        referred
            .headers_mut()
            .insert(header::ORIGIN, "null".parse().unwrap());
        assert_eq!(check(&rules, &referred, None, "http"), Err(403));
        referred
            .headers_mut()
            .append(header::ORIGIN, "http://app.example".parse().unwrap());
        assert_eq!(check(&rules, &referred, None, "http"), Err(400));
    }
    #[test]
    fn profiles_intersect_and_use_only_verified_scheme_and_forwarded_authority() {
        let mut explicit = rule();
        explicit.allow_same_origin = false;
        explicit.allow_origins = vec!["https://internal.example:443".into()];
        let rules = prepare(&[rule(), explicit]).unwrap();
        let mut input = request("POST", "/login", Some("https://internal.example/"));
        input
            .headers_mut()
            .insert("x-forwarded-host", "internal.example".parse().unwrap());
        input
            .headers_mut()
            .insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(check(&rules, &input, None, "http"), Err(403));
        assert_eq!(
            check(&rules, &input, Some("internal.example:443"), "https"),
            Ok(())
        );
        let mut missing = rule();
        missing.allow_missing_origin = true;
        assert_eq!(
            check(
                &prepare(&[missing]).unwrap(),
                &request("POST", "/login", None),
                None,
                "http"
            ),
            Ok(())
        );
    }

    #[test]
    fn explicit_verified_port_is_used_only_for_authorities_without_a_port() {
        let rules = prepare(&[rule()]).unwrap();
        let input = request("POST", "/login", Some("https://app.example:8443"));
        assert_eq!(
            super::check(&rules, &input, Some("app.example"), "https", Some(8443)),
            Ok(())
        );
        assert_eq!(
            super::check(
                &rules,
                &request("POST", "/login", Some("https://app.example")),
                Some("app.example"),
                "https",
                Some(8443)
            ),
            Err(403)
        );
        assert_eq!(
            super::check(&rules, &input, Some("app.example:8443"), "https", Some(443)),
            Ok(())
        );
        assert_eq!(
            super::check(
                &rules,
                &request("pAtCh", "/login", None),
                None,
                "http",
                None
            ),
            Err(403)
        );
        assert_eq!(
            super::check(
                &rules,
                &request("POST", "/login", Some("https://app.example")),
                Some("app.example"),
                "https",
                None
            ),
            Ok(())
        );
    }
}
