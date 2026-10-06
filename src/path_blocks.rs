//! Explicit host/path deny namespaces evaluated before routing or origin work.
use anyhow::{Result, ensure};
use hyper::Request;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Canonical absolute path. Matches itself and slash-delimited descendants.
    pub path: String,
    /// Empty means every host. Uses the ordinary bounded hostname glob syntax.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(
        rules.len() <= 128,
        "settings.path_blocks allows at most 128 rules"
    );
    let mut text = 0;
    for rule in rules {
        ensure!(
            crate::resource_policy::canonical_path(&rule.path)? == rule.path,
            "blocked path must be canonical, without percent escapes"
        );
        ensure!(
            rule.path == "/" || !rule.path.ends_with('/'),
            "blocked path must not end in / (except root)"
        );
        ensure!(
            rule.hosts.len() <= 16,
            "blocked path allows at most 16 hosts"
        );
        text += rule.path.len();
        for host in &rule.hosts {
            crate::host_match::validate_pattern(host)?;
            text += host.len();
        }
    }
    ensure!(text <= 32 * 1024, "settings.path_blocks exceeds 32 KiB");
    Ok(())
}

pub(crate) fn check<B>(
    rules: &[Rule],
    request: &Request<B>,
    forwarded_host: Option<&str>,
) -> Result<(), u16> {
    if rules.is_empty() {
        return Ok(());
    }
    let raw = crate::resource_guard::request_host(request);
    let forwarded =
        forwarded_host.and_then(|value| value.parse::<hyper::http::uri::Authority>().ok());
    let absolute = request.uri().authority();
    let scoped = |rule: &&Rule| {
        rule.hosts.is_empty()
            || rule.hosts.iter().any(|pattern| {
                [
                    raw.as_deref(),
                    forwarded.as_ref().map(|host| host.host()),
                    absolute.map(|host| host.host()),
                ]
                .into_iter()
                .flatten()
                .any(|host| crate::host_match::matches(pattern, host.trim_end_matches('.')))
            })
    };
    if !rules.iter().any(|rule| scoped(&rule)) {
        return Ok(());
    }
    // A strict profile for scoped hosts rejects aliases instead of guessing
    // how each backend decodes percent escapes, separators and traversal.
    let path = crate::resource_policy::canonical_path(request.uri().path()).map_err(|_| 400u16)?;
    if rules.iter().filter(scoped).any(|rule| {
        rule.path == "/"
            || path == rule.path
            || path
                .strip_prefix(&rule.path)
                .is_some_and(|tail| tail.starts_with('/'))
    }) {
        return Err(404);
    }
    Ok(())
}

pub(crate) fn selector_matches<B>(
    scope: &Rule,
    request: &Request<B>,
    forwarded_host: Option<&str>,
    include_subpaths: bool,
) -> Result<bool, u16> {
    if !scope_host_matches(scope, request, forwarded_host) {
        return Ok(false);
    }
    let path = crate::resource_policy::canonical_path(request.uri().path()).map_err(|_| 400u16)?;
    Ok(path == scope.path
        || (scope.path != "/" && path.strip_suffix('/') == Some(scope.path.as_str()))
        || (include_subpaths
            && (scope.path == "/"
                || path
                    .strip_prefix(&scope.path)
                    .is_some_and(|tail| tail.starts_with('/')))))
}

pub(crate) fn scope_host_matches<B>(
    scope: &Rule,
    request: &Request<B>,
    forwarded_host: Option<&str>,
) -> bool {
    let raw = crate::resource_guard::request_host(request);
    let forwarded =
        forwarded_host.and_then(|value| value.parse::<hyper::http::uri::Authority>().ok());
    let candidates = [
        raw.as_deref(),
        forwarded.as_ref().map(|host| host.host()),
        request.uri().authority().map(|host| host.host()),
    ];
    scope.hosts.is_empty()
        || scope.hosts.iter().any(|pattern| {
            candidates
                .into_iter()
                .flatten()
                .any(|host| crate::host_match::matches(pattern, host.trim_end_matches('.')))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denies_namespaces_and_rejects_aliases_without_matching_sibling_prefixes() {
        let rules = vec![Rule {
            path: "/private".into(),
            hosts: vec!["app.example".into()],
        }];
        validate(&rules).unwrap();
        for path in [
            "/private",
            "/private/a",
            "/pr%69vate",
            "/private?ignored=yes",
        ] {
            let request = Request::builder()
                .uri(path)
                .header("host", "app.example")
                .body(())
                .unwrap();
            assert_eq!(check(&rules, &request, None), Err(404), "{path}");
        }
        for path in [
            "/%2570rivate",
            "/public/../private",
            "/private%2fa",
            "/private;parameter",
            "//private",
            "/private\\a",
        ] {
            let request = Request::builder()
                .uri(path)
                .header("host", "app.example")
                .body(())
                .unwrap();
            assert_eq!(check(&rules, &request, None), Err(400), "{path}");
        }
        for (path, host) in [
            ("/private-news", "app.example"),
            ("/private", "other.example"),
        ] {
            let request = Request::builder()
                .uri(path)
                .header("host", host)
                .body(())
                .unwrap();
            assert_eq!(check(&rules, &request, None), Ok(()));
        }
        let request = Request::builder()
            .uri("/private")
            .header("host", "other.example")
            .body(())
            .unwrap();
        assert_eq!(check(&rules, &request, Some("app.example:443")), Err(404));
    }
}
