//! Gateway host/path resource namespaces, independent of route predicates.
use crate::config::{HttpRoute, HttpRuntime, PathMatch};
use hyper::{Request, header};
use std::sync::Arc;

pub(crate) fn request_host<B>(request: &Request<B>) -> Option<String> {
    request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(authority_host)
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|authority| authority.host().to_owned())
        })
}
fn authority_host(value: &str) -> Option<String> {
    value
        .parse::<hyper::http::uri::Authority>()
        .ok()
        .map(|authority| authority.host().to_owned())
}
pub(crate) fn host_matches(
    route: &HttpRoute,
    regex: Option<&regex::Regex>,
    actual: Option<&str>,
) -> bool {
    if route.host.as_ref().is_some_and(|pattern| {
        !actual.is_some_and(|host| crate::host_match::matches(pattern, host))
    }) {
        return false;
    }
    if !route.hosts.is_empty()
        && !actual.is_some_and(|host| {
            route
                .hosts
                .iter()
                .any(|pattern| crate::host_match::matches(pattern, host))
        })
    {
        return false;
    }
    !regex.is_some_and(|regex| {
        !actual.is_some_and(|host| host.len() <= 253 && host.is_ascii() && regex.is_match(host))
    })
}
pub(crate) fn path_matches(route: &HttpRoute, path: &str) -> bool {
    let Some(prefix) = &route.path_prefix else {
        return true;
    };
    match route.path_match {
        PathMatch::Prefix => path.starts_with(prefix),
        PathMatch::Exact => path == prefix,
        PathMatch::SegmentPrefix => {
            let base = prefix.trim_end_matches('/');
            base.is_empty()
                || path == base
                || path
                    .strip_prefix(base)
                    .is_some_and(|tail| tail.starts_with('/'))
        }
    }
}
fn scope_host(runtime: &HttpRuntime, host: Option<&str>) -> bool {
    host_matches(&runtime.route, runtime.host_regex.as_ref(), host)
        || host.is_some_and(|host| {
            host_matches(
                &runtime.route,
                runtime.host_regex.as_ref(),
                Some(host.trim_end_matches('.')),
            )
        })
}
fn same_host(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}
/// A strict path profile applies to the entire host if it has any protected
/// namespace. Ambiguous hosts are rejected even if only the alternate authority
/// matches a guard. Disabled routes retain their namespace until explicit release.
pub(crate) fn check<'a, B>(
    guards: &'a [Arc<HttpRuntime>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
) -> Result<(Option<&'a str>, Option<String>), u16> {
    if guards.is_empty() {
        return Ok((None, None));
    }
    let raw = request_host(request);
    let forwarded = forwarded_host.and_then(authority_host);
    let absolute = request.uri().authority().map(|authority| authority.host());
    let candidates = [raw.as_deref(), forwarded.as_deref(), absolute];
    if !guards
        .iter()
        .any(|runtime| candidates.iter().any(|host| scope_host(runtime, *host)))
    {
        return Ok((None, None));
    }
    if !same_host(raw.as_deref(), forwarded.as_deref())
        || absolute.is_some_and(|host| !same_host(raw.as_deref(), Some(host)))
        || raw.as_deref().is_some_and(|host| host.ends_with('.'))
    {
        return Err(400);
    }
    let path = crate::resource_policy::canonical_path(request.uri().path()).map_err(|_| 400u16)?;
    let mut resource = None;
    for runtime in guards {
        if scope_host(runtime, raw.as_deref()) && path_matches(&runtime.route, &path) {
            let id = runtime
                .route
                .resource_policy
                .as_ref()
                .expect("compiled guard")
                .resource_id
                .as_str();
            if resource.is_some_and(|old| old != id) {
                return Err(403);
            }
            resource = Some(id);
        }
    }
    Ok((resource, Some(path)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Snapshot};
    use serde_json::json;

    #[test]
    #[ignore = "owned release-mode microbenchmark, not a network throughput test"]
    fn namespace_guard_microbenchmark() {
        for count in [0, 1, 32, 256] {
            let routes: Vec<_> = (0..count).map(|index| json!({
                "id":format!("route-{index}"), "host":"app.test",
                "path_prefix":format!("/resource-{index}/"), "access_mode":"protected",
                "auth":{"url":"http://127.0.0.1:9/check", "response_headers":["x-subject"]},
                "backends":["http://127.0.0.1:9"],
                "resource_policy":{"resource_id":format!("resource-{index}"),
                    "principal":{"source":"external", "subject_header":"x-subject"}, "allow":[]}
            })).collect();
            let config: Config = serde_json::from_value(json!({"http":routes})).unwrap();
            let snapshot = Snapshot::new(config).unwrap();
            let request = Request::builder()
                .uri(format!("/resource-{}/item", count.max(1) - 1))
                .header("host", "app.test")
                .body(())
                .unwrap();
            let iterations = 200_000;
            let started = std::time::Instant::now();
            for _ in 0..iterations {
                std::hint::black_box(
                    check(
                        std::hint::black_box(&snapshot.resource_guards),
                        std::hint::black_box(&request),
                        Some("app.test"),
                    )
                    .unwrap(),
                );
            }
            println!(
                "resource_guards={count} iterations={iterations} mean_ns={:.2}",
                started.elapsed().as_nanos() as f64 / f64::from(iterations)
            );
        }
    }
}
