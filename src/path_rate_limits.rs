//! Bounded per-process, shared-across-clients URL token buckets.
use anyhow::{Result, ensure};
use hyper::Request;
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

fn default_burst() -> u32 {
    1
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    /// Exact URL by default; descendants require an explicit opt-in.
    #[serde(default)]
    pub include_subpaths: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Sustained requests per second, shared across all matching clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tps: Option<u32>,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limits: Vec<Window>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Window {
    pub requests: u32,
    pub window_seconds: u32,
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(
        rules.len() <= 128,
        "settings.path_rate_limits allows at most 128 rules"
    );
    crate::path_blocks::validate(
        &rules
            .iter()
            .map(|r| crate::path_blocks::Rule {
                path: r.path.clone(),
                hosts: r.hosts.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    for (index, rule) in rules.iter().enumerate() {
        ensure!(!rules[..index].contains(rule), "duplicate path rate rule");
        ensure!(
            rule.tps.is_none_or(|tps| (1..=1_000_000).contains(&tps)),
            "path rate tps must be 1..1000000"
        );
        ensure!(
            (1..=1_000_000).contains(&rule.burst),
            "path rate burst must be 1..1000000"
        );
        ensure!(
            rule.tps.is_some() || !rule.limits.is_empty(),
            "rate rule needs tps or limits"
        );
        ensure!(rule.limits.len() <= 8, "rate rule allows at most 8 windows");
        for window in &rule.limits {
            ensure!(
                (1..=1_000_000).contains(&window.requests)
                    && (1..=86400).contains(&window.window_seconds),
                "rate window requests must be 1..1000000 and seconds 1..86400"
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct State {
    updated: Instant,
    credit: u64,
    windows: Vec<(Instant, u32)>,
}
#[derive(Debug)]
pub struct Bucket {
    rule: Rule,
    state: Mutex<State>,
}
impl Bucket {
    fn new(rule: Rule) -> Self {
        let credit = u64::from(rule.burst) * 1_000_000_000;
        let now = Instant::now();
        let windows = rule.limits.iter().map(|_| (now, 0)).collect();
        Self {
            rule,
            state: Mutex::new(State {
                updated: now,
                credit,
                windows,
            }),
        }
    }
    fn admit(&self, now: Instant) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let refill = now
            .saturating_duration_since(state.updated)
            .as_nanos()
            .saturating_mul(u128::from(self.rule.tps.unwrap_or(0)));
        let capacity = u64::from(self.rule.burst) * 1_000_000_000;
        state.credit = (u128::from(state.credit)
            .saturating_add(refill)
            .min(u128::from(capacity))) as u64;
        state.updated = now.max(state.updated);
        for (index, limit) in self.rule.limits.iter().enumerate() {
            let window = &mut state.windows[index];
            if now.saturating_duration_since(window.0).as_secs() >= u64::from(limit.window_seconds)
            {
                *window = (now.max(window.0), 0);
            }
        }
        if (self.rule.tps.is_some() && state.credit < 1_000_000_000)
            || self
                .rule
                .limits
                .iter()
                .zip(&state.windows)
                .any(|(limit, (_, used))| *used >= limit.requests)
        {
            return false;
        }
        if self.rule.tps.is_some() {
            state.credit -= 1_000_000_000;
        }
        for (_, used) in &mut state.windows {
            *used += 1;
        }
        true
    }
}

pub(crate) fn prepare(rules: &[Rule], previous: &[Arc<Bucket>]) -> Vec<Arc<Bucket>> {
    rules
        .iter()
        .map(|rule| {
            previous
                .iter()
                .find(|old| old.rule == *rule)
                .cloned()
                .unwrap_or_else(|| Arc::new(Bucket::new(rule.clone())))
        })
        .collect()
}

/// Every matching rule applies; changing routes cannot bypass a namespace.
pub(crate) fn check<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
) -> Result<(), u16> {
    if buckets.is_empty() {
        return Ok(());
    }
    let raw = crate::resource_guard::request_host(request);
    let forwarded =
        forwarded_host.and_then(|value| value.parse::<hyper::http::uri::Authority>().ok());
    let absolute = request.uri().authority();
    let scoped = |bucket: &&Arc<Bucket>| {
        bucket.rule.hosts.is_empty()
            || bucket.rule.hosts.iter().any(|pattern| {
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
    if !buckets.iter().any(|bucket| scoped(&bucket)) {
        return Ok(());
    }
    let path = crate::resource_policy::canonical_path(request.uri().path()).map_err(|_| 400u16)?;
    let now = Instant::now();
    for bucket in buckets.iter().filter(scoped) {
        let base = &bucket.rule.path;
        if (&path == base
            || (base != "/" && path.strip_suffix('/') == Some(base.as_str()))
            || (bucket.rule.include_subpaths
                && (base == "/"
                    || path
                        .strip_prefix(base)
                        .is_some_and(|tail| tail.starts_with('/')))))
            && !bucket.admit(now)
        {
            return Err(429);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_limits_and_ambiguous_configuration_are_rejected() {
        for (path, tps, burst) in [("/x", 0, 1), ("/x", 1, 0), ("/%78", 1, 1), ("/x/", 1, 1)] {
            assert!(
                validate(&[Rule {
                    path: path.into(),
                    include_subpaths: false,
                    hosts: vec![],
                    tps: Some(tps),
                    burst,
                    limits: vec![],
                }])
                .is_err()
            );
        }
    }
    #[test]
    fn concurrency_cannot_overspend_and_reload_preserves_budget() {
        let rule = Rule {
            path: "/api".into(),
            include_subpaths: false,
            hosts: vec![],
            tps: Some(1),
            burst: 7,
            limits: vec![],
        };
        let buckets = prepare(std::slice::from_ref(&rule), &[]);
        let now = Instant::now();
        let accepted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..64)
                .map(|_| scope.spawn(|| buckets[0].admit(now)))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|accepted| *accepted)
                .count()
        });
        assert_eq!(accepted, 7);
        let reloaded = prepare(std::slice::from_ref(&rule), &buckets);
        assert!(Arc::ptr_eq(&buckets[0], &reloaded[0]));
        assert!(!reloaded[0].admit(now));
        assert!(reloaded[0].admit(now + std::time::Duration::from_secs(1)));
    }

    #[test]
    fn minute_and_day_windows_apply_together_without_partial_charges() {
        let bucket = Bucket::new(Rule {
            path: "/login".into(),
            hosts: vec![],
            include_subpaths: false,
            tps: None,
            burst: 1,
            limits: vec![
                Window {
                    requests: 2,
                    window_seconds: 60,
                },
                Window {
                    requests: 3,
                    window_seconds: 86400,
                },
            ],
        });
        let now = Instant::now();
        assert!(bucket.admit(now));
        assert!(bucket.admit(now));
        assert!(!bucket.admit(now));
        assert!(bucket.admit(now + std::time::Duration::from_secs(60)));
        assert!(!bucket.admit(now + std::time::Duration::from_secs(60)));
        assert!(bucket.admit(now + std::time::Duration::from_secs(86400)));
    }
}
