//! Bounded per-process URL token buckets, shared across clients by default or
//! kept per effective client IP with a bounded least-recently-used table.
use anyhow::{Result, ensure};
use hyper::Request;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

/// Client buckets kept per rule when `max_clients` is not set.
pub const DEFAULT_MAX_CLIENTS: u32 = 65_536;
/// Upper bound for one rule's `max_clients` and for the sum over all rules,
/// so per-client state stays within a predictable memory budget.
pub const MAX_TOTAL_CLIENTS: u64 = 1_048_576;

fn default_burst() -> u32 {
    1
}

fn is_false(value: &bool) -> bool {
    !*value
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
    /// Keep a separate budget for each effective client IP (resolved through
    /// trusted proxies) instead of one budget shared by every client.
    #[serde(default, skip_serializing_if = "is_false")]
    pub per_client: bool,
    /// Most client budgets kept for a `per_client` rule; the least recently
    /// used one is dropped first. Default 65,536.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_clients: Option<u32>,
}

impl Rule {
    pub(crate) fn client_capacity(&self) -> usize {
        self.max_clients.unwrap_or(DEFAULT_MAX_CLIENTS) as usize
    }
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
        ensure!(
            rule.per_client || rule.max_clients.is_none(),
            "path rate max_clients requires per_client"
        );
        ensure!(
            rule.max_clients
                .is_none_or(|max| (1..=MAX_TOTAL_CLIENTS).contains(&u64::from(max))),
            "path rate max_clients must be 1..1048576"
        );
        for window in &rule.limits {
            ensure!(
                (1..=1_000_000).contains(&window.requests)
                    && (1..=86400).contains(&window.window_seconds),
                "rate window requests must be 1..1000000 and seconds 1..86400"
            );
        }
    }
    let total: u64 = rules
        .iter()
        .filter(|rule| rule.per_client)
        .map(|rule| rule.client_capacity() as u64)
        .sum();
    ensure!(
        total <= MAX_TOTAL_CLIENTS,
        "path rate per_client rules may keep at most 1048576 clients in total"
    );
    Ok(())
}

#[derive(Debug)]
struct State {
    updated: Instant,
    credit: u64,
    windows: Vec<(Instant, u32)>,
}
impl State {
    fn new(rule: &Rule, now: Instant) -> Self {
        Self {
            updated: now,
            credit: u64::from(rule.burst) * 1_000_000_000,
            windows: rule.limits.iter().map(|_| (now, 0)).collect(),
        }
    }

    /// Check every limit first, then charge all of them, so a rejected
    /// request never consumes part of a budget.
    fn admit(&mut self, rule: &Rule, now: Instant) -> bool {
        let refill = now
            .saturating_duration_since(self.updated)
            .as_nanos()
            .saturating_mul(u128::from(rule.tps.unwrap_or(0)));
        let capacity = u64::from(rule.burst) * 1_000_000_000;
        self.credit = (u128::from(self.credit)
            .saturating_add(refill)
            .min(u128::from(capacity))) as u64;
        self.updated = now.max(self.updated);
        for (index, limit) in rule.limits.iter().enumerate() {
            let window = &mut self.windows[index];
            if now.saturating_duration_since(window.0).as_secs() >= u64::from(limit.window_seconds)
            {
                *window = (now.max(window.0), 0);
            }
        }
        if (rule.tps.is_some() && self.credit < 1_000_000_000)
            || rule
                .limits
                .iter()
                .zip(&self.windows)
                .any(|(limit, (_, used))| *used >= limit.requests)
        {
            return false;
        }
        if rule.tps.is_some() {
            self.credit -= 1_000_000_000;
        }
        for (_, used) in &mut self.windows {
            *used += 1;
        }
        true
    }
}

/// Per-client budgets with least-recently-used eviction. `order` maps the
/// last-use tick to the client so eviction and touch are O(log n).
#[derive(Debug, Default)]
struct Clients {
    states: HashMap<IpAddr, (State, u64)>,
    order: BTreeMap<u64, IpAddr>,
    tick: u64,
}

impl Clients {
    fn admit(&mut self, rule: &Rule, ip: IpAddr, now: Instant) -> bool {
        self.tick += 1;
        let tick = self.tick;
        if let Some((_, used)) = self.states.get_mut(&ip) {
            self.order.remove(used);
            *used = tick;
        } else {
            while self.states.len() >= rule.client_capacity() {
                let Some((_, oldest)) = self.order.pop_first() else {
                    break;
                };
                self.states.remove(&oldest);
            }
            self.states.insert(ip, (State::new(rule, now), tick));
        }
        self.order.insert(tick, ip);
        let (state, _) = self
            .states
            .get_mut(&ip)
            .expect("client state was inserted above");
        state.admit(rule, now)
    }
}

#[derive(Debug)]
pub struct Bucket {
    rule: Rule,
    state: Mutex<State>,
    clients: Mutex<Clients>,
}
impl Bucket {
    fn new(rule: Rule) -> Self {
        let state = State::new(&rule, Instant::now());
        Self {
            rule,
            state: Mutex::new(state),
            clients: Mutex::new(Clients::default()),
        }
    }
    fn admit(&self, ip: IpAddr, now: Instant) -> bool {
        if self.rule.per_client {
            return self
                .clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .admit(&self.rule, ip.to_canonical(), now);
        }
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit(&self.rule, now)
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
    client_ip: IpAddr,
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
            && !bucket.admit(client_ip, now)
        {
            return Err(429);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));

    fn per_client_rule(burst: u32, max_clients: Option<u32>) -> Rule {
        Rule {
            path: "/login".into(),
            include_subpaths: false,
            hosts: vec![],
            tps: Some(1),
            burst,
            limits: vec![],
            per_client: true,
            max_clients,
        }
    }

    fn ip(n: u32) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::from(0xc633_6400 + n))
    }

    #[test]
    fn per_client_budgets_are_independent_and_shared_mode_is_unchanged() {
        let bucket = Bucket::new(per_client_rule(2, None));
        let now = Instant::now();
        assert!(bucket.admit(ip(1), now));
        assert!(bucket.admit(ip(1), now));
        assert!(
            !bucket.admit(ip(1), now),
            "one client exhausted its own budget"
        );
        assert!(bucket.admit(ip(2), now), "another client keeps its budget");
        // IPv4-mapped IPv6 is the same client as its IPv4 form.
        let mapped: IpAddr = "::ffff:198.51.100.1".parse().unwrap();
        assert!(!bucket.admit(mapped, now));
        assert!(bucket.admit(ip(1), now + std::time::Duration::from_secs(1)));

        let mut shared = per_client_rule(2, None);
        shared.per_client = false;
        let bucket = Bucket::new(shared);
        assert!(bucket.admit(ip(1), now));
        assert!(bucket.admit(ip(2), now));
        assert!(!bucket.admit(ip(3), now), "shared mode spends one budget");
    }

    #[test]
    fn per_client_table_is_bounded_and_evicts_least_recently_used() {
        let bucket = Bucket::new(per_client_rule(1, Some(3)));
        let now = Instant::now();
        for n in 1..=3 {
            assert!(bucket.admit(ip(n), now));
        }
        // Touch client 1 so client 2 becomes the least recently used.
        assert!(!bucket.admit(ip(1), now));
        assert!(bucket.admit(ip(4), now));
        {
            let clients = bucket.clients.lock().unwrap();
            assert_eq!(clients.states.len(), 3);
            assert_eq!(clients.order.len(), 3);
            assert!(!clients.states.contains_key(&ip(2)));
        }
        assert!(
            !bucket.admit(ip(1), now),
            "recently used client kept its state"
        );
        assert!(!bucket.admit(ip(3), now), "client 3 kept its state");
        // A flood of new addresses never grows the table past its bound.
        for n in 100..1100 {
            bucket.admit(ip(n), now);
        }
        let clients = bucket.clients.lock().unwrap();
        assert_eq!(clients.states.len(), 3);
        assert_eq!(clients.order.len(), 3);
    }

    #[test]
    fn per_client_capacity_is_validated_per_rule_and_in_total() {
        assert!(validate(&[per_client_rule(1, Some(0))]).is_err());
        assert!(validate(&[per_client_rule(1, Some(1_048_577))]).is_err());
        assert!(validate(&[per_client_rule(1, Some(1_048_576))]).is_ok());
        let mut shared = per_client_rule(1, Some(10));
        shared.per_client = false;
        assert!(validate(&[shared]).is_err(), "max_clients needs per_client");
        let mut second = per_client_rule(1, Some(1_048_576 - 65_536));
        second.path = "/other".into();
        assert!(validate(&[per_client_rule(1, None), second.clone()]).is_ok());
        second.max_clients = Some(1_048_576 - 65_535);
        assert!(validate(&[per_client_rule(1, None), second]).is_err());
    }

    #[test]
    fn shared_rules_serialize_without_per_client_fields() {
        let mut rule = per_client_rule(1, None);
        rule.per_client = false;
        let json = serde_json::to_value(&rule).unwrap();
        assert!(json.get("per_client").is_none());
        assert!(json.get("max_clients").is_none());
    }
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
                    per_client: false,
                    max_clients: None,
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
            per_client: false,
            max_clients: None,
        };
        let buckets = prepare(std::slice::from_ref(&rule), &[]);
        let now = Instant::now();
        let accepted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..64)
                .map(|_| scope.spawn(|| buckets[0].admit(IP, now)))
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
        assert!(!reloaded[0].admit(IP, now));
        assert!(reloaded[0].admit(IP, now + std::time::Duration::from_secs(1)));
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
            per_client: false,
            max_clients: None,
        });
        let now = Instant::now();
        assert!(bucket.admit(IP, now));
        assert!(bucket.admit(IP, now));
        assert!(!bucket.admit(IP, now));
        assert!(bucket.admit(IP, now + std::time::Duration::from_secs(60)));
        assert!(!bucket.admit(IP, now + std::time::Duration::from_secs(60)));
        assert!(bucket.admit(IP, now + std::time::Duration::from_secs(86400)));
    }
}
