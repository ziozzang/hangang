//! Bounded, rule-local client-IP bans after selected URL response failures.
use anyhow::{Result, ensure};
use hyper::Request;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_CLIENTS: usize = 1024;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    #[default]
    Url,
    Host,
    Global,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct BanEvent {
    pub path: String,
    pub ban_seconds: u32,
}

fn default_statuses() -> Vec<u16> {
    vec![401, 403]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub include_subpaths: bool,
    pub failures: u32,
    pub window_seconds: u32,
    pub ban_seconds: u32,
    #[serde(default = "default_statuses")]
    pub statuses: Vec<u16>,
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(
        rules.len() <= 128,
        "path failure bans allow at most 128 rules"
    );
    crate::path_blocks::validate(
        &rules
            .iter()
            .map(|rule| crate::path_blocks::Rule {
                path: rule.path.clone(),
                hosts: rule.hosts.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    for (index, rule) in rules.iter().enumerate() {
        ensure!(
            !rules[..index].contains(rule),
            "duplicate path failure ban rule"
        );
        ensure!(
            (1..=1000).contains(&rule.failures),
            "path failure threshold must be 1..1000"
        );
        ensure!(
            (1..=86400).contains(&rule.window_seconds) && (1..=86400).contains(&rule.ban_seconds),
            "path failure window and ban must be 1..86400 seconds"
        );
        ensure!(
            !rule.statuses.is_empty() && rule.statuses.len() <= 16,
            "path failure statuses must contain 1..16 values"
        );
        for (index, status) in rule.statuses.iter().enumerate() {
            ensure!(
                (400..=599).contains(status) && !rule.statuses[..index].contains(status),
                "path failure statuses must be distinct values in 400..599"
            );
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Record {
    generation: Arc<()>,
    updated: Instant,
    window_started: Instant,
    failures: u32,
    banned_since: Option<Instant>,
    in_flight: usize,
}

impl Record {
    fn banned(&self, rule: &Rule, now: Instant) -> bool {
        self.banned_since.is_some_and(|started| {
            now.saturating_duration_since(started)
                < Duration::from_secs(u64::from(rule.ban_seconds))
        })
    }

    fn window_live(&self, rule: &Rule, now: Instant) -> bool {
        now.saturating_duration_since(self.window_started)
            < Duration::from_secs(u64::from(rule.window_seconds))
    }

    fn reset_expired(&mut self, rule: &Rule, now: Instant) {
        if self.banned_since.is_some() && !self.banned(rule, now) {
            self.banned_since = None;
            self.failures = 0;
            self.window_started = now;
        } else if self.banned_since.is_none() && !self.window_live(rule, now) {
            self.failures = 0;
            self.window_started = now;
        }
    }
}

#[derive(Debug)]
pub struct Bucket {
    rule: Rule,
    selector: crate::path_blocks::Rule,
    clients: Mutex<HashMap<IpAddr, Record>>,
}

impl Bucket {
    fn new(rule: Rule) -> Self {
        Self {
            selector: crate::path_blocks::Rule {
                path: rule.path.clone(),
                hosts: rule.hosts.clone(),
            },
            rule,
            clients: Mutex::new(HashMap::new()),
        }
    }

    fn reserve(self: &Arc<Self>, ip: IpAddr, now: Instant) -> Result<Lease, u16> {
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !clients.contains_key(&ip) && clients.len() >= MAX_CLIENTS {
            // Never evict a live ban or an in-flight observation to make room
            // for an attacker rotating addresses. Only expired entries go.
            clients.retain(|_, record| {
                record.in_flight != 0
                    || record.banned(&self.rule, now)
                    || (record.banned_since.is_none()
                        && record.failures != 0
                        && record.window_live(&self.rule, now))
            });
            if clients.len() >= MAX_CLIENTS {
                return Err(503);
            }
        }
        let record = clients.entry(ip).or_insert_with(|| Record {
            generation: Arc::new(()),
            updated: now,
            window_started: now,
            failures: 0,
            banned_since: None,
            in_flight: 0,
        });
        let now = now.max(record.updated);
        record.updated = now;
        record.reset_expired(&self.rule, now);
        if record.banned(&self.rule, now) {
            return Err(429);
        }
        record.in_flight = record.in_flight.checked_add(1).ok_or(503u16)?;
        Ok(Lease {
            bucket: self.clone(),
            ip,
            generation: record.generation.clone(),
        })
    }

    fn record(&self, ip: IpAddr, generation: &Arc<()>, status: u16, now: Instant) -> bool {
        if !self.rule.statuses.contains(&status) {
            return false;
        }
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(record) = clients.get_mut(&ip) else {
            return false;
        };
        if !Arc::ptr_eq(&record.generation, generation) {
            return false;
        }
        // Response tasks can acquire this lock in a different order from
        // their timestamp samples. Never backdate a new window or ban.
        let now = now.max(record.updated);
        record.updated = now;
        record.reset_expired(&self.rule, now);
        // A response admitted before the threshold must not slide an active
        // ban's deadline on every delayed concurrent failure.
        if record.banned(&self.rule, now) {
            return false;
        }
        if record.failures == 0 {
            record.window_started = now;
        }
        record.failures = record.failures.saturating_add(1).min(self.rule.failures);
        if record.failures >= self.rule.failures {
            record.banned_since = Some(now);
            // Every request admitted before this ban belongs to the retired
            // failure generation. Its delayed response must not establish a
            // second ban after natural expiry; its Drop must not decrement
            // reservations admitted in the replacement generation either.
            record.generation = Arc::new(());
            record.in_flight = 0;
            return true;
        }
        false
    }
}

struct Lease {
    bucket: Arc<Bucket>,
    ip: IpAddr,
    generation: Arc<()>,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut clients = self
            .bucket
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(record) = clients.get_mut(&self.ip) {
            if !Arc::ptr_eq(&record.generation, &self.generation) {
                return;
            }
            record.in_flight -= 1;
            if record.in_flight == 0 && record.failures == 0 && record.banned_since.is_none() {
                clients.remove(&self.ip);
            }
        }
    }
}

/// A response observation owns bounded client-map reservations. Dropping it
/// without a response records no failure, including request cancellation.
pub(crate) struct Observation {
    leases: Vec<Lease>,
}

impl Observation {
    pub(crate) fn is_failure(&self, status: u16) -> bool {
        self.leases
            .iter()
            .any(|lease| lease.bucket.rule.statuses.contains(&status))
    }
    pub(crate) fn record(self, status: u16) -> Vec<BanEvent> {
        self.record_at(status, Instant::now())
    }

    fn record_at(self, status: u16, now: Instant) -> Vec<BanEvent> {
        let mut events = Vec::new();
        for lease in &self.leases {
            if lease
                .bucket
                .record(lease.ip, &lease.generation, status, now)
            {
                events.push(BanEvent {
                    path: lease.bucket.rule.path.clone(),
                    ban_seconds: lease.bucket.rule.ban_seconds,
                });
            }
        }
        events
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub(crate) struct BanInfo {
    pub ip: IpAddr,
    pub path: String,
    pub remaining_seconds: u64,
}

pub(crate) fn list(
    buckets: &[Arc<Bucket>],
    ip: Option<IpAddr>,
    limit: usize,
) -> (Vec<BanInfo>, bool) {
    list_at(
        buckets,
        ip.map(|ip| ip.to_canonical()),
        limit,
        Instant::now(),
    )
}

fn list_at(
    buckets: &[Arc<Bucket>],
    ip: Option<IpAddr>,
    limit: usize,
    now: Instant,
) -> (Vec<BanInfo>, bool) {
    let limit = limit.min(200);
    let mut bans = Vec::new();
    let mut truncated = false;
    for bucket in buckets {
        let clients = bucket
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (client, record) in &*clients {
            if ip.is_some_and(|ip| ip != *client) || !record.banned(&bucket.rule, now) {
                continue;
            }
            if bans.len() == limit {
                truncated = true;
                break;
            }
            let elapsed =
                now.saturating_duration_since(record.banned_since.expect("active ban has start"));
            let remaining =
                Duration::from_secs(u64::from(bucket.rule.ban_seconds)).saturating_sub(elapsed);
            bans.push(BanInfo {
                ip: *client,
                path: bucket.rule.path.clone(),
                remaining_seconds: remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0),
            });
        }
        if truncated {
            break;
        }
    }
    bans.sort_by(|left, right| {
        left.ip
            .cmp(&right.ip)
            .then_with(|| left.path.cmp(&right.path))
    });
    (bans, truncated)
}

/// Removing the record creates a new generation on the next admission.
/// Old response observations and their Drop paths cannot mutate that record.
pub(crate) fn clear(buckets: &[Arc<Bucket>], ip: IpAddr) -> usize {
    let ip = ip.to_canonical();
    buckets
        .iter()
        .filter(|bucket| {
            bucket
                .clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&ip)
                .is_some()
        })
        .count()
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

pub(crate) fn check<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    ip: IpAddr,
    scope: Scope,
) -> Result<Observation, u16> {
    check_scope_at(
        buckets,
        request,
        forwarded_host,
        ip.to_canonical(),
        scope,
        Instant::now(),
    )
}

pub(crate) fn precheck<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    ip: IpAddr,
    scope: Scope,
) -> Result<(), u16> {
    precheck_at(
        buckets,
        request,
        forwarded_host,
        ip.to_canonical(),
        scope,
        Instant::now(),
    )
}

fn precheck_at<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    ip: IpAddr,
    scope: Scope,
    now: Instant,
) -> Result<(), u16> {
    for bucket in buckets {
        let banned = bucket
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ip)
            .is_some_and(|record| record.banned(&bucket.rule, now));
        if !banned {
            continue;
        }
        let matches = match scope {
            Scope::Global => true,
            Scope::Host => {
                crate::path_blocks::scope_host_matches(&bucket.selector, request, forwarded_host)
            }
            Scope::Url => crate::path_blocks::selector_matches(
                &bucket.selector,
                request,
                forwarded_host,
                bucket.rule.include_subpaths,
            )?,
        };
        if matches {
            return Err(429);
        }
    }
    Ok(())
}

#[cfg(test)]
fn check_at<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    ip: IpAddr,
    now: Instant,
) -> Result<Observation, u16> {
    check_scope_at(buckets, request, forwarded_host, ip, Scope::Url, now)
}

fn check_scope_at<B>(
    buckets: &[Arc<Bucket>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    ip: IpAddr,
    scope: Scope,
    now: Instant,
) -> Result<Observation, u16> {
    precheck_at(buckets, request, forwarded_host, ip, scope, now)?;
    let mut observation = Observation { leases: Vec::new() };
    for bucket in buckets {
        if crate::path_blocks::selector_matches(
            &bucket.selector,
            request,
            forwarded_host,
            bucket.rule.include_subpaths,
        )? {
            observation.leases.push(bucket.reserve(ip, now)?);
        }
    }
    Ok(observation)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule() -> Rule {
        Rule {
            path: "/login".into(),
            hosts: vec![],
            include_subpaths: false,
            failures: 3,
            window_seconds: 10,
            ban_seconds: 30,
            statuses: default_statuses(),
        }
    }
    fn request(path: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header("host", "app.example")
            .body(())
            .unwrap()
    }
    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }
    fn observe(buckets: &[Arc<Bucket>], ip: IpAddr, now: Instant) -> Observation {
        check_at(buckets, &request("/login"), None, ip, now).unwrap()
    }
    fn denied(buckets: &[Arc<Bucket>], ip: IpAddr, now: Instant) -> Option<u16> {
        check_at(buckets, &request("/login"), None, ip, now).err()
    }

    #[test]
    fn validation_bounds_and_duplicate_rules_are_closed() {
        validate(&[rule()]).unwrap();
        assert!(validate(&[rule(), rule()]).is_err());
        for bad in [0, 1001] {
            let mut invalid = rule();
            invalid.failures = bad;
            assert!(validate(&[invalid]).is_err());
        }
        for bad in [0, 86401] {
            let mut invalid = rule();
            invalid.window_seconds = bad;
            assert!(validate(&[invalid]).is_err());
            let mut invalid = rule();
            invalid.ban_seconds = bad;
            assert!(validate(&[invalid]).is_err());
        }
        for statuses in [
            vec![],
            vec![200],
            vec![600],
            vec![401, 401],
            (400..417).collect(),
        ] {
            let mut invalid = rule();
            invalid.statuses = statuses;
            assert!(validate(&[invalid]).is_err());
        }
        let wire: Rule = serde_json::from_str(
            r#"{"path":"/login","failures":3,"window_seconds":10,"ban_seconds":30}"#,
        )
        .unwrap();
        assert_eq!(wire, rule());
        assert!(serde_json::from_str::<Rule>(r#"{"path":"/login","failures":3,"window_seconds":10,"ban_seconds":30,"unknown":true}"#).is_err());
    }

    #[test]
    fn failures_are_ip_local_fixed_window_and_bans_expire_without_sliding() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        assert!(observe(&buckets, ip(1), now).record_at(401, now).is_empty());
        assert!(observe(&buckets, ip(1), now).record_at(403, now).is_empty());
        assert!(observe(&buckets, ip(1), now).record_at(200, now).is_empty());
        assert!(observe(&buckets, ip(1), now).record_at(500, now).is_empty());
        assert_eq!(denied(&buckets, ip(1), now), None);
        let delayed = observe(&buckets, ip(1), now);
        assert_eq!(
            observe(&buckets, ip(1), now).record_at(401, now),
            vec![BanEvent {
                path: "/login".into(),
                ban_seconds: 30
            }]
        );
        assert_eq!(denied(&buckets, ip(1), now), Some(429));
        assert_eq!(denied(&buckets, ip(2), now), None);
        assert!(
            delayed
                .record_at(401, now + Duration::from_secs(29))
                .is_empty()
        );
        assert_eq!(
            denied(&buckets, ip(1), now + Duration::from_secs(29)),
            Some(429)
        );
        assert_eq!(denied(&buckets, ip(1), now + Duration::from_secs(30)), None);
        // An expired failure window starts over; two old failures are not
        // enough to ban on the first failure of a new window.
        let _ = observe(&buckets, ip(2), now).record_at(401, now);
        let _ = observe(&buckets, ip(2), now).record_at(401, now);
        let _ = observe(&buckets, ip(2), now + Duration::from_secs(10))
            .record_at(401, now + Duration::from_secs(10));
        assert_eq!(denied(&buckets, ip(2), now + Duration::from_secs(10)), None);
    }

    #[test]
    fn parallel_completion_threshold_and_reload_share_one_ban() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        let pending: Vec<_> = (0..64).map(|_| observe(&buckets, ip(1), now)).collect();
        let event_count = std::thread::scope(|scope| {
            let handles: Vec<_> = pending
                .into_iter()
                .map(|observation| scope.spawn(move || observation.record_at(401, now).len()))
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .sum::<usize>()
        });
        assert_eq!(
            event_count, 1,
            "concurrent completions must emit one ban transition"
        );
        assert_eq!(denied(&buckets, ip(1), now), Some(429));
        let next = prepare(&[rule()], &buckets);
        assert!(Arc::ptr_eq(&next[0], &buckets[0]));
        assert_eq!(denied(&next, ip(1), now), Some(429));
        assert_eq!(buckets[0].clients.lock().unwrap()[&ip(1)].failures, 3);
        assert_eq!(buckets[0].clients.lock().unwrap()[&ip(1)].in_flight, 0);
    }

    #[test]
    fn cancellation_and_capacity_cannot_evict_live_clients_or_bans() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        let pending: Vec<_> = (0..MAX_CLIENTS)
            .map(|index| {
                observe(
                    &buckets,
                    IpAddr::from([10, 0, (index / 256) as u8, (index % 256) as u8]),
                    now,
                )
            })
            .collect();
        assert_eq!(denied(&buckets, ip(1), now), Some(503));
        assert_eq!(buckets[0].clients.lock().unwrap().len(), MAX_CLIENTS);
        drop(pending);
        assert!(buckets[0].clients.lock().unwrap().is_empty());
        for index in 0..MAX_CLIENTS {
            let client = IpAddr::from([10, 0, (index / 256) as u8, (index % 256) as u8]);
            for _ in 0..3 {
                let _ = observe(&buckets, client, now).record_at(401, now);
            }
        }
        assert_eq!(
            denied(&buckets, ip(1), now + Duration::from_secs(29)),
            Some(503)
        );
        assert_eq!(denied(&buckets, ip(1), now + Duration::from_secs(30)), None);
        assert!(buckets[0].clients.lock().unwrap().is_empty());
    }

    #[test]
    fn selectors_reject_aliases_and_reserve_only_exact_or_opted_in_paths() {
        let mut scoped = rule();
        scoped.hosts = vec!["app.example".into()];
        let buckets = prepare(&[scoped.clone()], &[]);
        let now = Instant::now();
        let _ = observe(&buckets, ip(1), now).record_at(401, now);
        let encoded =
            check_at(&buckets, &request("/log%69n?ignored=yes"), None, ip(1), now).unwrap();
        let _ = encoded.record_at(401, now);
        let _ = observe(&buckets, ip(1), now).record_at(401, now);
        assert_eq!(denied(&buckets, ip(1), now), Some(429));
        assert!(check_at(&buckets, &request("/login/image.png"), None, ip(1), now).is_ok());
        assert_eq!(
            check_at(&buckets, &request("/login%2fimage"), None, ip(1), now).err(),
            Some(400)
        );
        let other_host = Request::builder()
            .uri("/login")
            .header("host", "other.example")
            .body(())
            .unwrap();
        assert!(check_at(&buckets, &other_host, None, ip(1), now).is_ok());
        assert_eq!(
            check_at(&buckets, &other_host, Some("app.example.:443"), ip(1), now).err(),
            Some(429)
        );
        scoped.include_subpaths = true;
        let children = prepare(&[scoped], &[]);
        let selected = check_at(&children, &request("/login/image.png"), None, ip(1), now).unwrap();
        assert_eq!(selected.leases.len(), 1);
        assert!(
            check_at(&children, &request("/login-other"), None, ip(1), now)
                .unwrap()
                .leases
                .is_empty()
        );
    }

    #[test]
    fn optional_host_and_global_scopes_reuse_existing_url_bans_without_reserving_other_paths() {
        let mut scoped = rule();
        scoped.hosts = vec!["app.example".into()];
        let buckets = prepare(&[scoped], &[]);
        let now = Instant::now();
        for _ in 0..3 {
            let _ = observe(&buckets, ip(1), now).record_at(401, now);
        }
        let static_path = request("/image.png");
        let other_host = Request::builder()
            .uri("/image.png")
            .header("host", "other.example")
            .body(())
            .unwrap();
        assert_eq!(
            precheck_at(&buckets, &static_path, None, ip(1), Scope::Url, now),
            Ok(())
        );
        assert_eq!(
            precheck_at(&buckets, &static_path, None, ip(1), Scope::Host, now),
            Err(429)
        );
        assert_eq!(
            precheck_at(&buckets, &other_host, None, ip(1), Scope::Host, now),
            Ok(())
        );
        assert_eq!(
            precheck_at(
                &buckets,
                &other_host,
                Some("app.example:443"),
                ip(1),
                Scope::Host,
                now
            ),
            Err(429)
        );
        assert_eq!(
            precheck_at(&buckets, &other_host, None, ip(1), Scope::Global, now),
            Err(429)
        );
        assert_eq!(
            precheck_at(&buckets, &other_host, None, ip(2), Scope::Global, now),
            Ok(())
        );
        assert!(
            check_scope_at(&buckets, &other_host, None, ip(2), Scope::Global, now)
                .unwrap()
                .leases
                .is_empty()
        );
        assert_eq!(buckets[0].clients.lock().unwrap().len(), 1);
        assert_eq!(
            precheck_at(
                &buckets,
                &other_host,
                None,
                ip(1),
                Scope::Global,
                now + Duration::from_secs(30)
            ),
            Ok(())
        );
    }

    #[test]
    fn expired_short_bans_release_capacity_even_when_failure_window_is_longer() {
        let mut short = rule();
        short.failures = 1;
        short.window_seconds = 100;
        short.ban_seconds = 1;
        let buckets = prepare(&[short], &[]);
        let now = Instant::now();
        for index in 0..MAX_CLIENTS {
            let client = IpAddr::from([10, 0, (index / 256) as u8, (index % 256) as u8]);
            let _ = observe(&buckets, client, now).record_at(401, now);
        }
        assert_eq!(denied(&buckets, ip(1), now), Some(503));
        assert_eq!(denied(&buckets, ip(1), now + Duration::from_secs(1)), None);
        assert!(buckets[0].clients.lock().unwrap().is_empty());
    }

    #[test]
    fn later_rule_capacity_failure_rolls_back_prior_empty_reservations() {
        let first = rule();
        let mut second = rule();
        second.failures = 1;
        let buckets = prepare(&[first, second], &[]);
        let now = Instant::now();
        let held: Vec<_> = (0..MAX_CLIENTS)
            .map(|index| {
                let client = IpAddr::from([10, 0, (index / 256) as u8, (index % 256) as u8]);
                buckets[1].reserve(client, now).unwrap()
            })
            .collect();
        assert_eq!(denied(&buckets, ip(1), now), Some(503));
        assert!(buckets[0].clients.lock().unwrap().is_empty());
        drop(held);
        assert!(buckets[1].clients.lock().unwrap().is_empty());
    }

    #[test]
    fn public_api_canonicalizes_mapped_ipv4_and_observation_is_extension_safe() {
        fn extension_safe<T: Send + Sync + 'static>() {}
        extension_safe::<Observation>();
        let buckets = prepare(&[rule()], &[]);
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let observation = check(&buckets, &request("/login"), None, mapped, Scope::Url).unwrap();
        assert!(observation.record(401).is_empty());
        assert!(buckets[0].clients.lock().unwrap().contains_key(&ip(1)));
        assert!(!buckets[0].clients.lock().unwrap().contains_key(&mapped));
        assert_eq!(
            precheck(&buckets, &request("/login"), None, mapped, Scope::Global),
            Ok(())
        );
    }

    #[test]
    fn out_of_order_response_timestamps_do_not_backdate_the_ban() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        let first = observe(&buckets, ip(1), now);
        let second = observe(&buckets, ip(1), now);
        let third = observe(&buckets, ip(1), now);
        assert!(first.record_at(401, now).is_empty());
        assert!(
            second
                .record_at(401, now + Duration::from_secs(2))
                .is_empty()
        );
        assert_eq!(third.record_at(401, now + Duration::from_secs(1)).len(), 1);
        assert_eq!(
            denied(&buckets, ip(1), now + Duration::from_secs(31)),
            Some(429)
        );
        assert_eq!(denied(&buckets, ip(1), now + Duration::from_secs(32)), None);
    }

    #[test]
    fn natural_ban_expiry_fences_every_pre_ban_response_and_drop() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        let delayed: Vec<_> = (0..64).map(|_| observe(&buckets, ip(1), now)).collect();
        for _ in 0..3 {
            let _ = observe(&buckets, ip(1), now).record_at(401, now);
        }
        assert_eq!(denied(&buckets, ip(1), now), Some(429));
        let expired = now + Duration::from_secs(30);
        let fresh = observe(&buckets, ip(1), expired);
        std::thread::scope(|scope| {
            for old in delayed {
                scope.spawn(move || assert!(old.record_at(401, expired).is_empty()));
            }
        });
        let clients = buckets[0].clients.lock().unwrap();
        assert_eq!(clients[&ip(1)].failures, 0);
        assert_eq!(clients[&ip(1)].in_flight, 1);
        drop(clients);
        assert!(fresh.record_at(401, expired).is_empty());
        assert_eq!(denied(&buckets, ip(1), expired), None);
        assert_eq!(buckets[0].clients.lock().unwrap()[&ip(1)].in_flight, 0);
        // Fresh failures still establish a new ban normally.
        assert!(
            observe(&buckets, ip(1), expired)
                .record_at(401, expired)
                .is_empty()
        );
        assert_eq!(
            observe(&buckets, ip(1), expired)
                .record_at(401, expired)
                .len(),
            1
        );
        assert_eq!(denied(&buckets, ip(1), expired), Some(429));
    }

    #[test]
    fn admin_release_fences_old_completions_and_preserves_other_clients() {
        let buckets = prepare(&[rule()], &[]);
        let now = Instant::now();
        let delayed: Vec<_> = (0..64).map(|_| observe(&buckets, ip(1), now)).collect();
        for _ in 0..3 {
            let _ = observe(&buckets, ip(1), now).record_at(401, now);
            let _ = observe(&buckets, ip(2), now).record_at(401, now);
        }
        let next = prepare(&[rule()], &buckets);
        assert_eq!(clear(&next, "::ffff:192.0.2.1".parse().unwrap()), 1);
        assert_eq!(denied(&next, ip(2), now), Some(429));
        let fresh = observe(&next, ip(1), now);
        std::thread::scope(|scope| {
            for old in delayed {
                scope.spawn(move || assert!(old.record_at(401, now).is_empty()));
            }
        });
        let clients = next[0].clients.lock().unwrap();
        assert_eq!(
            clients[&ip(1)].in_flight,
            1,
            "old Drop cannot decrement a new generation"
        );
        assert_eq!(clients[&ip(1)].failures, 0);
        drop(clients);
        assert!(fresh.record_at(401, now).is_empty());
        assert_eq!(denied(&next, ip(1), now), None);
        assert_eq!(
            clear(&next, ip(1)),
            1,
            "release also clears an incomplete failure streak"
        );
        assert_eq!(clear(&next, ip(1)), 0);
        assert_eq!(denied(&next, ip(2), now), Some(429));
    }

    #[test]
    fn admin_list_is_bounded_filters_ips_and_ceil_rounds_remaining_time() {
        let mut instant_ban = rule();
        instant_ban.failures = 1;
        let buckets = prepare(&[instant_ban], &[]);
        let now = Instant::now();
        for index in 0..201 {
            let client = IpAddr::from([10, 0, (index / 256) as u8, (index % 256) as u8]);
            let _ = observe(&buckets, client, now).record_at(401, now);
        }
        let (bounded, truncated) = list_at(&buckets, None, usize::MAX, now);
        assert_eq!(bounded.len(), 200);
        assert!(truncated);
        let selected = IpAddr::from([10, 0, 0, 7]);
        let (single, truncated) = list_at(
            &buckets,
            Some(selected),
            200,
            now + Duration::from_millis(1001),
        );
        assert!(!truncated);
        assert_eq!(
            single,
            vec![BanInfo {
                ip: selected,
                path: "/login".into(),
                remaining_seconds: 29
            }]
        );
        let (mapped, truncated) = list(&buckets, Some("::ffff:10.0.0.7".parse().unwrap()), 200);
        assert!(!truncated);
        assert_eq!(mapped.len(), 1);
        assert_eq!(mapped[0].ip, selected);
        assert_eq!(list_at(&buckets, Some(selected), 0, now), (vec![], true));
        assert_eq!(
            list_at(&buckets, None, 200, now + Duration::from_secs(30)),
            (vec![], false)
        );
    }
}
