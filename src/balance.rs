//! Weighted admission and optional passive health; requests are never replayed.
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    RoundRobin,
    LeastConnections,
}
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthPolicy {
    pub failure_threshold: u32,
    pub cooldown_ms: u64,
}
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InitialHealthState {
    #[default]
    Healthy,
    Checking,
}
fn initially_healthy(state: &InitialHealthState) -> bool {
    *state == InitialHealthState::Healthy
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveHealthPolicy {
    pub path: String,
    #[serde(default)]
    pub host: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub healthy_statuses: Vec<u16>,
    pub unhealthy_statuses: Vec<u16>,
    pub healthy_successes: u32,
    pub unhealthy_http_failures: u32,
    pub unhealthy_tcp_failures: u32,
    pub unhealthy_timeouts: u32,
    /// Checking withholds a backend until enough healthy active probes have
    /// completed. Healthy preserves the historical immediately-eligible boot.
    #[serde(default, skip_serializing_if = "initially_healthy")]
    pub initial_state: InitialHealthState,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PassiveHealthPolicy {
    pub healthy_statuses: Vec<u16>,
    pub unhealthy_statuses: Vec<u16>,
    pub unhealthy_http_failures: u32,
    pub unhealthy_tcp_failures: u32,
    pub unhealthy_timeouts: u32,
}
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalanceConfig {
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub weights: Vec<u16>,
    #[serde(default)]
    pub health: Option<HealthPolicy>,
    #[serde(default)]
    pub active_health: Option<ActiveHealthPolicy>,
    #[serde(default)]
    pub passive_health: Option<PassiveHealthPolicy>,
}
impl BalanceConfig {
    pub fn validate(&self, count: usize) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.weights.is_empty() || self.weights.len() == count,
            "weights must match backend count"
        );
        anyhow::ensure!(
            self.weights.iter().all(|w| (1..=1000).contains(w)),
            "backend weights must be 1..1000"
        );
        if let Some(health) = self.health {
            anyhow::ensure!(
                (1..=100).contains(&health.failure_threshold)
                    && (10..=300_000).contains(&health.cooldown_ms),
                "invalid backend health thresholds"
            );
        }
        if let Some(active) = &self.active_health {
            anyhow::ensure!(
                self.health.is_none(),
                "active_health conflicts with legacy cooldown health"
            );
            anyhow::ensure!(
                active.path.starts_with('/')
                    && active.path.len() <= 256
                    && active
                        .path
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() && byte != b'?' && byte != b'#'),
                "active health path must be a printable absolute path without query or fragment"
            );
            if let Some(host) = &active.host {
                let parsed: hyper::http::uri::Authority = host.parse()?;
                anyhow::ensure!(
                    !host.is_empty()
                        && host.len() <= 253
                        && parsed.host() == host
                        && !host.contains('@')
                        && hyper::header::HeaderValue::from_str(host).is_ok(),
                    "active health host must be a bare, printable HTTP host"
                );
            }
            anyhow::ensure!(
                (100..=300_000).contains(&active.interval_ms)
                    && (100..=60_000).contains(&active.timeout_ms)
                    && active.timeout_ms <= active.interval_ms,
                "active health interval/timeout is invalid"
            );
            anyhow::ensure!(
                (1..=100).contains(&active.healthy_successes)
                    && (1..=100).contains(&active.unhealthy_http_failures)
                    && (1..=100).contains(&active.unhealthy_tcp_failures)
                    && (1..=100).contains(&active.unhealthy_timeouts),
                "active health thresholds must be 1..100"
            );
            validate_statuses(&active.healthy_statuses, &active.unhealthy_statuses)?;
        }
        if let Some(passive) = &self.passive_health {
            anyhow::ensure!(
                self.active_health.is_some() && self.health.is_none(),
                "passive_health requires active_health and conflicts with legacy cooldown health"
            );
            anyhow::ensure!(
                (1..=100).contains(&passive.unhealthy_http_failures)
                    && (1..=100).contains(&passive.unhealthy_tcp_failures)
                    && (1..=100).contains(&passive.unhealthy_timeouts),
                "passive health thresholds must be 1..100"
            );
            validate_statuses(&passive.healthy_statuses, &passive.unhealthy_statuses)?;
        }
        Ok(())
    }
}
fn validate_statuses(healthy: &[u16], unhealthy: &[u16]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !healthy.is_empty()
            && !unhealthy.is_empty()
            && healthy.len() <= 64
            && unhealthy.len() <= 64,
        "health status lists must contain 1..64 codes"
    );
    let mut seen = std::collections::HashSet::new();
    for code in healthy.iter().chain(unhealthy.iter()) {
        anyhow::ensure!(
            (100..=599).contains(code) && seen.insert(*code),
            "health status codes must be unique and between 100 and 599"
        );
    }
    Ok(())
}
#[derive(Default)]
struct Node {
    active: crate::member_admission::MemberAdmission,
    failures: AtomicUsize,
    unavailable_until: AtomicU64,
    active_unhealthy: std::sync::atomic::AtomicBool,
    initial_check_pending: std::sync::atomic::AtomicBool,
    active_probe_seen: std::sync::atomic::AtomicBool,
    passive_unhealthy: std::sync::atomic::AtomicBool,
    active_successes: AtomicUsize,
    active_http_failures: AtomicUsize,
    active_tcp_failures: AtomicUsize,
    active_timeouts: AtomicUsize,
    passive_http_failures: AtomicUsize,
    passive_tcp_failures: AtomicUsize,
    passive_timeouts: AtomicUsize,
}
pub struct Balancer {
    config: BalanceConfig,
    nodes: Vec<Arc<Node>>,
    cursor: AtomicU64,
    total_weight: u64,
}
/// An old generation selected for retirement after durable publication.
/// Constructing or dropping this handle never changes admission state.
pub(crate) struct BackendRetirement(Arc<Node>);

impl BackendRetirement {
    pub(crate) fn retire(&self) {
        self.0.active.retire();
    }
}
/// A read-only view of the current selection state. `available` means the
/// balancer may select this node; it does not prove network reachability.
#[derive(Debug, Clone, Serialize)]
pub struct BackendState {
    pub available: bool,
    pub health_mode: &'static str,
    pub probe_observed: Option<bool>,
    /// Whether a checking initial state has yet to pass its healthy probe
    /// threshold. None for backends without active health monitoring.
    pub initial_check_pending: Option<bool>,
    /// HTTP modes all acquire leases. Kept optional for API compatibility.
    pub active_requests: Option<usize>,
}
#[derive(Clone)]
pub struct BackendLease(Arc<LeaseInner>);
struct LeaseInner {
    node: Arc<Node>,
    health: Option<HealthPolicy>,
    passive: Option<PassiveHealthPolicy>,
}
impl Drop for LeaseInner {
    fn drop(&mut self) {
        self.node.active.release();
    }
}
impl BackendLease {
    pub fn record(&self, success: bool) {
        let Some(health) = self.0.health else { return };
        if success {
            self.0.node.failures.store(0, Ordering::Relaxed);
            self.0.node.unavailable_until.store(0, Ordering::Relaxed);
        } else if self.0.node.failures.fetch_add(1, Ordering::Relaxed) + 1
            >= health.failure_threshold as usize
        {
            self.0
                .node
                .unavailable_until
                .store(now_ms() + health.cooldown_ms, Ordering::Relaxed);
        }
    }
    pub fn record_http_status(&self, status: u16) {
        if let Some(passive) = &self.0.passive {
            // Kong's configured passive healthy.successes=0 makes healthy
            // status reports no-ops; they do not reset a failure streak.
            if passive.unhealthy_statuses.contains(&status)
                && self
                    .0
                    .node
                    .passive_http_failures
                    .fetch_add(1, Ordering::Relaxed)
                    + 1
                    >= passive.unhealthy_http_failures as usize
            {
                self.0.node.passive_unhealthy.store(true, Ordering::Release);
            }
        } else {
            self.record(status < 500);
        }
    }
    pub fn record_transport_failure(&self) {
        if let Some(passive) = &self.0.passive {
            if self
                .0
                .node
                .passive_tcp_failures
                .fetch_add(1, Ordering::Relaxed)
                + 1
                >= passive.unhealthy_tcp_failures as usize
            {
                self.0.node.passive_unhealthy.store(true, Ordering::Release);
            }
        } else {
            self.record(false);
        }
    }
    pub fn record_timeout(&self) {
        if let Some(passive) = &self.0.passive {
            if self.0.node.passive_timeouts.fetch_add(1, Ordering::Relaxed) + 1
                >= passive.unhealthy_timeouts as usize
            {
                self.0.node.passive_unhealthy.store(true, Ordering::Release);
            }
        } else {
            self.record(false);
        }
    }
}
fn now_ms() -> u64 {
    static START: std::sync::LazyLock<std::time::Instant> =
        std::sync::LazyLock::new(std::time::Instant::now);
    START.elapsed().as_millis() as u64
}
impl Balancer {
    pub fn new(config: BalanceConfig, count: usize) -> Self {
        let checking = config
            .active_health
            .as_ref()
            .is_some_and(|policy| policy.initial_state == InitialHealthState::Checking);
        let total_weight = if config.weights.is_empty() {
            count as u64
        } else {
            config.weights.iter().map(|w| *w as u64).sum()
        };
        Self {
            config,
            nodes: (0..count)
                .map(|_| {
                    Arc::new(Node {
                        active_unhealthy: std::sync::atomic::AtomicBool::new(checking),
                        initial_check_pending: std::sync::atomic::AtomicBool::new(checking),
                        ..Node::default()
                    })
                })
                .collect(),
            cursor: AtomicU64::new(0),
            total_weight,
        }
    }
    /// Construct a selector over compatible generation nodes. Mapping is by
    /// validated stable identity at the snapshot boundary, never array position.
    /// Policy changes get fresh health; old leases retain their original node.
    pub fn with_reused_nodes(
        config: BalanceConfig,
        previous: &Self,
        mapping: &[Option<usize>],
    ) -> Self {
        let compatible = config.health == previous.config.health
            && config.active_health == previous.config.active_health
            && config.passive_health == previous.config.passive_health;
        let mut next = Self::new(config, mapping.len());
        if compatible {
            for (node, old_index) in next.nodes.iter_mut().zip(mapping) {
                if let Some(old) = old_index.and_then(|index| previous.nodes.get(index)) {
                    *node = old.clone();
                }
            }
        }
        next
    }

    /// Collect old nodes absent from the successor by pointer identity. This
    /// is preparation-only: the caller retires them after the publication
    /// boundary, never while validating or building a candidate snapshot.
    pub(crate) fn retirements(&self, successor: Option<&Self>) -> Vec<BackendRetirement> {
        self.nodes
            .iter()
            .filter(|old| {
                successor.is_none_or(|next| !next.nodes.iter().any(|node| Arc::ptr_eq(old, node)))
            })
            .cloned()
            .map(BackendRetirement)
            .collect()
    }

    pub fn available(&self, index: usize) -> bool {
        self.nodes[index].active.is_open()
            && !self.nodes[index]
                .initial_check_pending
                .load(Ordering::Acquire)
            && !self.nodes[index].active_unhealthy.load(Ordering::Acquire)
            && !self.nodes[index].passive_unhealthy.load(Ordering::Acquire)
            && (self.config.health.is_none()
                || self.nodes[index].unavailable_until.load(Ordering::Relaxed) <= now_ms())
    }
    pub fn backend_state(&self, index: usize) -> Option<BackendState> {
        let node = self.nodes.get(index)?;
        let health_mode = if self.config.active_health.is_some() {
            if self.config.passive_health.is_some() {
                "active_passive"
            } else {
                "active"
            }
        } else if self.config.health.is_some() {
            "cooldown"
        } else {
            "unmonitored"
        };
        Some(BackendState {
            available: self.available(index),
            health_mode,
            probe_observed: self
                .config
                .active_health
                .as_ref()
                .map(|_| node.active_probe_seen.load(Ordering::Acquire)),
            initial_check_pending: self
                .config
                .active_health
                .as_ref()
                .map(|_| node.initial_check_pending.load(Ordering::Acquire)),
            active_requests: Some(node.active.active()),
        })
    }
    fn weight(&self, index: usize) -> usize {
        self.config.weights.get(index).copied().unwrap_or(1) as usize
    }
    pub fn select(&self) -> Option<usize> {
        if self.nodes.is_empty() {
            return None;
        }
        let cursor = self.cursor.fetch_add(1, Ordering::Relaxed);
        if self.config.mode == Mode::LeastConnections {
            let start = cursor as usize % self.nodes.len();
            let mut best = None;
            for offset in 0..self.nodes.len() {
                let index = (start + offset) % self.nodes.len();
                if !self.available(index) {
                    continue;
                }
                if best.is_none_or(|previous: usize| {
                    self.nodes[index].active.active() * self.weight(previous)
                        < self.nodes[previous].active.active() * self.weight(index)
                }) {
                    best = Some(index);
                }
            }
            return best;
        }
        let mut slot = cursor % self.total_weight;
        let mut selected = 0;
        if self.config.weights.is_empty() {
            selected = slot as usize;
        } else {
            for (index, weight) in self.config.weights.iter().enumerate() {
                if slot < *weight as u64 {
                    selected = index;
                    break;
                }
                slot -= *weight as u64;
            }
        }
        (0..self.nodes.len())
            .map(|offset| (selected + offset) % self.nodes.len())
            .find(|index| self.available(*index))
    }
    pub fn acquire(&self, index: usize) -> Option<BackendLease> {
        if !self.available(index) {
            return None;
        }
        if !self.nodes[index].active.acquire() {
            return None;
        }
        Some(BackendLease(Arc::new(LeaseInner {
            node: self.nodes[index].clone(),
            health: self.config.health,
            passive: self.config.passive_health.clone(),
        })))
    }
    pub fn record_active_status(&self, index: usize, status: u16) {
        let Some(policy) = &self.config.active_health else {
            return;
        };
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        node.active_probe_seen.store(true, Ordering::Release);
        if policy.healthy_statuses.contains(&status) {
            node.active_http_failures.store(0, Ordering::Relaxed);
            node.active_tcp_failures.store(0, Ordering::Relaxed);
            node.active_timeouts.store(0, Ordering::Relaxed);
            if node.active_successes.fetch_add(1, Ordering::Relaxed) + 1
                >= policy.healthy_successes as usize
            {
                node.active_unhealthy.store(false, Ordering::Release);
                node.passive_unhealthy.store(false, Ordering::Release);
                node.passive_http_failures.store(0, Ordering::Relaxed);
                node.passive_tcp_failures.store(0, Ordering::Relaxed);
                node.passive_timeouts.store(0, Ordering::Relaxed);
                node.initial_check_pending.store(false, Ordering::Release);
            }
        } else if policy.unhealthy_statuses.contains(&status) {
            node.active_successes.store(0, Ordering::Relaxed);
            if node.active_http_failures.fetch_add(1, Ordering::Relaxed) + 1
                >= policy.unhealthy_http_failures as usize
            {
                node.active_unhealthy.store(true, Ordering::Release);
            }
        } else {
            // Preserve legacy healthy-default recovery semantics: a neutral
            // status was a no-op. Checking explicitly requires consecutive
            // healthy probes, so a neutral observation breaks its streak.
            if policy.initial_state == InitialHealthState::Checking {
                node.active_successes.store(0, Ordering::Relaxed);
            }
        }
    }
    pub fn record_active_transport_failure(&self, index: usize) {
        let Some(policy) = &self.config.active_health else {
            return;
        };
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        node.active_probe_seen.store(true, Ordering::Release);
        node.active_successes.store(0, Ordering::Relaxed);
        if node.active_tcp_failures.fetch_add(1, Ordering::Relaxed) + 1
            >= policy.unhealthy_tcp_failures as usize
        {
            node.active_unhealthy.store(true, Ordering::Release);
        }
    }
    pub fn record_active_timeout(&self, index: usize) {
        let Some(policy) = &self.config.active_health else {
            return;
        };
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        node.active_probe_seen.store(true, Ordering::Release);
        node.active_successes.store(0, Ordering::Relaxed);
        if node.active_timeouts.fetch_add(1, Ordering::Relaxed) + 1
            >= policy.unhealthy_timeouts as usize
        {
            node.active_unhealthy.store(true, Ordering::Release);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn active_policy() -> ActiveHealthPolicy {
        ActiveHealthPolicy {
            path: "/health/readiness".into(),
            host: None,
            interval_ms: 3000,
            timeout_ms: 2000,
            healthy_statuses: vec![200],
            unhealthy_statuses: vec![429, 500, 503],
            healthy_successes: 1,
            unhealthy_http_failures: 2,
            unhealthy_tcp_failures: 2,
            unhealthy_timeouts: 2,
            initial_state: InitialHealthState::Healthy,
        }
    }
    fn passive_policy() -> PassiveHealthPolicy {
        PassiveHealthPolicy {
            healthy_statuses: vec![200, 201],
            unhealthy_statuses: vec![429, 500, 503],
            unhealthy_http_failures: 2,
            unhealthy_tcp_failures: 2,
            unhealthy_timeouts: 2,
        }
    }
    #[test]
    fn initial_checking_withholds_selection_until_consecutive_healthy_probes() {
        let mut active = active_policy();
        active.initial_state = InitialHealthState::Checking;
        active.healthy_successes = 3;
        let balancer = Balancer::new(
            BalanceConfig {
                active_health: Some(active),
                passive_health: Some(passive_policy()),
                ..Default::default()
            },
            1,
        );
        assert_eq!(balancer.select(), None);
        assert!(balancer.acquire(0).is_none());
        assert_eq!(
            balancer.backend_state(0).unwrap().probe_observed,
            Some(false)
        );
        assert_eq!(
            balancer.backend_state(0).unwrap().initial_check_pending,
            Some(true)
        );

        // A passive report (for example from an older in-flight lease) cannot
        // satisfy the active startup gate, even if its status is healthy.
        let in_flight = BackendLease(Arc::new(LeaseInner {
            node: balancer.nodes[0].clone(),
            health: None,
            passive: Some(passive_policy()),
        }));
        assert!(balancer.nodes[0].active.acquire());
        in_flight.record_http_status(200);
        in_flight.record_transport_failure();
        assert!(!balancer.available(0));

        balancer.record_active_status(0, 200);
        assert_eq!(
            balancer.backend_state(0).unwrap().probe_observed,
            Some(true)
        );
        assert_eq!(balancer.select(), None);
        // Neither a neutral status nor a classified failure completes a
        // consecutive healthy-success streak.
        balancer.record_active_status(0, 204);
        balancer.record_active_status(0, 200);
        balancer.record_active_status(0, 503);
        balancer.record_active_status(0, 200);
        balancer.record_active_timeout(0);
        balancer.record_active_status(0, 200);
        balancer.record_active_transport_failure(0);
        assert_eq!(balancer.select(), None);
        balancer.record_active_status(0, 200);
        balancer.record_active_status(0, 200);
        assert_eq!(balancer.select(), None);
        assert_eq!(
            balancer.backend_state(0).unwrap().initial_check_pending,
            Some(true)
        );
        balancer.record_active_status(0, 200);
        assert_eq!(balancer.select(), Some(0));
        assert!(balancer.acquire(0).is_some());
        assert_eq!(
            balancer.backend_state(0).unwrap().initial_check_pending,
            Some(false)
        );
        // Later health loss is distinct from the already completed initial
        // check; the UI must not label it as still checking.
        balancer.record_active_status(0, 503);
        balancer.record_active_status(0, 503);
        assert!(!balancer.available(0));
        assert_eq!(
            balancer.backend_state(0).unwrap().initial_check_pending,
            Some(false)
        );
    }

    #[test]
    fn initial_state_defaults_omit_healthy_and_reject_unknown_values() {
        let active = active_policy();
        let value = serde_json::to_value(&active).unwrap();
        assert!(value.get("initial_state").is_none());
        let restored: ActiveHealthPolicy = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(restored.initial_state, InitialHealthState::Healthy);
        let mut checking = value;
        checking["initial_state"] = "checking".into();
        let checking: ActiveHealthPolicy = serde_json::from_value(checking).unwrap();
        assert_eq!(checking.initial_state, InitialHealthState::Checking);
        assert_eq!(
            serde_json::to_value(checking).unwrap()["initial_state"],
            "checking"
        );
        let mut invalid = serde_json::to_value(active).unwrap();
        invalid["initial_state"] = "ready".into();
        assert!(serde_json::from_value::<ActiveHealthPolicy>(invalid).is_err());
    }
    #[test]
    fn default_healthy_keeps_neutral_probe_recovery_compatibility() {
        let mut active = active_policy();
        active.healthy_successes = 2;
        let balancer = Balancer::new(
            BalanceConfig {
                active_health: Some(active),
                ..Default::default()
            },
            1,
        );
        assert!(balancer.available(0));
        balancer.record_active_status(0, 503);
        balancer.record_active_status(0, 503);
        assert!(!balancer.available(0));
        balancer.record_active_status(0, 200);
        balancer.record_active_status(0, 204);
        assert!(!balancer.available(0));
        balancer.record_active_status(0, 200);
        assert!(balancer.available(0));
    }
    #[test]
    fn mapped_nodes_retain_load_and_health_while_selector_weights_change() {
        let original = Balancer::new(
            BalanceConfig {
                health: Some(HealthPolicy {
                    failure_threshold: 1,
                    cooldown_ms: 60000,
                }),
                ..Default::default()
            },
            2,
        );
        let lease = original.acquire(0).unwrap();
        lease.record(false);
        let next = Balancer::with_reused_nodes(
            BalanceConfig {
                mode: Mode::LeastConnections,
                weights: vec![7, 2, 1],
                ..original.config.clone()
            },
            &original,
            &[Some(1), Some(0), None],
        );
        assert!(next.available(0));
        assert!(!next.available(1));
        assert!(next.available(2));
        assert_eq!(next.backend_state(1).unwrap().active_requests, Some(1));
        drop(lease);
        assert_eq!(next.backend_state(1).unwrap().active_requests, Some(0));
        assert!(
            !original.available(0),
            "preparation did not modify old health"
        );
    }

    #[test]
    fn changed_health_policy_and_unknown_identity_do_not_inherit_nodes() {
        let original = Balancer::new(
            BalanceConfig {
                active_health: Some(active_policy()),
                ..Default::default()
            },
            1,
        );
        original.record_active_status(0, 503);
        original.record_active_status(0, 503);
        assert!(!original.available(0));
        let mut changed = original.config.clone();
        changed.active_health.as_mut().unwrap().initial_state = InitialHealthState::Checking;
        let next = Balancer::with_reused_nodes(changed, &original, &[Some(0)]);
        assert_eq!(next.backend_state(0).unwrap().probe_observed, Some(false));
        assert_eq!(
            next.backend_state(0).unwrap().initial_check_pending,
            Some(true)
        );
        original.record_active_status(0, 200);
        assert!(!next.available(0));
        let renamed = Balancer::with_reused_nodes(original.config.clone(), &original, &[None]);
        assert_eq!(
            renamed.backend_state(0).unwrap().probe_observed,
            Some(false)
        );
    }

    #[test]
    fn round_robin_leases_count_once_and_retired_nodes_drain() {
        let balancer = Balancer::new(BalanceConfig::default(), 1);
        let lease = balancer
            .acquire(0)
            .expect("round robin must track its request");
        let response_owner = lease.clone();
        assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(1));
        balancer.nodes[0].active.retire();
        assert_eq!(balancer.select(), None);
        assert!(balancer.acquire(0).is_none());
        drop(lease);
        assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(1));
        drop(response_owner);
        assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(0));
        assert!(!balancer.available(0));
    }

    #[test]
    fn retirement_plan_excludes_shared_nodes_and_has_no_prepublication_effect() {
        let old = Balancer::new(BalanceConfig::default(), 2);
        let held = old.acquire(0).unwrap();
        // Successor index 0 is old member 1; index 1 is a fresh generation.
        let successor =
            Balancer::with_reused_nodes(BalanceConfig::default(), &old, &[Some(1), None]);
        assert!(old.retirements(Some(&old)).is_empty());
        assert_eq!(old.retirements(None).len(), 2);
        let abandoned = old.retirements(Some(&successor));
        assert_eq!(abandoned.len(), 1);
        drop(abandoned);
        assert!(
            old.available(0),
            "dropping a candidate cannot retire live work"
        );
        assert!(old.acquire(0).is_some());
        assert_eq!(old.backend_state(0).unwrap().active_requests, Some(1));

        for retirement in old.retirements(Some(&successor)) {
            retirement.retire();
        }
        assert!(!old.available(0));
        assert!(old.acquire(0).is_none());
        assert_eq!(old.backend_state(0).unwrap().active_requests, Some(1));
        assert!(old.available(1), "shared old node must remain open");
        assert!(
            successor.available(0),
            "shared successor node must remain open"
        );
        assert!(
            successor.available(1),
            "fresh successor node must remain open"
        );
        drop(held);
        assert_eq!(old.backend_state(0).unwrap().active_requests, Some(0));
    }

    #[test]
    fn backend_state_reports_observation_and_real_lease_load() {
        let unmonitored = Balancer::new(BalanceConfig::default(), 1);
        let state = unmonitored.backend_state(0).unwrap();
        assert!(state.available);
        assert_eq!(state.health_mode, "unmonitored");
        assert_eq!(state.probe_observed, None);
        assert_eq!(state.active_requests, Some(0));
        assert!(unmonitored.backend_state(1).is_none());

        let balancer = Balancer::new(
            BalanceConfig {
                mode: Mode::LeastConnections,
                active_health: Some(active_policy()),
                passive_health: Some(passive_policy()),
                ..Default::default()
            },
            1,
        );
        let state = balancer.backend_state(0).unwrap();
        assert!(state.available);
        assert_eq!(state.health_mode, "active_passive");
        assert_eq!(state.probe_observed, Some(false));
        let lease = balancer.acquire(0).unwrap();
        assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(1));
        balancer.record_active_status(0, 503);
        balancer.record_active_status(0, 503);
        let state = balancer.backend_state(0).unwrap();
        assert_eq!(state.probe_observed, Some(true));
        assert!(!state.available);
        balancer.record_active_status(0, 200);
        assert!(balancer.backend_state(0).unwrap().available);
        drop(lease);
        assert_eq!(balancer.backend_state(0).unwrap().active_requests, Some(0));
    }
    #[test]
    fn passive_status_threshold_and_active_recovery_are_independent() {
        let balancer = Balancer::new(
            BalanceConfig {
                active_health: Some(active_policy()),
                passive_health: Some(passive_policy()),
                ..Default::default()
            },
            2,
        );
        let first = balancer.acquire(0).unwrap();
        first.record_http_status(503);
        assert!(balancer.available(0));
        first.record_http_status(429);
        assert!(!balancer.available(0));
        assert_eq!(balancer.select(), Some(1));
        // healthy.successes=0 ignores the healthy response entirely; a
        // healthy response between failures does not reset that streak.
        first.record_http_status(201);
        assert!(!balancer.available(0));
        balancer.record_active_status(0, 200);
        assert!(balancer.available(0));
        balancer.record_active_transport_failure(0);
        balancer.record_active_timeout(0);
        assert!(balancer.available(0));
        balancer.record_active_timeout(0);
        assert!(!balancer.available(0));
        balancer.record_active_status(0, 200);
        assert!(balancer.available(0));
    }

    #[test]
    fn passive_healthy_status_with_successes_disabled_does_not_reset_failure_count() {
        let balancer = Balancer::new(
            BalanceConfig {
                active_health: Some(active_policy()),
                passive_health: Some(passive_policy()),
                ..Default::default()
            },
            1,
        );
        let lease = balancer.acquire(0).unwrap();
        lease.record_http_status(503);
        lease.record_http_status(200);
        lease.record_http_status(503);
        assert!(!balancer.available(0));
    }
    #[test]
    fn active_health_configuration_fails_closed_for_unsafe_or_ambiguous_policy() {
        let good = BalanceConfig {
            active_health: Some(active_policy()),
            passive_health: Some(passive_policy()),
            ..Default::default()
        };
        good.validate(2).unwrap();
        let mut broken = good.clone();
        broken.active_health.as_mut().unwrap().path = "http://other/health".into();
        assert!(broken.validate(2).is_err());
        broken = good.clone();
        broken.active_health.as_mut().unwrap().healthy_statuses = vec![200, 503];
        assert!(broken.validate(2).is_err());
        broken = good.clone();
        broken.active_health.as_mut().unwrap().timeout_ms = 4000;
        assert!(broken.validate(2).is_err());
        broken = good.clone();
        broken.active_health.as_mut().unwrap().host = Some("user@origin".into());
        assert!(broken.validate(2).is_err());
        broken = good;
        broken.active_health = None;
        assert!(broken.validate(2).is_err());
    }
    #[test]
    fn weighted_round_robin_is_exact() {
        let b = Balancer::new(
            BalanceConfig {
                weights: vec![3, 1],
                ..Default::default()
            },
            2,
        );
        let mut counts = [0; 2];
        for _ in 0..400 {
            counts[b.select().unwrap()] += 1;
        }
        assert_eq!(counts, [300, 100]);
    }
    #[test]
    fn least_connections_accounts_for_stream_lifetime() {
        let b = Balancer::new(
            BalanceConfig {
                mode: Mode::LeastConnections,
                ..Default::default()
            },
            2,
        );
        let first = b.select().unwrap();
        let lease = b.acquire(first).unwrap();
        for _ in 0..8 {
            assert_eq!(b.select(), Some(1 - first));
        }
        drop(lease);
        assert!(b.select().is_some());
    }
    #[tokio::test]
    async fn failures_quarantine_and_recover_without_replay() {
        let b = Balancer::new(
            BalanceConfig {
                health: Some(HealthPolicy {
                    failure_threshold: 1,
                    cooldown_ms: 20,
                }),
                ..Default::default()
            },
            1,
        );
        let lease = b.acquire(0).unwrap();
        lease.record(false);
        assert_eq!(b.select(), None);
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(b.select(), Some(0));
    }
}
