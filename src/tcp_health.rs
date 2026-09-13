//! Bounded, per-backend TCP active-health state. Network probes are scheduled
//! by the TCP runtime; connection admission reads only the published flags.
use crate::balance::InitialHealthState;
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU8, AtomicU64, Ordering},
};

const AVAILABLE: u8 = 1;
const PROBE_OBSERVED: u8 = 2;
const INITIAL_CHECK_PENDING: u8 = 4;

fn initially_healthy(state: &InitialHealthState) -> bool {
    *state == InitialHealthState::Healthy
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpHealthPolicy {
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub healthy_successes: u32,
    pub unhealthy_failures: u32,
    #[serde(default, skip_serializing_if = "initially_healthy")]
    pub initial_state: InitialHealthState,
}

impl TcpHealthPolicy {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            (100..=300_000).contains(&self.interval_ms)
                && (100..=60_000).contains(&self.timeout_ms)
                && self.timeout_ms <= self.interval_ms,
            "TCP health interval/timeout is invalid"
        );
        anyhow::ensure!(
            (1..=100).contains(&self.healthy_successes)
                && (1..=100).contains(&self.unhealthy_failures),
            "TCP health thresholds must be 1..100"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TcpBackendState {
    /// Eligible for a new connection; not proof of current reachability.
    pub available: bool,
    pub probe_observed: bool,
    /// The initial checking gate has not yet seen enough healthy probes.
    pub initial_check_pending: bool,
}

#[derive(Default)]
struct Streaks {
    epoch: u64,
    successes: u32,
    failures: u32,
    unhealthy: bool,
    initial_check_pending: bool,
    probe_observed: bool,
}

struct Node {
    streaks: Mutex<Streaks>,
    flags: AtomicU8,
    epoch: AtomicU64,
}

impl Node {
    fn new(checking: bool) -> Self {
        Self {
            streaks: Mutex::new(Streaks {
                initial_check_pending: checking,
                ..Streaks::default()
            }),
            flags: AtomicU8::new(if checking {
                INITIAL_CHECK_PENDING
            } else {
                AVAILABLE
            }),
            epoch: AtomicU64::new(0),
        }
    }

    fn publish(&self, streaks: &Streaks) {
        let mut flags = 0;
        if !streaks.unhealthy && !streaks.initial_check_pending {
            flags |= AVAILABLE;
        }
        if streaks.probe_observed {
            flags |= PROBE_OBSERVED;
        }
        if streaks.initial_check_pending {
            flags |= INITIAL_CHECK_PENDING;
        }
        self.flags.store(flags, Ordering::Release);
    }
}

pub struct TcpHealth {
    policy: TcpHealthPolicy,
    nodes: Vec<Arc<Node>>,
}

impl TcpHealth {
    pub fn new(policy: TcpHealthPolicy, count: usize) -> Self {
        let checking = policy.initial_state == InitialHealthState::Checking;
        Self {
            policy,
            nodes: (0..count).map(|_| Arc::new(Node::new(checking))).collect(),
        }
    }

    /// Preserve compatible health/endpoint epochs by validated stable identity.
    /// Mapping never mutates previous state or changes an existing stream.
    pub fn with_reused_nodes(
        policy: TcpHealthPolicy,
        previous: &Self,
        mapping: &[Option<usize>],
    ) -> Self {
        let compatible = policy == previous.policy;
        let mut next = Self::new(policy, mapping.len());
        if compatible {
            for (node, old_index) in next.nodes.iter_mut().zip(mapping) {
                if let Some(old) = old_index.and_then(|index| previous.nodes.get(index)) {
                    *node = old.clone();
                }
            }
        }
        next
    }

    pub fn available(&self, index: usize) -> bool {
        self.available_for(index, 0)
    }

    /// A changed endpoint generation must be observed before new admissions.
    /// The epoch is monotonic per backend index; stale observations are
    /// ignored. An equal epoch is an idempotent no-op.
    pub fn observe_epoch(&self, index: usize, epoch: u64) -> bool {
        let Some(node) = self.nodes.get(index) else {
            return false;
        };
        let current = node.epoch.load(Ordering::Acquire);
        if current == epoch {
            return true;
        }
        if current > epoch {
            return false;
        }
        let mut state = node
            .streaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_epoch(node, &mut state, epoch)
    }

    /// A fast read for the exact resolved endpoint generation. Recheck the
    /// epoch around the flags so a concurrent replacement cannot admit a
    /// request using an old generation's qualification.
    pub fn available_for(&self, index: usize, epoch: u64) -> bool {
        self.nodes.get(index).is_some_and(|node| {
            node.epoch.load(Ordering::Acquire) == epoch
                && node.flags.load(Ordering::Acquire) & AVAILABLE != 0
                && node.epoch.load(Ordering::Acquire) == epoch
        })
    }

    pub fn backend_state(&self, index: usize) -> Option<TcpBackendState> {
        let flags = self.nodes.get(index)?.flags.load(Ordering::Acquire);
        Some(TcpBackendState {
            available: flags & AVAILABLE != 0,
            probe_observed: flags & PROBE_OBSERVED != 0,
            initial_check_pending: flags & INITIAL_CHECK_PENDING != 0,
        })
    }

    pub fn record_success(&self, index: usize) {
        self.record_success_for(index, 0);
    }

    pub fn record_success_for(&self, index: usize, epoch: u64) {
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        let mut state = node
            .streaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.ensure_epoch(node, &mut state, epoch) {
            return;
        }
        state.probe_observed = true;
        state.failures = 0;
        state.successes = state
            .successes
            .saturating_add(1)
            .min(self.policy.healthy_successes);
        if state.successes >= self.policy.healthy_successes {
            state.unhealthy = false;
            state.initial_check_pending = false;
        }
        node.publish(&state);
    }

    pub fn record_failure(&self, index: usize) {
        self.record_failure_for(index, 0);
    }

    pub fn record_failure_for(&self, index: usize, epoch: u64) {
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        let mut state = node
            .streaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !self.ensure_epoch(node, &mut state, epoch) {
            return;
        }
        self.record_failure_locked(node, &mut state);
    }

    /// Record a failed resolution against the currently observed endpoint.
    /// Unlike an epoch-zero callback, this also closes a dynamic endpoint
    /// after its threshold when discovery becomes temporarily unavailable.
    pub fn record_failure_current(&self, index: usize) {
        let Some(node) = self.nodes.get(index) else {
            return;
        };
        let mut state = node
            .streaks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.record_failure_locked(node, &mut state);
    }

    fn record_failure_locked(&self, node: &Node, state: &mut Streaks) {
        state.probe_observed = true;
        state.successes = 0;
        state.failures = state
            .failures
            .saturating_add(1)
            .min(self.policy.unhealthy_failures);
        if state.failures >= self.policy.unhealthy_failures {
            state.unhealthy = true;
        }
        node.publish(state);
    }

    fn ensure_epoch(&self, node: &Node, state: &mut Streaks, epoch: u64) -> bool {
        if epoch < state.epoch {
            return false;
        }
        if epoch > state.epoch {
            state.epoch = epoch;
            state.successes = 0;
            state.failures = 0;
            state.unhealthy = false;
            state.initial_check_pending = self.policy.initial_state == InitialHealthState::Checking;
            state.probe_observed = false;
            // A checking replacement closes the gate before its new epoch is
            // visible; a late result from an older epoch then fails equality.
            node.publish(state);
            node.epoch.store(epoch, Ordering::Release);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy(initial_state: InitialHealthState) -> TcpHealthPolicy {
        TcpHealthPolicy {
            interval_ms: 3000,
            timeout_ms: 1000,
            healthy_successes: 2,
            unhealthy_failures: 2,
            initial_state,
        }
    }

    #[test]
    fn stable_mapping_keeps_epochs_and_reordered_health_but_not_new_identity() {
        let policy = policy(InitialHealthState::Checking);
        let old = TcpHealth::new(policy.clone(), 2);
        old.observe_epoch(0, 8);
        old.record_success_for(0, 8);
        old.record_success_for(0, 8);
        assert!(old.available_for(0, 8));
        let next = TcpHealth::with_reused_nodes(policy.clone(), &old, &[Some(1), Some(0), None]);
        assert!(!next.available(0));
        assert!(next.available_for(1, 8));
        assert!(!next.available(2));
        // Results on a continuously retained endpoint refer to the same
        // member even though its display index moved. New epoch still fences
        // both selector generations from delayed old observations.
        next.observe_epoch(1, 9);
        old.record_success_for(0, 8);
        assert!(!next.available_for(1, 9));
        assert!(!old.available_for(0, 8));
        let fresh = TcpHealth::with_reused_nodes(policy, &next, &[None]);
        assert!(!fresh.backend_state(0).unwrap().probe_observed);
    }

    #[test]
    fn checking_requires_consecutive_successes_and_recovery_uses_same_threshold() {
        let health = TcpHealth::new(policy(InitialHealthState::Checking), 2);
        assert_eq!(
            health.backend_state(0),
            Some(TcpBackendState {
                available: false,
                probe_observed: false,
                initial_check_pending: true,
            })
        );
        assert!(!health.available(1));
        assert!(!health.available(2));
        assert_eq!(health.backend_state(2), None);
        health.record_success(0);
        assert!(!health.available(0));
        health.record_failure(0);
        health.record_success(0);
        assert!(!health.available(0));
        health.record_success(0);
        assert!(health.available(0));
        assert!(!health.backend_state(0).unwrap().initial_check_pending);
        health.record_failure(0);
        assert!(health.available(0));
        health.record_failure(0);
        assert!(!health.available(0));
        assert!(!health.backend_state(0).unwrap().initial_check_pending);
        health.record_success(0);
        assert!(!health.available(0));
        health.record_success(0);
        assert!(health.available(0));
        assert!(!health.available(1), "other backend remains unqualified");
        health.record_failure(99);
        health.record_success(99);
    }

    #[test]
    fn healthy_default_is_eligible_before_probes_and_serialization_omits_it() {
        let default = policy(InitialHealthState::Healthy);
        let value = serde_json::to_value(&default).unwrap();
        assert!(value.get("initial_state").is_none());
        assert_eq!(
            serde_json::from_value::<TcpHealthPolicy>(value).unwrap(),
            default
        );
        let health = TcpHealth::new(default, 1);
        assert!(health.available(0));
        assert!(!health.backend_state(0).unwrap().probe_observed);
        health.record_failure(0);
        assert!(health.available(0));
        health.record_failure(0);
        assert!(!health.available(0));
    }

    #[test]
    fn bounds_and_unknown_fields_are_rejected() {
        let mut good = policy(InitialHealthState::Checking);
        good.validate().unwrap();
        good.timeout_ms = good.interval_ms + 1;
        assert!(good.validate().is_err());
        good = policy(InitialHealthState::Checking);
        good.healthy_successes = 0;
        assert!(good.validate().is_err());
        good = policy(InitialHealthState::Checking);
        good.unhealthy_failures = 101;
        assert!(good.validate().is_err());
        assert!(serde_json::from_str::<TcpHealthPolicy>(
            r#"{"interval_ms":1000,"timeout_ms":500,"healthy_successes":1,"unhealthy_failures":1,"initial_state":"pending"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<TcpHealthPolicy>(
            r#"{"interval_ms":1000,"timeout_ms":500,"healthy_successes":1,"unhealthy_failures":1,"extra":true}"#
        )
        .is_err());
    }

    #[test]
    fn new_endpoint_epoch_requalifies_and_stale_results_cannot_release_it() {
        let checking = TcpHealth::new(policy(InitialHealthState::Checking), 1);
        assert!(!checking.available_for(0, 7));
        assert!(checking.observe_epoch(0, 7));
        checking.record_success_for(0, 7);
        assert!(!checking.available_for(0, 7));
        assert!(checking.observe_epoch(0, 8));
        assert!(!checking.backend_state(0).unwrap().probe_observed);
        checking.record_success_for(0, 7);
        checking.record_failure_for(0, 7);
        assert!(!checking.available_for(0, 7));
        assert!(!checking.available_for(0, 8));
        assert!(!checking.observe_epoch(0, 7));
        checking.record_success_for(0, 8);
        assert!(!checking.available_for(0, 8));
        checking.record_success_for(0, 8);
        assert!(checking.available_for(0, 8));
        assert!(!checking.available_for(0, 7));

        // A newer result can itself establish a previously unseen epoch;
        // older callbacks can never resurrect the prior endpoint.
        checking.record_failure_for(0, 9);
        assert!(!checking.available_for(0, 9));
        checking.record_success_for(0, 8);
        checking.record_success_for(0, 9);
        assert!(!checking.available_for(0, 9));
        checking.record_success_for(0, 9);
        assert!(checking.available_for(0, 9));
        assert!(!checking.available(0), "epoch-zero static API is now stale");
        checking.record_failure_current(0);
        assert!(checking.available_for(0, 9));
        checking.record_failure_current(0);
        assert!(!checking.available_for(0, 9));
        assert!(!checking.available_for(0, 0));

        let healthy = TcpHealth::new(policy(InitialHealthState::Healthy), 1);
        assert!(healthy.observe_epoch(0, 4));
        assert!(healthy.available_for(0, 4), "healthy default remains open");
        assert!(!healthy.available_for(0, 0));
    }
}
