use std::sync::atomic::{AtomicU64, Ordering};
#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_bypasses: AtomicU64,
    pub errors: AtomicU64,
    pub rejected_requests: AtomicU64,
    pub active_connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub policy_errors: AtomicU64,
    /// Subset of policy_errors caused by local Lua route-policy worker
    /// saturation or restart admission.
    pub policy_capacity_rejections: AtomicU64,
    pub body_transform_errors: AtomicU64,
    pub config_updates: AtomicU64,
}
impl Metrics {
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, kind, value) in [
            ("requests_total", "counter", &self.requests),
            ("cache_hits_total", "counter", &self.cache_hits),
            ("cache_misses_total", "counter", &self.cache_misses),
            ("cache_bypasses_total", "counter", &self.cache_bypasses),
            ("errors_total", "counter", &self.errors),
            (
                "rejected_requests_total",
                "counter",
                &self.rejected_requests,
            ),
            ("active_connections", "gauge", &self.active_connections),
            (
                "rejected_connections_total",
                "counter",
                &self.rejected_connections,
            ),
            ("policy_errors_total", "counter", &self.policy_errors),
            (
                "policy_capacity_rejections_total",
                "counter",
                &self.policy_capacity_rejections,
            ),
            (
                "body_transform_errors_total",
                "counter",
                &self.body_transform_errors,
            ),
            ("config_updates_total", "counter", &self.config_updates),
        ] {
            out.push_str(&format!("# HELP hangang_{name} Hangang {name}.\n# TYPE hangang_{name} {kind}\nhangang_{name} {}\n", value.load(Ordering::Relaxed)));
        }
        out
    }
}

/// Keeps admission capacity and metrics alive across HTTP protocol upgrades.
pub struct ConnectionLease {
    _permit: tokio::sync::OwnedSemaphorePermit,
    metrics: std::sync::Arc<Metrics>,
}
impl ConnectionLease {
    pub fn new(
        permit: tokio::sync::OwnedSemaphorePermit,
        metrics: std::sync::Arc<Metrics>,
    ) -> Self {
        metrics.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            _permit: permit,
            metrics,
        }
    }
}
impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.metrics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}
