use std::sync::atomic::{AtomicU64, Ordering};
#[derive(Default)]
pub struct Metrics {
    pub tcp_history: std::sync::Arc<crate::tcp_history::History>,
    pub geoip: crate::country_metrics::Counters,
    pub requests: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub cache_bypasses: AtomicU64,
    pub errors: AtomicU64,
    pub jwt_auth_rejections: AtomicU64,
    pub jwt_auth_unavailable: AtomicU64,
    pub jwt_lease_terminations: AtomicU64,
    pub http_mtls_rejections: AtomicU64,
    pub http_mtls_lease_terminations: AtomicU64,
    pub workload_auth_rejections: AtomicU64,
    pub workload_route_terminations: AtomicU64,
    pub tcp_mtls_rejections: AtomicU64,
    pub tcp_mtls_lease_terminations: AtomicU64,
    pub jwt_auth_capacity_rejections: AtomicU64,
    pub rejected_requests: AtomicU64,
    pub active_connections: AtomicU64,
    pub rejected_connections: AtomicU64,
    pub policy_errors: AtomicU64,
    /// Subset of policy_errors caused by local Lua route-policy worker
    /// saturation or restart admission.
    pub policy_capacity_rejections: AtomicU64,
    pub body_transform_errors: AtomicU64,
    pub config_updates: AtomicU64,
    /// Risk contexts sent to Hopae by level (low, elevated, high), and omitted.
    pub risk_context_sent: [AtomicU64; 3],
    pub risk_context_omitted: AtomicU64,
}
impl Metrics {
    pub fn risk_context_sent(&self, level: crate::risk_context::Level) {
        self.risk_context_sent[level as usize].fetch_add(1, Ordering::Relaxed);
    }
    pub fn risk_context_omitted(&self) {
        self.risk_context_omitted.fetch_add(1, Ordering::Relaxed);
    }
    pub fn render(&self) -> String {
        let mut out = String::new();
        for (name, kind, value) in [
            (
                "http_mtls_rejections_total",
                "counter",
                &self.http_mtls_rejections,
            ),
            (
                "http_mtls_lease_terminations_total",
                "counter",
                &self.http_mtls_lease_terminations,
            ),
            (
                "workload_auth_rejections_total",
                "counter",
                &self.workload_auth_rejections,
            ),
            (
                "workload_route_terminations_total",
                "counter",
                &self.workload_route_terminations,
            ),
            (
                "jwt_lease_terminations_total",
                "counter",
                &self.jwt_lease_terminations,
            ),
            ("requests_total", "counter", &self.requests),
            ("cache_hits_total", "counter", &self.cache_hits),
            ("cache_misses_total", "counter", &self.cache_misses),
            ("cache_bypasses_total", "counter", &self.cache_bypasses),
            ("errors_total", "counter", &self.errors),
            (
                "jwt_auth_rejections_total",
                "counter",
                &self.jwt_auth_rejections,
            ),
            (
                "tcp_mtls_rejections_total",
                "counter",
                &self.tcp_mtls_rejections,
            ),
            (
                "tcp_mtls_lease_terminations_total",
                "counter",
                &self.tcp_mtls_lease_terminations,
            ),
            (
                "jwt_auth_unavailable_total",
                "counter",
                &self.jwt_auth_unavailable,
            ),
            (
                "jwt_auth_capacity_rejections_total",
                "counter",
                &self.jwt_auth_capacity_rejections,
            ),
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
        out.push_str("# HELP hangang_risk_context_sent_total Signed risk contexts sent to Hopae by level.\n# TYPE hangang_risk_context_sent_total counter\n");
        for (i, level) in ["low", "elevated", "high"].iter().enumerate() {
            out.push_str(&format!(
                "hangang_risk_context_sent_total{{level=\"{level}\"}} {}\n",
                self.risk_context_sent[i].load(Ordering::Relaxed)
            ));
        }
        out.push_str(&format!("# HELP hangang_risk_context_omitted_total Risk contexts omitted for lack of Sumunjang evidence.\n# TYPE hangang_risk_context_omitted_total counter\nhangang_risk_context_omitted_total {}\n", self.risk_context_omitted.load(Ordering::Relaxed)));
        self.geoip.render(&mut out);
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
