//! Route authorization using identity established by a dedicated inbound mTLS listener.
//!
//! Request headers, Host, SNI, and forwarded-proxy metadata never construct
//! this evidence. The listener supplies `workload_http::Evidence` only after
//! a mandatory client-certificate handshake and exact URI-SAN verification.

use crate::{
    config::{HttpRoute, Snapshot},
    workload_http::Evidence,
};
use anyhow::{Result, ensure};
use hyper::header::HeaderName;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub listener_ids: Vec<String>,
    pub allowed_uri_sans: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_header: Option<String>,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=64).contains(&self.listener_ids.len()),
            "workload_auth listener_ids must contain 1..=64 listeners"
        );
        let mut listeners = HashSet::with_capacity(self.listener_ids.len());
        for id in &self.listener_ids {
            ensure!(
                !id.is_empty()
                    && id.len() <= 128
                    && id.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
                    }),
                "invalid workload_auth listener ID"
            );
            ensure!(listeners.insert(id), "duplicate workload_auth listener ID");
        }
        ensure!(
            (1..=128).contains(&self.allowed_uri_sans.len()),
            "workload_auth allowed_uri_sans must contain 1..=128 identities"
        );
        let mut identities = HashSet::with_capacity(self.allowed_uri_sans.len());
        for uri in &self.allowed_uri_sans {
            crate::workload_tls::validate_spiffe_id(uri)?;
            ensure!(identities.insert(uri), "duplicate workload_auth URI SAN");
        }
        if let Some(name) = &self.identity_header {
            crate::jwt_runtime::validate_identity_header(name)?;
        }
        Ok(())
    }
}

/// Prepared route authorization, reused only when the *entire* route is
/// unchanged. A stream from the old route must retire after any auth, rule,
/// scope, or workload-listener mapping change.
pub struct Runtime {
    route: HttpRoute,
    listeners: HashSet<String>,
    identities: HashSet<String>,
    reserved: Vec<HeaderName>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denial {
    /// The request has no matching verified identity for this route.
    Forbidden,
    /// The accepted TLS transport belongs to a retired listener generation.
    Retired,
}

impl Runtime {
    pub fn new(route: &HttpRoute) -> Result<Self> {
        let policy = route
            .workload_auth
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("route has no workload_auth policy"))?;
        policy.validate()?;
        let reserved = policy
            .identity_header
            .as_ref()
            .map(|name| crate::jwt_runtime::validate_identity_header(name))
            .transpose()?
            .into_iter()
            .collect();
        Ok(Self {
            route: route.clone(),
            listeners: policy.listener_ids.iter().cloned().collect(),
            identities: policy.allowed_uri_sans.iter().cloned().collect(),
            reserved,
        })
    }

    pub fn matches_route(&self, route: &HttpRoute) -> bool {
        self.route == *route
    }

    pub fn reserved_headers(&self) -> &[HeaderName] {
        &self.reserved
    }

    pub fn authorize<'a>(
        &self,
        evidence: Option<&'a Evidence>,
        snapshot: &Snapshot,
    ) -> std::result::Result<&'a crate::workload_tls::Identity, Denial> {
        let evidence = evidence.ok_or(Denial::Forbidden)?;
        if !evidence.current(snapshot) {
            return Err(Denial::Retired);
        }
        if !self.listeners.contains(evidence.listener_id())
            || !self.identities.contains(&evidence.identity().uri)
        {
            return Err(Denial::Forbidden);
        }
        Ok(evidence.identity())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            listener_ids: vec!["private-edge".into()],
            allowed_uri_sans: vec!["spiffe://example.org/ns/app/sa/caller".into()],
            identity_header: Some("x-workload-subject".into()),
        }
    }

    #[test]
    fn policy_is_bounded_and_rejects_ambiguous_or_unsafe_identity_configuration() {
        let mut policy = policy();
        policy.validate().unwrap();
        policy.listener_ids.push("private-edge".into());
        assert!(policy.validate().is_err());
        policy.listener_ids.pop();
        policy
            .allowed_uri_sans
            .push(policy.allowed_uri_sans[0].clone());
        assert!(policy.validate().is_err());
        policy.allowed_uri_sans.pop();
        policy.allowed_uri_sans[0] = "spiffe://example.org/ns/../admin".into();
        assert!(policy.validate().is_err());
        policy.allowed_uri_sans[0] = "spiffe://example.org/ns/app/sa/caller".into();
        policy.identity_header = Some("x-forwarded-client-cert".into());
        assert!(policy.validate().is_err());
        policy.identity_header = Some("authorization".into());
        assert!(policy.validate().is_err());
    }
}
