//! Bounded reusable mTLS gRPC channel with monotonically increasing revision fencing.
use anyhow::{Result, ensure};
use pumgye_grpc::v1::{DecisionReply, DecisionRequest, authorization_client::AuthorizationClient};
use pumgye_protocol::{Query, Reply};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Native resource/action scope; classification remains owned by Pumgye.
pub struct ResourceQuery<'a> {
    pub service_id: &'a str,
    pub minimum_revision: u64,
    pub ip: std::net::IpAddr,
    pub aal: u8,
    pub guard: pumgye_core::GuardEvidence,
    pub resource: &'a str,
    pub action: &'a str,
    pub subject: &'a str,
}
#[derive(Debug, PartialEq, Eq)]
pub struct ResourceReply {
    pub revision: u64,
    pub decision: pumgye_core::ResourceDecision,
}

/// Native target only; identity and assurance come from the checked receipt.
pub struct AuthenticatedQuery<'a> {
    pub route: Option<&'a pumgye_grpc::v1::NativeRouteReference>,
    pub resource: &'a str,
    pub action: &'a str,
    pub ip: std::net::IpAddr,
    pub minimum_revision: u64,
    pub request_sha256: [u8; 32],
}
pub struct AuthenticatedReply {
    pub revision: u64,
    pub network_revision: u64,
    pub allow: bool,
}
pub struct Client {
    channel: Channel,
    token: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    slots: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    revision: AtomicU64,
    network_revision: AtomicU64,
    sequence: AtomicU64,
}
impl Client {
    pub fn new(config: &crate::pumgye::AuthorityConfig, token: &str) -> Result<Self> {
        let tls = config
            .tls
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("gRPC Pumgye requires mTLS"))?;
        let timeout = Duration::from_millis(config.timeout_ms);
        let tls = ClientTlsConfig::new()
            .domain_name(&tls.server_name)
            .ca_certificate(Certificate::from_pem(crate::tls::read_bounded(&tls.ca)?))
            .identity(Identity::from_pem(
                crate::tls::read_bounded(&tls.certificate)?,
                crate::tls::read_bounded(&tls.key)?,
            ));
        let endpoint = Endpoint::from_shared(format!("https://{}", config.decision_address))?
            .tls_config(tls)?
            .connect_timeout(timeout)
            .timeout(timeout)
            .buffer_size(config.pool_size)
            .tcp_nodelay(true);
        let mut token = format!("Bearer {token}").parse::<tonic::metadata::MetadataValue<_>>()?;
        token.set_sensitive(true);
        Ok(Self {
            channel: endpoint.connect_lazy(),
            token,
            slots: Arc::new(tokio::sync::Semaphore::new(config.pool_size)),
            timeout,
            revision: AtomicU64::new(config.minimum_revision),
            network_revision: AtomicU64::new(0),
            sequence: AtomicU64::new(1),
        })
    }
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    /// Local observed floors only; this does not query remote owners or grant a lease.
    pub fn authenticated_observation_current(&self, reply: &AuthenticatedReply) -> bool {
        reply.revision != 0
            && reply.network_revision != 0
            && reply.revision == self.revision()
            && reply.network_revision == self.network_revision.load(Ordering::Acquire)
    }
    pub fn require_revision(&self, revision: u64) {
        self.revision.fetch_max(revision, Ordering::AcqRel);
    }
    pub async fn decide_authenticated_resource(
        &self,
        query: &AuthenticatedQuery<'_>,
        receipt: &crate::projection_receipt::CheckedServiceReceipt,
    ) -> Result<AuthenticatedReply> {
        use std::time::{Instant, SystemTime, UNIX_EPOCH};
        let begun = Instant::now();
        let clock = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_millis().min(u64::MAX as u128) as u64)
        };
        let before = clock()?;
        let context = receipt.context();
        ensure!(
            query.minimum_revision <= 9_007_199_254_740_991
                && query.request_sha256 == context.request_sha256
                && receipt.authentication().valid_at(before),
            "authenticated request binding or expiry refused"
        );
        ensure!(
            [query.resource, query.action]
                .iter()
                .all(|value| !value.is_empty()
                    && value.len() <= 128
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))),
            "invalid authenticated resource scope"
        );
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("gRPC decision capacity"))?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                (value < 9_007_199_254_740_991).then(|| value + 1)
            })
            .map_err(|_| anyhow::anyhow!("gRPC request sequence exhausted"))?;
        let floor = self.revision().max(query.minimum_revision);
        let timeout = self.timeout.min(Duration::from_millis(
            receipt.authentication().expires_ms() - before,
        ));
        let mut request = tonic::Request::new(pumgye_grpc::v1::AuthenticatedResourceRequest {
            route: query.route.cloned(),
            request_id,
            minimum_revision: floor,
            ip: match query.ip {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            },
            resource: query.resource.into(),
            action: query.action.into(),
            context: Some(hopae_grpc::v1::AuthenticationReceiptContext {
                issuer_ref: context.issuer_ref.into(),
                key_epoch: context.key_epoch,
                identity_authority_epoch: context.identity_authority_epoch.into(),
                identity: Some(hopae_grpc::v1::ReceiptIdentity {
                    subject_ref: context.identity.subject_ref.into(),
                    kind: 2,
                    aal: 0,
                    revision: context.identity.revision,
                    credential_generation: context.identity.credential_generation,
                }),
                service: context.service.into(),
                audience: context.audience.into(),
                request_sha256: context.request_sha256.to_vec(),
            }),
            receipt: receipt.authentication().receipt_bytes().to_vec(),
            request_sha256: query.request_sha256.to_vec(),
        });
        request.set_timeout(timeout);
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        let mut client = pumgye_grpc::v1::authenticated_resource_authorization_client::AuthenticatedResourceAuthorizationClient::new(self.channel.clone()).max_encoding_message_size(4096).max_decoding_message_size(128);
        let reply = tokio::time::timeout(timeout, client.decide(request))
            .await
            .map_err(|_| anyhow::anyhow!("gRPC authenticated deadline"))??
            .into_inner();
        let after = clock()?;
        let final_ms = after
            .max(before.saturating_add(begun.elapsed().as_millis().min(u64::MAX as u128) as u64));
        ensure!(
            after >= before && receipt.authentication().valid_at(final_ms),
            "authenticated response expired or clock reversed"
        );
        let reply = decode_authenticated(
            reply,
            request_id,
            floor.max(self.revision()),
            self.network_revision.load(Ordering::Acquire),
            query.route.is_some(),
        )?;
        self.network_revision
            .fetch_max(reply.network_revision, Ordering::AcqRel);
        self.require_revision(reply.revision);
        ensure!(
            reply.revision >= self.revision()
                && reply.network_revision >= self.network_revision.load(Ordering::Acquire),
            "authenticated authority revision changed"
        );
        Ok(reply)
    }
    pub async fn decide_resource(&self, query: &ResourceQuery<'_>) -> Result<ResourceReply> {
        ensure!(
            query.aal <= 3
                && [
                    query.service_id,
                    query.resource,
                    query.action,
                    query.subject
                ]
                .iter()
                .all(|v| !v.is_empty()
                    && v.len() <= 128
                    && v.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))),
            "invalid resource decision scope"
        );
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("gRPC decision capacity"))?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| anyhow::anyhow!("gRPC request sequence exhausted"))?;
        let floor = self.revision().max(query.minimum_revision);
        let input = pumgye_grpc::v1::ResourceDecisionRequest {
            service_id: query.service_id.into(),
            request_id,
            minimum_revision: floor,
            ip: match query.ip {
                std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
            },
            aal: query.aal.into(),
            guard: match query.guard {
                pumgye_core::GuardEvidence::EnforcedAllow => 1,
                pumgye_core::GuardEvidence::Deny => 2,
                pumgye_core::GuardEvidence::Observe => 3,
                pumgye_core::GuardEvidence::Unavailable => 4,
            },
            resource: query.resource.into(),
            action: query.action.into(),
            subject: query.subject.into(),
        };
        let mut request = tonic::Request::new(input);
        request.set_timeout(self.timeout);
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        let mut client =
            pumgye_grpc::v1::resource_authorization_client::ResourceAuthorizationClient::new(
                self.channel.clone(),
            )
            .max_decoding_message_size(1024)
            .max_encoding_message_size(2048);
        let response = tokio::time::timeout(self.timeout, client.decide(request))
            .await
            .map_err(|_| anyhow::anyhow!("gRPC decision deadline"))??
            .into_inner();
        let reply = decode_resource(response, request_id, floor.max(self.revision()))?;
        self.require_revision(reply.revision);
        ensure!(
            reply.revision >= self.revision(),
            "gRPC resource revision changed"
        );
        Ok(reply)
    }
    pub async fn decide(&self, query: &Query<'_>) -> Result<Reply> {
        let mut replies = self.decide_batch(std::slice::from_ref(query)).await?;
        Ok(replies.remove(0))
    }
    pub async fn decide_batch(&self, queries: &[Query<'_>]) -> Result<Vec<Reply>> {
        ensure!(
            !queries.is_empty() && queries.len() <= 64,
            "invalid gRPC decision batch"
        );
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("gRPC decision capacity"))?;
        tokio::time::timeout(self.timeout, async {
            let mut replies = Vec::with_capacity(queries.len());
            let mut client = AuthorizationClient::new(self.channel.clone())
                .max_decoding_message_size(1024)
                .max_encoding_message_size(2048);
            for query in queries {
                query.encode(&mut [0; pumgye_protocol::MAX_QUERY])?;
                let request_id = self
                    .sequence
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                        value.checked_add(1)
                    })
                    .map_err(|_| anyhow::anyhow!("gRPC request sequence exhausted"))?;
                let floor = self.revision().max(query.minimum_revision);
                let input = DecisionRequest {
                    request_id,
                    minimum_revision: floor,
                    ip: match query.ip {
                        std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
                        std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
                    },
                    aal: u32::from(query.aal),
                    guard: match query.guard {
                        pumgye_core::GuardEvidence::EnforcedAllow => 1,
                        pumgye_core::GuardEvidence::Deny => 2,
                        pumgye_core::GuardEvidence::Observe => 3,
                        pumgye_core::GuardEvidence::Unavailable => 4,
                    },
                    service_id: query.service_id.into(),
                    subject: query.subject.into(),
                    permission: query.permission.into(),
                    information_class: query.information_class.into(),
                };
                let mut request = tonic::Request::new(input);
                request.set_timeout(self.timeout);
                request
                    .metadata_mut()
                    .insert("authorization", self.token.clone());
                let result = client.decide(request).await?.into_inner();
                let reply = decode(result, request_id, floor.max(self.revision()))?;
                self.require_revision(reply.revision);
                replies.push(reply);
            }
            let revision = replies[0].revision;
            ensure!(
                replies.iter().all(|r| r.revision == revision) && revision >= self.revision(),
                "gRPC batch revision changed"
            );
            Ok(replies)
        })
        .await
        .map_err(|_| anyhow::anyhow!("gRPC decision deadline"))?
    }
}
fn decode_authenticated(
    reply: pumgye_grpc::v1::AuthenticatedResourceReply,
    request_id: u64,
    policy_floor: u64,
    network_floor: u64,
    route_required: bool,
) -> Result<AuthenticatedReply> {
    ensure!(
        reply.request_id == request_id
            && (1..=9_007_199_254_740_991).contains(&reply.revision)
            && reply.revision >= policy_floor
            && (1..=9_007_199_254_740_991).contains(&reply.network_revision)
            && reply.network_revision >= network_floor
            && reply.cache_ttl_ms == 0
            && reply.route_observed == route_required
            && matches!(reply.verdict, 1 | 2),
        "invalid authenticated response"
    );
    Ok(AuthenticatedReply {
        revision: reply.revision,
        network_revision: reply.network_revision,
        allow: reply.verdict == 1,
    })
}
fn decode_resource(
    result: pumgye_grpc::v1::ResourceDecisionReply,
    request_id: u64,
    floor: u64,
) -> Result<ResourceReply> {
    use pumgye_core::{Decision as D, ResourceDecision as R};
    ensure!(
        result.request_id == request_id && result.revision >= floor && result.cache_ttl_ms == 0,
        "invalid gRPC resource envelope"
    );
    let decision = match (result.verdict, result.reason.as_str()) {
        (1, "Allow") => R::Decided(D::Allow),
        (2, "UnknownResource") => R::UnknownResource,
        (2, "UnknownAction") => R::UnknownAction,
        (2, "UnknownService") => R::Decided(D::UnknownService),
        (2, "Guest") => R::Decided(D::Guest),
        (2, "NetworkGuest") => R::Decided(D::NetworkGuest),
        (2, "PermissionDenied") => R::Decided(D::PermissionDenied),
        (2, "ClassDenied") => R::Decided(D::ClassDenied),
        (2, "AssuranceDenied") => R::Decided(D::AssuranceDenied),
        (2, "GuardDenied") => R::Decided(D::GuardDenied),
        _ => anyhow::bail!("unavailable or inconsistent gRPC resource verdict"),
    };
    Ok(ResourceReply {
        revision: result.revision,
        decision,
    })
}
fn decode(result: DecisionReply, request_id: u64, floor: u64) -> Result<Reply> {
    ensure!(
        result.request_id == request_id && result.revision >= floor && result.cache_ttl_ms == 0,
        "invalid gRPC decision envelope"
    );
    let reason = u8::try_from(result.native_reason)?;
    ensure!(
        matches!((result.verdict, reason), (1, 0) | (2, 1..=8) | (3, 255)),
        "inconsistent gRPC verdict"
    );
    let mut bytes = [0; pumgye_protocol::REPLY_SIZE];
    bytes[0] = 1;
    bytes[1] = reason;
    bytes[4..12].copy_from_slice(&request_id.to_be_bytes());
    bytes[12..20].copy_from_slice(&result.revision.to_be_bytes());
    let reply = Reply::decode(&bytes)?;
    ensure!(reply.decision.is_some(), "gRPC authority unavailable");
    Ok(reply)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authenticated_reply_refuses_unsupported_verdict_cache_and_stale_owners() {
        let reply = || pumgye_grpc::v1::AuthenticatedResourceReply {
            route_observed: false,
            request_id: 7,
            revision: 3,
            network_revision: 4,
            verdict: 1,
            cache_ttl_ms: 0,
        };
        assert!(decode_authenticated(reply(), 7, 3, 4, false).unwrap().allow);
        assert!(decode_authenticated(reply(), 7, 3, 4, true).is_err());
        let mut routed = reply();
        routed.route_observed = true;
        assert!(decode_authenticated(routed, 7, 3, 4, true).unwrap().allow);
        assert!(decode_authenticated(routed, 7, 3, 4, false).is_err());

        for field in ["id", "policy", "network", "verdict", "cache", "overflow"] {
            let mut value = reply();
            match field {
                "id" => value.request_id = 8,
                "policy" => value.revision = 2,
                "network" => value.network_revision = 3,
                "verdict" => value.verdict = 3,
                "cache" => value.cache_ttl_ms = 1,
                "overflow" => value.revision = u64::MAX,
                _ => unreachable!(),
            }
            assert!(
                decode_authenticated(value, 7, 3, 4, false).is_err(),
                "{field}"
            );
        }
        let mut denied = reply();
        denied.verdict = 2;
        assert!(!decode_authenticated(denied, 7, 3, 4, false).unwrap().allow);
    }
    #[test]
    fn resource_reply_rejects_default_conflicting_stale_and_cached_allow() {
        use pumgye_grpc::v1::ResourceDecisionReply;
        let valid = ResourceDecisionReply {
            request_id: 7,
            revision: 3,
            verdict: 1,
            reason: "Allow".into(),
            cache_ttl_ms: 0,
        };
        assert_eq!(
            decode_resource(valid.clone(), 7, 3).unwrap().decision,
            pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::Allow)
        );
        for bad in [
            ResourceDecisionReply::default(),
            ResourceDecisionReply {
                verdict: 2,
                ..valid.clone()
            },
            ResourceDecisionReply {
                reason: "Guest".into(),
                ..valid.clone()
            },
            ResourceDecisionReply {
                request_id: 8,
                ..valid.clone()
            },
            ResourceDecisionReply {
                revision: 2,
                ..valid.clone()
            },
            ResourceDecisionReply {
                cache_ttl_ms: 1,
                ..valid.clone()
            },
            ResourceDecisionReply {
                verdict: 3,
                reason: "Unavailable".into(),
                ..valid.clone()
            },
            ResourceDecisionReply {
                verdict: 3,
                reason: "GuardUnavailable".into(),
                ..valid.clone()
            },
            ResourceDecisionReply {
                verdict: 2,
                reason: "future-reason".into(),
                ..valid.clone()
            },
        ] {
            assert!(decode_resource(bad, 7, 3).is_err());
        }
        let deny = ResourceDecisionReply {
            verdict: 2,
            reason: "UnknownAction".into(),
            ..valid
        };
        assert_eq!(
            decode_resource(deny, 7, 3).unwrap().decision,
            pumgye_core::ResourceDecision::UnknownAction
        );
    }
    #[test]
    fn response_defaults_conflicts_and_stale_revisions_never_allow() {
        let valid = DecisionReply {
            request_id: 7,
            revision: 3,
            verdict: 1,
            native_reason: 0,
            cache_ttl_ms: 0,
        };
        assert_eq!(
            decode(valid, 7, 3).unwrap().decision,
            Some(pumgye_core::Decision::Allow)
        );
        for bad in [
            DecisionReply {
                verdict: 0,
                ..valid
            },
            DecisionReply {
                native_reason: 1,
                ..valid
            },
            DecisionReply {
                request_id: 8,
                ..valid
            },
            DecisionReply {
                revision: 2,
                ..valid
            },
            DecisionReply {
                cache_ttl_ms: 1,
                ..valid
            },
            DecisionReply {
                verdict: 3,
                native_reason: 255,
                ..valid
            },
        ] {
            assert!(decode(bad, 7, 3).is_err());
        }
        let deny = DecisionReply {
            verdict: 2,
            native_reason: 2,
            ..valid
        };
        assert_eq!(
            decode(deny, 7, 3).unwrap().decision,
            Some(pumgye_core::Decision::Guest)
        );
    }
    #[tokio::test]
    async fn native_observation_is_invalidated_by_either_observed_owner_floor() {
        let client = Client {
            channel: Endpoint::from_static("https://unused.example.test").connect_lazy(),
            token: "Bearer owned-fixture".parse().unwrap(),
            slots: Arc::new(tokio::sync::Semaphore::new(1)),
            timeout: Duration::from_secs(1),
            revision: AtomicU64::new(1),
            network_revision: AtomicU64::new(1),
            sequence: AtomicU64::new(1),
        };
        let mut reply = AuthenticatedReply {
            revision: 1,
            network_revision: 1,
            allow: true,
        };
        assert!(client.authenticated_observation_current(&reply));
        client.require_revision(2);
        assert!(!client.authenticated_observation_current(&reply));
        reply.revision = 2;
        assert!(client.authenticated_observation_current(&reply));
        client.network_revision.fetch_max(2, Ordering::AcqRel);
        assert!(!client.authenticated_observation_current(&reply));
        reply.network_revision = 2;
        assert!(client.authenticated_observation_current(&reply));
        reply.network_revision = 0;
        assert!(!client.authenticated_observation_current(&reply));
    }
}
