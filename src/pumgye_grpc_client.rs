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

pub struct Client {
    channel: Channel,
    token: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    slots: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    revision: AtomicU64,
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
            sequence: AtomicU64::new(1),
        })
    }
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    pub fn require_revision(&self, revision: u64) {
        self.revision.fetch_max(revision, Ordering::AcqRel);
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
}
