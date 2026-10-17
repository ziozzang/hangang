//! gRPC network transport; domain interpretation remains in GuardClient.
use super::{Action, Config, Decision, Mode, TCP_POOL_SIZE};
use anyhow::{Result, ensure};
use guard_grpc::v1::{NetworkReply, NetworkRequest, network_client::NetworkClient};
use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

pub(super) struct Client {
    channel: Channel,
    token: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    slots: Arc<tokio::sync::Semaphore>,
    revision: AtomicU64,
    sequence: AtomicU64,
    timeout: Duration,
    cancel: CancellationToken,
    include_evidence: bool,
}

/// The additive request and reply of the Network service with evidence
/// (Sumunjang `network.proto` fields 4 and 6). Field numbers and types match
/// the original messages, so an older service ignores `include_evidence`
/// and answers the original reply (no evidence).
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct EvidenceRequest {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ip: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub minimum_revision: u64,
    #[prost(bool, tag = "4")]
    pub include_evidence: bool,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct EvidenceReply {
    #[prost(uint64, tag = "1")]
    pub request_id: u64,
    #[prost(uint64, tag = "2")]
    pub revision: u64,
    #[prost(int32, tag = "3")]
    pub verdict: i32,
    #[prost(int32, tag = "4")]
    pub mode: i32,
    #[prost(uint32, tag = "5")]
    pub ttl_ms: u32,
    #[prost(message, optional, tag = "6")]
    pub evidence: Option<NetworkEvidence>,
}
#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct NetworkEvidence {
    #[prost(string, tag = "1")]
    pub reason_code: String,
    #[prost(int32, tag = "2")]
    pub deciding_stage: i32,
    #[prost(string, repeated, tag = "3")]
    pub rule_ids: Vec<String>,
    #[prost(bool, tag = "4")]
    pub rule_ids_truncated: bool,
    #[prost(string, tag = "5")]
    pub block_network: String,
    #[prost(uint32, tag = "6")]
    pub asn: u32,
    #[prost(string, tag = "7")]
    pub country: String,
    #[prost(int32, tag = "8")]
    pub enforce_verdict: i32,
    #[prost(string, tag = "9")]
    pub enforce_reason_code: String,
    #[prost(string, repeated, tag = "10")]
    pub zone_ids: Vec<String>,
    #[prost(bool, tag = "11")]
    pub zone_ids_truncated: bool,
    #[prost(uint64, tag = "12")]
    pub zone_revision: u64,
    #[prost(uint32, tag = "13")]
    pub risk_score: u32,
    #[prost(int32, tag = "14")]
    pub risk_stage: i32,
}

impl Client {
    pub(super) fn new(config: &Config, token: &str, cancel: CancellationToken) -> Result<Self> {
        let tls = config
            .decision_tls
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("guard gRPC requires mTLS"))?;
        let address = config
            .decision_tcp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("guard gRPC requires address"))?;
        let tls = ClientTlsConfig::new()
            .domain_name(&tls.server_name)
            .ca_certificate(Certificate::from_pem(crate::tls::read_bounded(&tls.ca)?))
            .identity(Identity::from_pem(
                crate::tls::read_bounded(&tls.certificate)?,
                crate::tls::read_bounded(&tls.key)?,
            ));
        let timeout = Duration::from_millis(config.timeout_ms);
        let endpoint = Endpoint::from_shared(format!("https://{address}"))?
            .tls_config(tls)?
            .connect_timeout(timeout)
            .timeout(timeout)
            .buffer_size(TCP_POOL_SIZE)
            .tcp_nodelay(true);
        let mut token = format!("Bearer {token}").parse::<tonic::metadata::MetadataValue<_>>()?;
        token.set_sensitive(true);
        Ok(Self {
            channel: endpoint.connect_lazy(),
            token,
            slots: Arc::new(tokio::sync::Semaphore::new(TCP_POOL_SIZE)),
            revision: AtomicU64::new(0),
            sequence: AtomicU64::new(1),
            timeout,
            cancel,
            include_evidence: config.include_evidence,
        })
    }
    pub(super) async fn query(&self, ip: IpAddr) -> Result<Decision> {
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("guard gRPC capacity"))?;
        let request_id = self
            .sequence
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| anyhow::anyhow!("guard gRPC sequence exhausted"))?;
        if self.include_evidence {
            return self.query_with_evidence(ip, request_id).await;
        }
        let mut request = tonic::Request::new(NetworkRequest {
            request_id,
            minimum_revision: self.revision.load(Ordering::Acquire),
            ip: match ip.to_canonical() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            },
        });
        request.set_timeout(self.timeout);
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        let operation = async {
            let mut client = NetworkClient::new(self.channel.clone())
                .max_encoding_message_size(2048)
                .max_decoding_message_size(1024);
            let reply = client.check(request).await?.into_inner();
            let result = decode(reply, request_id, self.revision.load(Ordering::Acquire))?;
            self.revision.fetch_max(result.revision, Ordering::AcqRel);
            ensure!(
                result.revision >= self.revision.load(Ordering::Acquire),
                "guard gRPC revision changed"
            );
            Ok(result)
        };
        tokio::select! { biased;
            _=self.cancel.cancelled()=>Err(anyhow::anyhow!("guard gRPC cancelled")),
            result=tokio::time::timeout(self.timeout,operation)=>result.map_err(|_|anyhow::anyhow!("guard gRPC deadline"))?,
        }
    }
}
impl Client {
    /// `Check` with `include_evidence`, through the additive messages above.
    async fn query_with_evidence(&self, ip: IpAddr, request_id: u64) -> Result<Decision> {
        let mut request = tonic::Request::new(EvidenceRequest {
            request_id,
            minimum_revision: self.revision.load(Ordering::Acquire),
            ip: match ip.to_canonical() {
                IpAddr::V4(ip) => ip.octets().to_vec(),
                IpAddr::V6(ip) => ip.octets().to_vec(),
            },
            include_evidence: true,
        });
        request.set_timeout(self.timeout);
        request
            .metadata_mut()
            .insert("authorization", self.token.clone());
        let operation = async {
            let mut grpc = tonic::client::Grpc::new(self.channel.clone())
                .max_encoding_message_size(2048)
                .max_decoding_message_size(2048);
            grpc.ready().await?;
            let reply: EvidenceReply = grpc
                .unary(
                    request,
                    tonic::codegen::http::uri::PathAndQuery::from_static(
                        "/hangang.sumunjang.v1.Network/Check",
                    ),
                    tonic_prost::ProstCodec::default(),
                )
                .await?
                .into_inner();
            let evidence = reply.evidence.clone();
            let mut result = decode(
                NetworkReply {
                    request_id: reply.request_id,
                    revision: reply.revision,
                    verdict: reply.verdict,
                    mode: reply.mode,
                    ttl_ms: reply.ttl_ms,
                },
                request_id,
                self.revision.load(Ordering::Acquire),
            )?;
            result.evidence = evidence.and_then(|e| evidence_of(e, &result));
            self.revision.fetch_max(result.revision, Ordering::AcqRel);
            ensure!(
                result.revision >= self.revision.load(Ordering::Acquire),
                "guard gRPC revision changed"
            );
            Ok(result)
        };
        tokio::select! { biased;
            _=self.cancel.cancelled()=>Err(anyhow::anyhow!("guard gRPC cancelled")),
            result=tokio::time::timeout(self.timeout,operation)=>result.map_err(|_|anyhow::anyhow!("guard gRPC deadline"))?,
        }
    }
}

/// Bounded evidence for the risk context; malformed evidence is dropped
/// (the verdict still stands, the header is omitted).
fn evidence_of(e: NetworkEvidence, d: &Decision) -> Option<Arc<crate::risk_context::Evidence>> {
    let code_ok = |s: &str| {
        s.len() <= 128
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    };
    if !code_ok(&e.reason_code)
        || !code_ok(&e.enforce_reason_code)
        || !(e.country.is_empty()
            || (e.country.len() == 2 && e.country.bytes().all(|b| b.is_ascii_uppercase())))
        || !(0..=5).contains(&e.deciding_stage)
        || !(0..=3).contains(&e.enforce_verdict)
        || e.zone_ids.len() > 8
        || !e.zone_ids.iter().all(|z| crate::risk_context::zone_ok(z))
        || e.risk_score > 100
        || !(0..=5).contains(&e.risk_stage)
    {
        return None;
    }
    let risk = crate::risk_context::RiskStage::from_wire(e.risk_stage)
        .map(|stage| ((e.risk_score / 10 * 10) as u8, stage));
    Some(Arc::new(crate::risk_context::Evidence {
        reason_code: e.reason_code,
        deciding_stage: e.deciding_stage,
        asn: e.asn,
        country: e.country,
        enforce_verdict: e.enforce_verdict,
        enforce_reason_code: e.enforce_reason_code,
        observe: d.mode == Mode::Observe,
        revision: d.revision,
        zones: e.zone_ids,
        risk,
    }))
}

fn decode(reply: NetworkReply, request_id: u64, floor: u64) -> Result<Decision> {
    ensure!(
        reply.request_id == request_id && reply.revision >= floor && reply.ttl_ms <= 5000,
        "invalid guard gRPC envelope"
    );
    let action = match reply.verdict {
        1 => Action::Allow,
        2 => Action::Deny,
        _ => anyhow::bail!("guard gRPC unavailable or invalid verdict"),
    };
    let mode = match reply.mode {
        1 => Mode::Observe,
        2 => Mode::Enforce,
        _ => anyhow::bail!("invalid guard gRPC mode"),
    };
    ensure!(
        !matches!((mode, action), (Mode::Observe, Action::Deny)),
        "observe cannot deny"
    );
    Ok(Decision {
        version: 1,
        revision: reply.revision,
        action,
        mode,
        reason: None,
        ttl_ms: u64::from(reply.ttl_ms),
        evidence: None,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evidence_keeps_sumunjang_zone_ids_and_refuses_others() {
        let d = decode(
            NetworkReply {
                request_id: 1,
                revision: 2,
                verdict: 1,
                mode: 1,
                ttl_ms: 1000,
            },
            1,
            0,
        )
        .unwrap();
        let e = |zones: &[&str]| NetworkEvidence {
            reason_code: "sumunjang.observe.mode".into(),
            deciding_stage: 1,
            zone_ids: zones.iter().map(|z| z.to_string()).collect(),
            risk_score: 30,
            risk_stage: 3,
            ..NetworkEvidence::default()
        };
        let kept = evidence_of(e(&["Corp:VPN", "legacy.orders.1"]), &d).unwrap();
        assert_eq!(kept.zones, ["Corp:VPN", "legacy.orders.1"]);
        assert_eq!(
            kept.risk,
            Some((30, crate::risk_context::RiskStage::Suspicious))
        );
        assert!(
            evidence_of(e(&["corp vpn"]), &d).is_none(),
            "refused, never silently trimmed"
        );
    }
    #[test]
    fn defaults_unavailable_conflicts_and_stale_replies_fail_closed() {
        let reply = NetworkReply {
            request_id: 7,
            revision: 4,
            verdict: 1,
            mode: 2,
            ttl_ms: 1000,
        };
        assert!(matches!(decode(reply, 7, 4).unwrap().action, Action::Allow));
        for bad in [
            NetworkReply {
                verdict: 0,
                ..reply
            },
            NetworkReply {
                verdict: 3,
                ..reply
            },
            NetworkReply { mode: 0, ..reply },
            NetworkReply {
                verdict: 2,
                mode: 1,
                ..reply
            },
            NetworkReply {
                revision: 3,
                ..reply
            },
            NetworkReply {
                request_id: 8,
                ..reply
            },
            NetworkReply {
                ttl_ms: 5001,
                ..reply
            },
        ] {
            assert!(decode(bad, 7, 4).is_err());
        }
    }
}
