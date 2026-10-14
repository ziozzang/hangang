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
    })
}
#[cfg(test)]
mod tests {
    use super::*;
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
