//! Provider-independent gRPC transport for the existing gateway verification contract.
use super::{invalid, wire};
use hopae_grpc::v1::{Header, VerifyRequest, authentication_client::AuthenticationClient};
use hyper::{HeaderMap, Response};
use std::{
    io,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
pub(super) struct Client {
    channel: Channel,
    key: tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    slots: tokio::sync::Semaphore,
    next: AtomicU64,
    receipt_revision: AtomicU64,
    receipt_wall: Duration,
    receipt_started: std::time::Instant,
}
impl Client {
    pub(super) fn new(
        settings: &crate::config::HopaeNative,
        key: &hyper::header::HeaderValue,
    ) -> anyhow::Result<Self> {
        let tls = settings
            .tls
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Hopae gRPC requires mTLS"))?;
        let tls = ClientTlsConfig::new()
            .domain_name(&tls.server_name)
            .ca_certificate(Certificate::from_pem(crate::tls::read_bounded(&tls.ca)?))
            .identity(Identity::from_pem(
                crate::tls::read_bounded(&tls.certificate)?,
                crate::tls::read_bounded(&tls.key)?,
            ));
        let endpoint = Endpoint::from_shared(format!("https://{}", settings.address))?
            .tls_config(tls)?
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(1))
            .buffer_size(settings.pool_size)
            .tcp_nodelay(true);
        let mut key =
            format!("Bearer {}", key.to_str()?).parse::<tonic::metadata::MetadataValue<_>>()?;
        key.set_sensitive(true);
        let receipt_started = std::time::Instant::now();
        let receipt_wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
        Ok(Self {
            channel: endpoint.connect_lazy(),
            key,
            slots: tokio::sync::Semaphore::new(settings.pool_size),
            next: AtomicU64::new(1),
            receipt_revision: AtomicU64::new(0),
            receipt_wall,
            receipt_started,
        })
    }
    pub(super) async fn issue_service_receipt(
        &self,
        headers: &HeaderMap,
        scope: &crate::projection_receipt::ServiceScope<'_>,
        pin: &crate::projection_receipt::IssuerPin,
    ) -> io::Result<crate::projection_receipt::CheckedServiceReceipt> {
        let _permit = self
            .slots
            .try_acquire()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Hopae gRPC capacity"))?;
        let fields = headers
            .iter()
            .filter(|(n, _)| n.as_str() != "x-hopae-gateway-key")
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        wire::encode_request(&fields)?;
        let request_id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| invalid())?;
        let mut request = tonic::Request::new(hopae_grpc::v1::ServiceReceiptRequest {
            verification: Some(VerifyRequest {
                request_id,
                headers: fields
                    .into_iter()
                    .map(|(name, value)| Header { name, value })
                    .collect(),
            }),
            service: scope.service.into(),
            audience: scope.audience.into(),
            request_sha256: scope.request_sha256.to_vec(),
        });
        request.set_timeout(Duration::from_secs(1));
        request
            .metadata_mut()
            .insert("authorization", self.key.clone());
        let operation = async {
            let mut client =
                hopae_grpc::v1::authentication_receipts_client::AuthenticationReceiptsClient::new(
                    self.channel.clone(),
                )
                .max_decoding_message_size(2048)
                .max_encoding_message_size(wire::MAX_FRAME);
            let reply = client
                .issue_service(request)
                .await
                .map_err(|_| invalid())?
                .into_inner();
            let now = receipt_now(self.receipt_wall, self.receipt_started.elapsed())?;
            let checked = pin
                .verify_service_reply(request_id, scope, reply, now)
                .map_err(|_| invalid())?;
            if checked.revision()
                < self
                    .receipt_revision
                    .fetch_max(checked.revision(), Ordering::AcqRel)
            {
                return Err(invalid());
            }
            Ok(checked)
        };
        tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Hopae receipt deadline"))?
    }

    pub(super) async fn verify(
        &self,
        headers: &HeaderMap,
    ) -> io::Result<Response<crate::proxy::Body>> {
        let _permit = self
            .slots
            .try_acquire()
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "Hopae gRPC capacity"))?;
        let fields = headers
            .iter()
            .filter(|(n, _)| n.as_str() != "x-hopae-gateway-key")
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        wire::encode_request(&fields)?;
        let request_id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
            .map_err(|_| invalid())?;
        let mut request = tonic::Request::new(VerifyRequest {
            request_id,
            headers: fields
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
        });
        request.set_timeout(Duration::from_secs(1));
        request
            .metadata_mut()
            .insert("authorization", self.key.clone());
        let operation = async {
            let mut client = AuthenticationClient::new(self.channel.clone())
                .max_decoding_message_size(wire::MAX_FRAME)
                .max_encoding_message_size(wire::MAX_FRAME);
            let reply = client
                .verify(request)
                .await
                .map_err(|_| invalid())?
                .into_inner();
            if reply.request_id != request_id {
                return Err(invalid());
            }
            let reply = wire::Reply {
                status: u16::try_from(reply.status).map_err(|_| invalid())?,
                headers: reply
                    .headers
                    .into_iter()
                    .map(|h| (h.name, h.value))
                    .collect(),
                body: reply.body,
            };
            wire::encode_reply(&reply)?;
            super::response(reply)
        };
        tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Hopae gRPC deadline"))?
    }
}

fn receipt_now(wall: Duration, elapsed: Duration) -> io::Result<u64> {
    let now = wall.checked_add(elapsed).ok_or_else(invalid)?;
    u64::try_from(now.as_millis()).map_err(|_| invalid())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn receipt_clock_keeps_fractional_wall_time_until_final_rounding() {
        assert_eq!(
            receipt_now(Duration::from_micros(100_999), Duration::from_micros(200)).unwrap(),
            101
        );
        assert!(receipt_now(Duration::MAX, Duration::from_secs(1)).is_err());
    }
}
