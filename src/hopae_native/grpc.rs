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
        Ok(Self {
            channel: endpoint.connect_lazy(),
            key,
            slots: tokio::sync::Semaphore::new(settings.pool_size),
            next: AtomicU64::new(1),
        })
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
