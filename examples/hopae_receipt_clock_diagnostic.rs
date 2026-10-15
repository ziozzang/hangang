//! Owned diagnostic only: compares local time checks; never authorizes a request.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use hangang::projection_receipt::{IssuerPin, ServiceScope};
use hopae_grpc::v1::{
    Header, ServiceReceiptRequest, VerifyRequest,
    authentication_receipts_client::AuthenticationReceiptsClient,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("owned configuration required")?;
    let config: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let settings: hangang::config::HopaeNative =
        serde_json::from_value(config["settings"].clone())?;
    let tls = settings.tls.context("mTLS required")?;
    let tls = ClientTlsConfig::new()
        .domain_name(&tls.server_name)
        .ca_certificate(Certificate::from_pem(std::fs::read(&tls.ca)?))
        .identity(Identity::from_pem(
            std::fs::read(&tls.certificate)?,
            std::fs::read(&tls.key)?,
        ));
    let channel = Endpoint::from_shared(format!("https://{}", settings.address))?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(1))
        .timeout(Duration::from_secs(1))
        .connect()
        .await?;
    let string = |key: &str| config[key].as_str().context("owned string required");
    let public: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(string("public_key")?)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public pin"))?;
    let pin = IssuerPin::new(
        string("issuer_ref")?.into(),
        config["key_epoch"].as_u64().context("epoch required")?,
        public,
    )
    .map_err(|_| anyhow::anyhow!("invalid pin"))?;
    let request = hyper::Request::builder()
        .method(string("method")?)
        .uri(string("target")?)
        .body(bytes::Bytes::copy_from_slice(string("body")?.as_bytes()))?;
    let hash =
        hangang::projection_binding::digest(string("service")?, string("audience")?, &request)
            .map_err(|_| anyhow::anyhow!("invalid scope"))?;
    let scope = ServiceScope {
        service: string("service")?,
        audience: string("audience")?,
        request_sha256: hash,
    };
    let fields: Vec<(String, String)> = serde_json::from_value(config["headers"].clone())?;
    let mut headers = fields
        .into_iter()
        .map(|(name, value)| Header {
            name,
            value: value.into_bytes(),
        })
        .collect::<Vec<_>>();
    headers.push(Header {
        name: "authorization".into(),
        value: format!("Bearer {}", std::env::var("OWNED_RECEIPT_CREDENTIAL")?).into_bytes(),
    });
    let mut rpc = tonic::Request::new(ServiceReceiptRequest {
        verification: Some(VerifyRequest {
            request_id: 1,
            headers,
        }),
        service: scope.service.into(),
        audience: scope.audience.into(),
        request_sha256: hash.to_vec(),
    });
    let mut caller: tonic::metadata::MetadataValue<_> =
        format!("Bearer {}", std::env::var("OWNED_RECEIPT_CALLER")?).parse()?;
    caller.set_sensitive(true);
    rpc.metadata_mut().insert("authorization", caller);
    let before = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    let reply = AuthenticationReceiptsClient::new(channel)
        .max_decoding_message_size(2048)
        .max_encoding_message_size(4096)
        .issue_service(rpc)
        .await?
        .into_inner();
    let after = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    ensure!(
        reply.receipt.len() == hopae_grpc::receipt::LENGTH,
        "invalid receipt length"
    );
    let issued = u64::from_be_bytes(reply.receipt[2..10].try_into()?);
    let ordinary = pin
        .verify_service_reply(1, &scope, reply.clone(), after)
        .is_ok();
    let signature_and_binding = pin
        .verify_service_reply(1, &scope, reply, after.max(issued))
        .is_ok();
    println!(
        "{}",
        serde_json::json!({"diagnostic_only":true,"signature_and_binding_valid":signature_and_binding,"ordinary_local_time_accepts":ordinary,"issued_minus_local_received_ms":i128::from(issued)-i128::from(after),"rpc_elapsed_ms":after.saturating_sub(before)})
    );
    Ok(())
}
