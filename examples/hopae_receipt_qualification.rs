//! Owned interactive receipt fixture. Tokens enter only through environment references.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hangang::{
    config::HopaeNative,
    hopae_native::Client,
    projection_binding,
    projection_receipt::{IssuerPin, ServiceScope},
};
use hyper::{
    HeaderMap, Request,
    header::{HeaderName, HeaderValue},
};
use serde::Deserialize;
use std::io::{BufRead, Write};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    settings: HopaeNative,
    issuer_ref: String,
    key_epoch: u64,
    public_key: String,
    service: String,
    audience: String,
    method: String,
    target: String,
    body: String,
    headers: Vec<(String, String)>,
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .context("private fixture configuration required")?;
    let config: Configuration = serde_json::from_slice(&std::fs::read(path)?)?;
    let mut key = HeaderValue::from_str(
        &std::env::var("OWNED_RECEIPT_CALLER").context("caller reference unavailable")?,
    )?;
    key.set_sensitive(true);
    let client = Client::from_config(&config.settings, key)?;
    let public: [u8; 32] = STANDARD
        .decode(config.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public pin"))?;
    let pin = IssuerPin::new(config.issuer_ref, config.key_epoch, public)
        .map_err(|_| anyhow::anyhow!("invalid native issuer pin"))?;
    let request = Request::builder()
        .method(config.method.as_str())
        .uri(&config.target)
        .body(Bytes::from(config.body))?;
    let digest = projection_binding::digest(&config.service, &config.audience, &request)
        .map_err(|_| anyhow::anyhow!("invalid native request binding"))?;
    let scope = ServiceScope {
        service: &config.service,
        audience: &config.audience,
        request_sha256: digest,
    };
    let mut headers = HeaderMap::new();
    for (name, value) in config.headers {
        ensure!(
            !name.eq_ignore_ascii_case("authorization")
                && !name.eq_ignore_ascii_case("x-hopae-gateway-key"),
            "credential headers require native references"
        );
        headers.append(
            HeaderName::from_bytes(name.as_bytes())?,
            HeaderValue::from_str(&value)?,
        );
    }
    let mut credential = HeaderValue::from_str(&format!(
        "Bearer {}",
        std::env::var("OWNED_RECEIPT_CREDENTIAL")
            .context("service credential reference unavailable")?
    ))?;
    credential.set_sensitive(true);
    headers.insert("authorization", credential);
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        ensure!(
            matches!(command.as_str(), "allow" | "deny"),
            "unknown fixture command"
        );
        let outcome = client.issue_service_receipt(&headers, &scope, &pin).await;
        match (command.as_str(), outcome) {
            ("allow", Ok(checked)) => {
                ensure!(
                    checked.context().request_sha256 == digest,
                    "binding changed"
                );
                println!(
                    "{}",
                    serde_json::json!({"allowed":true,"revision":checked.revision()})
                );
            }
            ("deny", Err(_)) => println!("{}", serde_json::json!({"allowed":false})),
            _ => anyhow::bail!("receipt result differed from expected outcome"),
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
