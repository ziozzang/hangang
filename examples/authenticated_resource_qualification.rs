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
    pumgye_grpc_address: String,
    #[serde(rename = "pumgye_endpoint")]
    _pumgye_endpoint: Option<String>,
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
    ensure!(
        config.pumgye_grpc_address.starts_with("https://localhost:")
            || config.pumgye_grpc_address.starts_with("https://127.0.0.1:"),
        "owned Pumgye endpoint required"
    );
    let address = config
        .pumgye_grpc_address
        .strip_prefix("https://")
        .unwrap()
        .replacen("localhost:", "127.0.0.1:", 1);
    let tls = config
        .settings
        .tls
        .as_ref()
        .context("native TLS required")?;
    let authority: hangang::pumgye::AuthorityConfig = serde_json::from_value(
        serde_json::json!({"transport":"grpc","decision_address":address,"management_address":address,"decision_token_env":"PUMGYE_DECISION_TOKEN","admin_token_env":"PUMGYE_ADMIN_TOKEN","tls":{"server_name":tls.server_name,"ca":tls.ca,"certificate":tls.certificate,"key":tls.key},"pool_size":8,"timeout_ms":1000,"minimum_revision":1}),
    )?;
    authority.validate()?;
    let pumgye = hangang::pumgye_grpc_client::Client::new(
        &authority,
        &std::env::var("PUMGYE_DECISION_TOKEN")?,
    )?;
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
    let query = hangang::pumgye_grpc_client::AuthenticatedQuery {
        resource: "db:orders",
        action: "select",
        ip: "203.0.113.9".parse()?,
        minimum_revision: 1,
        request_sha256: digest,
    };
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    };
    let mut prior: Option<hangang::projection_receipt::CheckedServiceReceipt> = None;
    for command in std::io::stdin().lock().lines() {
        let command = command?;
        ensure!(
            matches!(
                command.as_str(),
                "allow" | "deny" | "deny-network" | "outage"
            ),
            "unknown fixture command"
        );
        if matches!(command.as_str(), "deny" | "outage")
            && let Some(old) = &prior
        {
            ensure!(
                old.authentication().valid_at(now()),
                "cached receipt expired before lifecycle query"
            );
            let result = pumgye.decide_authenticated_resource(&query, old).await;
            ensure!(
                result.is_err() || result.is_ok_and(|result| !result.allow),
                "retired or unavailable proof accepted"
            );
        }
        if command == "outage" {
            println!("{}", serde_json::json!({"allowed":false}));
            std::io::stdout().flush()?;
            continue;
        }
        let outcome = client.issue_service_receipt(&headers, &scope, &pin).await;
        let outcome = match outcome {
            Ok(checked) => match pumgye.decide_authenticated_resource(&query, &checked).await {
                Ok(reply) if reply.allow => {
                    let revision = checked.revision();
                    prior = Some(checked);
                    Ok(revision)
                }
                _ => Err(anyhow::anyhow!("native authenticated decision refused")),
            },
            Err(_) => Err(anyhow::anyhow!("native authentication refused")),
        };
        match (command.as_str(), outcome) {
            ("allow", Ok(revision)) => println!(
                "{}",
                serde_json::json!({"allowed":true,"revision":revision})
            ),
            ("deny" | "deny-network", Err(_)) => {
                println!("{}", serde_json::json!({"allowed":false}))
            }
            _ => anyhow::bail!("native result differed from expected outcome"),
        }
        std::io::stdout().flush()?;
    }
    Ok(())
}
