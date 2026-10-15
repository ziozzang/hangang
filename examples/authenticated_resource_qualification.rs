//! Owned interactive receipt fixture. Tokens enter only through environment references.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use hangang::{config::HopaeNative, hopae_native::Client, projection_receipt::IssuerPin};
use http_body_util::{BodyExt, Full, StreamBody};
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
    pumgye_endpoint: String,
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
    let management = reqwest::Url::parse(&config.pumgye_endpoint)?;
    ensure!(
        management.host_str() == Some("127.0.0.1") && management.port().is_some(),
        "owned management endpoint required"
    );
    let management_address = format!("127.0.0.1:{}", management.port().unwrap());
    let tls = config
        .settings
        .tls
        .as_ref()
        .context("native TLS required")?;
    let authority: hangang::pumgye::AuthorityConfig = serde_json::from_value(
        serde_json::json!({"transport":"grpc","decision_address":address,"management_address":management_address,"decision_token_env":"PUMGYE_DECISION_TOKEN","admin_token_env":"PUMGYE_ADMIN_TOKEN","tls":{"server_name":tls.server_name,"ca":tls.ca,"certificate":tls.certificate,"key":tls.key},"pool_size":8,"timeout_ms":1000,"minimum_revision":1}),
    )?;
    authority.validate()?;
    let pumgye = hangang::pumgye::AuthorityRuntime::prepare(&authority)?;
    let public: [u8; 32] = STANDARD
        .decode(&config.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid public pin"))?;
    let gate = hangang::pumgye::ResourceGate {
        service_id: config.service.clone(),
        resource: "db:orders".into(),
        actions: std::collections::BTreeMap::from([("GET".into(), "select".into())]),
    };
    let native_configuration = hangang::native_resource::Configuration {
        audience: config.audience.clone(),
        issuer_ref: config.issuer_ref.clone(),
        key_epoch: config.key_epoch,
        public_key: config.public_key.clone(),
        permission_permit: None,
        maximum_body_bytes: 1024 * 1024,
        body_timeout_ms: 1000,
    };
    let binding = native_configuration.compile(gate.clone())?;
    let request = Request::builder()
        .method(config.method.as_str())
        .uri(&config.target)
        .body(Bytes::from(config.body))?;
    ensure!(
        request.uri().scheme().is_none() && request.uri().authority().is_none(),
        "owned origin target required"
    );
    let (mut parts, bytes) = request.into_parts();
    parts.uri = format!("https://orders.example.test{}", parts.uri).parse()?;
    let fragment_mode = std::env::var("OWNED_RECEIPT_FRAGMENTED_ENTITY").ok();
    ensure!(
        fragment_mode
            .as_deref()
            .is_none_or(|mode| matches!(mode, "0" | "1")),
        "invalid owned frame mode"
    );
    let fragmented = fragment_mode.as_deref() == Some("1");
    let entity_frames = if fragmented {
        2
    } else {
        usize::from(!bytes.is_empty())
    };
    let body: hangang::proxy::Body = if fragmented {
        ensure!(bytes.len() > 1, "owned fragmented entity required");
        let midpoint = bytes.len().div_ceil(2);
        let frames: [Result<hyper::body::Frame<Bytes>, hangang::proxy::BodyError>; 2] = [
            Ok(hyper::body::Frame::data(bytes.slice(..midpoint))),
            Ok(hyper::body::Frame::data(bytes.slice(midpoint..))),
        ];
        StreamBody::new(futures_util::stream::iter(frames)).boxed_unsync()
    } else {
        Full::new(bytes)
            .map_err(|never| match never {})
            .boxed_unsync()
    };
    let prepared = binding
        .prepare(
            Request::from_parts(parts, body),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
        )
        .await
        .map_err(|_| anyhow::anyhow!("final entity preparation refused"))?;
    let digest = prepared.digest();
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
    let ip = "203.0.113.9".parse()?;
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
            ensure!(
                client.validate_service_receipt(old).await.is_err(),
                "retired or unavailable issuer proof accepted"
            );
            ensure!(
                old.authentication().valid_at(now()),
                "cached receipt expired before Pumgye lifecycle query"
            );
            let result = pumgye
                .observe_authenticated_resource(&gate, "GET", ip, digest, old)
                .await;
            ensure!(
                result.is_err()
                    || result.is_ok_and(|result| result.is_none_or(|reply| !reply.allow)),
                "retired or unavailable proof accepted"
            );
        }
        if command == "outage" {
            println!("{}", serde_json::json!({"allowed":false}));
            std::io::stdout().flush()?;
            continue;
        }
        let outcome = binding
            .observe(&prepared, &headers, &client, &pumgye, ip)
            .await;
        let outcome = match outcome {
            Ok(observation) if observation.allowed() => {
                let checked = observation.into_receipt();
                let replacement = hangang::native_resource::Binding::new(
                    gate.clone(),
                    config.audience.clone(),
                    IssuerPin::new(config.issuer_ref.clone(), config.key_epoch, public)
                        .map_err(|_| anyhow::anyhow!("invalid replacement pin"))?,
                )?;
                ensure!(
                    replacement
                        .observe(&prepared, &headers, &client, &pumgye, ip)
                        .await
                        .is_err(),
                    "another binding accepted the prepared request"
                );
                let mut wrong_service = gate.clone();
                wrong_service.service_id = "billing".into();
                ensure!(
                    pumgye
                        .observe_authenticated_resource(&wrong_service, "GET", ip, digest, &checked)
                        .await
                        .is_err(),
                    "cross-service receipt accepted"
                );
                ensure!(
                    pumgye
                        .observe_authenticated_resource(&gate, "POST", ip, digest, &checked)
                        .await?
                        .is_none(),
                    "unassigned route method accepted"
                );
                let mut wrong_digest = digest;
                wrong_digest[0] ^= 1;
                ensure!(
                    pumgye
                        .observe_authenticated_resource(&gate, "GET", ip, wrong_digest, &checked)
                        .await
                        .is_err(),
                    "changed request binding accepted"
                );
                let revision = checked.revision();
                prior = Some(checked);
                Ok(revision)
            }
            _ => Err(anyhow::anyhow!("native authenticated decision refused")),
        };
        match (command.as_str(), outcome) {
            ("allow", Ok(revision)) => println!(
                "{}",
                serde_json::json!({"allowed":true,"revision":revision,"entity_frames":entity_frames})
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
