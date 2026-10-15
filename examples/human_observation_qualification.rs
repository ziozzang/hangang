//! Owned seed-only observer. Actual SDK source proof; never a Root dispatch grant.
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use hopae_grpc::{human_observed_client as sdk, request_binding_v2 as v2};
use serde::Deserialize;
use std::{io::Read, path::Path, sync::Arc, time::Duration};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    service: String,
    audience: String,
    app_id: String,
    route_id: String,
    route_revision: u64,
    destination_sha256: [u8; 32],
    header_policy_revision: u64,
    header_names: Vec<String>,
    reserved_names: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundHeader {
    name: String,
    value: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    endpoint: String,
    server_name: String,
    ca: String,
    certificate: String,
    key: String,
    caller_file: String,
    cookie_file: String,
    public_key: String,
    issuer_ref: String,
    key_epoch: u64,
    identity_authority: String,
    minimum_source_revision: u64,
    minimum_application_generation: u64,
    minimum_key_registry_revision: u64,
    source_error_ppm: u32,
    receiver_error_ppm: u32,
    scope: Scope,
    frontend_url: String,
    client_ip: std::net::IpAddr,
    method: String,
    target: String,
    body: String,
    bound_headers: Vec<BoundHeader>,
}
fn read(path: impl AsRef<Path>, maximum: usize) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    ensure!(file.metadata()?.is_file(), "regular fixture input required");
    let mut bytes = Vec::new();
    file.take(u64::try_from(maximum)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "fixture input bound"
    );
    Ok(bytes)
}
trait Redacted<T> {
    fn redacted(self) -> Result<T>;
}
impl<T, E> Redacted<T> for std::result::Result<T, E> {
    fn redacted(self) -> Result<T> {
        self.map_err(|_| anyhow::anyhow!("owned source operation refused"))
    }
}
async fn run() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("private configuration required"))?;
    let config: Configuration = serde_json::from_slice(&read(path, 17 * 1024 * 1024)?)?;
    let endpoint: hyper::Uri = config.endpoint.parse()?;
    ensure!(
        endpoint.scheme_str() == Some("https")
            && endpoint
                .host()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "localhost"))
            && endpoint.port_u16().is_some_and(|port| port > 0),
        "owned HTTPS endpoint required"
    );
    let frontend: hyper::Uri = config.frontend_url.parse()?;
    ensure!(
        frontend.scheme_str() == Some("https")
            && frontend.host() == Some("app.example.test")
            && frontend.port_u16().is_none()
            && frontend
                .authority()
                .is_some_and(|value| !value.as_str().contains('@')),
        "fixed owned frontend required"
    );
    ensure!(
        frontend.path_and_query().map(|value| value.as_str()) == Some(config.target.as_str()),
        "seed frontend and actual target must match"
    );
    ensure!(
        config.body.len() <= 16 * 1024 * 1024 && config.bound_headers.len() <= 16,
        "actual request bound"
    );
    let ca = read(&config.ca, 128 * 1024)?;
    let certificate = read(&config.certificate, 128 * 1024)?;
    let key = Zeroizing::new(read(&config.key, 128 * 1024)?);
    let caller = Zeroizing::new(String::from_utf8(read(&config.caller_file, 256)?)?);
    let cookie = Zeroizing::new(String::from_utf8(read(&config.cookie_file, 4096)?)?);
    ensure!(
        cookie
            .bytes()
            .all(|byte| (33..=126).contains(&byte) && !b"\";,\\".contains(&byte)),
        "native cookie value required"
    );
    let public: [u8; 32] = STANDARD
        .decode(&config.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public pin length"))?;
    ensure!(
        STANDARD.encode(public) == config.public_key,
        "canonical public pin required"
    );
    let s = config.scope;
    let scope = sdk::HumanScope {
        service: s.service,
        audience: s.audience,
        app_id: s.app_id,
        route_id: s.route_id,
        route_revision: s.route_revision,
        destination_sha256: s.destination_sha256,
        header_policy_revision: s.header_policy_revision,
        header_names: s.header_names,
        reserved_names: s.reserved_names,
    };
    let client = sdk::Client::new_human(
        sdk::EndpointConfig {
            address: &config.endpoint,
            server_name: &config.server_name,
            ca: &ca,
            certificate: &certificate,
            private_key: &key,
            caller_key: &caller,
        },
        sdk::HumanTrustPolicy {
            issuer_ref: config.issuer_ref,
            key_epoch: config.key_epoch,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&public).redacted()?,
            identity_authority: config.identity_authority,
            scopes: vec![scope.clone()],
            minimum_source_revision: config.minimum_source_revision,
            minimum_application_generation: config.minimum_application_generation,
            minimum_key_registry_revision: config.minimum_key_registry_revision,
        },
        Arc::new(hangang_runtime::time::ReceiverClock::new(rand::random()).redacted()?),
        hopae_grpc::receipt_time::ClockRates::new(
            config.source_error_ppm,
            config.receiver_error_ppm,
        )
        .redacted()?,
        sdk::Limits {
            concurrent: 1,
            timeout: Duration::from_secs(1),
        },
    )
    .redacted()?;
    let headers = [
        ("x-hopae-contract", "1".into()),
        ("x-original-url", config.frontend_url.clone()),
        ("x-forwarded-proto", "https".into()),
        ("x-forwarded-host", "app.example.test".into()),
        ("x-forwarded-for", config.client_ip.to_string()),
        ("x-original-method", config.method.clone()),
        ("x-hangang-canonical-path", frontend.path().into()),
        ("x-hangang-route-id", scope.route_id.clone()),
        ("cookie", format!("__Host-hopae={}", &*cookie)),
    ]
    .into_iter()
    .map(|(name, value): (&str, String)| hopae_grpc::v1::Header {
        name: name.into(),
        value: value.into_bytes(),
    })
    .collect();
    let bound = config
        .bound_headers
        .iter()
        .map(|header| v2::BoundHeader {
            name: &header.name,
            value: header.value.as_ref().map(|value| value.as_bytes()),
        })
        .collect::<Vec<_>>();
    let prepared = client
        .prepare(
            &scope,
            &v2::Request {
                service: &scope.service,
                audience: &scope.audience,
                route_id: &scope.route_id,
                route_revision: scope.route_revision,
                destination_sha256: &scope.destination_sha256,
                method: &config.method,
                target: &config.target,
                body: config.body.as_bytes(),
                bound_headers: &bound,
            },
            headers,
        )
        .redacted()?;
    let issued = client.issue(prepared).await.redacted()?;
    client.check(&issued, issued.request()).redacted()?;
    let digest: [u8; 32] = issued
        .context()
        .request_sha256
        .as_slice()
        .try_into()
        .redacted()?;
    let current = client
        .observe(
            client
                .prepare_observation(issued.context().clone(), issued.receipt(), digest)
                .redacted()?,
        )
        .await
        .redacted()?;
    client.check(&current, current.request()).redacted()?;
    client.check(&issued, issued.request()).redacted()?;
    ensure!(
        current.context() == issued.context() && current.scope() == &scope,
        "independent source mismatch"
    );
    let identity = current
        .context()
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("identity missing"))
        .redacted()?;
    ensure!(
        identity.kind == 1 && matches!(identity.aal, 1 | 2),
        "actual Human assurance required"
    );
    let fingerprint = current.scope().fingerprint().redacted()?;
    let hex = fingerprint
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect::<String>();
    println!(
        "{}",
        serde_json::json!({"contract":"human-seed-observer-v1","seed_only":true,
        "issued":true,"independently_observed":true,"subject":identity.subject_ref,"aal":identity.aal,"scope_sha256":hex})
    );
    Ok(())
}
#[tokio::main(worker_threads = 2)]
async fn main() {
    if run().await.is_err() {
        eprintln!("{{\"ok\":false,\"stage\":\"human_seed_observer\"}}");
        std::process::exit(1);
    }
}
