//! Owned Sumunjang fixture only; changes a disposable block record.
use anyhow::{Result, ensure};
use hangang::guard::{Config, FailureMode, GuardClient, NativeTls, TransportMode};
use pumgye_core::GuardEvidence;
use tokio_util::sync::CancellationToken;
#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    ensure!(
        args.len() == 5,
        "expected decision endpoint, API origin, CA, client cert and key"
    );
    let configuration = |name: &str, token: &str| Config {
        decision_tcp: Some(args[0].parse().unwrap()),
        decision_grpc: true,
        decision_tls: Some(NativeTls {
            server_name: name.into(),
            ca: args[2].clone().into(),
            certificate: args[3].clone().into(),
            key: args[4].clone().into(),
        }),
        transport_mode: TransportMode::Query,
        failure_mode: FailureMode::Deny,
        timeout_ms: 1000,
        cache_ms: 0,
        url: args[1].clone(),
        source_id: "owned-grpc-fixture".into(),
        token_env: token.into(),
        honeypot_paths: vec![],
        scanner_paths: vec![],
    };
    let cancel = CancellationToken::new();
    let guard = GuardClient::start(
        configuration("sumunjang.example.test", "HANGANG_GUARD_COLLECTOR_TOKEN"),
        cancel.clone(),
    )?;
    let denied = "192.0.2.1".parse()?;
    let allowed = "192.0.2.2".parse()?;
    ensure!(
        guard.authorization_evidence(denied).await == GuardEvidence::Deny,
        "enforced deny evidence"
    );
    ensure!(
        guard.rejection(denied, "/ordinary").await == Some(403),
        "request denial"
    );
    ensure!(
        guard.authorization_evidence(allowed).await == GuardEvidence::EnforcedAllow,
        "enforced allow evidence"
    );
    let wrong = GuardClient::start(
        configuration("sumunjang.example.test", "HANGANG_GUARD_ADMIN_TOKEN"),
        cancel.clone(),
    )?;
    ensure!(
        wrong.authorization_evidence(allowed).await == GuardEvidence::Unavailable,
        "admin credential rejected"
    );
    ensure!(
        wrong.rejection(allowed, "/ordinary").await == Some(503),
        "no HTTP fallback"
    );
    let wrong_name = GuardClient::start(
        configuration("wrong.example.test", "HANGANG_GUARD_COLLECTOR_TOKEN"),
        cancel.clone(),
    )?;
    ensure!(
        wrong_name.authorization_evidence(allowed).await == GuardEvidence::Unavailable,
        "server name mismatch"
    );
    let response = reqwest::Client::new()
        .delete(format!("{}/v1/blocks", args[1]))
        .bearer_auth(std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?)
        .json(&serde_json::json!({"network":"192.0.2.1/32"}))
        .send()
        .await?;
    ensure!(response.status().is_success(), "owned block removal");
    ensure!(
        guard.authorization_evidence(denied).await == GuardEvidence::EnforcedAllow,
        "same-channel block removal"
    );
    ensure!(
        guard.rejection(denied, "/ordinary").await.is_none(),
        "request admission after removal"
    );
    let response=reqwest::Client::new().post(format!("{}/v1/blocks",args[1])).bearer_auth(std::env::var("HANGANG_GUARD_ADMIN_TOKEN")?).json(&serde_json::json!({"network":"192.0.2.1/32","expires_at":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs()+600,"reason":"owned gRPC qualification"})).send().await?;
    ensure!(response.status().is_success(), "owned block restore");
    ensure!(
        guard.authorization_evidence(denied).await == GuardEvidence::Deny,
        "same-channel block restore"
    );
    cancel.cancel();
    ensure!(
        guard.authorization_evidence(allowed).await == GuardEvidence::Unavailable,
        "cancelled transport"
    );
    println!(
        "PASS: Hangang/Sumunjang gRPC enforcement, mTLS identity, role refusal, no fallback, same-channel block updates and cancellation"
    );
    Ok(())
}
