//! Owned-fixture qualification only; never point this at an operational policy DB.
use anyhow::{Result, ensure};
use hangang::pumgye::{AuthorityConfig, AuthorityRuntime, Gate};
use std::collections::BTreeMap;
#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("owned fixture configuration required"))?;
    let config: AuthorityConfig = serde_json::from_slice(&std::fs::read(path)?)?;
    let runtime = AuthorityRuntime::prepare(&config)?;
    let gate = Gate {
        service_id: "orders".into(),
        information_class: "public".into(),
        permissions: BTreeMap::from([("GET".into(), vec!["read".into()])]),
    };
    let ip = "192.0.2.8".parse()?;
    let query = pumgye_protocol::Query {
        request_id: 0,
        minimum_revision: 0,
        ip,
        aal: 1,
        guard: pumgye_core::GuardEvidence::EnforcedAllow,
        service_id: "orders",
        subject: "fixture",
        permission: "read",
        information_class: "public",
    };
    let wrong_role = hangang::pumgye_grpc_client::Client::new(
        &config,
        &std::env::var(&config.admin_token_env)?,
    )?;
    ensure!(
        wrong_role.decide(&query).await.is_err(),
        "admin role cannot authorize decisions"
    );
    let mut wrong_server = config.clone();
    wrong_server.tls.as_mut().unwrap().server_name = "wrong.example.test".into();
    let wrong_server = hangang::pumgye_grpc_client::Client::new(
        &wrong_server,
        &std::env::var(&config.decision_token_env)?,
    )?;
    ensure!(
        wrong_server.decide(&query).await.is_err(),
        "server name mismatch must fail closed"
    );
    let resources = hangang::pumgye_grpc_client::Client::new(
        &config,
        &std::env::var(&config.decision_token_env)?,
    )?;
    let mut resource_query = hangang::pumgye_grpc_client::ResourceQuery {
        service_id: "orders",
        minimum_revision: 0,
        ip,
        aal: 2,
        guard: pumgye_core::GuardEvidence::EnforcedAllow,
        resource: "db:orders",
        action: "select",
        subject: "fixture",
    };
    ensure!(
        wrong_role.decide_resource(&resource_query).await.is_err(),
        "resource admin role refusal"
    );
    ensure!(
        wrong_server.decide_resource(&resource_query).await.is_err(),
        "resource server name refusal"
    );
    ensure!(
        resources.decide_resource(&resource_query).await?.decision
            == pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::Allow),
        "native resource allow"
    );
    resource_query.service_id = "billing";
    ensure!(
        resources.decide_resource(&resource_query).await?.decision
            == pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::UnknownService),
        "cross-service resource refusal"
    );
    resource_query.service_id = "orders";
    resource_query.aal = 1;
    ensure!(
        resources.decide_resource(&resource_query).await?.decision
            == pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::AssuranceDenied),
        "owner assurance refusal"
    );
    resource_query.aal = 2;
    let allow = runtime
        .authorize(
            &gate,
            "GET",
            "fixture",
            ip,
            1,
            pumgye_core::GuardEvidence::EnforcedAllow,
        )
        .await?;
    ensure!(allow == Some(1), "owned allow fixture");
    ensure!(
        runtime
            .authorize(
                &gate,
                "GET",
                "guest",
                ip,
                1,
                pumgye_core::GuardEvidence::EnforcedAllow
            )
            .await?
            .is_none(),
        "guest denial"
    );
    let mut multiple = gate.clone();
    multiple
        .permissions
        .insert("GET".into(), vec!["read".into(), "missing".into()]);
    ensure!(
        runtime
            .authorize(
                &multiple,
                "GET",
                "fixture",
                ip,
                1,
                pumgye_core::GuardEvidence::EnforcedAllow
            )
            .await?
            .is_none(),
        "all permissions required"
    );
    let policy = serde_json::json!({"version":1,"information_classes":["public"],"services":{"orders":{"permissions":["read"],"require_guard":true,"roles":{"reader":{"permissions":["read"],"information_classes":["public"],"minimum_aal":1}},"users":{},"networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]}}});
    let (status, _) = runtime
        .management(
            reqwest::Method::PUT,
            "v1/policy",
            Some(serde_json::to_vec(
                &serde_json::json!({"revision":1,"policy":policy}),
            )?),
            Some(1),
            None,
        )
        .await?;
    ensure!(
        status == 200,
        "owned revocation publication status {status}"
    );
    ensure!(
        runtime
            .authorize(
                &gate,
                "GET",
                "fixture",
                ip,
                1,
                pumgye_core::GuardEvidence::EnforcedAllow
            )
            .await?
            .is_none(),
        "immediate revocation on reusable channel"
    );
    ensure!(runtime.revision() == 2, "revision advancement");
    let retired = resources.decide_resource(&resource_query).await?;
    ensure!(
        retired.revision == 2 && retired.decision == pumgye_core::ResourceDecision::UnknownResource,
        "catalog removal must apply on the same channel"
    );
    resources.require_revision(999);
    ensure!(
        resources.decide_resource(&resource_query).await.is_err(),
        "resource unavailable revision refusal"
    );

    runtime.require_revision(999);
    ensure!(
        runtime
            .authorize(
                &gate,
                "GET",
                "fixture",
                ip,
                1,
                pumgye_core::GuardEvidence::EnforcedAllow
            )
            .await
            .is_err(),
        "unavailable revision must fail closed"
    );
    println!(
        "PASS: Hangang gRPC service/resource clients, assurance and role denial, same-channel policy/catalog revocation and revision fencing"
    );
    Ok(())
}
