//! Native authority phase for an immutable final request. Observations are not
//! dispatch/projection permits; the gateway still owns final routing/effect fences.
use crate::{hopae_native, projection_entity, projection_receipt, pumgye};
use anyhow::{Result, ensure};
use std::sync::Arc;

/// Immutable route-owned binding, compiled before request processing.
pub struct Binding {
    scope: Arc<projection_entity::Scope>,
    pin: projection_receipt::IssuerPin,
    gate: pumgye::ResourceGate,
}
pub struct Observation {
    receipt: projection_receipt::CheckedServiceReceipt,
    reply: crate::pumgye_grpc_client::AuthenticatedReply,
}
impl Observation {
    pub fn allowed(&self) -> bool {
        self.reply.allow
    }
    pub fn receipt(&self) -> &projection_receipt::CheckedServiceReceipt {
        &self.receipt
    }
    /// Authentication evidence only, not a transferable permission.
    pub fn into_receipt(self) -> projection_receipt::CheckedServiceReceipt {
        self.receipt
    }
}
impl Binding {
    pub fn new(
        gate: pumgye::ResourceGate,
        audience: String,
        pin: projection_receipt::IssuerPin,
    ) -> Result<Self> {
        gate.validate_remote()?;
        let scope = projection_entity::Scope::new(gate.service_id.clone(), audience)
            .map_err(|_| anyhow::anyhow!("invalid native route scope"))?;
        Ok(Self { scope, pin, gate })
    }
    pub fn scope(&self) -> Arc<projection_entity::Scope> {
        self.scope.clone()
    }
    pub async fn observe(
        &self,
        prepared: &projection_entity::Prepared,
        headers: &hyper::HeaderMap,
        hopae: &hopae_native::Client,
        pumgye: &pumgye::AuthorityRuntime,
        ip: std::net::IpAddr,
    ) -> Result<Observation> {
        ensure!(
            prepared.belongs_to(&self.scope),
            "final request belongs to another route binding"
        );
        let method = prepared.request().method().as_str();
        ensure!(
            self.gate.actions.contains_key(method),
            "native route method unassigned"
        );
        let receipt = hopae
            .issue_service_receipt(headers, &prepared.service_scope(), &self.pin)
            .await?;
        let reply = pumgye
            .observe_authenticated_resource(&self.gate, method, ip, prepared.digest(), &receipt)
            .await?
            .ok_or_else(|| anyhow::anyhow!("native route method unassigned"))?;
        if reply.allow {
            hopae.validate_service_receipt(&receipt).await?;
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            ensure!(
                receipt.authentication().valid_at(now)
                    && pumgye.authenticated_observation_current(&reply),
                "native authority observation superseded or expired"
            );
        }
        Ok(Observation { receipt, reply })
    }
}
