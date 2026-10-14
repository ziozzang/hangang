//! Native authority phase for an immutable final request. Observations are not
//! dispatch/projection permits; the gateway still owns final routing/effect fences.
use crate::{hopae_native, projection_entity, projection_receipt, pumgye};
use anyhow::{Result, ensure};
use std::sync::Arc;

/// Public configuration only; credentials and signing seeds stay with owners.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub audience: String,
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
    #[serde(default = "default_body_limit")]
    pub maximum_body_bytes: usize,
    #[serde(default = "default_body_timeout")]
    pub body_timeout_ms: u64,
}
fn default_body_limit() -> usize {
    1024 * 1024
}
fn default_body_timeout() -> u64 {
    1000
}
impl Configuration {
    pub fn compile(&self, gate: pumgye::ResourceGate) -> Result<Binding> {
        use base64::Engine;
        ensure!(
            (1..=16 * 1024 * 1024).contains(&self.maximum_body_bytes)
                && (1..=5000).contains(&self.body_timeout_ms),
            "invalid native entity budget"
        );
        let decoded = base64::engine::general_purpose::STANDARD.decode(&self.public_key)?;
        let public: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid native issuer public pin"))?;
        ensure!(
            base64::engine::general_purpose::STANDARD.encode(public) == self.public_key,
            "noncanonical native issuer public pin"
        );
        let pin =
            projection_receipt::IssuerPin::new(self.issuer_ref.clone(), self.key_epoch, public)
                .map_err(|_| anyhow::anyhow!("invalid native issuer public pin"))?;
        let mut binding = Binding::new(gate, self.audience.clone(), pin)?;
        binding.maximum_body_bytes = self.maximum_body_bytes;
        binding.body_timeout = std::time::Duration::from_millis(self.body_timeout_ms);
        Ok(binding)
    }
}

/// Immutable route-owned binding, compiled before request processing.
pub struct Binding {
    scope: Arc<projection_entity::Scope>,
    pin: projection_receipt::IssuerPin,
    gate: pumgye::ResourceGate,
    maximum_body_bytes: usize,
    body_timeout: std::time::Duration,
}
pub struct Observation {
    receipt: projection_receipt::CheckedServiceReceipt,
    reply: crate::pumgye_grpc_client::AuthenticatedReply,
}
impl Observation {
    pub fn allowed(&self) -> bool {
        self.reply.allow
    }
    /// Local observed floors/expiry only; no remote freshness or stream lease.
    pub fn local_fences_hold(&self, authority: &pumgye::AuthorityRuntime) -> bool {
        let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) else {
            return false;
        };
        self.reply.allow
            && self
                .receipt
                .authentication()
                .valid_at(now.as_millis().min(u64::MAX as u128) as u64)
            && authority.authenticated_observation_current(&self.reply)
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
        Ok(Self {
            scope,
            pin,
            gate,
            maximum_body_bytes: default_body_limit(),
            body_timeout: std::time::Duration::from_millis(default_body_timeout()),
        })
    }
    pub fn scope(&self) -> Arc<projection_entity::Scope> {
        self.scope.clone()
    }
    /// Use the gateway's shared admission pool, not a new semaphore per request.
    pub async fn prepare(
        &self,
        request: hyper::Request<crate::proxy::Body>,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> Result<projection_entity::Prepared, projection_entity::Refused> {
        projection_entity::prepare_scoped(
            request,
            self.scope.clone(),
            admission,
            self.maximum_body_bytes,
            self.body_timeout,
        )
        .await
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    fn configuration() -> Configuration {
        Configuration {
            audience: "orders-api".into(),
            issuer_ref: "owned".into(),
            key_epoch: 1,
            public_key: base64::engine::general_purpose::STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            maximum_body_bytes: default_body_limit(),
            body_timeout_ms: default_body_timeout(),
        }
    }
    fn gate() -> pumgye::ResourceGate {
        pumgye::ResourceGate {
            service_id: "orders".into(),
            resource: "db:orders".into(),
            actions: std::collections::BTreeMap::from([("GET".into(), "select".into())]),
        }
    }
    #[test]
    fn public_configuration_rejects_invalid_pins_budgets_and_private_fields() {
        let valid = configuration();
        assert!(valid.compile(gate()).is_ok());
        let mut invalid = valid.clone();
        invalid.maximum_body_bytes = 0;
        assert!(invalid.compile(gate()).is_err());
        invalid = valid.clone();
        invalid.maximum_body_bytes = 16 * 1024 * 1024 + 1;
        assert!(invalid.compile(gate()).is_err());
        for timeout in [0, 5001, u64::MAX] {
            invalid = valid.clone();
            invalid.body_timeout_ms = timeout;
            assert!(invalid.compile(gate()).is_err());
        }
        for epoch in [0, 9_007_199_254_740_992, u64::MAX] {
            invalid = valid.clone();
            invalid.key_epoch = epoch;
            assert!(invalid.compile(gate()).is_err());
        }
        for key in [
            "invalid".into(),
            base64::engine::general_purpose::STANDARD.encode([0; 32]),
            base64::engine::general_purpose::STANDARD.encode([1; 31]),
        ] {
            invalid = valid.clone();
            invalid.public_key = key;
            assert!(invalid.compile(gate()).is_err());
        }
        let mut json = serde_json::to_value(valid).unwrap();
        json["signing_seed"] = "must-not-be-accepted".into();
        assert!(serde_json::from_value::<Configuration>(json).is_err());
    }
    #[tokio::test]
    async fn compiled_budget_limits_actual_preparation() {
        use http_body_util::{BodyExt, Full};
        let mut config = configuration();
        config.maximum_body_bytes = 1;
        let binding = config.compile(gate()).unwrap();
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let request = hyper::Request::builder()
            .uri("https://orders.example.test/orders")
            .body(
                Full::new(bytes::Bytes::from_static(b"xx"))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        assert!(matches!(
            binding.prepare(request, admission.clone()).await,
            Err(projection_entity::Refused::TooLarge)
        ));
        assert_eq!(admission.available_permits(), 1);
    }
}
