//! Native authority phase for an immutable final request. Observations are not
//! dispatch/projection permits; the gateway still owns final routing/effect fences.
pub use crate::native_human::Configuration as HumanBinding;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_permit: Option<crate::projection_permit::Configuration>,
    #[serde(default)]
    pub project_credentials: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed: Option<crate::native_observed::Configuration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub human_binding: Option<HumanBinding>,
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
        ensure!(
            self.human_binding.is_some()
                == self
                    .observed
                    .as_ref()
                    .is_some_and(|c| c.authentication_class
                        == crate::native_observed::AuthenticationClass::Human),
            "Human binding requires explicit Human observed class"
        );
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
        ensure!(
            self.permission_permit
                .as_ref()
                .is_none_or(|permit| permit.public_key != self.public_key),
            "authentication and permit purpose keys must be independent"
        );
        ensure!(
            !self.project_credentials || self.permission_permit.is_some(),
            "credential projection requires signed permission permits"
        );
        binding.project_credentials = self.project_credentials;
        if let Some(observed) = &self.observed {
            ensure!(
                self.project_credentials && self.permission_permit.is_some(),
                "observed mode requires authentication, observed permit and observed projection peers"
            );
            binding.observed = Some(crate::native_observed::Owner::compile(
                observed.clone(),
                self.issuer_ref.clone(),
                self.key_epoch,
                public,
                binding.gate.service_id.clone(),
                self.audience.clone(),
            )?);
        }
        binding.permit_pin = self
            .permission_permit
            .as_ref()
            .map(|configuration| {
                configuration
                    .compile()
                    .map_err(|_| anyhow::anyhow!("invalid native permit issuer pin"))
            })
            .transpose()?;
        binding.maximum_body_bytes = self.maximum_body_bytes;
        binding.body_timeout = std::time::Duration::from_millis(self.body_timeout_ms);
        Ok(binding)
    }
    pub(crate) fn compile_for_route(
        &self,
        gate: pumgye::ResourceGate,
        route: &crate::config::HttpRoute,
        revision: u64,
    ) -> Result<Binding> {
        let mut binding = self.compile(gate)?;
        if let Some(config) = &self.human_binding {
            let scopes = crate::native_human::Scopes::compile(
                config,
                route,
                revision,
                &binding.gate.service_id,
                &self.audience,
            )?;
            binding
                .observed
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("Human observed owner required"))?
                .set_human_scopes(scopes.clone())?;
            binding.scope = projection_entity::Scope::with_human(
                binding.gate.service_id.clone(),
                self.audience.clone(),
                scopes.clone(),
            )
            .map_err(|_| anyhow::anyhow!("invalid Human body scope"))?;
            binding.human = Some(scopes);
        }
        Ok(binding)
    }
}

pub(crate) struct OwnerScope<'a> {
    pub(crate) service: &'a str,
    pub(crate) audience: &'a str,
    pub(crate) resource: &'a str,
    pub(crate) action: &'a str,
}
/// Immutable route-owned binding, compiled before request processing.
pub struct Binding {
    scope: Arc<projection_entity::Scope>,
    pin: projection_receipt::IssuerPin,
    permit_pin: Option<crate::projection_permit::Pin>,
    project_credentials: bool,
    observed: Option<crate::native_observed::Owner>,
    human: Option<Arc<crate::native_human::Scopes>>,
    gate: pumgye::ResourceGate,
    maximum_body_bytes: usize,
    body_timeout: std::time::Duration,
}
pub struct Observation {
    credential: Option<crate::projected_credential::Credential>,
    permit: Option<crate::projection_permit::CheckedPermit>,
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
            && self.credential.as_ref().is_none_or(|credential| {
                credential.valid_at(now.as_millis().min(u64::MAX as u128) as u64)
            })
            && self
                .permit
                .as_ref()
                .is_none_or(|permit| permit.valid_at(now.as_millis().min(u64::MAX as u128) as u64))
            && self
                .receipt
                .authentication()
                .valid_at(now.as_millis().min(u64::MAX as u128) as u64)
            && authority.authenticated_observation_current(&self.reply)
    }
    pub(crate) fn install_credential(&self, headers: &mut hyper::HeaderMap) -> Result<()> {
        if let Some(credential) = &self.credential {
            let now = u64::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)?
                    .as_millis(),
            )?;
            let (name, value) = credential.header(now)?;
            headers.insert(name, value);
        }
        Ok(())
    }
    pub fn receipt(&self) -> &projection_receipt::CheckedServiceReceipt {
        &self.receipt
    }
    /// Authentication evidence only, not a transferable permission.
    pub fn into_receipt(self) -> projection_receipt::CheckedServiceReceipt {
        self.receipt
    }
}
pub enum DispatchObservation {
    Strict(Observation),
    Observed(crate::native_observed::Dispatch),
}
impl DispatchObservation {
    pub(crate) fn remaining_dispatch(&self) -> Option<Result<std::time::Duration>> {
        match self {
            Self::Strict(_) => None,
            Self::Observed(v) => Some(v.remaining()),
        }
    }
    pub fn allowed(&self) -> bool {
        match self {
            Self::Strict(v) => v.allowed(),
            Self::Observed(_) => true,
        }
    }
    pub fn local_fences_hold(&self, authority: &pumgye::AuthorityRuntime) -> bool {
        match self {
            Self::Strict(v) => v.local_fences_hold(authority),
            Self::Observed(v) => v.current(authority),
        }
    }
    pub(crate) fn projected_slot(&self) -> Option<&hyper::header::HeaderName> {
        match self {
            Self::Strict(_) => None,
            Self::Observed(v) => Some(v.projected_slot()),
        }
    }
    pub(crate) fn install_credential(&self, headers: &mut hyper::HeaderMap) -> Result<()> {
        match self {
            Self::Strict(v) => v.install_credential(headers),
            Self::Observed(v) => v.install(headers),
        }
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
            permit_pin: None,
            project_credentials: false,
            observed: None,
            human: None,
            gate,
            maximum_body_bytes: default_body_limit(),
            body_timeout: std::time::Duration::from_millis(default_body_timeout()),
        })
    }
    /// Native configuration selects this metadata; no response or caller header
    /// can choose the principal class or a different permission endpoint.
    pub(crate) fn observed_authentication(
        &self,
    ) -> Option<(crate::native_observed::AuthenticationClass, &str)> {
        self.observed
            .as_ref()
            .map(|o| (o.configured_class(), o.issuer_ref()))
    }
    pub(crate) fn human_mode(&self) -> bool {
        self.human.is_some()
    }
    pub(crate) fn strip_human_credentials(&self, headers: &mut hyper::HeaderMap) {
        if let Some(scopes) = &self.human {
            for name in scopes.reserved() {
                headers.remove(name);
            }
            headers.remove(hyper::header::COOKIE);
            headers.remove(hyper::header::AUTHORIZATION);
        }
    }
    pub(crate) fn observed_class(&self) -> Option<crate::native_observed::AuthenticationClass> {
        self.observed.as_ref().map(|owner| owner.configured_class())
    }
    pub(crate) fn observed_mode(&self) -> bool {
        self.observed.is_some()
    }
    pub(crate) fn prepare_transport(&self, transport: &hopae_native::Client) -> Result<()> {
        if let Some(owner) = &self.observed {
            owner.client(transport)?;
        }
        Ok(())
    }
    pub(crate) fn retire(&self) {
        if let Some(owner) = &self.observed {
            owner.retire();
        }
    }
    pub(crate) fn owner_scope(&self, method: &hyper::Method) -> Option<OwnerScope<'_>> {
        Some(OwnerScope {
            service: &self.gate.service_id,
            audience: self.scope.audience(),
            resource: &self.gate.resource,
            action: self.gate.actions.get(method.as_str())?,
        })
    }
    pub(crate) fn owns(&self, prepared: &projection_entity::Prepared) -> bool {
        prepared.belongs_to(&self.scope)
            && self
                .gate
                .actions
                .contains_key(prepared.request().method().as_str())
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
    pub(crate) async fn prepare_for_origin(
        &self,
        request: hyper::Request<crate::proxy::Body>,
        admission: Arc<tokio::sync::Semaphore>,
        origin: &hyper::Uri,
    ) -> Result<projection_entity::Prepared, projection_entity::Refused> {
        projection_entity::prepare_selected(
            request,
            self.scope.clone(),
            admission,
            self.maximum_body_bytes,
            self.body_timeout,
            origin,
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
        match self
            .observe_with_route(prepared, headers, hopae, pumgye, ip, None)
            .await?
        {
            DispatchObservation::Strict(observation) => Ok(observation),
            DispatchObservation::Observed(_) => {
                anyhow::bail!("observed dispatch requires native route ownership")
            }
        }
    }
    pub async fn observe_with_route(
        &self,
        prepared: &projection_entity::Prepared,
        headers: &hyper::HeaderMap,
        hopae: &hopae_native::Client,
        pumgye: &pumgye::AuthorityRuntime,
        ip: std::net::IpAddr,
        route: Option<&pumgye_grpc::v1::NativeRouteReference>,
    ) -> Result<DispatchObservation> {
        self.observe_after_preliminary(prepared, headers, hopae, pumgye, ip, route, None)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn observe_after_preliminary(
        &self,
        prepared: &projection_entity::Prepared,
        headers: &hyper::HeaderMap,
        hopae: &hopae_native::Client,
        pumgye: &pumgye::AuthorityRuntime,
        ip: std::net::IpAddr,
        route: Option<&pumgye_grpc::v1::NativeRouteReference>,
        preliminary: Option<(&str, u8)>,
    ) -> Result<DispatchObservation> {
        ensure!(
            prepared.belongs_to(&self.scope),
            "final request belongs to another route binding"
        );
        if let Some(owner) = &self.observed {
            let action = self
                .gate
                .actions
                .get(prepared.request().method().as_str())
                .ok_or_else(|| anyhow::anyhow!("native route method unassigned"))?;
            let route = route.ok_or_else(|| {
                anyhow::anyhow!("observed projection requires native route owner")
            })?;
            let dispatch = owner
                .dispatch(
                    prepared,
                    headers,
                    hopae,
                    pumgye,
                    self.permit_pin
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("observed permission pin missing"))?,
                    &self.gate.resource,
                    action,
                    ip,
                    route,
                    preliminary,
                )
                .await?;
            return Ok(DispatchObservation::Observed(dispatch));
        }
        let method = prepared.request().method().as_str();
        ensure!(
            self.gate.actions.contains_key(method),
            "native route method unassigned"
        );
        let receipt = hopae
            .issue_service_receipt(headers, &prepared.service_scope(), &self.pin)
            .await?;
        let (reply, permit) = if let Some(pin) = &self.permit_pin {
            let (reply, permit) = pumgye
                .issue_projection_permit(
                    &self.gate,
                    method,
                    ip,
                    prepared.digest(),
                    &receipt,
                    route,
                    pin,
                )
                .await?;
            (reply, Some(permit))
        } else {
            let reply = pumgye
                .observe_authenticated_resource_with_route(
                    &self.gate,
                    method,
                    ip,
                    prepared.digest(),
                    &receipt,
                    route,
                )
                .await?
                .ok_or_else(|| anyhow::anyhow!("native route method unassigned"))?;
            (reply, None)
        };
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
        let credential = if reply.allow && self.project_credentials {
            ensure!(
                route.is_some(),
                "credential projection requires native route ownership"
            );
            Some(
                hopae
                    .project_credential(
                        &receipt,
                        permit
                            .as_ref()
                            .ok_or_else(|| anyhow::anyhow!("signed permission missing"))?,
                    )
                    .await?,
            )
        } else {
            None
        };
        Ok(DispatchObservation::Strict(Observation {
            credential,
            receipt,
            reply,
            permit,
        }))
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
            permission_permit: None,
            project_credentials: false,
            observed: None,
            human_binding: None,
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
    #[test]
    #[cfg(target_os = "linux")]
    fn observed_configuration_requires_the_entire_chain_and_explicit_bounded_clocks() {
        let mut config = configuration();
        config.observed = Some(crate::native_observed::Configuration {
            authentication_class: crate::native_observed::AuthenticationClass::Service,
            identity_authority: "profiles".into(),
            minimum_profile_revision: 1,
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
            source_error_ppm: 100,
            receiver_error_ppm: 100,
            maximum_final_header_bytes: 32768,
        });
        assert!(config.compile(gate()).is_err());
        config.project_credentials = true;
        assert!(config.compile(gate()).is_err());
        config.permission_permit = Some(crate::projection_permit::Configuration {
            issuer_ref: "pum-owned".into(),
            key_epoch: 1,
            public_key: base64::engine::general_purpose::STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        });
        assert!(config.compile(gate()).is_ok());
        config.observed.as_mut().unwrap().source_error_ppm = 1_000_000;
        assert!(config.compile(gate()).is_err());
        config.observed.as_mut().unwrap().source_error_ppm = 100;
        config
            .observed
            .as_mut()
            .unwrap()
            .minimum_key_registry_revision = 0;
        assert!(config.compile(gate()).is_err());
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
    #[test]
    #[cfg(target_os = "linux")]
    fn workload_configuration_requires_complete_observed_chain_and_canonical_authority_limit() {
        let mut config = configuration();
        config.observed = Some(crate::native_observed::Configuration {
            authentication_class: crate::native_observed::AuthenticationClass::Workload,
            identity_authority: "w".repeat(40),
            minimum_profile_revision: 1,
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
            source_error_ppm: 100,
            receiver_error_ppm: 100,
            maximum_final_header_bytes: 32768,
        });
        assert!(config.compile(gate()).is_err());
        config.project_credentials = true;
        assert!(config.compile(gate()).is_err());
        config.permission_permit = Some(crate::projection_permit::Configuration {
            issuer_ref: "pum-owned".into(),
            key_epoch: 1,
            public_key: base64::engine::general_purpose::STANDARD.encode(
                ed25519_dalek::SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
        });
        assert!(config.compile(gate()).is_ok());
        config
            .observed
            .as_mut()
            .unwrap()
            .identity_authority
            .push('w');
        assert!(config.compile(gate()).is_err());
        config.observed.as_mut().unwrap().authentication_class =
            crate::native_observed::AuthenticationClass::Service;
        assert!(config.compile(gate()).is_ok());
        config.observed.as_mut().unwrap().authentication_class =
            crate::native_observed::AuthenticationClass::Human;
        assert!(
            config.compile(gate()).is_err(),
            "Human must declare its fixed binding"
        );
        config.human_binding = Some(HumanBinding {
            app_id: "native-app".into(),
            header_policy_revision: 13,
            header_names: vec!["x-tenant".into()],
        });
        assert!(config.compile(gate()).is_ok());
        let route: crate::config::HttpRoute = serde_json::from_value(serde_json::json!({
            "id":"owned-route", "host":"frontend.test", "backends":["https://one.test", "https://two.test"]
        })).unwrap();
        assert!(config.compile_for_route(gate(), &route, 11).is_ok());
        assert!(config.compile_for_route(gate(), &route, 0).is_err());
        config.human_binding.as_mut().unwrap().header_names = vec!["cookie".into()];
        assert!(config.compile_for_route(gate(), &route, 11).is_err());
        config.observed.as_mut().unwrap().authentication_class =
            crate::native_observed::AuthenticationClass::Service;
        assert!(
            config.compile(gate()).is_err(),
            "non-Human must not silently ignore Human binding"
        );
    }
}
