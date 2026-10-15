//! Separate native observed chain. Each source contributes only a receiver-local
//! deadline; no source absolute expiry is compared with another clock domain.
use anyhow::{Result, ensure};
use hopae_grpc::{observed_client as sdk, receipt_time};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub identity_authority: String,
    pub minimum_profile_revision: u64,
    pub minimum_application_generation: u64,
    pub minimum_key_registry_revision: u64,
    pub source_error_ppm: u32,
    pub receiver_error_ppm: u32,
    pub maximum_final_header_bytes: usize,
}

/// Route/configuration-owned client, shared across dynamic subjects and source
/// process domains. Retired before publishing a successor route configuration.
pub(crate) struct Owner {
    configuration: Configuration,
    pub(crate) clock: Arc<hangang_runtime::time::ReceiverClock>,
    issuer: String,
    epoch: u64,
    public: [u8; 32],
    scope: sdk::ServiceScope,
    client: OnceLock<(Arc<()>, Arc<sdk::Client>)>,
    active: AtomicBool,
}
impl Owner {
    pub(crate) fn compile(
        configuration: Configuration,
        issuer: String,
        epoch: u64,
        public: [u8; 32],
        service: String,
        audience: String,
    ) -> Result<Self> {
        ensure!(
            !configuration.identity_authority.is_empty()
                && configuration.identity_authority.len() <= 64
                && configuration
                    .identity_authority
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b)),
            "invalid observed identity authority"
        );
        ensure!(
            [
                configuration.minimum_profile_revision,
                configuration.minimum_application_generation,
                configuration.minimum_key_registry_revision
            ]
            .iter()
            .all(|v| (1..=9_007_199_254_740_991).contains(v)),
            "invalid observed revision floor"
        );
        ensure!(
            (4096..=1_048_576).contains(&configuration.maximum_final_header_bytes),
            "invalid observed final header budget"
        );
        receipt_time::ClockRates::new(
            configuration.source_error_ppm,
            configuration.receiver_error_ppm,
        )
        .map_err(|_| anyhow::anyhow!("invalid observed clock rates"))?;
        Ok(Self {
            clock: fresh_clock()?,
            configuration,
            issuer,
            epoch,
            public,
            scope: sdk::ServiceScope { service, audience },
            client: OnceLock::new(),
            active: AtomicBool::new(true),
        })
    }
    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
        if let Some((_, client)) = self.client.get() {
            client.retire();
        }
    }
    pub(crate) fn client(
        &self,
        transport: &crate::hopae_native::Client,
    ) -> Result<Arc<sdk::Client>> {
        ensure!(
            self.active.load(Ordering::Acquire),
            "observed route owner retired"
        );
        if let Some((owner, client)) = self.client.get() {
            ensure!(
                Arc::ptr_eq(owner, &transport.observed_owner),
                "observed transport owner mismatch"
            );
            return Ok(client.clone());
        }
        let policy = sdk::ServiceTrustPolicy {
            issuer_ref: self.issuer.clone(),
            key_epoch: self.epoch,
            verifying_key: ed25519_dalek::VerifyingKey::from_bytes(&self.public)?,
            identity_authority: self.configuration.identity_authority.clone(),
            scopes: vec![self.scope.clone()],
            minimum_profile_revision: self.configuration.minimum_profile_revision,
            minimum_application_generation: self.configuration.minimum_application_generation,
            minimum_key_registry_revision: self.configuration.minimum_key_registry_revision,
        };
        let rates = receipt_time::ClockRates::new(
            self.configuration.source_error_ppm,
            self.configuration.receiver_error_ppm,
        )
        .map_err(|_| anyhow::anyhow!("invalid observed clock rates"))?;
        let client = Arc::new(transport.observed_client(policy, self.clock.clone(), rates)?);
        // A racing first request may construct an unused client, but only the
        // published persistent client may issue or observe any proof.
        let _ = self.client.set((transport.observed_owner.clone(), client));
        let (owner, client) = self.client.get().unwrap();
        ensure!(
            Arc::ptr_eq(owner, &transport.observed_owner),
            "observed transport owner mismatch"
        );
        let client = client.clone();
        if !self.active.load(Ordering::Acquire) {
            client.retire();
            anyhow::bail!("observed route owner retired");
        }
        Ok(client)
    }
    pub(crate) async fn issue(
        &self,
        prepared: &crate::projection_entity::Prepared,
        headers: &hyper::HeaderMap,
        transport: &crate::hopae_native::Client,
    ) -> Result<Authentication> {
        let client = self.client(transport)?;
        let headers = headers
            .iter()
            .filter(|(n, _)| n.as_str() != "x-hopae-gateway-key")
            .map(|(n, v)| hopae_grpc::v1::Header {
                name: n.to_string(),
                value: v.as_bytes().to_vec(),
            })
            .collect();
        let request = client
            .prepare_issue_digest(self.scope.clone(), prepared.digest(), headers)
            .map_err(|_| anyhow::anyhow!("observed request preparation refused"))?;
        let evidence = client
            .issue(request)
            .await
            .map_err(|_| anyhow::anyhow!("observed authentication refused"))?;
        ensure!(
            self.active.load(Ordering::Acquire),
            "observed route owner retired"
        );
        Ok(Authentication { client, evidence })
    }
}
pub(crate) struct Authentication {
    client: Arc<sdk::Client>,
    evidence: sdk::Observation,
}
impl Authentication {
    pub(crate) fn remaining(&self) -> Result<std::time::Duration> {
        self.client
            .check(&self.evidence, self.evidence.request())
            .map_err(|_| anyhow::anyhow!("observed authentication expired or retired"))
    }
    pub(crate) fn context(&self) -> &hopae_grpc::v1::AuthenticationReceiptContext {
        self.evidence.context()
    }
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        self.evidence.evidence().sha256()
    }
    pub(crate) fn receipt(&self) -> &[u8] {
        self.evidence.receipt()
    }
    pub(crate) async fn refresh(self) -> Result<Self> {
        let evidence = self
            .client
            .refresh(self.evidence)
            .await
            .map_err(|_| anyhow::anyhow!("observed authentication refresh refused"))?;
        Ok(Self {
            client: self.client,
            evidence,
        })
    }
}

fn fresh_clock() -> Result<Arc<hangang_runtime::time::ReceiverClock>> {
    use std::io::Read;
    let mut generation = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut generation)?;
    Ok(Arc::new(
        hangang_runtime::time::ReceiverClock::new(generation)
            .map_err(|_| anyhow::anyhow!("receiver clock unavailable"))?,
    ))
}

/// Kept private to the authenticated native RPC path. Public numeric reports
/// cannot mint a permission observation through this module.
pub(crate) struct Permit {
    pub(crate) owner: Arc<()>,
    pub(crate) original: pumgye_grpc::v1::AuthenticatedResourceRequest,
    pub(crate) wire: pumgye_grpc::v1::ProjectionPermitReply,
    deadline: hangang_runtime::time::LocalDeadline,
    clock: Arc<hangang_runtime::time::ReceiverClock>,
}
impl Permit {
    pub(crate) fn remaining(&self) -> Result<std::time::Duration> {
        self.deadline
            .remaining(&self.clock)
            .map_err(|_| anyhow::anyhow!("observed permission expired or retired"))
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_owner_reply(
        original: pumgye_grpc::v1::AuthenticatedResourceRequest,
        reply: pumgye_grpc::v1::ObservedProjectionPermitReply,
        pin: &crate::projection_permit::Pin,
        authentication: &Authentication,
        clock: Arc<hangang_runtime::time::ReceiverClock>,
        sample: hangang_runtime::time::ExchangeSample,
        rates: &receipt_time::ClockRates,
        network_floor: u64,
        owner: Arc<()>,
    ) -> Result<Self> {
        let wire = reply
            .permit
            .ok_or_else(|| anyhow::anyhow!("observed permit missing"))?;
        let report = reply
            .observation
            .ok_or_else(|| anyhow::anyhow!("observed permit report missing"))?;
        let proof = pin
            .verify_observed_signature(
                original.request_id,
                &original.resource,
                &original.action,
                original.minimum_revision,
                network_floor,
                authentication,
                wire.clone(),
            )
            .map_err(|_| anyhow::anyhow!("observed permit signature or binding refused"))?;
        let binding = wire
            .binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("observed permit binding missing"))?;
        ensure!(
            report.request_id == original.request_id
                && report.cache_ttl_ms == 0
                && report.clock_domain == binding.authority_epoch
                && valid_domain(&report.clock_domain, "pobs1:", true)
                && report.policy_revision == binding.policy_revision
                && report.network_revision == binding.network_revision
                && report.route_revision == binding.route_revision
                && report.plan_revision == binding.plan_revision
                && u64::from(report.proof_remaining_ms)
                    == proof
                        .claims()
                        .expires_ms
                        .saturating_sub(report.owner_now_ms)
                && report.remaining_ms <= report.proof_remaining_ms,
            "observed permit owner facts refused"
        );
        let bounds = receipt_time::Bounds::from_signature_with_rates(
            &proof,
            &receipt_time::Report {
                owner_now_ms: report.owner_now_ms,
                remaining_ms: report.remaining_ms,
                receipt_sha256: report.receipt_sha256.as_slice().try_into()?,
            },
            &receipt_time::Exchange {
                before_ms: sample.before_ticks(),
                after_ms: sample.after_ticks(),
                elapsed_ms: sample.elapsed_ms(),
            },
            rates,
        )
        .map_err(|_| anyhow::anyhow!("observed permit budget refused"))?;
        let now = clock
            .sample_ticks()
            .map_err(|_| anyhow::anyhow!("receiver clock unavailable"))?;
        let auth_remaining = authentication.remaining()?;
        let auth_until = now
            .checked_add(u64::try_from(auth_remaining.as_millis())?)
            .ok_or_else(|| anyhow::anyhow!("observed budget overflow"))?;
        let (deadline, _) = sample
            .bind_bounds(
                bounds.admit_until_ms().min(auth_until),
                bounds.retain_until_ms(),
            )
            .map_err(|_| anyhow::anyhow!("observed permission budget elapsed"))?;
        Ok(Self {
            original,
            wire,
            deadline,
            clock,
            owner,
        })
    }
}
fn valid_domain(domain: &str, prefix: &str, authority: bool) -> bool {
    let Some(value) = domain.strip_prefix(prefix) else {
        return false;
    };
    let (nonce, base) = if authority {
        let Some((nonce, base)) = value.split_once(':') else {
            return false;
        };
        (nonce, Some(base))
    } else {
        (value, None)
    };
    nonce.len() == 32
        && nonce.bytes().any(|b| b != b'0')
        && nonce
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && base.is_none_or(|base| {
            !base.is_empty()
                && base.len() <= 64
                && base
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        })
}

/// Constructed only after three authenticated native exchanges. Kept with the
/// immutable prepared request until the proxy's final owner/route checks.
pub struct Dispatch {
    authentication: Authentication,
    permit: Permit,
    credential: Output,
    authority: crate::pumgye_grpc_client::AuthenticatedReply,
    maximum_final_header_bytes: usize,
}
struct Output {
    name: hyper::header::HeaderName,
    value: zeroize::Zeroizing<Vec<u8>>,
    deadline: hangang_runtime::time::LocalDeadline,
    clock: Arc<hangang_runtime::time::ReceiverClock>,
}
impl Dispatch {
    pub(crate) fn remaining(&self) -> Result<std::time::Duration> {
        Ok(self
            .authentication
            .remaining()?
            .min(self.permit.remaining()?)
            .min(
                self.credential
                    .deadline
                    .remaining(&self.credential.clock)
                    .map_err(|_| anyhow::anyhow!("observed output expired"))?,
            ))
    }
    pub(crate) fn current(&self, authority: &crate::pumgye::AuthorityRuntime) -> bool {
        self.authentication.remaining().is_ok()
            && self.permit.remaining().is_ok()
            && self
                .credential
                .deadline
                .remaining(&self.credential.clock)
                .is_ok()
            && authority.authenticated_observation_current(&self.authority)
            && authority.observed_permit_current(&self.permit)
    }
    pub(crate) fn install(&self, headers: &mut hyper::HeaderMap) -> Result<()> {
        self.authentication.remaining()?;
        self.permit.remaining()?;
        self.credential
            .deadline
            .remaining(&self.credential.clock)
            .map_err(|_| anyhow::anyhow!("observed credential expired"))?;
        let mut value = hyper::header::HeaderValue::from_bytes(&self.credential.value)?;
        value.set_sensitive(true);
        let total = headers
            .iter()
            .filter(|(name, _)| **name != self.credential.name)
            .try_fold(0usize, |sum, (name, value)| {
                sum.checked_add(name.as_str().len())?
                    .checked_add(value.as_bytes().len())?
                    .checked_add(4)
            })
            .ok_or_else(|| anyhow::anyhow!("final header budget overflow"))?;
        ensure!(
            total
                .checked_add(self.credential.name.as_str().len())
                .and_then(|v| v.checked_add(value.as_bytes().len()))
                .and_then(|v| v.checked_add(4))
                .is_some_and(|v| v <= self.maximum_final_header_bytes),
            "final projected headers exceed budget"
        );
        headers.insert(self.credential.name.clone(), value);
        Ok(())
    }
}
impl Owner {
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn dispatch(
        &self,
        prepared: &crate::projection_entity::Prepared,
        headers: &hyper::HeaderMap,
        hopae: &crate::hopae_native::Client,
        pumgye: &crate::pumgye::AuthorityRuntime,
        pin: &crate::projection_permit::Pin,
        resource: &str,
        action: &str,
        ip: std::net::IpAddr,
        route: &pumgye_grpc::v1::NativeRouteReference,
    ) -> Result<Dispatch> {
        let authentication = self.issue(prepared, headers, hopae).await?;
        let rates = receipt_time::ClockRates::new(
            self.configuration.source_error_ppm,
            self.configuration.receiver_error_ppm,
        )
        .map_err(|_| anyhow::anyhow!("invalid observed clock rates"))?;
        let permit = pumgye
            .issue_observed_permit(
                &crate::pumgye_grpc_client::AuthenticatedQuery {
                    route: Some(route),
                    resource,
                    action,
                    ip,
                    minimum_revision: 1,
                    request_sha256: prepared.digest(),
                },
                &authentication,
                pin,
                self.clock.clone(),
                &rates,
            )
            .await?;
        let authentication = authentication.refresh().await?;
        let query = pumgye_grpc::v1::PermitValidationRequest {
            request_id: permit.original.request_id,
            request: Some(permit.original.clone()),
            permit: Some(permit.wire.clone()),
        };
        let timeout = authentication.remaining()?.min(permit.remaining()?);
        let before = self
            .clock
            .begin_exchange()
            .map_err(|_| anyhow::anyhow!("receiver clock unavailable"))?;
        let (reply, chain_sha256) = hopae.project_observed(query, timeout).await?;
        let sample = self
            .clock
            .finish_exchange(before)
            .map_err(|_| anyhow::anyhow!("receiver clock unavailable"))?;
        let credential = self.check_output(
            reply,
            prepared.digest(),
            chain_sha256,
            &authentication,
            &permit,
            sample,
            &rates,
        )?;
        let binding = permit.wire.binding.as_ref().unwrap();
        let authority = crate::pumgye_grpc_client::AuthenticatedReply {
            allow: true,
            revision: binding.policy_revision,
            network_revision: binding.network_revision,
        };
        let dispatch = Dispatch {
            authentication,
            permit,
            credential,
            authority,
            maximum_final_header_bytes: self.configuration.maximum_final_header_bytes,
        };
        ensure!(
            self.active.load(Ordering::Acquire) && dispatch.current(pumgye),
            "observed chain superseded before output"
        );
        Ok(dispatch)
    }
    #[allow(clippy::too_many_arguments)]
    fn check_output(
        &self,
        mut reply: hopae_grpc::v1::ObservedProjectionReply,
        digest: [u8; 32],
        chain_digest: [u8; 32],
        authentication: &Authentication,
        permit: &Permit,
        sample: hangang_runtime::time::ExchangeSample,
        rates: &receipt_time::ClockRates,
    ) -> Result<Output> {
        let value = zeroize::Zeroizing::new(std::mem::take(&mut reply.header_value));
        let epoch = hopae_grpc::service_epoch::decode_clock(
            &authentication.context().identity_authority_epoch,
        )
        .map_err(|_| anyhow::anyhow!("observed authentication epoch refused"))?;
        ensure!(
            reply.service == self.scope.service
                && reply.audience == self.scope.audience
                && reply.request_sha256.as_slice() == digest
                && reply.chain_sha256.as_slice() == chain_digest
                && reply.cache_ttl_ms == 0
                && valid_domain(&reply.output_clock_domain, "hproj1:", false)
                && reply.owner_now_ms > 0
                && reply.profile_revision == epoch.epoch.profile_revision
                && reply.application_generation == epoch.epoch.application_generation
                && reply.key_registry_revision == authentication.evidence.key_registry_revision()
                && reply.plan_revision == permit.wire.binding.as_ref().unwrap().plan_revision
                && !value.is_empty()
                && value.len() <= 4103,
            "observed projection output binding refused"
        );
        match reply.header_name.as_str() {
            "authorization" => {
                let token = value
                    .strip_prefix(b"Bearer ")
                    .ok_or_else(|| anyhow::anyhow!("invalid projected bearer"))?;
                let end = token.iter().rposition(|b| *b != b'=').map_or(0, |i| i + 1);
                ensure!(
                    end > 0
                        && token[..end]
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(b))
                        && token[end..].iter().all(|b| *b == b'='),
                    "invalid projected bearer"
                );
            }
            "x-hopae-subject" => ensure!(
                value.as_slice()
                    == authentication
                        .context()
                        .identity
                        .as_ref()
                        .unwrap()
                        .subject_ref
                        .as_bytes(),
                "projected subject mismatch"
            ),
            _ => anyhow::bail!("projected header refused"),
        }
        hyper::header::HeaderValue::from_bytes(&value)?;
        // The shared numeric helper accounts for rates and one millisecond
        // uncertainty. Source output ticks are never compared with our ticks.
        let bound = rates
            .remaining_admission_until(
                reply.remaining_ms,
                &receipt_time::Exchange {
                    before_ms: sample.before_ticks(),
                    after_ms: sample.after_ticks(),
                    elapsed_ms: sample.elapsed_ms(),
                },
            )
            .map_err(|_| anyhow::anyhow!("observed output budget refused"))?;
        let (deadline, _) = sample
            .bind_bounds(bound, bound)
            .map_err(|_| anyhow::anyhow!("observed output expired"))?;
        authentication.remaining()?;
        permit.remaining()?;
        ensure!(
            self.active.load(Ordering::Acquire),
            "observed route owner retired"
        );
        Ok(Output {
            name: hyper::header::HeaderName::from_bytes(reply.header_name.as_bytes())?,
            value,
            deadline,
            clock: self.clock.clone(),
        })
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests;
