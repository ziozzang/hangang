//! Native permission signature checking, not replay admission or credential delivery.
use crate::projection_receipt::CheckedServiceReceipt;
use ed25519_dalek::VerifyingKey;
use hopae_grpc::{receipt, receipt_binding};
use pumgye_grpc::v1::ProjectionPermitReply;
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
#[derive(Debug)]
pub struct Denied;
impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("native permit denied")
    }
}
impl std::error::Error for Denied {}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub issuer_ref: String,
    pub key_epoch: u64,
    pub public_key: String,
}
pub struct Pin {
    issuer: String,
    epoch: u64,
    key: VerifyingKey,
}
/// Private constructor, no Clone/Debug/serde. A receiver still must consume replay.
pub struct CheckedPermit {
    wire: ProjectionPermitReply,
    original: Option<pumgye_grpc::v1::AuthenticatedResourceRequest>,
    checked_ms: u64,
    begun: std::time::Instant,
    expires_ms: u64,
    signed_expires_ms: u64,
}
impl Configuration {
    pub fn compile(&self) -> Result<Pin, Refused> {
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&self.public_key)
            .map_err(|_| Refused)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| Refused)?;
        if self.issuer_ref.is_empty()
            || self.issuer_ref.len() > 128
            || !self
                .issuer_ref
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !(1..=9_007_199_254_740_991).contains(&self.key_epoch)
            || base64::engine::general_purpose::STANDARD.encode(bytes) != self.public_key
        {
            return Err(Refused);
        }
        let key = VerifyingKey::from_bytes(&bytes).map_err(|_| Refused)?;
        if key.is_weak() {
            return Err(Refused);
        }
        Ok(Pin {
            issuer: self.issuer_ref.clone(),
            epoch: self.key_epoch,
            key,
        })
    }
}
impl CheckedPermit {
    pub(crate) fn bind_original(&mut self, request: pumgye_grpc::v1::AuthenticatedResourceRequest) {
        self.original = Some(request);
    }
    pub(crate) fn original(&self) -> Option<&pumgye_grpc::v1::AuthenticatedResourceRequest> {
        self.original.as_ref()
    }

    pub fn valid_at(&self, now: u64) -> bool {
        now >= self.checked_ms
            && now.max(
                self.checked_ms
                    .saturating_add(self.begun.elapsed().as_millis().min(u64::MAX as u128) as u64),
            ) < self.expires_ms
    }
    pub(crate) fn signed_expires_ms(&self) -> u64 {
        self.signed_expires_ms
    }
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub(crate) fn accept_owner_reply(
        &mut self,
        request_id: u64,
        reply: pumgye_grpc::v1::PermitValidationReply,
        now: u64,
    ) -> Result<(), Refused> {
        if reply.request_id != request_id
            || reply.cache_ttl_ms != 0
            || !self.valid_at(now)
            || reply.expires_ms <= now
            || reply.expires_ms > self.expires_ms
        {
            return Err(Refused);
        }
        self.expires_ms = reply.expires_ms;
        Ok(())
    }
    pub fn revision(&self) -> u64 {
        self.wire
            .binding
            .as_ref()
            .expect("checked binding")
            .policy_revision
    }
    pub fn network_revision(&self) -> u64 {
        self.wire
            .binding
            .as_ref()
            .expect("checked binding")
            .network_revision
    }
    /// Signed permission evidence only, never a projected upstream credential.
    pub fn wire(&self) -> &ProjectionPermitReply {
        &self.wire
    }
}
impl Pin {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn verify_observed_signature(
        &self,
        request_id: u64,
        resource: &str,
        action: &str,
        minimum_revision: u64,
        network_floor: u64,
        authentication: &crate::native_observed::Authentication,
        wire: ProjectionPermitReply,
    ) -> Result<hopae_grpc::receipt::SignatureEvidence, Refused> {
        let auth = authentication.context();
        let context = wire.context.as_ref().ok_or(Refused)?;
        let identity = context.identity.as_ref().ok_or(Refused)?;
        let auth_identity = auth.identity.as_ref().ok_or(Refused)?;
        let p = wire.binding.as_ref().ok_or(Refused)?;
        if wire.request_id != request_id
            || wire.cache_ttl_ms != 0
            || context.issuer_ref != self.issuer
            || context.key_epoch != self.epoch
            || context.identity_authority_epoch != auth.identity_authority_epoch
            || identity.subject_ref != auth_identity.subject_ref
            || identity.kind != 2
            || identity.aal != 0
            || identity.revision != auth_identity.revision
            || identity.credential_generation != auth_identity.credential_generation
            || context.service != auth.service
            || context.audience != auth.audience
            || context.request_sha256.as_slice() != auth.request_sha256.as_slice()
            || p.resource != resource
            || p.action != action
            || p.policy_revision < minimum_revision
            || p.catalog_revision != p.policy_revision
            || p.network_revision < network_floor
            || p.authentication_receipt_sha256.as_slice() != authentication.sha256()
            || authentication.remaining().is_err()
        {
            return Err(Refused);
        }
        let context = receipt_binding::Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: hopae_grpc::PrincipalKind::Service,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: auth
                .request_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
        };
        let permit = receipt_binding::Permit {
            authentication_receipt_sha256: p
                .authentication_receipt_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
            decision_ref: &p.decision_ref,
            resource: &p.resource,
            action: &p.action,
            authority_epoch: &p.authority_epoch,
            catalog_revision: p.catalog_revision,
            policy_revision: p.policy_revision,
            network_revision: p.network_revision,
            route_revision: p.route_revision,
            plan_revision: p.plan_revision,
        };
        let binding = receipt_binding::digest(&context, Some(&permit)).map_err(|_| Refused)?;
        let checked =
            receipt::verify_signature(&self.key, &wire.receipt, receipt::Purpose::Permit, &binding)
                .map_err(|_| Refused)?;
        Ok(checked)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        request_id: u64,
        resource: &str,
        action: &str,
        minimum_revision: u64,
        network_floor: u64,
        authentication: &CheckedServiceReceipt,
        wire: ProjectionPermitReply,
        now: u64,
    ) -> Result<CheckedPermit, Refused> {
        let auth = authentication.context();
        let context = wire.context.as_ref().ok_or(Refused)?;
        let identity = context.identity.as_ref().ok_or(Refused)?;
        let p = wire.binding.as_ref().ok_or(Refused)?;
        if wire.request_id != request_id
            || wire.cache_ttl_ms != 0
            || context.issuer_ref != self.issuer
            || context.key_epoch != self.epoch
            || context.identity_authority_epoch != auth.identity_authority_epoch
            || identity.subject_ref != auth.identity.subject_ref
            || identity.kind != 2
            || identity.aal != 0
            || identity.revision != auth.identity.revision
            || identity.credential_generation != auth.identity.credential_generation
            || context.service != auth.service
            || context.audience != auth.audience
            || context.request_sha256.as_slice() != auth.request_sha256
            || p.resource != resource
            || p.action != action
            || p.policy_revision < minimum_revision
            || p.catalog_revision != p.policy_revision
            || p.network_revision < network_floor
            || p.authentication_receipt_sha256.as_slice()
                != authentication.authentication().authentication_sha256()
            || !authentication.authentication().valid_at(now)
        {
            return Err(Refused);
        }
        let context = receipt_binding::Context {
            issuer_ref: &context.issuer_ref,
            key_epoch: context.key_epoch,
            identity_authority_epoch: &context.identity_authority_epoch,
            identity: receipt_binding::Identity {
                subject_ref: &identity.subject_ref,
                kind: hopae_grpc::PrincipalKind::Service,
                aal: 0,
                revision: identity.revision,
                credential_generation: identity.credential_generation,
            },
            service: &context.service,
            audience: &context.audience,
            request_sha256: auth.request_sha256,
        };
        let permit = receipt_binding::Permit {
            authentication_receipt_sha256: p
                .authentication_receipt_sha256
                .as_slice()
                .try_into()
                .map_err(|_| Refused)?,
            decision_ref: &p.decision_ref,
            resource: &p.resource,
            action: &p.action,
            authority_epoch: &p.authority_epoch,
            catalog_revision: p.catalog_revision,
            policy_revision: p.policy_revision,
            network_revision: p.network_revision,
            route_revision: p.route_revision,
            plan_revision: p.plan_revision,
        };
        let binding = receipt_binding::digest(&context, Some(&permit)).map_err(|_| Refused)?;
        let checked = receipt::verify(
            &self.key,
            &wire.receipt,
            receipt::Purpose::Permit,
            &binding,
            now,
        )
        .map_err(|_| Refused)?;
        if checked.claims().expires_ms > authentication.authentication().expires_ms() {
            return Err(Refused);
        }
        let expires_ms = checked.claims().expires_ms;
        Ok(CheckedPermit {
            original: None,
            signed_expires_ms: expires_ms,
            wire,
            checked_ms: now,
            begun: std::time::Instant::now(),
            expires_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projection_receipt::{IssuerPin, ServiceScope};
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    fn fixture() -> (Pin, CheckedServiceReceipt, ProjectionPermitReply) {
        let authentication_key = SigningKey::from_bytes(&[7; 32]);
        let permission_key = SigningKey::from_bytes(&[8; 32]);
        let identity = || hopae_grpc::v1::ReceiptIdentity {
            subject_ref: "s_owned".into(),
            kind: 2,
            aal: 0,
            revision: 1,
            credential_generation: 1,
        };
        let auth = receipt_binding::Context {
            issuer_ref: "hopae",
            key_epoch: 1,
            identity_authority_epoch: "owned-epoch",
            identity: receipt_binding::Identity {
                subject_ref: "s_owned",
                kind: hopae_grpc::PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        };
        let auth_bytes = receipt::sign(
            &authentication_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 900,
                binding: receipt_binding::digest(&auth, None).unwrap(),
                nonce: [1; 32],
            },
        )
        .unwrap();
        let authentication = IssuerPin::new(
            "hopae".into(),
            1,
            authentication_key.verifying_key().to_bytes(),
        )
        .unwrap()
        .verify_service_reply(
            1,
            &ServiceScope {
                service: "orders",
                audience: "orders-api",
                request_sha256: [3; 32],
            },
            hopae_grpc::v1::ServiceReceiptReply {
                request_id: 1,
                context: Some(hopae_grpc::v1::AuthenticationReceiptContext {
                    issuer_ref: "hopae".into(),
                    key_epoch: 1,
                    identity_authority_epoch: "owned-epoch".into(),
                    identity: Some(identity()),
                    service: "orders".into(),
                    audience: "orders-api".into(),
                    request_sha256: vec![3; 32],
                }),
                receipt: auth_bytes.to_vec(),
            },
            101,
        )
        .unwrap();
        let context = receipt_binding::Context {
            issuer_ref: "pumgye",
            key_epoch: 1,
            ..auth
        };
        let permit = receipt_binding::Permit {
            authentication_receipt_sha256: authentication.authentication().authentication_sha256(),
            decision_ref: "owned-decision",
            resource: "db:orders",
            action: "select",
            authority_epoch: "owned-policy",
            catalog_revision: 2,
            policy_revision: 2,
            network_revision: 3,
            route_revision: 4,
            plan_revision: 5,
        };
        let bytes = receipt::sign(
            &permission_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms: 102,
                expires_ms: 800,
                binding: receipt_binding::digest(&context, Some(&permit)).unwrap(),
                nonce: [2; 32],
            },
        )
        .unwrap();
        let pin = Configuration {
            issuer_ref: "pumgye".into(),
            key_epoch: 1,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(permission_key.verifying_key().to_bytes()),
        }
        .compile()
        .unwrap();
        let wire = ProjectionPermitReply {
            request_id: 7,
            cache_ttl_ms: 0,
            receipt: bytes.to_vec(),
            context: Some(hopae_grpc::v1::AuthenticationReceiptContext {
                issuer_ref: "pumgye".into(),
                key_epoch: 1,
                identity_authority_epoch: "owned-epoch".into(),
                identity: Some(identity()),
                service: "orders".into(),
                audience: "orders-api".into(),
                request_sha256: vec![3; 32],
            }),
            binding: Some(pumgye_grpc::v1::PermitBinding {
                authentication_receipt_sha256: permit.authentication_receipt_sha256.to_vec(),
                decision_ref: "owned-decision".into(),
                resource: "db:orders".into(),
                action: "select".into(),
                authority_epoch: "owned-policy".into(),
                catalog_revision: 2,
                policy_revision: 2,
                network_revision: 3,
                route_revision: 4,
                plan_revision: 5,
            }),
        };
        (pin, authentication, wire)
    }
    #[test]
    fn projected_credential_rejects_scope_header_and_deadline_attacks() {
        use crate::projected_credential::Credential;
        let (pin, auth, wire) = fixture();
        let checked = pin
            .verify(7, "db:orders", "select", 2, 3, &auth, wire, 103)
            .unwrap();
        let valid = || hopae_grpc::v1::ProjectionReply {
            request_id: 9,
            service: "orders".into(),
            audience: "orders-api".into(),
            request_sha256: vec![3; 32],
            plan_revision: 5,
            expires_ms: 700,
            header_name: "authorization".into(),
            header_value: b"Bearer owned-origin".to_vec(),
        };
        for attack in 0..13 {
            let mut reply = valid();
            match attack {
                0 => reply.request_id += 1,
                1 => reply.service = "other".into(),
                2 => reply.audience = "other".into(),
                3 => reply.request_sha256[0] ^= 1,
                4 => reply.plan_revision += 1,
                5 => reply.expires_ms = 801,
                6 => reply.expires_ms = 104,
                7 => reply.header_name = "host".into(),
                8 => reply.header_value = b"Bearer injected\r\nX-Test: true".to_vec(),
                9 => reply.header_value = b"Basic owned".to_vec(),
                10 => reply.header_value = b"Bearer =a".to_vec(),
                11 => reply.header_value = vec![b'a'; 4104],
                _ => {
                    reply.header_name = "x-hopae-subject".into();
                    reply.header_value = b"forged".to_vec();
                }
            }
            assert!(
                Credential::check(reply, 9, &auth, &checked, 104).is_err(),
                "attack {attack}"
            );
        }
        let mut checked = checked;
        checked
            .accept_owner_reply(
                9,
                pumgye_grpc::v1::PermitValidationReply {
                    request_id: 9,
                    expires_ms: 650,
                    cache_ttl_ms: 0,
                },
                104,
            )
            .unwrap();
        // Independent live observations may conservatively differ. Their
        // intersection must never extend this gateway's previously accepted bound.
        let output = Credential::check(valid(), 9, &auth, &checked, 104).unwrap();
        assert!(output.header(650).is_err());
        assert_eq!(checked.signed_expires_ms(), 800);
        let (name, value) = output.header(105).unwrap();
        assert_eq!(name, "authorization");
        assert!(value.is_sensitive());
        assert!(output.header(103).is_err());
        assert!(output.header(700).is_err());
        let mut identity = valid();
        identity.header_name = "x-hopae-subject".into();
        identity.header_value = b"s_owned".to_vec();
        assert!(Credential::check(identity, 9, &auth, &checked, 104).is_ok());
    }

    #[test]
    fn checked_permit_retains_native_binding_time_and_revision_fences() {
        let (pin, auth, wire) = fixture();
        let checked = pin
            .verify(7, "db:orders", "select", 2, 3, &auth, wire, 103)
            .unwrap();
        assert_eq!((checked.revision(), checked.network_revision()), (2, 3));
        assert!(checked.valid_at(104));
        assert!(!checked.valid_at(102));
        assert!(!checked.valid_at(800));
    }
    #[test]
    fn live_owner_reply_cannot_extend_or_cache_a_checked_permit() {
        let (pin, auth, wire) = fixture();
        let mut checked = pin
            .verify(7, "db:orders", "select", 2, 3, &auth, wire, 103)
            .unwrap();
        let reply = |request_id, expires_ms, cache_ttl_ms| pumgye_grpc::v1::PermitValidationReply {
            request_id,
            expires_ms,
            cache_ttl_ms,
        };
        for bad in [
            reply(8, 700, 0),
            reply(7, 801, 0),
            reply(7, 104, 0),
            reply(7, 700, 1),
        ] {
            assert!(checked.accept_owner_reply(7, bad, 104).is_err());
        }
        checked
            .accept_owner_reply(7, reply(7, 700, 0), 104)
            .unwrap();
        assert_eq!(checked.expires_ms(), 700);
        assert!(checked.valid_at(105));
        assert!(!checked.valid_at(700));
        assert!(
            checked
                .accept_owner_reply(7, reply(7, 701, 0), 105)
                .is_err()
        );
        assert!(
            checked
                .accept_owner_reply(7, reply(7, 650, 0), 102)
                .is_err()
        );
    }
    #[test]
    fn scope_chain_purpose_signature_and_retirement_refuse_hostile_replies() {
        let (pin, auth, wire) = fixture();
        for case in 0..16 {
            let mut bad = wire.clone();
            match case {
                0 => bad.request_id = 8,
                1 => bad.cache_ttl_ms = 1,
                2 => bad.context.as_mut().unwrap().issuer_ref = "other".into(),
                3 => {
                    bad.context
                        .as_mut()
                        .unwrap()
                        .identity
                        .as_mut()
                        .unwrap()
                        .subject_ref = "other".into()
                }
                4 => bad.context.as_mut().unwrap().identity_authority_epoch = "other".into(),
                5 => bad.context.as_mut().unwrap().request_sha256[0] ^= 1,
                6 => bad.binding.as_mut().unwrap().resource = "other".into(),
                7 => bad.binding.as_mut().unwrap().action = "write".into(),
                8 => bad.binding.as_mut().unwrap().authentication_receipt_sha256[0] ^= 1,
                9 => bad.binding.as_mut().unwrap().policy_revision = 1,
                10 => bad.binding.as_mut().unwrap().catalog_revision = 1,
                11 => bad.binding.as_mut().unwrap().network_revision = 2,
                12 => bad.binding.as_mut().unwrap().route_revision = 0,
                13 => bad.binding.as_mut().unwrap().plan_revision = 0,
                14 => bad.receipt[1] = 1,
                _ => bad.receipt[100] ^= 1,
            }
            assert!(
                pin.verify(7, "db:orders", "select", 2, 3, &auth, bad, 103)
                    .is_err(),
                "case {case}"
            );
        }
        assert!(
            pin.verify(7, "db:orders", "select", 3, 3, &auth, wire.clone(), 103)
                .is_err()
        );
        assert!(
            pin.verify(7, "db:orders", "select", 2, 4, &auth, wire.clone(), 103)
                .is_err()
        );
        assert!(
            pin.verify(7, "db:orders", "select", 2, 3, &auth, wire, 800)
                .is_err()
        );
    }
}
