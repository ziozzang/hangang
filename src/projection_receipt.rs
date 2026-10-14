//! Authentication receipt checks only. Runtime adapters must authenticate the
//! current owner context; this result grants no permissions or credential output.
use ed25519_dalek::VerifyingKey;
use hopae_grpc::{receipt, receipt_binding};
use sha2::{Digest, Sha256};
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;
pub struct IssuerPin {
    issuer: String,
    epoch: u64,
    key: VerifyingKey,
}
/// No Clone/Debug/serde: do not install this as an ordinary authentication header.
pub struct CheckedAuthentication {
    bytes: [u8; receipt::LENGTH],
    expires_ms: u64,
}
impl IssuerPin {
    pub fn new(issuer: String, epoch: u64, public_key: [u8; 32]) -> Result<Self, Refused> {
        if issuer.is_empty()
            || issuer.len() > 128
            || !issuer
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !(1..=9_007_199_254_740_991).contains(&epoch)
        {
            return Err(Refused);
        }
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| Refused)?;
        if key.is_weak() {
            return Err(Refused);
        }
        Ok(Self { issuer, epoch, key })
    }
    /// `current` must come from authenticated native owners and the bound final
    /// request, never from unverified receipt response fields. Caller owns freshness.
    pub fn verify_authentication(
        &self,
        current: &receipt_binding::Context<'_>,
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<CheckedAuthentication, Refused> {
        if current.issuer_ref != self.issuer || current.key_epoch != self.epoch {
            return Err(Refused);
        }
        let binding = receipt_binding::digest(current, None).map_err(|_| Refused)?;
        let checked = receipt::verify(
            &self.key,
            bytes,
            receipt::Purpose::Authentication,
            &binding,
            now_ms,
        )
        .map_err(|_| Refused)?;
        Ok(CheckedAuthentication {
            bytes: bytes.try_into().map_err(|_| Refused)?,
            expires_ms: checked.claims().expires_ms,
        })
    }
}
impl CheckedAuthentication {
    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
    pub fn authentication_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.bytes).into()
    }
    pub fn receipt_bytes(&self) -> &[u8; receipt::LENGTH] {
        &self.bytes
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hopae_grpc::PrincipalKind;
    fn context() -> receipt_binding::Context<'static> {
        receipt_binding::Context {
            issuer_ref: "owned",
            key_epoch: 1,
            identity_authority_epoch: "epoch1",
            identity: receipt_binding::Identity {
                subject_ref: "service_worker",
                kind: PrincipalKind::Service,
                aal: 0,
                revision: 1,
                credential_generation: 1,
            },
            service: "orders",
            audience: "orders-api",
            request_sha256: [3; 32],
        }
    }
    #[test]
    fn pinned_authentication_refuses_tamper_changed_native_context_epoch_and_expiry() {
        let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let pin = IssuerPin::new("owned".into(), 1, signer.verifying_key().to_bytes()).unwrap();
        let bytes = receipt::sign(
            &signer,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: 100,
                expires_ms: 1100,
                binding: receipt_binding::digest(&context(), None).unwrap(),
                nonce: [8; 32],
            },
        )
        .unwrap();
        let checked = pin.verify_authentication(&context(), &bytes, 101).unwrap();
        assert_eq!(checked.expires_ms(), 1100);
        assert_eq!(checked.receipt_bytes(), &bytes);
        assert_eq!(
            checked.authentication_sha256(),
            <[u8; 32]>::from(Sha256::digest(bytes))
        );
        for index in 0..receipt::LENGTH {
            let mut bad = bytes;
            bad[index] ^= 1;
            assert!(pin.verify_authentication(&context(), &bad, 101).is_err());
        }
        for mutate in [
            |c: &mut receipt_binding::Context<'_>| c.key_epoch = 2,
            |c: &mut receipt_binding::Context<'_>| c.identity.revision = 2,
            |c: &mut receipt_binding::Context<'_>| c.request_sha256 = [4; 32],
            |c: &mut receipt_binding::Context<'_>| c.identity.credential_generation = 2,
        ] {
            let mut c = context();
            mutate(&mut c);
            assert!(pin.verify_authentication(&c, &bytes, 101).is_err());
        }
        for now in [99, 1100, u64::MAX] {
            assert!(pin.verify_authentication(&context(), &bytes, now).is_err());
        }
        assert!(IssuerPin::new("owned".into(), 0, signer.verifying_key().to_bytes()).is_err());
    }
}
