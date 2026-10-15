//! Private final-dispatch credential; never ordinary authentication output.
use hyper::header::{HeaderName, HeaderValue};
use zeroize::Zeroizing;
pub(crate) struct Credential {
    name: HeaderName,
    value: Zeroizing<Vec<u8>>,
    checked_ms: u64,
    started: std::time::Instant,
    expires_ms: u64,
}
impl Credential {
    pub(crate) fn check(
        mut reply: hopae_grpc::v1::ProjectionReply,
        id: u64,
        receipt: &crate::projection_receipt::CheckedServiceReceipt,
        permit: &crate::projection_permit::CheckedPermit,
        now: u64,
    ) -> std::io::Result<Self> {
        let value = Zeroizing::new(std::mem::take(&mut reply.header_value));
        let context = receipt.context();
        if reply.request_id != id
            || reply.service != context.service
            || reply.audience != context.audience
            || reply.request_sha256.as_slice() != context.request_sha256
            || reply.plan_revision
                != permit
                    .wire()
                    .binding
                    .as_ref()
                    .ok_or_else(super::hopae_native::invalid)?
                    .plan_revision
            || reply.expires_ms <= now
            || reply.expires_ms > permit.signed_expires_ms()
            || !permit.valid_at(now)
            || !receipt.authentication().valid_at(now)
            || value.is_empty()
            || value.len() > 4103
        {
            return Err(super::hopae_native::invalid());
        }
        match reply.header_name.as_str() {
            "authorization" => {
                let token = value
                    .strip_prefix(b"Bearer ")
                    .ok_or_else(super::hopae_native::invalid)?;
                let end = token.iter().rposition(|b| *b != b'=').map_or(0, |i| i + 1);
                if end == 0
                    || !token[..end]
                        .iter()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(b))
                    || !token[end..].iter().all(|b| *b == b'=')
                {
                    return Err(super::hopae_native::invalid());
                }
            }
            "x-hopae-subject" if value.as_slice() == context.identity.subject_ref.as_bytes() => {}
            _ => return Err(super::hopae_native::invalid()),
        }
        HeaderValue::from_bytes(&value).map_err(|_| super::hopae_native::invalid())?;
        Ok(Self {
            name: HeaderName::from_bytes(reply.header_name.as_bytes())
                .map_err(|_| super::hopae_native::invalid())?,
            value,
            checked_ms: now,
            started: std::time::Instant::now(),
            expires_ms: reply.expires_ms.min(permit.expires_ms()),
        })
    }
    pub(crate) fn valid_at(&self, now: u64) -> bool {
        now >= self.checked_ms && now.max(self.checked_ms.saturating_add(self.started.elapsed().as_millis().min(u64::MAX as u128) as u64)) < self.expires_ms
    }
    pub(crate) fn header(&self, now: u64) -> std::io::Result<(HeaderName, HeaderValue)> {
        if !self.valid_at(now) {
            return Err(super::hopae_native::invalid());
        }
        let mut value =
            HeaderValue::from_bytes(&self.value).map_err(|_| super::hopae_native::invalid())?;
        value.set_sensitive(true);
        Ok((self.name.clone(), value))
    }
}
