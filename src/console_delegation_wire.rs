//! Signed actor evidence for trusted Hangang -> Hopae console delegation.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    pub actor_id: i64,
    pub actor_name: String,
    pub timestamp: u64,
    pub nonce: String,
    pub method: String,
    pub path: String,
    pub body_sha256: String,
    pub handle_sha256: String,
    pub client_ip: String,
    pub user_agent: Option<String>,
}
pub fn digest(body: &[u8]) -> String {
    format!("{:x}", Sha256::digest(body))
}
pub fn sign(assertion: &Assertion, key: &[u8]) -> Option<(String, String)> {
    let bytes = serde_json::to_vec(assertion).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(&bytes);
    Some((
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
    ))
}
pub fn verify(encoded: &str, signature: &str, key: &[u8], now: u64) -> Option<Assertion> {
    if encoded.len() > 2048 || signature.len() > 64 {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    let signature = URL_SAFE_NO_PAD.decode(signature).ok()?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).ok()?;
    mac.update(&bytes);
    mac.verify_slice(&signature).ok()?;
    let a: Assertion = serde_json::from_slice(&bytes).ok()?;
    if a.actor_id < 0
        || (a.actor_id == 0 && a.actor_name != "system")
        || a.actor_name.is_empty()
        || a.actor_name.len() > 64
        || a.timestamp.abs_diff(now) > 10
        || a.nonce.len() != 32
        || !a.nonce.bytes().all(|b| b.is_ascii_hexdigit())
        || a.path.len() > 256
        || a.body_sha256.len() != 64
        || a.client_ip.parse::<std::net::IpAddr>().is_err()
        || a.user_agent.as_ref().is_some_and(|v| v.len() > 1024)
    {
        return None;
    }
    Some(a)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_and_freshness_are_signed() {
        let a = Assertion {
            authority: None,
            actor_id: 1,
            actor_name: "operator".into(),
            timestamp: 100,
            nonce: "0123456789abcdef0123456789abcdef".into(),
            method: "POST".into(),
            path: "/v1/users/disable".into(),
            body_sha256: digest(b"{}"),
            handle_sha256: digest(b"handle"),
            client_ip: "192.0.2.1".into(),
            user_agent: None,
        };
        let (e, s) = sign(&a, b"fixture-key").unwrap();
        assert!(verify(&e, &s, b"fixture-key", 100).is_some());
        assert!(verify(&e, &s, b"wrong", 100).is_none());
        assert!(verify(&e, &s, b"fixture-key", 111).is_none());
        let mut b = a.clone();
        b.path = "/v1/sessions/terminate".into();
        let (e, _) = sign(&b, b"fixture-key").unwrap();
        assert!(verify(&e, &s, b"fixture-key", 100).is_none());
    }
}
