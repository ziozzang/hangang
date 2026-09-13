//! Route-owned JWT policy and bounded asynchronous verification admission.
use crate::jwks_remote::{RemoteJwksConfig, RemoteJwksProvider, RemoteKeyError};
use crate::jwt_auth::{JwtConfig, JwtVerifier, PreparedKeys, Verified};
use anyhow::{Result, ensure};
use hyper::header::HeaderName;
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use std::sync::Arc;

/// Preserve duplicate detection before JSON maps can silently replace a key.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PublicJwks(serde_json::Value);
impl<'de> Deserialize<'de> for PublicJwks {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let value = crate::jwt_auth::StrictValue::deserialize(deserializer)?.0;
        if serde_json::to_vec(&value).map_err(D::Error::custom)?.len() > 128 * 1024 {
            return Err(D::Error::custom("JWKS exceeds 128 KiB"));
        }
        Ok(Self(value))
    }
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum KeySource {
    Local { jwks: PublicJwks },
    Remote { config: RemoteJwksConfig },
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtAuth {
    pub verification: JwtConfig,
    pub keys: KeySource,
    #[serde(default = "hide_default")]
    pub hide_credentials: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_header: Option<String>,
}
fn hide_default() -> bool {
    true
}
impl JwtAuth {
    pub fn validate(&self) -> Result<()> {
        JwtVerifier::prepare(self.verification.clone())?;
        if let Some(name) = &self.identity_header {
            ensure!(name.len() <= 128, "JWT identity header exceeds 128 bytes");
            validate_identity_header(name)?;
        }
        match &self.keys {
            KeySource::Local { jwks } => {
                PreparedKeys::from_jwks_json(
                    &serde_json::to_vec(&jwks.0)?,
                    &self.verification.algorithms,
                )?;
            }
            KeySource::Remote { config } => {
                RemoteJwksProvider::new(
                    config.clone(),
                    &self.verification.issuer,
                    &self.verification.algorithms,
                )?;
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_identity_header(name: &str) -> Result<HeaderName> {
    let name: HeaderName = name.parse()?;
    ensure!(
        name.as_str().len() <= 128
            && !crate::config::is_protected_response_header(name.as_str())
            && !matches!(
                name.as_str(),
                "host"
                    | "authorization"
                    | "proxy-authorization"
                    | "proxy-authenticate"
                    | "proxy-connection"
                    | "cookie"
                    | "set-cookie"
                    | "forwarded"
                    | "x-real-ip"
                    | "x-hangang-auth-terminal"
            )
            && !name.as_str().starts_with("x-forwarded-")
            && !name.as_str().starts_with("x-original-")
            && !name.as_str().starts_with("sec-websocket-"),
        "unsafe JWT identity header"
    );
    Ok(name)
}
enum Keys {
    Local(PreparedKeys),
    Remote(RemoteJwksProvider),
}
pub struct Runtime {
    verifier: Arc<JwtVerifier>,
    config: JwtAuth,
    keys: Keys,
    reserved: Vec<HeaderName>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthFailure {
    Invalid,
    Forbidden,
    Unavailable,
    Capacity,
}
impl Runtime {
    pub fn new(config: JwtAuth) -> Result<Self> {
        let verifier = Arc::new(JwtVerifier::prepare(config.verification.clone())?);
        let keys = match &config.keys {
            KeySource::Local { jwks } => Keys::Local(PreparedKeys::from_jwks_json(
                &serde_json::to_vec(&jwks.0)?,
                &config.verification.algorithms,
            )?),
            KeySource::Remote { config: remote } => Keys::Remote(RemoteJwksProvider::new(
                remote.clone(),
                &config.verification.issuer,
                &config.verification.algorithms,
            )?),
        };
        let reserved = config
            .identity_header
            .iter()
            .map(|name| validate_identity_header(name))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            verifier,
            config,
            keys,
            reserved,
        })
    }
    pub fn reserved_headers(&self) -> &[HeaderName] {
        &self.reserved
    }
    pub async fn authenticate(
        &self,
        token: &str,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> std::result::Result<Verified, AuthFailure> {
        let request = self
            .verifier
            .key_request(token)
            .map_err(|_| AuthFailure::Invalid)?;
        let key = match &self.keys {
            Keys::Local(keys) => keys
                .get(&request.kid, request.algorithm)
                .ok_or(AuthFailure::Invalid)?,
            Keys::Remote(provider) => {
                provider.key(&request).await.map_err(|error| match error {
                    RemoteKeyError::UnknownKey => AuthFailure::Invalid,
                    RemoteKeyError::Unavailable => AuthFailure::Unavailable,
                })?
            }
        };
        let permit = admission
            .try_acquire_owned()
            .map_err(|_| AuthFailure::Capacity)?;
        let verifier = self.verifier.clone();
        let task_key = key.clone();
        let token = token.to_owned();
        // The blocking task owns its permit even when the requesting client is
        // canceled. Unfinished cryptography cannot silently escape the CPU bound.
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| AuthFailure::Unavailable)?
                .as_secs();
            verifier
                .verify(&token, &task_key, now)
                .map_err(|_| AuthFailure::Invalid)
        })
        .await
        .map_err(|_| AuthFailure::Unavailable)??;
        let admitted_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| AuthFailure::Unavailable)?
            .as_secs();
        if !verified.valid_at(admitted_at, self.config.verification.leeway_seconds) {
            return Err(AuthFailure::Invalid);
        }
        if let Keys::Remote(provider) = &self.keys
            && !provider.is_current(&request, &key)
        {
            return Err(AuthFailure::Unavailable);
        }
        if !self
            .config
            .verification
            .required_scopes
            .iter()
            .all(|scope| verified.scopes.contains(scope))
            || !self
                .config
                .verification
                .required_groups
                .iter()
                .all(|group| verified.groups.contains(group))
        {
            return Err(AuthFailure::Forbidden);
        }
        Ok(verified)
    }
}

pub(crate) fn verification_admission() -> Arc<tokio::sync::Semaphore> {
    static ADMISSION: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| {
            let slots = std::thread::available_parallelism()
                .map_or(2, |cpus| cpus.get().saturating_mul(2))
                .clamp(2, 64);
            Arc::new(tokio::sync::Semaphore::new(slots))
        });
    ADMISSION.clone()
}
