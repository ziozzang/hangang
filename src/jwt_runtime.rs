//! Route-owned JWT policy and bounded asynchronous verification admission.
use crate::jwks_remote::{RemoteJwksConfig, RemoteJwksProvider, RemoteKeyError};
use crate::jwt_auth::{JwtConfig, JwtVerifier, KeyRequest, PreparedKey, PreparedKeys, Verified};
use anyhow::{Result, ensure};
use hyper::header::HeaderName;
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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
    Remote(Arc<RemoteJwksProvider>),
}
pub struct Runtime {
    verifier: Arc<JwtVerifier>,
    config: JwtAuth,
    keys: Keys,
    reserved: Vec<HeaderName>,
    refresh: Option<Arc<RefreshMonitor>>,
}

/// Verified admission evidence. Clones share one monitor lease and retain no
/// bearer token, signature, or unverified claims.
#[derive(Clone)]
pub struct Session(Arc<SessionInner>);

struct SessionInner {
    verified: Verified,
    request: KeyRequest,
    key: Arc<PreparedKey>,
    verifier: Arc<JwtVerifier>,
    monotonic_deadline: Instant,
    refresh: Option<Arc<RefreshMonitor>>,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        if let Some(refresh) = &self.refresh {
            let mut state = refresh.state.lock().expect("JWT refresh monitor poisoned");
            state.active -= 1;
            if state.active == 0 {
                state.idle_deadline = Some(Instant::now() + MONITOR_IDLE_GRACE);
            }
            drop(state);
            refresh.changed.notify_one();
        }
    }
}

impl Session {
    pub fn verified(&self) -> &Verified {
        &self.0.verified
    }
}

struct RefreshMonitor {
    provider: Weak<RemoteJwksProvider>,
    state: Mutex<RefreshState>,
    changed: tokio::sync::Notify,
}

#[derive(Default)]
struct RefreshState {
    active: usize,
    running: bool,
    request: Option<KeyRequest>,
    idle_deadline: Option<Instant>,
    #[cfg(test)]
    starts: usize,
}

const MONITOR_IDLE_GRACE: Duration = Duration::from_secs(2);

impl RefreshMonitor {
    fn retain(self: &Arc<Self>, request: &KeyRequest) {
        let mut state = self.state.lock().expect("JWT refresh monitor poisoned");
        if state.active == 0 {
            state.request = Some(request.clone());
            state.idle_deadline = None;
        }
        state.active += 1;
        if !state.running {
            state.running = true;
            #[cfg(test)]
            {
                state.starts += 1;
            }
            tokio::spawn(Self::run(self.clone()));
        }
        drop(state);
        self.changed.notify_one();
    }

    async fn run(self: Arc<Self>) {
        loop {
            // Construct the notification before testing active, so a final
            // session drop cannot be lost between the check and the sleep.
            let changed = self.changed.notified();
            let (request, idle_delay) = {
                let mut state = self.state.lock().expect("JWT refresh monitor poisoned");
                if state.active == 0 {
                    let deadline = state
                        .idle_deadline
                        .get_or_insert_with(|| Instant::now() + MONITOR_IDLE_GRACE);
                    if Instant::now() >= *deadline {
                        state.running = false;
                        state.request = None;
                        state.idle_deadline = None;
                        return;
                    }
                    (
                        None,
                        Some(deadline.saturating_duration_since(Instant::now())),
                    )
                } else {
                    (
                        Some(
                            state
                                .request
                                .clone()
                                .expect("active JWT monitor has request"),
                        ),
                        None,
                    )
                }
            };
            if let Some(delay) = idle_delay {
                // Cached request bursts share one monitor. No network work is
                // performed during the bounded idle grace.
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {},
                    _ = changed => {},
                }
                continue;
            }
            let request = request.expect("active JWT monitor has request");
            let Some(provider) = self.provider.upgrade() else {
                let mut state = self.state.lock().expect("JWT refresh monitor poisoned");
                state.running = false;
                return;
            };
            let delay = provider.refresh_delay();
            drop(provider);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {
                    if let Some(provider) = self.provider.upgrade() {
                        // One provider-wide singleflight fetch, regardless
                        // of the number of live streams or cloned leases.
                        let _ = provider.key(&request).await;
                    }
                }
                _ = changed => {}
            }
        }
    }
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
            KeySource::Remote { config: remote } => {
                Keys::Remote(Arc::new(RemoteJwksProvider::new(
                    remote.clone(),
                    &config.verification.issuer,
                    &config.verification.algorithms,
                )?))
            }
        };
        let reserved = config
            .identity_header
            .iter()
            .map(|name| validate_identity_header(name))
            .collect::<Result<Vec<_>>>()?;
        let refresh = match &keys {
            Keys::Remote(provider) => Some(Arc::new(RefreshMonitor {
                provider: Arc::downgrade(provider),
                state: Mutex::new(RefreshState::default()),
                changed: tokio::sync::Notify::new(),
            })),
            Keys::Local(_) => None,
        };
        Ok(Self {
            verifier,
            config,
            keys,
            reserved,
            refresh,
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
        // Compatibility entrypoint does not retain a long-lived session or
        // start a refresh task for a short request.
        Ok(self
            .authenticate_inner(token, admission, false)
            .await?
            .0
            .verified
            .clone())
    }

    pub async fn authenticate_session(
        &self,
        token: &str,
        admission: Arc<tokio::sync::Semaphore>,
    ) -> std::result::Result<Session, AuthFailure> {
        self.authenticate_inner(token, admission, true).await
    }

    pub fn session_current(&self, session: &Session) -> bool {
        if !Arc::ptr_eq(&self.verifier, &session.0.verifier)
            || Instant::now() >= session.0.monotonic_deadline
        {
            return false;
        }
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        if !session
            .0
            .verified
            .valid_at(now.as_secs(), self.config.verification.leeway_seconds)
        {
            return false;
        }
        match &self.keys {
            Keys::Local(keys) => keys
                .get(&session.0.request.kid, session.0.request.algorithm)
                .is_some_and(|key| Arc::ptr_eq(&key, &session.0.key)),
            Keys::Remote(provider) => provider.is_current(&session.0.request, &session.0.key),
        }
    }

    async fn authenticate_inner(
        &self,
        token: &str,
        admission: Arc<tokio::sync::Semaphore>,
        retain: bool,
    ) -> std::result::Result<Session, AuthFailure> {
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
        // Anchor the monotonic budget before reading wall time. A scheduler
        // pause during the remaining checks must not extend the JWT lifetime.
        let admitted_mono = Instant::now();
        let admitted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthFailure::Unavailable)?;
        if !verified.valid_at(
            admitted_at.as_secs(),
            self.config.verification.leeway_seconds,
        ) {
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
        let end = verified
            .expires_at
            .saturating_add(self.config.verification.leeway_seconds);
        let remaining = Duration::from_secs(end)
            .checked_sub(admitted_at)
            .ok_or(AuthFailure::Invalid)?;
        let monotonic_deadline = admitted_mono
            .checked_add(remaining)
            .ok_or(AuthFailure::Unavailable)?;
        let refresh = if retain { self.refresh.clone() } else { None };
        if let Some(monitor) = &refresh {
            monitor.retain(&request);
        }
        Ok(Session(Arc::new(SessionInner {
            verified,
            request,
            key,
            verifier: self.verifier.clone(),
            monotonic_deadline,
            refresh,
        })))
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{Value, json};

    fn jwks(signing: &SigningKey) -> Value {
        json!({"keys":[{"kty":"OKP","crv":"Ed25519",
            "kid":"test-key","alg":"EdDSA","use":"sig",
            "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes())}]})
    }

    fn local_runtime(seed: u8) -> (Runtime, SigningKey) {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let auth: JwtAuth = serde_json::from_value(json!({
            "verification":{"issuer":"https://issuer.example.test/",
                "audiences":["hangang-api"],"profile":"rfc9068",
                "algorithms":["EdDSA"],"max_lifetime_seconds":3600},
            "keys":{"source":"local","jwks":jwks(&signing)}
        }))
        .unwrap();
        (Runtime::new(auth).unwrap(), signing)
    }

    fn token(signing: &SigningKey, expires_at: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"EdDSA","kid":"test-key","typ":"at+jwt"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            json!({"iss":"https://issuer.example.test/","aud":"hangang-api",
                "sub":"alice","client_id":"client-1","jti":"session-test",
                "iat":now.saturating_sub(1),"exp":expires_at})
            .to_string(),
        );
        let message = format!("{header}.{claims}");
        format!(
            "{message}.{}",
            URL_SAFE_NO_PAD.encode(signing.sign(message.as_bytes()).to_bytes())
        )
    }

    #[tokio::test]
    async fn session_is_bound_to_runtime_key_and_monotonic_expiry() {
        let (runtime, signing) = local_runtime(37);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let admission = Arc::new(tokio::sync::Semaphore::new(1));
        let session = runtime
            .authenticate_session(&token(&signing, now + 5), admission)
            .await
            .unwrap();
        assert_eq!(session.verified().subject, "alice");
        assert!(runtime.session_current(&session));
        let cloned = session.clone();
        let (replacement, _) = local_runtime(38);
        assert!(
            !replacement.session_current(&session),
            "another runtime cannot adopt evidence"
        );
        drop(cloned);
        let mut expired = session.clone();
        assert!(Arc::get_mut(&mut expired.0).is_none());
        drop(session);
        Arc::get_mut(&mut expired.0).unwrap().monotonic_deadline =
            Instant::now() - Duration::from_millis(1);
        assert!(
            !runtime.session_current(&expired),
            "clock rollback cannot extend admission"
        );
    }

    #[tokio::test]
    async fn monitor_amortizes_cached_requests_and_stops_after_last_clone() {
        let (runtime, signing) = local_runtime(41);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut session = runtime
            .authenticate_session(
                &token(&signing, now + 30),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        let provider = Arc::new(
            RemoteJwksProvider::new(
                RemoteJwksConfig {
                    endpoint: crate::jwks_remote::RemoteJwksEndpoint::Jwks {
                        url: "https://issuer.example.test/jwks".into(),
                    },
                    cache_ttl_seconds: 300,
                    refresh_cooldown_seconds: 10,
                    timeout_ms: 100,
                    ca_pem: None,
                },
                "https://issuer.example.test/",
                &[crate::jwt_auth::JwtAlgorithm::EdDSA],
            )
            .unwrap(),
        );
        let monitor = Arc::new(RefreshMonitor {
            provider: Arc::downgrade(&provider),
            state: Mutex::new(RefreshState::default()),
            changed: tokio::sync::Notify::new(),
        });
        monitor.retain(&session.0.request);
        Arc::get_mut(&mut session.0).unwrap().refresh = Some(monitor.clone());
        let clone = session.clone();
        drop(session);
        assert_eq!(monitor.state.lock().unwrap().active, 1);
        drop(clone);
        assert_eq!(monitor.state.lock().unwrap().active, 0);
        let mut next = runtime
            .authenticate_session(
                &token(&signing, now + 30),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        monitor.retain(&next.0.request);
        Arc::get_mut(&mut next.0).unwrap().refresh = Some(monitor.clone());
        assert_eq!(monitor.state.lock().unwrap().starts, 1);
        drop(next);
        tokio::time::timeout(Duration::from_secs(3), async {
            while monitor.state.lock().unwrap().running {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(monitor.state.lock().unwrap().starts, 1);
    }

    #[tokio::test]
    async fn remote_session_closes_on_key_withdrawal_and_hard_expiry() {
        let signing = SigningKey::from_bytes(&[51; 32]);
        let auth: JwtAuth = serde_json::from_value(json!({
            "verification":{"issuer":"https://issuer.example.test/",
                "audiences":["hangang-api"],"profile":"rfc9068",
                "algorithms":["EdDSA"],"max_lifetime_seconds":3600},
            "keys":{"source":"remote","config":{
                "endpoint":{"kind":"jwks","url":"https://issuer.example.test/jwks"},
                "cache_ttl_seconds":300,"refresh_cooldown_seconds":10,"timeout_ms":100}}
        }))
        .unwrap();
        let runtime = Runtime::new(auth).unwrap();
        let Keys::Remote(provider) = &runtime.keys else {
            unreachable!()
        };
        provider.seed_test_cache(
            PreparedKeys::from_jwks_json(
                jwks(&signing).to_string().as_bytes(),
                &[crate::jwt_auth::JwtAlgorithm::EdDSA],
            )
            .unwrap(),
            Duration::from_secs(60),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = runtime
            .authenticate_session(
                &token(&signing, now + 30),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        assert!(runtime.session_current(&session));
        provider.expire_test_cache();
        assert!(
            !runtime.session_current(&session),
            "hard TTL expiry remains fail closed during outage"
        );
        provider.seed_test_cache(
            PreparedKeys::from_jwks_json(
                jwks(&signing).to_string().as_bytes(),
                &[crate::jwt_auth::JwtAlgorithm::EdDSA],
            )
            .unwrap(),
            Duration::from_secs(60),
        );
        let session = runtime
            .authenticate_session(
                &token(&signing, now + 30),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        assert!(runtime.session_current(&session));
        let replacement = SigningKey::from_bytes(&[52; 32]);
        provider.seed_test_cache(
            PreparedKeys::from_jwks_json(
                jwks(&replacement).to_string().as_bytes(),
                &[crate::jwt_auth::JwtAlgorithm::EdDSA],
            )
            .unwrap(),
            Duration::from_secs(60),
        );
        assert!(
            !runtime.session_current(&session),
            "same kid with new public key retires old admission"
        );
    }

    /// Diagnostic only: the steady-state local session guard after one
    /// admission. This excludes signature verification, routing, network I/O,
    /// HTTP framing, and any vendor or gateway throughput comparison.
    /// Run explicitly with:
    /// cargo test --release --lib jwt_session_current_microbenchmark -- --ignored --nocapture
    #[tokio::test]
    #[ignore = "explicit release-mode local guard diagnostic"]
    async fn jwt_session_current_microbenchmark() {
        let (runtime, signing) = local_runtime(61);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = runtime
            .authenticate_session(
                &token(&signing, now + 60),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        assert!(runtime.session_current(&session));

        const ITERATIONS: usize = 2_000_000;
        let started = Instant::now();
        let mut accepted = 0usize;
        for _ in 0..ITERATIONS {
            accepted += usize::from(std::hint::black_box(
                std::hint::black_box(&runtime).session_current(std::hint::black_box(&session)),
            ));
        }
        let elapsed = started.elapsed();
        assert_eq!(
            accepted, ITERATIONS,
            "every guard check must remain authorized"
        );
        eprintln!(
            "local JWT session_current guard: {ITERATIONS} checks in {elapsed:?} ({:.0} checks/s); excludes signature, network, HTTP, and routing",
            ITERATIONS as f64 / elapsed.as_secs_f64()
        );
    }
}
