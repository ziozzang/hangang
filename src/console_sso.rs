//! Optional console SSO broker. Provider credentials stay in Hopae. Opaque
//! browser sessions require their native Hopae cookie on every request; the
//! upstream receives only private five-second leases for existing accounts.
use anyhow::{Context, Result, ensure};
use base64::Engine;
use hangang::{admin_plugins::ClientContext, admin_users::User, hopae_native::Client};
use hyper::{HeaderMap, header::HeaderValue};
use serde::Deserialize;
use std::{
    collections::HashMap,
    io::Read,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    public_url: String,
    native_address: SocketAddr,
    #[serde(default)]
    native_tls: Option<hangang::config::HopaeNativeTls>,
    gateway_key_env: String,
    upstream_token_env: String,
    #[serde(default = "cookie_name")]
    cookie: String,
    /// Stable opaque Hopae IDs -> existing Hangang usernames. Never email matching.
    accounts: HashMap<String, String>,
}
fn cookie_name() -> String {
    "__Host-hopae".into()
}
#[derive(Clone)]
struct Session {
    identity: String,
    handle: String,
    ip: std::net::IpAddr,
    ua: Option<String>,
    expires: Instant,
    lease: Arc<tokio::sync::Mutex<Option<Lease>>>,
}
struct Lease {
    token: HeaderValue,
    user: User,
    expires: Instant,
}
pub struct Sso {
    config: Config,
    native: Client,
    system: HeaderValue,
    origin: String,
    sessions: Mutex<HashMap<String, Session>>,
}
fn secret(value: String) -> Result<HeaderValue> {
    ensure!(
        (32..=4096).contains(&value.len()),
        "invalid SSO credential size"
    );
    let mut v = HeaderValue::from_str(&value)?;
    v.set_sensitive(true);
    Ok(v)
}
impl Sso {
    pub fn load(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let meta = f.metadata()?;
        ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0 && meta.len() <= 65536,
            "SSO configuration must be a private bounded regular file"
        );
        let mut bytes = Vec::new();
        Read::by_ref(&mut f).take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "SSO configuration too large");
        let config: Config = serde_json::from_slice(&bytes)?;
        let url = reqwest::Url::parse(&config.public_url)?;
        let local = url
            .host_str()
            .and_then(|h| h.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback());
        ensure!(
            url.scheme() == "https" || (url.scheme() == "http" && local),
            "SSO origin requires HTTPS or literal loopback"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && url.path() == "/",
            "SSO public_url must be an origin"
        );
        ensure!(
            (config.native_address.ip().is_loopback() || config.native_tls.is_some())
                && config.native_address.port() != 0,
            "remote SSO native peer requires mTLS"
        );
        ensure!(
            config.cookie.len() <= 64
                && !config.cookie.is_empty()
                && config
                    .cookie
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid SSO cookie name"
        );
        ensure!(
            !config.accounts.is_empty() && config.accounts.len() <= 256,
            "SSO requires explicit bounded account mappings"
        );
        for (id, name) in &config.accounts {
            ensure!(
                id.starts_with("u_") && id.len() <= 64,
                "invalid Hopae identity"
            );
            hangang::admin_users::validate_username(name)?;
        }
        let key =
            secret(std::env::var(&config.gateway_key_env).context("SSO gateway key unavailable")?)?;
        let token = std::env::var(&config.upstream_token_env)
            .context("SSO upstream credential unavailable")?;
        let system = secret(format!("Bearer {token}"))?;
        let native = Client::from_config(
            &hangang::config::HopaeNative {
                address: config.native_address,
                pool_size: 8,
                tls: config.native_tls.clone(),
            },
            key,
        )?;
        let origin = url.origin().ascii_serialization();
        Ok(Self {
            config,
            native,
            system,
            origin,
            sessions: Mutex::new(HashMap::new()),
        })
    }
    pub fn discovery(&self) -> serde_json::Value {
        serde_json::json!({"provider":"hopae","login_url":"/_hopae/login?return=%2Fui%2F%3Fsso%3Dhopae"})
    }
    pub fn exchange_allowed(&self, h: &HeaderMap) -> bool {
        let one = |name: &str| {
            let mut i = h.get_all(name).iter();
            let v = i.next().and_then(|v| v.to_str().ok());
            if i.next().is_some() { None } else { v }
        };
        one("origin") == Some(self.origin.as_str())
            && one("x-hangang-sso") == Some("1")
            && h.get("sec-fetch-site").is_none_or(|v| v == "same-origin")
    }
    fn handle(&self, h: &HeaderMap) -> Result<String> {
        let mut found = Vec::new();
        let mut size = 0;
        for v in h.get_all("cookie") {
            size += v.as_bytes().len();
            ensure!(size <= 8192, "SSO cookies too large");
            for part in v.to_str()?.split(';') {
                if let Some((name, value)) = part.trim().split_once('=')
                    && name == self.config.cookie
                {
                    found.push(value.to_owned());
                }
            }
        }
        ensure!(found.len() == 1, "native Hopae login required");
        let handle = found.pop().unwrap();
        ensure!(
            handle.len() <= 256 && !handle.is_empty(),
            "invalid Hopae handle"
        );
        Ok(handle)
    }
    async fn identity(&self, handle: &str, context: &ClientContext) -> Result<String> {
        let mut h = HeaderMap::new();
        for (n, v) in [
            ("x-hopae-contract", "1".to_owned()),
            ("x-original-url", format!("{}/ui/", self.origin)),
            ("x-original-method", "GET".into()),
            ("x-hangang-canonical-path", "/ui/".into()),
            ("x-hangang-route-id", "hangang-console-sso".into()),
            (
                "x-forwarded-host",
                self.origin.split_once("://").unwrap().1.to_owned(),
            ),
            (
                "x-forwarded-proto",
                reqwest::Url::parse(&self.origin)?.scheme().into(),
            ),
            ("x-forwarded-for", context.ip.to_string()),
            ("cookie", format!("{}={handle}", self.config.cookie)),
            ("accept", "application/json".into()),
        ] {
            let mut v = HeaderValue::from_str(&v)?;
            if n == "cookie" {
                v.set_sensitive(true);
            }
            h.insert(hyper::header::HeaderName::from_bytes(n.as_bytes())?, v);
        }
        if let Some(ua) = &context.user_agent {
            h.insert("user-agent", HeaderValue::from_str(ua)?);
        }
        let response =
            tokio::time::timeout(Duration::from_secs(2), self.native.verify(&h)).await??;
        ensure!(response.status() == 200, "Hopae session rejected");
        let id = response
            .headers()
            .get("x-forwarded-user")
            .context("Hopae identity missing")?
            .to_str()?;
        ensure!(
            self.config.accounts.contains_key(id),
            "Hopae identity is not mapped to a Hangang account"
        );
        Ok(id.into())
    }
    async fn lease(
        &self,
        session: &Session,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
    ) -> Result<(HeaderValue, User)> {
        let mut cached = session.lease.lock().await;
        if let Some(lease) = cached.as_ref().filter(|v| v.expires > Instant::now()) {
            return Ok((lease.token.clone(), lease.user.clone()));
        }
        let mut response = client
            .post(upstream.join("v1/auth/sso-lease")?)
            .header("authorization", self.system.clone())
            .json(&serde_json::json!({"username":self.config.accounts[&session.identity]}))
            .timeout(Duration::from_secs(2))
            .send()
            .await?;
        ensure!(
            response.status() == 200,
            "mapped Hangang account unavailable"
        );
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 16384,
                "SSO lease response too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        #[derive(Deserialize)]
        struct Reply {
            token: String,
            user: User,
        }
        let r: Reply = serde_json::from_slice(&bytes)?;
        ensure!(
            r.user.enabled
                && r.user
                    .username
                    .eq_ignore_ascii_case(&self.config.accounts[&session.identity]),
            "invalid Hangang identity"
        );
        let token = secret(format!("Bearer {}", r.token))?;
        let user = r.user;
        *cached = Some(Lease {
            token: token.clone(),
            user: user.clone(),
            expires: Instant::now() + Duration::from_secs(1),
        });
        Ok((token, user))
    }
    pub async fn exchange(
        &self,
        h: &HeaderMap,
        context: &ClientContext,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
    ) -> Result<serde_json::Value> {
        ensure!(
            self.exchange_allowed(h),
            "same-origin SSO exchange required"
        );
        let handle = self.handle(h)?;
        let identity = self.identity(&handle, context).await?;
        let session = Session {
            identity,
            handle,
            ip: context.ip,
            ua: context.user_agent.clone(),
            expires: Instant::now() + Duration::from_secs(28800),
            lease: Arc::new(tokio::sync::Mutex::new(None)),
        };
        let (_, user) = self.lease(&session, client, upstream).await?;
        let mut random = [0; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
        let token = format!(
            "hsso_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random)
        );
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.retain(|_, v| v.expires > Instant::now());
        ensure!(sessions.len() < 512, "SSO session capacity reached");
        sessions.insert(token.clone(), session);
        Ok(serde_json::json!({"token":token,"user":user,"expires_in_seconds":28800}))
    }
    pub async fn authorization(
        &self,
        token: &str,
        h: &HeaderMap,
        context: &ClientContext,
        client: &reqwest::Client,
        upstream: &reqwest::Url,
    ) -> Result<HeaderValue> {
        let session = self
            .sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
            .context("SSO session expired")?;
        ensure!(
            session.expires > Instant::now()
                && session.ip == context.ip
                && session.ua == context.user_agent
                && self.handle(h)? == session.handle,
            "SSO session binding rejected"
        );
        ensure!(
            self.identity(&session.handle, context).await? == session.identity,
            "SSO identity changed"
        );
        Ok(self.lease(&session, client, upstream).await?.0)
    }
    pub fn logout(&self, token: &str) {
        self.sessions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangang::hopae_wire;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    #[tokio::test]
    async fn native_identity_is_live_and_explicitly_mapped() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let allow = Arc::new(AtomicBool::new(true));
        let flag = allow.clone();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = [0; 16];
            socket.read_exact(&mut head).await.unwrap();
            let (id, len) = hopae_wire::parse_header(head).unwrap();
            assert_eq!(id, 0);
            let mut key = vec![0; len];
            socket.read_exact(&mut key).await.unwrap();
            assert_eq!(key, b"fixture-key-at-least-thirty-two-bytes");
            socket
                .write_all(&hopae_wire::frame_header(0, 1).unwrap())
                .await
                .unwrap();
            socket.write_all(&[1]).await.unwrap();
            loop {
                if socket.read_exact(&mut head).await.is_err() {
                    break;
                }
                let (id, len) = hopae_wire::parse_header(head).unwrap();
                let mut bytes = vec![0; len];
                socket.read_exact(&mut bytes).await.unwrap();
                let h = hopae_wire::decode_request(&bytes).unwrap();
                assert!(
                    h.iter()
                        .any(|(n, v)| n == "cookie" && v == b"__Host-hopae=fixture-handle")
                );
                let reply = hopae_wire::Reply {
                    status: if flag.load(Ordering::SeqCst) {
                        200
                    } else {
                        403
                    },
                    headers: vec![("x-forwarded-user".into(), b"u_fixture".to_vec())],
                    body: vec![],
                };
                let bytes = hopae_wire::encode_reply(&reply).unwrap();
                socket
                    .write_all(&hopae_wire::frame_header(id, bytes.len()).unwrap())
                    .await
                    .unwrap();
                socket.write_all(&bytes).await.unwrap();
            }
        });
        let config = Config {
            public_url: "https://console.example.test/".into(),
            native_address: address,
            native_tls: None,
            gateway_key_env: "FIXTURE".into(),
            upstream_token_env: "FIXTURE".into(),
            cookie: cookie_name(),
            accounts: HashMap::from([("u_fixture".into(), "operator".into())]),
        };
        let sso = Sso {
            config,
            native: Client::new(
                address,
                2,
                secret("fixture-key-at-least-thirty-two-bytes".into()).unwrap(),
            ),
            system: secret("fixture-system-at-least-thirty-two-bytes".into()).unwrap(),
            origin: "https://console.example.test".into(),
            sessions: Mutex::new(HashMap::new()),
        };
        let context = ClientContext {
            ip: "192.0.2.1".parse().unwrap(),
            user_agent: None,
        };
        assert_eq!(
            sso.identity("fixture-handle", &context).await.unwrap(),
            "u_fixture"
        );
        allow.store(false, Ordering::SeqCst);
        assert!(sso.identity("fixture-handle", &context).await.is_err());
        let mut h = HeaderMap::new();
        h.insert("origin", "https://console.example.test".parse().unwrap());
        h.insert("x-hangang-sso", "1".parse().unwrap());
        assert!(sso.exchange_allowed(&h));
        h.append("origin", "https://console.example.test".parse().unwrap());
        assert!(!sso.exchange_allowed(&h));
        let mut h = HeaderMap::new();
        h.insert("cookie", "__Host-hopae=a; __Host-hopae=b".parse().unwrap());
        assert!(sso.handle(&h).is_err());
        task.abort();
    }
}
