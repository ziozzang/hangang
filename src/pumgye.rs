//! Route-owned scope and clients for independent Pumgye authorization.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    pub service_id: String,
    pub information_class: String,
    pub permissions: BTreeMap<String, Vec<String>>,
}
impl Gate {
    pub fn validate(&self, policy: &pumgye_core::Policy) -> Result<()> {
        let service = policy
            .services
            .get(&self.service_id)
            .ok_or_else(|| anyhow::anyhow!("unknown Pumgye service"))?;
        ensure!(
            policy.information_classes.contains(&self.information_class),
            "unknown information class"
        );
        ensure!(
            !self.permissions.is_empty() && self.permissions.len() <= 16,
            "invalid method count"
        );
        for (method, permissions) in &self.permissions {
            ensure!(
                !method.is_empty()
                    && method.len() <= 32
                    && method.bytes().all(|b| b.is_ascii_uppercase()),
                "invalid permission method"
            );
            ensure!(
                !permissions.is_empty() && permissions.len() <= 64,
                "invalid permissions"
            );
            let mut seen = std::collections::BTreeSet::new();
            for permission in permissions {
                ensure!(
                    service.permissions.contains(permission) && seen.insert(permission),
                    "unknown or duplicate permission"
                );
            }
        }
        Ok(())
    }
}

/// Only call with authenticated native Hopae response headers.
pub fn identity(headers: &hyper::HeaderMap) -> Option<(&str, u8)> {
    let mut subjects = headers.get_all("x-forwarded-user").iter();
    let subject = subjects.next()?.to_str().ok()?;
    if subjects.next().is_some()
        || subject.is_empty()
        || subject.len() > 128
        || subject.chars().any(char::is_control)
    {
        return None;
    }
    let mut kinds = headers.get_all("x-hopae-principal-kind").iter();
    let kind = kinds.next().map(|v| v.as_bytes());
    if kinds.next().is_some() {
        return None;
    }
    let mut assurances = headers.get_all("x-hopae-aal").iter();
    let assurance = match assurances.next()?.as_bytes() {
        b"0" if kind == Some(b"service")
            && subject.len() == 50
            && subject.starts_with("s_")
            && subject.as_bytes()[2..]
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b)) =>
        {
            0
        }
        b"1" if (kind.is_none() || kind == Some(b"human")) && !subject.starts_with("s_") => 1,
        b"2" if (kind.is_none() || kind == Some(b"human")) && !subject.starts_with("s_") => 2,
        b"3" if (kind.is_none() || kind == Some(b"human")) && !subject.starts_with("s_") => 3,
        _ => return None,
    };
    if assurances.next().is_some() {
        return None;
    }
    Some((subject, assurance))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_identity_cannot_claim_human_assurance_or_reuse_human_subjects() {
        let mut headers = hyper::HeaderMap::new();
        let subject = format!("s_{}", "a".repeat(48));
        headers.insert("x-forwarded-user", subject.parse().unwrap());
        headers.insert("x-hopae-aal", "0".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.insert("x-hopae-principal-kind", "service".parse().unwrap());
        assert_eq!(identity(&headers), Some((subject.as_str(), 0)));
        headers.insert("x-hopae-aal", "2".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.insert("x-hopae-aal", "0".parse().unwrap());
        headers.insert("x-forwarded-user", "u_operator".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.insert("x-forwarded-user", subject.parse().unwrap());
        headers.append("x-hopae-principal-kind", "service".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.remove("x-hopae-principal-kind");
        headers.insert("x-forwarded-user", "u_operator".parse().unwrap());
        headers.insert("x-hopae-aal", "2".parse().unwrap());
        assert_eq!(identity(&headers), Some(("u_operator", 2)));
    }
    #[test]
    fn remote_authority_rejects_plaintext_and_scope_downgrades() {
        let mut authority:AuthorityConfig=serde_json::from_value(serde_json::json!({"decision_address":"127.0.0.1:9085","management_address":"127.0.0.1:9084","decision_token_env":"PUMGYE_DECISION_TOKEN","admin_token_env":"PUMGYE_ADMIN_TOKEN"})).unwrap();
        assert!(authority.validate().is_ok());
        authority.decision_address = "192.0.2.1:9085".parse().unwrap();
        assert!(authority.validate().is_err());
        authority.decision_address = "127.0.0.1:9085".parse().unwrap();
        authority.admin_token_env = authority.decision_token_env.clone();
        assert!(authority.validate().is_err());
        let mut gate = Gate {
            service_id: "orders".into(),
            information_class: "public".into(),
            permissions: BTreeMap::from([("GET".into(), vec!["read".into()])]),
        };
        assert!(gate.validate_remote().is_ok());
        gate.permissions
            .insert("POST".into(), vec!["read".into(), "read".into()]);
        assert!(gate.validate_remote().is_err());
        gate.permissions.remove("POST");
        gate.service_id = "client/request".into();
        assert!(gate.validate_remote().is_err());
    }
    #[test]
    fn route_scope_rejects_undefined_rights_and_empty_methods() {
        let policy: pumgye_core::Policy = serde_json::from_value(serde_json::json!({
            "version":1,"information_classes":["internal"],"services":{"orders":{
                "permissions":["read"],"roles":{},"users":{},"networks":[]
            }}
        }))
        .unwrap();
        let mut gate = Gate {
            service_id: "orders".into(),
            information_class: "internal".into(),
            permissions: BTreeMap::from([("GET".into(), vec!["read".into()])]),
        };
        assert!(gate.validate(&policy).is_ok());
        gate.permissions.insert("POST".into(), vec!["write".into()]);
        assert!(gate.validate(&policy).is_err());
        gate.permissions.remove("POST");
        gate.information_class = "unknown".into();
        assert!(gate.validate(&policy).is_err());
        gate.information_class = "internal".into();
        gate.permissions.clear();
        assert!(gate.validate(&policy).is_err());
    }
}

/// Credentials remain in local service environment, never in configuration JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    pub decision_address: std::net::SocketAddr,
    pub management_address: std::net::SocketAddr,
    pub decision_token_env: String,
    pub admin_token_env: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<AuthorityTls>,
    #[serde(default = "default_pool")]
    pub pool_size: usize,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_revision")]
    pub minimum_revision: u64,
}
fn default_pool() -> usize {
    64
}
fn default_timeout() -> u64 {
    100
}
fn default_revision() -> u64 {
    1
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityTls {
    pub server_name: String,
    pub ca: std::path::PathBuf,
    pub certificate: std::path::PathBuf,
    pub key: std::path::PathBuf,
}
impl AuthorityConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.tls.is_some()
                || (self.decision_address.ip().is_loopback()
                    && self.management_address.ip().is_loopback()),
            "remote Pumgye requires mTLS"
        );
        ensure!(
            !self.decision_address.ip().is_unspecified()
                && !self.management_address.ip().is_unspecified()
                && !self.decision_address.ip().is_multicast()
                && !self.management_address.ip().is_multicast(),
            "invalid Pumgye endpoint address"
        );
        ensure!(
            self.decision_address.port() > 0 && self.management_address.port() > 0,
            "Pumgye requires fixed listener ports"
        );
        ensure!(
            (1..=1024).contains(&self.pool_size)
                && (1..=1000).contains(&self.timeout_ms)
                && (1..=i64::MAX as u64).contains(&self.minimum_revision),
            "invalid Pumgye pool, deadline or revision"
        );
        for name in [&self.decision_token_env, &self.admin_token_env] {
            ensure!(
                !name.is_empty()
                    && name.len() <= 128
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
                "invalid Pumgye credential reference"
            );
        }
        ensure!(
            self.decision_token_env != self.admin_token_env,
            "Pumgye credentials must be separate"
        );
        if let Some(tls) = &self.tls {
            ensure!(
                !tls.server_name.is_empty()
                    && tls.server_name.len() <= 253
                    && tls
                        .server_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
                "invalid Pumgye TLS server name"
            );
            rustls::pki_types::ServerName::try_from(tls.server_name.clone())?;
            for path in [&tls.ca, &tls.certificate, &tls.key] {
                ensure!(!path.as_os_str().is_empty(), "missing Pumgye TLS path");
            }
        }
        Ok(())
    }
}
impl Gate {
    pub fn validate_remote(&self) -> Result<()> {
        let id = |v: &str| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
        };
        ensure!(
            id(&self.service_id) && id(&self.information_class),
            "invalid Pumgye service/class scope"
        );
        ensure!(
            !self.permissions.is_empty() && self.permissions.len() <= 16,
            "invalid method count"
        );
        for (method, permissions) in &self.permissions {
            ensure!(
                !method.is_empty()
                    && method.len() <= 32
                    && method.bytes().all(|b| b.is_ascii_uppercase()),
                "invalid permission method"
            );
            ensure!(
                !permissions.is_empty() && permissions.len() <= 64,
                "invalid permission count"
            );
            let mut seen = std::collections::BTreeSet::new();
            ensure!(
                permissions.iter().all(|p| id(p) && seen.insert(p)),
                "invalid or duplicate permission"
            );
        }
        Ok(())
    }
}
/// One domain authority runtime; policy and publication remain in the remote server.
pub struct AuthorityRuntime {
    pub config: AuthorityConfig,
    native: std::sync::Arc<pumgye_client::Client>,
    management: reqwest::Client,
    base_url: reqwest::Url,
    admin: Option<hyper::header::HeaderValue>,
    started: std::sync::atomic::AtomicBool,
    healthy: std::sync::atomic::AtomicBool,
    epoch: std::time::Instant,
    last_success_ms: std::sync::atomic::AtomicU64,
}
impl AuthorityRuntime {
    pub fn prepare(config: &AuthorityConfig) -> Result<std::sync::Arc<Self>> {
        use anyhow::Context;
        config.validate()?;
        fn token(name: &str) -> Result<String> {
            let value = std::env::var(name)
                .map_err(|_| anyhow::anyhow!("Pumgye credential reference unavailable"))?;
            ensure!(
                (16..=4096).contains(&value.len())
                    && value.bytes().all(|b| (0x21..=0x7e).contains(&b)),
                "invalid Pumgye credential"
            );
            Ok(value)
        }
        let decision = token(&config.decision_token_env)?;
        let admin = if std::env::var_os(&config.admin_token_env).is_some() {
            Some(token(&config.admin_token_env)?)
        } else {
            None
        };
        ensure!(
            admin.as_ref().is_none_or(|admin| *admin != decision),
            "Pumgye credentials must be distinct"
        );
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5));
        let (tls, base_url) = if let Some(tls) = &config.tls {
            let native = pumgye_client::Tls::from_files(
                &tls.server_name,
                &tls.ca,
                &tls.certificate,
                &tls.key,
            )
            .context("Pumgye TLS configuration rejected")?;
            let ca = crate::tls::read_bounded(&tls.ca)?;
            builder = builder.tls_built_in_root_certs(false);
            for cert in reqwest::Certificate::from_pem_bundle(&ca)? {
                builder = builder.add_root_certificate(cert);
            }
            let mut identity = crate::tls::read_bounded(&tls.certificate)?;
            identity.push(b'\n');
            identity.extend(crate::tls::read_bounded(&tls.key)?);
            builder = builder
                .identity(reqwest::Identity::from_pem(&identity)?)
                .resolve(
                    &tls.server_name.to_ascii_lowercase(),
                    config.management_address,
                );
            (
                Some(native),
                reqwest::Url::parse(&format!(
                    "https://{}:{}/",
                    tls.server_name,
                    config.management_address.port()
                ))?,
            )
        } else {
            (
                None,
                reqwest::Url::parse(&format!("http://{}/", config.management_address))?,
            )
        };
        let native = std::sync::Arc::new(pumgye_client::Client::new(
            config.decision_address,
            tls,
            decision,
            config.pool_size,
            std::time::Duration::from_millis(config.timeout_ms),
            config.minimum_revision,
        )?);
        let admin = admin
            .map(|value| {
                let mut header = hyper::header::HeaderValue::from_str(&format!("Bearer {value}"))?;
                header.set_sensitive(true);
                Ok::<_, anyhow::Error>(header)
            })
            .transpose()?;
        Ok(std::sync::Arc::new(Self {
            config: config.clone(),
            native,
            management: builder.build()?,
            base_url,
            admin,
            started: std::sync::atomic::AtomicBool::new(false),
            healthy: std::sync::atomic::AtomicBool::new(false),
            epoch: std::time::Instant::now(),
            last_success_ms: std::sync::atomic::AtomicU64::new(0),
        }))
    }
    fn success(&self) {
        use std::sync::atomic::Ordering;
        self.last_success_ms.store(
            self.epoch.elapsed().as_millis() as u64 + 1,
            Ordering::Release,
        );
        self.healthy.store(true, Ordering::Release);
    }
    fn start_watch(self: &std::sync::Arc<Self>) {
        use std::sync::atomic::Ordering;
        if self.started.load(Ordering::Relaxed)
            || self
                .started
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return;
        }
        let weak = std::sync::Arc::downgrade(self);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(500));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let Some(active) = weak.upgrade() else { break };
                let q = pumgye_protocol::Query {
                    request_id: 0,
                    minimum_revision: 0,
                    ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    aal: 0,
                    guard: pumgye_core::GuardEvidence::Unavailable,
                    service_id: "__pumgye_health",
                    subject: "__gateway_probe",
                    permission: "__health",
                    information_class: "public",
                };
                if active.native.decide(&q).await.is_ok() {
                    active.success();
                } else {
                    active.healthy.store(false, Ordering::Release);
                }
            }
        });
    }
    pub fn lease_current(&self, revision: u64) -> bool {
        use std::sync::atomic::Ordering;
        let last = self.last_success_ms.load(Ordering::Acquire);
        last > 0
            && self.healthy.load(Ordering::Acquire)
            && self.native.revision() == revision
            && (self.epoch.elapsed().as_millis() as u64 + 1).saturating_sub(last) <= 1000
    }
    pub fn revision(&self) -> u64 {
        self.native.revision()
    }
    pub fn require_revision(&self, revision: u64) {
        self.native.require_revision(revision);
    }
    pub async fn authorize(
        self: &std::sync::Arc<Self>,
        gate: &Gate,
        method: &str,
        subject: &str,
        ip: std::net::IpAddr,
        aal: u8,
        guard: pumgye_core::GuardEvidence,
    ) -> Result<Option<u64>> {
        let Some(permissions) = gate.permissions.get(method) else {
            return Ok(None);
        };
        self.start_watch();
        if let [permission] = permissions.as_slice() {
            let query = pumgye_protocol::Query {
                request_id: 0,
                minimum_revision: 0,
                ip,
                aal,
                guard,
                service_id: &gate.service_id,
                subject,
                permission,
                information_class: &gate.information_class,
            };
            let reply = self.native.decide(&query).await?;
            self.success();
            return Ok(
                (reply.decision == Some(pumgye_core::Decision::Allow)).then_some(reply.revision)
            );
        }
        let queries = permissions
            .iter()
            .map(|permission| pumgye_protocol::Query {
                request_id: 0,
                minimum_revision: 0,
                ip,
                aal,
                guard,
                service_id: &gate.service_id,
                subject,
                permission,
                information_class: &gate.information_class,
            })
            .collect::<Vec<_>>();
        let replies = self.native.decide_batch(&queries).await?;
        self.success();
        Ok(replies
            .iter()
            .all(|r| r.decision == Some(pumgye_core::Decision::Allow))
            .then(|| replies[0].revision))
    }

    /// Fixed owning-domain paths only; never forwards client URLs or credentials.
    pub async fn management(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        expected: Option<u64>,
        after_revision: Option<u64>,
    ) -> Result<(u16, Vec<u8>)> {
        ensure!(
            matches!(path, "v1/policy" | "v1/status" | "v1/audit")
                && (method == reqwest::Method::GET
                    || (path == "v1/policy" && method == reqwest::Method::PUT)),
            "invalid Pumgye management operation"
        );
        let mut url = self.base_url.join(path)?;
        if let Some(after) = after_revision {
            ensure!(
                path == "v1/audit" && after <= i64::MAX as u64,
                "invalid audit cursor"
            );
            url.query_pairs_mut()
                .append_pair("after_revision", &after.to_string());
        }
        let mut request = self.management.request(method, url).header(
            hyper::header::AUTHORIZATION,
            self.admin
                .clone()
                .ok_or_else(|| anyhow::anyhow!("Pumgye management credential unavailable"))?,
        );
        if let Some(body) = body {
            ensure!(body.len() <= 1024 * 1024, "policy exceeds bound");
            request = request
                .header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body);
        }
        if let Some(expected) = expected {
            request = request.header(hyper::header::IF_MATCH, format!("\"{expected}\""));
        }
        let mut response = request.send().await?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 1024 * 1024,
                "Pumgye response exceeds bound"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, bytes))
    }
}

#[derive(Debug)]
pub struct AuthorityScopeChanged;
impl std::fmt::Display for AuthorityScopeChanged {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Pumgye authority configuration changed")
    }
}
impl std::error::Error for AuthorityScopeChanged {}
