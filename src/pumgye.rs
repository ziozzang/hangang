//! Route-owned scope and clients for independent Pumgye authorization.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceGate {
    pub service_id: String,
    pub resource: String,
    pub actions: BTreeMap<String, String>,
}
impl ResourceGate {
    pub fn validate_remote(&self) -> Result<()> {
        let id = |v: &str| {
            !v.is_empty()
                && v.len() <= 128
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
        };
        ensure!(
            id(&self.service_id) && id(&self.resource),
            "invalid resource gate scope"
        );
        ensure!(
            !self.actions.is_empty() && self.actions.len() <= 16,
            "invalid resource method count"
        );
        for (method, action) in &self.actions {
            ensure!(
                !method.is_empty()
                    && method.len() <= 32
                    && method.bytes().all(|b| b.is_ascii_uppercase())
                    && id(action),
                "invalid resource method/action"
            );
        }
        Ok(())
    }
    pub fn validate(&self, policy: &pumgye_core::Policy) -> Result<()> {
        self.validate_remote()?;
        let resource = policy
            .resources
            .get(&self.resource)
            .ok_or_else(|| anyhow::anyhow!("unknown Pumgye resource"))?;
        ensure!(
            resource.service == self.service_id,
            "resource belongs to another service"
        );
        ensure!(
            self.actions
                .values()
                .all(|action| resource.actions.contains_key(action)),
            "unknown resource action"
        );
        Ok(())
    }
}
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
        b"0" if (kind == Some(b"service") || kind == Some(b"workload"))
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
    fn workload_identity_requires_canonical_nonhuman_subject_and_zero_assurance() {
        let mut headers = hyper::HeaderMap::new();
        let subject = format!("s_{}", "b".repeat(48));
        headers.insert("x-forwarded-user", subject.parse().unwrap());
        headers.insert("x-hopae-principal-kind", "workload".parse().unwrap());
        headers.insert("x-hopae-aal", "0".parse().unwrap());
        assert_eq!(identity(&headers), Some((subject.as_str(), 0)));
        for assurance in ["1", "2", "3"] {
            headers.insert("x-hopae-aal", assurance.parse().unwrap());
            assert!(identity(&headers).is_none());
        }
        headers.insert("x-hopae-aal", "0".parse().unwrap());
        headers.insert("x-forwarded-user", "u_operator".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.insert("x-forwarded-user", subject.parse().unwrap());
        headers.insert("x-hopae-principal-kind", "network".parse().unwrap());
        assert!(identity(&headers).is_none());
        headers.insert("x-hopae-principal-kind", "workload".parse().unwrap());
        headers.append("x-hopae-aal", "0".parse().unwrap());
        assert!(identity(&headers).is_none());
    }
    #[test]
    fn remote_authority_rejects_plaintext_and_scope_downgrades() {
        let mut authority:AuthorityConfig=serde_json::from_value(serde_json::json!({"decision_address":"127.0.0.1:9085","management_address":"127.0.0.1:9084","decision_token_env":"PUMGYE_DECISION_TOKEN","admin_token_env":"PUMGYE_ADMIN_TOKEN"})).unwrap();
        assert!(authority.validate().is_ok());
        authority.transport = DecisionTransport::Grpc;
        assert!(authority.validate().is_err());
        authority.transport = DecisionTransport::Native;
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
    fn native_service_dns_requires_tls_and_management_identity_match() {
        let mut authority: AuthorityConfig = serde_json::from_value(serde_json::json!({
            "decision_address":"pumgye.world.svc:9085", "management_address":"pumgye.world.svc:9084",
            "decision_token_env":"PUMGYE_DECISION_TOKEN", "admin_token_env":"PUMGYE_ADMIN_TOKEN"
        })).unwrap();
        assert!(authority.validate().is_err());
        authority.tls = Some(AuthorityTls {
            server_name: "pumgye.world.svc".into(),
            ca: "/tls/ca.pem".into(),
            certificate: "/tls/client.pem".into(),
            key: "/tls/client.key".into(),
        });
        assert!(authority.validate().is_ok());
        authority.tls.as_mut().unwrap().server_name = "other.world.svc".into();
        assert!(authority.validate().is_err());
    }
    #[test]
    fn resource_gate_validates_owner_service_actions_and_method_bounds() {
        let mut policy: pumgye_core::Policy = serde_json::from_value(serde_json::json!({
            "version":1,"information_classes":["internal"],
            "services":{"orders":{"permissions":["read"],"roles":{},"users":{},"networks":[]}},
            "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"}}}
        })).unwrap();
        let mut gate = ResourceGate {
            service_id: "orders".into(),
            resource: "db:orders".into(),
            actions: [("GET".into(), "select".into())].into(),
        };
        assert!(gate.validate(&policy).is_ok());
        gate.service_id = "billing".into();
        assert!(gate.validate(&policy).is_err());
        gate.service_id = "orders".into();
        gate.actions.insert("POST".into(), "drop".into());
        assert!(gate.validate(&policy).is_err());
        gate.actions.remove("POST");
        gate.actions.insert("get".into(), "select".into());
        assert!(gate.validate_remote().is_err());
        gate.actions.remove("get");
        policy.resources.clear();
        assert!(gate.validate(&policy).is_err());
        gate.actions.clear();
        assert!(gate.validate_remote().is_err());
    }

    #[test]
    fn owner_resource_catalog_survives_typed_roundtrip_and_enforces_assurance() {
        let value = serde_json::json!({
            "version":1,"information_classes":["internal"],
            "services":{"orders":{
                "permissions":["read"],"require_guard":true,
                "roles":{"reader":{"permissions":["read"],"information_classes":["internal"],"minimum_aal":1}},
                "users":{"fixture":["reader"]},
                "networks":[{"cidr":"192.0.2.0/24","roles":["reader"]}]
            }},
            "resources":{"db:orders":{"service":"orders","information_class":"internal","actions":{"select":"read"},"minimum_aal":2}}
        });
        let policy: pumgye_core::Policy = serde_json::from_value(value.clone()).unwrap();
        let serialized = serde_json::to_value(&policy).unwrap();
        assert_eq!(serialized["resources"], value["resources"]);
        let restored: pumgye_core::Policy = serde_json::from_value(serialized).unwrap();
        let compiled = restored.compile().unwrap();
        let ip = "192.0.2.10".parse().unwrap();
        for (aal, expected) in [
            (1, pumgye_core::Decision::AssuranceDenied),
            (2, pumgye_core::Decision::Allow),
        ] {
            assert_eq!(
                compiled.evaluate_resource(
                    "db:orders",
                    "select",
                    "fixture",
                    ip,
                    aal,
                    pumgye_core::GuardEvidence::EnforcedAllow
                ),
                pumgye_core::ResourceDecision::Decided(expected)
            );
        }
        assert_eq!(
            compiled.evaluate_resource(
                "db:orders",
                "drop",
                "fixture",
                ip,
                2,
                pumgye_core::GuardEvidence::EnforcedAllow
            ),
            pumgye_core::ResourceDecision::UnknownAction
        );
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionTransport {
    #[default]
    Native,
    Grpc,
}

/// Credentials remain in local service environment, never in configuration JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    #[serde(default)]
    pub transport: DecisionTransport,
    pub decision_address: pumgye_client::Endpoint,
    pub management_address: pumgye_client::Endpoint,
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
            self.transport != DecisionTransport::Grpc || self.tls.is_some(),
            "gRPC Pumgye requires mTLS"
        );
        self.decision_address.validate()?;
        self.management_address.validate()?;
        ensure!(
            self.tls.is_some()
                || (self.decision_address.is_loopback() && self.management_address.is_loopback()),
            "remote Pumgye requires mTLS"
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
            ensure!(
                self.management_address
                    .dns_name()
                    .is_none_or(|name| name.eq_ignore_ascii_case(&tls.server_name)),
                "Pumgye management Service DNS must match its TLS server name"
            );
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
enum DecisionClient {
    Native(std::sync::Arc<pumgye_client::Client>),
    Grpc(crate::pumgye_grpc_client::Client),
}
impl DecisionClient {
    fn revision(&self) -> u64 {
        match self {
            Self::Native(c) => c.revision(),
            Self::Grpc(c) => c.revision(),
        }
    }
    fn require_revision(&self, revision: u64) {
        match self {
            Self::Native(c) => c.require_revision(revision),
            Self::Grpc(c) => c.require_revision(revision),
        }
    }
    async fn decide(&self, q: &pumgye_protocol::Query<'_>) -> Result<pumgye_protocol::Reply> {
        match self {
            Self::Native(c) => c.decide(q).await,
            Self::Grpc(c) => c.decide(q).await,
        }
    }
    async fn decide_batch(
        &self,
        q: &[pumgye_protocol::Query<'_>],
    ) -> Result<Vec<pumgye_protocol::Reply>> {
        match self {
            Self::Native(c) => c.decide_batch(q).await,
            Self::Grpc(c) => c.decide_batch(q).await,
        }
    }
}
/// One domain authority runtime; policy and publication remain in the remote server.
pub struct AuthorityRuntime {
    pub config: AuthorityConfig,
    native: DecisionClient,
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
            builder = builder.identity(reqwest::Identity::from_pem(&identity)?);
            if let Some(address) = config.management_address.socket_addr() {
                builder = builder.resolve(&tls.server_name.to_ascii_lowercase(), address);
            } else {
                ensure!(
                    config
                        .management_address
                        .dns_name()
                        .is_some_and(|name| name.eq_ignore_ascii_case(&tls.server_name)),
                    "Pumgye management Service DNS must match its TLS server name"
                );
            }
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
        let native = match config.transport {
            DecisionTransport::Native => {
                DecisionClient::Native(std::sync::Arc::new(pumgye_client::Client::new(
                    config.decision_address.clone(),
                    tls,
                    decision,
                    config.pool_size,
                    std::time::Duration::from_millis(config.timeout_ms),
                    config.minimum_revision,
                )?))
            }
            DecisionTransport::Grpc => {
                DecisionClient::Grpc(crate::pumgye_grpc_client::Client::new(config, &decision)?)
            }
        };
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

    #[allow(clippy::too_many_arguments)]
    pub async fn authorize_resource(
        self: &std::sync::Arc<Self>,
        gate: &ResourceGate,
        method: &str,
        subject: &str,
        ip: std::net::IpAddr,
        aal: u8,
        guard: pumgye_core::GuardEvidence,
    ) -> Result<Option<u64>> {
        self.authorize_resource_typed(gate, method, subject, ip, aal, guard, false)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn authorize_workload_resource(
        self: &std::sync::Arc<Self>,
        gate: &ResourceGate,
        method: &str,
        subject: &str,
        ip: std::net::IpAddr,
        aal: u8,
        guard: pumgye_core::GuardEvidence,
    ) -> Result<Option<u64>> {
        anyhow::ensure!(aal == 0, "Workload point decision requires AAL0");
        self.authorize_resource_typed(gate, method, subject, ip, aal, guard, true)
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn authorize_resource_typed(
        self: &std::sync::Arc<Self>,
        gate: &ResourceGate,
        method: &str,
        subject: &str,
        ip: std::net::IpAddr,
        aal: u8,
        guard: pumgye_core::GuardEvidence,
        workload: bool,
    ) -> Result<Option<u64>> {
        let Some(action) = gate.actions.get(method) else {
            return Ok(None);
        };
        let DecisionClient::Grpc(client) = &self.native else {
            anyhow::bail!("resource authority requires gRPC");
        };
        self.start_watch();
        let query = crate::pumgye_grpc_client::ResourceQuery {
            service_id: &gate.service_id,
            resource: &gate.resource,
            action,
            subject,
            ip,
            aal,
            guard,
            minimum_revision: 0,
        };
        let reply = if workload {
            client.decide_workload_resource(&query).await?
        } else {
            client.decide_resource(&query).await?
        };
        self.success();
        Ok(
            (reply.decision
                == pumgye_core::ResourceDecision::Decided(pumgye_core::Decision::Allow))
            .then_some(reply.revision),
        )
    }

    /// Compare local observed policy/network floors without refreshing lease health.
    pub(crate) fn observed_permit_current(&self, permit: &crate::native_observed::Permit) -> bool {
        match &self.native {
            DecisionClient::Grpc(client) => client.observed_permit_current(permit),
            _ => false,
        }
    }
    pub fn authenticated_observation_current(
        &self,
        reply: &crate::pumgye_grpc_client::AuthenticatedReply,
    ) -> bool {
        match &self.native {
            DecisionClient::Grpc(client) => client.authenticated_observation_current(reply),
            DecisionClient::Native(_) => false,
        }
    }

    /// Fresh authenticated observation only; this is not a dispatch lease or permit.
    /// Resource ownership remains remote, while the route owns method/service scope.
    pub(crate) async fn issue_observed_permit(
        &self,
        query: &crate::pumgye_grpc_client::AuthenticatedQuery<'_>,
        authentication: &crate::native_observed::Authentication,
        pin: &crate::projection_permit::Pin,
        clock: std::sync::Arc<hangang_runtime::time::ReceiverClock>,
        rates: &hopae_grpc::receipt_time::ClockRates,
    ) -> Result<crate::native_observed::Permit> {
        let DecisionClient::Grpc(client) = &self.native else {
            anyhow::bail!("observed permission requires gRPC");
        };
        client
            .issue_observed_permit(query, authentication, pin, clock, rates)
            .await
    }
    pub async fn observe_authenticated_resource(
        &self,
        gate: &ResourceGate,
        method: &str,
        ip: std::net::IpAddr,
        request_sha256: [u8; 32],
        receipt: &crate::projection_receipt::CheckedServiceReceipt,
    ) -> Result<Option<crate::pumgye_grpc_client::AuthenticatedReply>> {
        self.observe_authenticated_resource_with_route(
            gate,
            method,
            ip,
            request_sha256,
            receipt,
            None,
        )
        .await
    }
    pub async fn observe_authenticated_resource_with_route(
        &self,
        gate: &ResourceGate,
        method: &str,
        ip: std::net::IpAddr,
        request_sha256: [u8; 32],
        receipt: &crate::projection_receipt::CheckedServiceReceipt,
        route: Option<&pumgye_grpc::v1::NativeRouteReference>,
    ) -> Result<Option<crate::pumgye_grpc_client::AuthenticatedReply>> {
        gate.validate_remote()?;
        ensure!(
            receipt.context().service == gate.service_id,
            "authenticated receipt belongs to another route service"
        );
        let Some(action) = gate.actions.get(method) else {
            return Ok(None);
        };
        let DecisionClient::Grpc(client) = &self.native else {
            anyhow::bail!("authenticated resource authority requires gRPC");
        };
        client
            .decide_authenticated_resource(
                &crate::pumgye_grpc_client::AuthenticatedQuery {
                    route,
                    resource: &gate.resource,
                    action,
                    ip,
                    minimum_revision: 0,
                    request_sha256,
                },
                receipt,
            )
            .await
            .map(Some)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn issue_projection_permit(
        &self,
        gate: &ResourceGate,
        method: &str,
        ip: std::net::IpAddr,
        request_sha256: [u8; 32],
        receipt: &crate::projection_receipt::CheckedServiceReceipt,
        route: Option<&pumgye_grpc::v1::NativeRouteReference>,
        pin: &crate::projection_permit::Pin,
    ) -> Result<(
        crate::pumgye_grpc_client::AuthenticatedReply,
        crate::projection_permit::CheckedPermit,
    )> {
        gate.validate_remote()?;
        ensure!(
            receipt.context().service == gate.service_id,
            "receipt service mismatch"
        );
        let action = gate
            .actions
            .get(method)
            .ok_or_else(|| anyhow::anyhow!("native route method unassigned"))?;
        let DecisionClient::Grpc(client) = &self.native else {
            anyhow::bail!("permit issuance requires gRPC");
        };
        client
            .issue_projection_permit(
                &crate::pumgye_grpc_client::AuthenticatedQuery {
                    route,
                    resource: &gate.resource,
                    action,
                    ip,
                    minimum_revision: 0,
                    request_sha256,
                },
                receipt,
                pin,
            )
            .await
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
