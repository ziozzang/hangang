//! Zero-trust protection for Kubernetes-declared routes (ADR 0022 P0, first
//! slice): the `ProtectionPolicy` kind of `world.hangang.dev/v1alpha1`.
//!
//! A policy attaches to Ingress objects of the controller's class by
//! `spec.targetRefs` (Gateway API direct policy attachment) or, with
//! `spec.namespaceDefault: true`, to every Ingress of its namespace that no
//! policy targets. It names an operator-approved Hopae identity profile, a
//! Pumgye service/resource/action mapping, and whether network enforcement
//! (Sumunjang admission and Pumgye network conditions) is required.
//!
//! Every decision here is a pure function of the cached objects and the
//! operator settings, so replicas with different event histories reach the
//! same routes and the same status. Anything that cannot be enforced as
//! declared withholds the Ingress (fail closed); nothing is ever published
//! with weaker protection than its policy asks for.
use crate::config::{AccessMode, Config, ExternalAuth, HttpRoute};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const GROUP: &str = "world.hangang.dev";
pub const VERSION: &str = "v1alpha1";
pub const KIND: &str = "ProtectionPolicy";
pub const PLURAL: &str = "protectionpolicies";
/// Gateway API `controllerName` written into policy ancestor status.
pub const CONTROLLER_NAME: &str = "hangang.dev/gateway-controller";
pub const INGRESS_GROUP: &str = "networking.k8s.io";
pub const GATEWAY_GROUP: &str = "gateway.networking.k8s.io";
/// Gateway API caps `status.ancestors` at 16 entries.
const MAX_ANCESTORS: usize = 16;
const MAX_TARGET_REFS: usize = 16;
const MAX_ACTIONS: usize = 16;
const MAX_MESSAGE: usize = 1024;
/// Rows kept in the console diagnostics report.
const MAX_REPORT_ROWS: usize = 1000;
const MAX_PROFILES: usize = 64;

// ---------------------------------------------------------------------------
// Operator settings (`--kubernetes-protection-config`)
// ---------------------------------------------------------------------------

/// Operator-owned protection settings. Tenants choose among these; they never
/// supply authentication endpoints, credentials or authority addresses.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Withhold every selected Ingress without an effective policy. On by
    /// default; turning it off is an explicit, documented migration step.
    #[serde(default = "enabled")]
    pub require_protection: bool,
    /// Hopae authentication profiles by name (`spec.identity.profileRef`).
    pub identity_profiles: BTreeMap<String, IdentityProfile>,
    /// Independent Pumgye decision authority used by every protected route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pumgye_authority: Option<crate::pumgye::AuthorityConfig>,
    /// Optional restriction: Pumgye service ID to the namespaces allowed to
    /// bind it. Absent means any namespace may name any service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pumgye_services: Option<BTreeMap<String, Vec<String>>>,
    /// How the gateway learns the real client address.
    #[serde(default)]
    pub client_address: ClientAddress,
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProfile {
    /// Namespaces allowed to reference the profile; empty allows every one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub namespaces: Vec<String>,
    /// Native Hopae external authorization template copied into each route.
    pub auth: ExternalAuth,
}

/// Client address preservation mode (ADR 0022 Decision 4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientAddress {
    /// Nothing preserves the client address: kube-proxy SNAT hides it.
    #[default]
    None,
    /// The gateway's own Service must be `LoadBalancer` or `NodePort` with
    /// `externalTrafficPolicy: Local`. Checked from the watched Service.
    ServiceLocal { namespace: String, name: String },
    /// PROXY protocol v2 from an explicitly trusted load balancer CIDR list
    /// (`--proxy-protocol-from`).
    ProxyProtocol,
    /// The gateway runs with `hostNetwork` on a bare-metal edge.
    HostNetwork,
}

/// Facts about this gateway process that a policy may depend on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayFacts {
    /// Sumunjang admission is configured (`--guard-url`).
    pub guard_configured: bool,
    /// Per-request query mode that fails closed: snapshot mode expires open,
    /// and `--guard-failure-mode allow` admits on failure.
    pub guard_enforcing: bool,
    /// PROXY protocol v2 is accepted on the public listener.
    pub proxy_protocol: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    pub settings: Settings,
    pub facts: GatewayFacts,
}

impl Settings {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("read protection settings {}", path.display()))?;
        ensure!(
            bytes.len() <= 1024 * 1024,
            "protection settings exceed 1 MiB"
        );
        let settings: Self = serde_json::from_slice(&bytes).context("parse protection settings")?;
        settings.validate()?;
        Ok(settings)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.identity_profiles.is_empty() && self.identity_profiles.len() <= MAX_PROFILES,
            "protection settings need 1..64 identity profiles"
        );
        let authority = self
            .pumgye_authority
            .as_ref()
            .context("protection settings need pumgye_authority")?;
        ensure!(
            authority.transport == crate::pumgye::DecisionTransport::Grpc
                && authority.tls.is_some(),
            "protection pumgye_authority must use gRPC with mTLS"
        );
        authority.validate()?;
        for (name, profile) in &self.identity_profiles {
            ensure!(dns_label(name), "invalid identity profile name {name:?}");
            ensure!(
                profile.namespaces.len() <= 1024
                    && profile.namespaces.iter().all(|ns| dns_label(ns)),
                "identity profile {name}: invalid namespace list"
            );
            ensure!(
                profile.auth.native_resource.is_none() && !profile.auth.terminal_response,
                "identity profile {name}: native_resource and terminal_response are route specific"
            );
            // Compile a probe route so an unusable profile fails at startup,
            // not on the first tenant policy.
            let compiled = Compiled {
                policy: ("probe".into(), "probe".into()),
                auth: profile.auth.clone(),
                gate: crate::pumgye::ResourceGate {
                    service_id: "probe".into(),
                    resource: "probe".into(),
                    actions: BTreeMap::from([("GET".into(), "read".into())]),
                },
            };
            let mut route: HttpRoute = serde_json::from_value(serde_json::json!({
                "id": "probe", "path_prefix": "/", "backends": ["http://probe.default.svc:80"]
            }))?;
            compiled.protect(&mut route);
            Config {
                http: vec![route],
                pumgye_authority: Some(authority.clone()),
                ..Config::default()
            }
            .validate()
            .with_context(|| format!("identity profile {name} cannot protect a route"))?;
        }
        if let Some(services) = &self.pumgye_services {
            ensure!(services.len() <= 4096, "too many pumgye_services entries");
            for (service, namespaces) in services {
                ensure!(id(service), "invalid Pumgye service ID {service:?}");
                ensure!(
                    namespaces.len() <= 1024 && namespaces.iter().all(|ns| dns_label(ns)),
                    "pumgye_services {service}: invalid namespace list"
                );
            }
        }
        if let ClientAddress::ServiceLocal { namespace, name } = &self.client_address {
            ensure!(
                dns_label(namespace) && dns_subdomain(name),
                "invalid client_address Service"
            );
        }
        Ok(())
    }
}

impl Options {
    pub fn validate(&self) -> Result<()> {
        self.settings.validate()?;
        ensure!(
            self.settings.client_address != ClientAddress::ProxyProtocol
                || self.facts.proxy_protocol,
            "client_address proxy_protocol requires --proxy-protocol-from on the public listener"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProtectionPolicy objects
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Spec {
    #[serde(default)]
    target_refs: Vec<TargetRef>,
    #[serde(default)]
    namespace_default: bool,
    identity: Identity,
    authorization: Authorization,
    #[serde(default)]
    network: Network,
    #[serde(default)]
    failure_mode: FailureMode,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TargetRef {
    pub group: String,
    pub kind: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
}
impl TargetRef {
    fn is_ingress(&self) -> bool {
        self.group == INGRESS_GROUP && self.kind == "Ingress"
    }
    fn validate(&self) -> Result<()> {
        match self.kind.as_str() {
            "Ingress" => {
                ensure!(
                    self.group == INGRESS_GROUP,
                    "Ingress targets use group networking.k8s.io"
                );
                ensure!(
                    self.section_name.is_none(),
                    "Ingress targets have no sections"
                );
            }
            "HTTPRoute" | "Gateway" => ensure!(
                self.group == GATEWAY_GROUP,
                "{} targets use group gateway.networking.k8s.io",
                self.kind
            ),
            other => anyhow::bail!("unsupported target kind {other:?}"),
        }
        ensure!(dns_subdomain(&self.name), "invalid target name");
        if let Some(section) = &self.section_name {
            ensure!(dns_subdomain(section), "invalid target sectionName");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Identity {
    profile_ref: LocalRef,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalRef {
    name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authorization {
    pumgye: PumgyeBinding,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct PumgyeBinding {
    service_id: String,
    resource: String,
    /// HTTP method to Pumgye action; unlisted methods are denied.
    actions: Vec<ActionMapping>,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionMapping {
    method: String,
    action: String,
}
impl PumgyeBinding {
    fn action_map(&self) -> BTreeMap<String, String> {
        self.actions
            .iter()
            .map(|mapping| (mapping.method.clone(), mapping.action.clone()))
            .collect()
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    #[serde(default)]
    enforcement: Enforcement,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
enum Enforcement {
    /// Sumunjang admission and Pumgye network conditions must see the real
    /// client address. The secure default.
    #[default]
    Required,
    /// Identity and authorization only; no network condition is claimed.
    None,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
enum FailureMode {
    #[default]
    Closed,
}

type ObjectKey = (String, String);

/// A parsed policy, or why it could not be parsed.
#[derive(Clone, Debug)]
struct Parsed {
    key: ObjectKey,
    generation: Option<i64>,
    age: (bool, String, bool, String),
    /// Best-effort targets even for an invalid policy, so that an invalid
    /// policy aimed at an Ingress withholds it instead of failing open.
    targets: Vec<TargetRef>,
    namespace_default: bool,
    spec: std::result::Result<Spec, String>,
}

fn parse(object: &Value) -> Option<Parsed> {
    let namespace = object.pointer("/metadata/namespace")?.as_str()?.to_owned();
    let name = object.pointer("/metadata/name")?.as_str()?.to_owned();
    let spec_value = object.get("spec").cloned().unwrap_or(Value::Null);
    let targets: Vec<TargetRef> = spec_value
        .get("targetRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_TARGET_REFS)
        .filter_map(|target| serde_json::from_value(target.clone()).ok())
        .collect();
    let namespace_default = spec_value
        .get("namespaceDefault")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let spec = serde_json::from_value::<Spec>(spec_value)
        .map_err(|error| bounded(&format!("invalid spec: {error}")))
        .and_then(|spec| {
            validate_spec(&spec)
                .map(|()| spec)
                .map_err(|e| bounded(&e.to_string()))
        });
    let created = object
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let uid = object
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(Parsed {
        key: (namespace, name),
        generation: object
            .pointer("/metadata/generation")
            .and_then(Value::as_i64),
        age: (
            created.is_none(),
            created.unwrap_or_default(),
            uid.is_none(),
            uid.unwrap_or_default(),
        ),
        targets,
        namespace_default,
        spec,
    })
}

/// Controller-side mirror of the CRD's structural schema and CEL rules: the
/// API server may run without them (older CRD, validation disabled), and a
/// policy the controller does not fully understand must never protect less.
fn validate_spec(spec: &Spec) -> Result<()> {
    ensure!(
        spec.target_refs.len() <= MAX_TARGET_REFS,
        "at most 16 targetRefs"
    );
    if spec.namespace_default {
        ensure!(
            spec.target_refs.is_empty(),
            "a namespace default policy has no targetRefs"
        );
    } else {
        ensure!(
            !spec.target_refs.is_empty(),
            "targetRefs are required unless namespaceDefault is true"
        );
    }
    let mut unique = BTreeSet::new();
    for target in &spec.target_refs {
        target.validate()?;
        ensure!(unique.insert(target), "duplicate targetRef");
    }
    ensure!(
        dns_label(&spec.identity.profile_ref.name),
        "invalid identity.profileRef.name"
    );
    let pumgye = &spec.authorization.pumgye;
    ensure!(
        id(&pumgye.service_id) && id(&pumgye.resource),
        "invalid authorization.pumgye serviceId or resource"
    );
    ensure!(
        !pumgye.actions.is_empty() && pumgye.actions.len() <= MAX_ACTIONS,
        "authorization.pumgye.actions needs 1..16 methods"
    );
    let mut methods = BTreeSet::new();
    for ActionMapping { method, action } in &pumgye.actions {
        ensure!(
            (1..=32).contains(&method.len()) && method.bytes().all(|b| b.is_ascii_uppercase()),
            "invalid HTTP method {method:?}"
        );
        ensure!(methods.insert(method), "duplicate HTTP method {method}");
        ensure!(id(action), "invalid Pumgye action {action:?}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compiled protection
// ---------------------------------------------------------------------------

/// Protection compiled from one policy for one Ingress.
#[derive(Clone, Debug, PartialEq)]
pub struct Compiled {
    pub policy: ObjectKey,
    pub auth: ExternalAuth,
    pub gate: crate::pumgye::ResourceGate,
}
impl Compiled {
    /// Turn a generated route into a protected one: Hopae authentication,
    /// then a Pumgye resource decision before any backend dispatch. The
    /// resource ID is derived from the route's scope so that moving a scope
    /// always goes through an explicit release (see [`release_plan`]).
    pub fn protect(&self, route: &mut HttpRoute) {
        route.access_mode = AccessMode::Protected;
        route.auth = Some(self.auth.clone());
        route.resource_policy = Some(crate::resource_policy::ResourcePolicy {
            pumgye: None,
            pumgye_resource: Some(self.gate.clone()),
            resource_id: resource_id(route),
            enforce: true,
            principal: crate::resource_policy::PrincipalSource::External {
                subject_header: "x-forwarded-user".into(),
            },
            allow: Vec::new(),
        });
    }
}

/// How the generated routes of one admitted Ingress are classified.
#[derive(Clone, Debug, PartialEq)]
pub enum RouteProtection {
    /// Deliberately unprotected (`require_protection: false`, no policy).
    Public,
    Protected(Arc<Compiled>),
}

/// The protection input of one Ingress conversion.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Protections {
    /// Admitted Ingresses; an Ingress absent from the map is withheld.
    pub routes: BTreeMap<ObjectKey, RouteProtection>,
    pub pumgye_authority: Option<crate::pumgye::AuthorityConfig>,
}

fn resource_id(route: &HttpRoute) -> String {
    use sha2::{Digest, Sha256};
    let scope = serde_json::json!([
        route.id,
        route.host,
        route.hosts,
        route.path_prefix,
        route.path_match,
    ]);
    let digest = Sha256::digest(scope.to_string().as_bytes());
    let hash: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    let prefix: String = route.id.chars().take(100).collect();
    format!("{prefix}:{hash}")
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Why an Ingress was not given protection, as a condition reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Withheld {
    pub reason: &'static str,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Decision {
    Protected(Arc<Compiled>),
    Public,
    Withheld(Withheld),
}

/// Per-target outcome recorded on a policy.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TargetFinding {
    target: TargetRef,
    accepted: (bool, &'static str, String),
    resolved: (bool, &'static str, String),
    /// `None` when programming depends on admission (the Ingress was
    /// handed to route generation); otherwise the refusal.
    programmed: Option<(&'static str, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyFinding {
    generation: Option<i64>,
    invalid: Option<String>,
    network_required: bool,
    targets: Vec<TargetFinding>,
    /// Ancestors beyond the 16 reported entries.
    truncated: usize,
}

/// Complete protection outcome of one candidate snapshot.
#[derive(Clone, Debug, PartialEq)]
pub struct Resolution {
    pub decisions: BTreeMap<ObjectKey, Decision>,
    /// Which policy (if any) applies to each selected Ingress.
    pub attached: BTreeMap<ObjectKey, ObjectKey>,
    policies: BTreeMap<ObjectKey, PolicyFinding>,
    pub client_address: std::result::Result<(), String>,
    pub require_protection: bool,
    pub facts: GatewayFacts,
}
impl Resolution {
    /// The protection input for route generation.
    pub fn protections(&self, options: &Options) -> Protections {
        Protections {
            routes: self
                .decisions
                .iter()
                .filter_map(|(key, decision)| match decision {
                    Decision::Protected(compiled) => {
                        Some((key.clone(), RouteProtection::Protected(compiled.clone())))
                    }
                    Decision::Public => Some((key.clone(), RouteProtection::Public)),
                    Decision::Withheld(_) => None,
                })
                .collect(),
            pumgye_authority: options.settings.pumgye_authority.clone(),
        }
    }
}

/// Inputs from the controller cache.
pub struct Inputs<'a> {
    /// Selected Ingress identities (class match, valid identity).
    pub ingresses: &'a BTreeSet<ObjectKey>,
    pub policies: Vec<&'a Value>,
    /// Looks up a cached Service by namespace/name.
    pub service: &'a dyn Fn(&str, &str) -> Option<&'a Value>,
}

/// Decide protection for every selected Ingress and record the per-policy
/// findings that status is written from.
pub fn resolve(options: &Options, inputs: Inputs<'_>) -> Resolution {
    let settings = &options.settings;
    let client_address = client_address_preserved(settings, options.facts, inputs.service);
    let mut parsed: Vec<Parsed> = inputs.policies.iter().filter_map(|p| parse(p)).collect();
    // Oldest first, so reports and truncation are stable.
    parsed.sort_by(|a, b| a.age.cmp(&b.age).then_with(|| a.key.cmp(&b.key)));

    // Every policy that names an Ingress, valid or not, by Ingress.
    let mut targeting: BTreeMap<ObjectKey, Vec<usize>> = BTreeMap::new();
    let mut defaults: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, policy) in parsed.iter().enumerate() {
        if policy.namespace_default && policy.targets.is_empty() {
            defaults
                .entry(policy.key.0.clone())
                .or_default()
                .push(index);
            continue;
        }
        let names: BTreeSet<&str> = policy
            .targets
            .iter()
            .filter(|t| t.is_ingress())
            .map(|t| t.name.as_str())
            .collect();
        for name in names {
            targeting
                .entry((policy.key.0.clone(), name.to_owned()))
                .or_default()
                .push(index);
        }
    }

    let mut resolution = Resolution {
        decisions: BTreeMap::new(),
        attached: BTreeMap::new(),
        policies: BTreeMap::new(),
        client_address: client_address.clone(),
        require_protection: settings.require_protection,
        facts: options.facts,
    };
    // Ingress -> applying policy index, or a conflict.
    let mut by_policy: BTreeMap<usize, Vec<ObjectKey>> = BTreeMap::new();
    let mut conflicted: BTreeMap<usize, Vec<(ObjectKey, Vec<ObjectKey>)>> = BTreeMap::new();
    for ingress in inputs.ingresses {
        let candidates: Vec<usize> = match targeting.get(ingress) {
            Some(direct) => direct.clone(),
            None => defaults.get(&ingress.0).cloned().unwrap_or_default(),
        };
        let decision = match candidates.as_slice() {
            [] if settings.require_protection => Decision::Withheld(Withheld {
                reason: "ProtectionRequired",
                message: "no ProtectionPolicy targets this Ingress and its namespace has no default policy; require_protection withholds it".into(),
            }),
            [] => Decision::Public,
            [single] => {
                by_policy.entry(*single).or_default().push(ingress.clone());
                resolution
                    .attached
                    .insert(ingress.clone(), parsed[*single].key.clone());
                decide(&parsed[*single], ingress, options, &client_address)
            }
            several => {
                let names: Vec<ObjectKey> = several.iter().map(|i| parsed[*i].key.clone()).collect();
                for index in several {
                    conflicted
                        .entry(*index)
                        .or_default()
                        .push((ingress.clone(), names.clone()));
                }
                Decision::Withheld(Withheld {
                    reason: "Conflicted",
                    message: bounded(&format!(
                        "{} policies apply ({}); ambiguous attachments are refused",
                        names.len(),
                        names.iter().map(|k| k.1.as_str()).collect::<Vec<_>>().join(", ")
                    )),
                })
            }
        };
        resolution.decisions.insert(ingress.clone(), decision);
    }

    for (index, policy) in parsed.iter().enumerate() {
        let mut finding = PolicyFinding {
            generation: policy.generation,
            invalid: policy.spec.as_ref().err().cloned(),
            network_required: policy
                .spec
                .as_ref()
                .is_ok_and(|spec| spec.network.enforcement == Enforcement::Required),
            targets: Vec::new(),
            truncated: 0,
        };
        let targets: Vec<TargetRef> = if policy.namespace_default {
            let mut applied: BTreeSet<ObjectKey> = by_policy
                .get(&index)
                .into_iter()
                .flatten()
                .cloned()
                .collect();
            applied.extend(
                conflicted
                    .get(&index)
                    .into_iter()
                    .flatten()
                    .map(|(ingress, _)| ingress.clone()),
            );
            applied
                .into_iter()
                .map(|(_, name)| TargetRef {
                    group: INGRESS_GROUP.into(),
                    kind: "Ingress".into(),
                    name,
                    section_name: None,
                })
                .collect()
        } else {
            policy.targets.clone()
        };
        for target in targets {
            if finding.targets.len() == MAX_ANCESTORS {
                finding.truncated += 1;
                continue;
            }
            finding.targets.push(target_finding(
                policy,
                &target,
                index,
                &resolution,
                &conflicted,
                inputs.ingresses,
            ));
        }
        resolution.policies.insert(policy.key.clone(), finding);
    }
    resolution
}

fn target_finding(
    policy: &Parsed,
    target: &TargetRef,
    index: usize,
    resolution: &Resolution,
    conflicted: &BTreeMap<usize, Vec<(ObjectKey, Vec<ObjectKey>)>>,
    ingresses: &BTreeSet<ObjectKey>,
) -> TargetFinding {
    let ok = |reason: &'static str| (true, reason, String::new());
    let mut finding = TargetFinding {
        target: target.clone(),
        accepted: ok("Accepted"),
        resolved: ok("ResolvedRefs"),
        programmed: None,
    };
    if let Err(message) = &policy.spec {
        finding.accepted = (false, "Invalid", message.clone());
        finding.resolved = (false, "Invalid", "the policy is invalid".into());
        finding.programmed = Some((
            "Invalid",
            "the policy is invalid; a targeted Ingress is withheld".into(),
        ));
        return finding;
    }
    if !target.is_ingress() {
        let message = format!(
            "{} attachment is not implemented by this release; nothing is programmed for it",
            target.kind
        );
        finding.accepted = (false, "Unsupported", message.clone());
        finding.programmed = Some(("Unsupported", message));
        return finding;
    }
    let key = (policy.key.0.clone(), target.name.clone());
    if !ingresses.contains(&key) {
        let message =
            "no Ingress of this controller's class with this name exists in the policy's namespace"
                .to_owned();
        finding.accepted = (false, "TargetNotFound", message.clone());
        finding.programmed = Some(("TargetNotFound", message));
        return finding;
    }
    if let Some((_, names)) = conflicted
        .get(&index)
        .into_iter()
        .flatten()
        .find(|(ingress, _)| *ingress == key)
    {
        let message = bounded(&format!(
            "policies {} all apply to this Ingress; it is withheld until exactly one applies",
            names
                .iter()
                .map(|k| k.1.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        finding.accepted = (false, "Conflicted", message.clone());
        finding.programmed = Some(("Conflicted", message));
        return finding;
    }
    match resolution.decisions.get(&key) {
        Some(Decision::Withheld(withheld)) => {
            if matches!(
                withheld.reason,
                "InvalidIdentityProfile" | "RefNotPermitted" | "AuthorityUnavailable"
            ) {
                finding.resolved = (false, withheld.reason, withheld.message.clone());
            }
            finding.programmed = Some((withheld.reason, withheld.message.clone()));
        }
        Some(_) => {}
        None => {
            finding.programmed = Some(("TargetNotFound", "the Ingress is not selected".into()));
        }
    }
    finding
}

fn decide(
    policy: &Parsed,
    ingress: &ObjectKey,
    options: &Options,
    client_address: &std::result::Result<(), String>,
) -> Decision {
    let withheld = |reason: &'static str, message: String| {
        Decision::Withheld(Withheld {
            reason,
            message: bounded(&message),
        })
    };
    let spec = match &policy.spec {
        Ok(spec) => spec,
        Err(message) => {
            return withheld(
                "Invalid",
                format!("ProtectionPolicy {} is invalid: {message}", policy.key.1),
            );
        }
    };
    let settings = &options.settings;
    let name = &spec.identity.profile_ref.name;
    let Some(profile) = settings.identity_profiles.get(name) else {
        return withheld(
            "InvalidIdentityProfile",
            format!("identity profile {name:?} is not configured on this gateway"),
        );
    };
    if !profile.namespaces.is_empty() && !profile.namespaces.contains(&ingress.0) {
        return withheld(
            "RefNotPermitted",
            format!(
                "identity profile {name:?} is not permitted in namespace {}",
                ingress.0
            ),
        );
    }
    let binding = &spec.authorization.pumgye;
    if let Some(services) = &settings.pumgye_services
        && !services
            .get(&binding.service_id)
            .is_some_and(|namespaces| namespaces.contains(&ingress.0))
    {
        return withheld(
            "RefNotPermitted",
            format!(
                "Pumgye service {:?} is not permitted in namespace {}",
                binding.service_id, ingress.0
            ),
        );
    }
    if settings.pumgye_authority.is_none() {
        return withheld(
            "AuthorityUnavailable",
            "no Pumgye authority is configured".into(),
        );
    }
    if spec.network.enforcement == Enforcement::Required {
        if !(options.facts.guard_configured && options.facts.guard_enforcing) {
            return withheld(
                "GuardUnavailable",
                "network enforcement is required but Sumunjang admission is not configured in fail-closed query mode (--guard-url, --guard-mode query, --guard-failure-mode deny)".into(),
            );
        }
        if let Err(message) = client_address {
            return withheld("ClientAddressUnavailable", message.clone());
        }
    }
    Decision::Protected(Arc::new(Compiled {
        policy: policy.key.clone(),
        auth: profile.auth.clone(),
        gate: crate::pumgye::ResourceGate {
            service_id: binding.service_id.clone(),
            resource: binding.resource.clone(),
            actions: binding.action_map(),
        },
    }))
}

fn client_address_preserved<'a>(
    settings: &Settings,
    facts: GatewayFacts,
    service: &'a dyn Fn(&str, &str) -> Option<&'a Value>,
) -> std::result::Result<(), String> {
    match &settings.client_address {
        ClientAddress::None => Err("client address preservation is not configured (client_address mode none): kube-proxy SNAT hides the real client address".into()),
        ClientAddress::HostNetwork => Ok(()),
        ClientAddress::ProxyProtocol if facts.proxy_protocol => Ok(()),
        ClientAddress::ProxyProtocol => Err("PROXY protocol is not enabled on the public listener".into()),
        ClientAddress::ServiceLocal { namespace, name } => {
            let Some(object) = service(namespace, name) else {
                return Err(format!("gateway Service {namespace}/{name} is not in the watched set"));
            };
            let kind = object.pointer("/spec/type").and_then(Value::as_str).unwrap_or("ClusterIP");
            let policy = object
                .pointer("/spec/externalTrafficPolicy")
                .and_then(Value::as_str)
                .unwrap_or("Cluster");
            if matches!(kind, "LoadBalancer" | "NodePort") && policy == "Local" {
                Ok(())
            } else {
                Err(format!(
                    "gateway Service {namespace}/{name} is type {kind} with externalTrafficPolicy {policy}; LoadBalancer or NodePort with Local is required"
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn condition(
    kind: &str,
    status: bool,
    reason: &str,
    message: &str,
    generation: Option<i64>,
) -> Value {
    let mut value = serde_json::json!({
        "type": kind,
        "status": if status { "True" } else { "False" },
        "reason": reason,
        "message": bounded(message),
    });
    if let Some(generation) = generation {
        value["observedGeneration"] = generation.into();
    }
    value
}

impl Resolution {
    /// The status this controller wants on `policy`, given the Ingresses the
    /// published snapshot admitted. Ancestor entries of other controllers
    /// are preserved. `None` for an object the resolution did not see.
    pub fn desired_status(&self, policy: &Value, admitted: &BTreeSet<ObjectKey>) -> Option<Value> {
        let key = (
            policy.pointer("/metadata/namespace")?.as_str()?.to_owned(),
            policy.pointer("/metadata/name")?.as_str()?.to_owned(),
        );
        let finding = self.policies.get(&key)?;
        let generation = finding.generation;
        let mut ancestors: Vec<Value> = policy
            .pointer("/status/ancestors")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|entry| {
                entry.get("controllerName").and_then(Value::as_str) != Some(CONTROLLER_NAME)
            })
            .cloned()
            .collect();
        let mut programmed_all = !finding.targets.is_empty();
        let mut first_failure: Option<(&'static str, String)> = None;
        for target in &finding.targets {
            let ingress = (key.0.clone(), target.target.name.clone());
            let programmed = match &target.programmed {
                Some((reason, message)) => (false, *reason, message.clone()),
                None if admitted.contains(&ingress) => (true, "Programmed", String::new()),
                None => (false, "Pending", "the Ingress was withdrawn by route validation, hostname ownership, TLS, or the route budget; see the controller log".to_owned()),
            };
            if !programmed.0 {
                programmed_all = false;
                first_failure.get_or_insert((programmed.1, programmed.2.clone()));
            }
            let mut reference = serde_json::json!({
                "group": target.target.group,
                "kind": target.target.kind,
                "name": target.target.name,
                "namespace": key.0,
            });
            if let Some(section) = &target.target.section_name {
                reference["sectionName"] = section.clone().into();
            }
            ancestors.push(serde_json::json!({
                "ancestorRef": reference,
                "controllerName": CONTROLLER_NAME,
                "conditions": [
                    condition("Accepted", target.accepted.0, target.accepted.1, &target.accepted.2, generation),
                    condition("ResolvedRefs", target.resolved.0, target.resolved.1, &target.resolved.2, generation),
                    condition("Programmed", programmed.0, programmed.1, &programmed.2, generation),
                ],
            }));
        }
        ancestors.truncate(MAX_ANCESTORS);
        let accepted = if let Some(message) = &finding.invalid {
            (false, "Invalid", message.clone())
        } else if let Some(target) = finding
            .targets
            .iter()
            .find(|t| t.accepted.1 == "Conflicted")
        {
            (false, "Conflicted", target.accepted.2.clone())
        } else if finding.targets.is_empty() {
            (
                false,
                "TargetNotFound",
                "the policy applies to no Ingress of this controller's class".to_owned(),
            )
        } else if finding.targets.iter().all(|t| !t.accepted.0) {
            let first = &finding.targets[0];
            (false, first.accepted.1, first.accepted.2.clone())
        } else {
            (true, "Accepted", String::new())
        };
        let resolved = finding
            .targets
            .iter()
            .find(|t| !t.resolved.0)
            .map(|t| (false, t.resolved.1, t.resolved.2.clone()))
            .unwrap_or((true, "ResolvedRefs", String::new()));
        let programmed = if programmed_all {
            let message = if finding.truncated > 0 {
                format!(
                    "{} further Ingresses are not listed in ancestors",
                    finding.truncated
                )
            } else {
                String::new()
            };
            (true, "Programmed", message)
        } else {
            let (reason, message) = first_failure
                .unwrap_or(("TargetNotFound", "the policy applies to no Ingress".into()));
            (false, reason, message)
        };
        let mut conditions = vec![
            condition("Accepted", accepted.0, accepted.1, &accepted.2, generation),
            condition(
                "ResolvedRefs",
                resolved.0,
                resolved.1,
                &resolved.2,
                generation,
            ),
            condition(
                "Programmed",
                programmed.0,
                programmed.1,
                &programmed.2,
                generation,
            ),
        ];
        if finding.network_required {
            conditions.push(match &self.client_address {
                Ok(()) => condition(
                    "ClientAddressPreserved",
                    true,
                    "ClientAddressPreserved",
                    "",
                    generation,
                ),
                Err(message) => condition(
                    "ClientAddressPreserved",
                    false,
                    "ClientAddressUnavailable",
                    message,
                    generation,
                ),
            });
        }
        let mut status = serde_json::json!({ "conditions": conditions, "ancestors": ancestors });
        if let Some(generation) = generation {
            status["observedGeneration"] = generation.into();
        }
        Some(carry_transition_times(policy.get("status"), status))
    }
}

/// Stamp `lastTransitionTime`: kept from the current status when a
/// condition's status did not change, otherwise now. Replicas therefore do
/// not fight over timestamps.
fn carry_transition_times(current: Option<&Value>, mut desired: Value) -> Value {
    let now = rfc3339_now();
    let previous = |path: &[&str], kind: &str| -> Option<(Value, Value)> {
        let mut node = current?;
        for part in path {
            node = node.get(part)?;
        }
        node.as_array()?
            .iter()
            .find(|c| c.get("type").and_then(Value::as_str) == Some(kind))
            .map(|c| (c["status"].clone(), c["lastTransitionTime"].clone()))
    };
    let stamp = |list: &mut Value, lookup: &dyn Fn(&str) -> Option<(Value, Value)>| {
        for condition in list.as_array_mut().into_iter().flatten() {
            let kind = condition["type"].as_str().unwrap_or_default().to_owned();
            let time = match lookup(&kind) {
                Some((status, time)) if status == condition["status"] && time.is_string() => time,
                _ => Value::String(now.clone()),
            };
            condition["lastTransitionTime"] = time;
        }
    };
    stamp(&mut desired["conditions"], &|kind| {
        previous(&["conditions"], kind)
    });
    let current_ancestors: Vec<Value> = current
        .and_then(|status| status.get("ancestors"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for ancestor in desired["ancestors"].as_array_mut().into_iter().flatten() {
        if ancestor.get("controllerName").and_then(Value::as_str) != Some(CONTROLLER_NAME) {
            continue;
        }
        let reference = ancestor["ancestorRef"].clone();
        let existing = current_ancestors
            .iter()
            .find(|entry| {
                entry["ancestorRef"] == reference
                    && entry.get("controllerName").and_then(Value::as_str) == Some(CONTROLLER_NAME)
            })
            .cloned();
        stamp(&mut ancestor["conditions"], &|kind| {
            existing
                .as_ref()?
                .get("conditions")?
                .as_array()?
                .iter()
                .find(|c| c.get("type").and_then(Value::as_str) == Some(kind))
                .map(|c| (c["status"].clone(), c["lastTransitionTime"].clone()))
        });
    }
    desired
}

/// Whether two statuses agree on everything but timestamps.
pub fn same_status(current: Option<&Value>, desired: &Value) -> bool {
    fn strip(value: &Value) -> Value {
        match value {
            Value::Object(fields) => Value::Object(
                fields
                    .iter()
                    .filter(|(key, _)| key.as_str() != "lastTransitionTime")
                    .map(|(key, value)| (key.clone(), strip(value)))
                    .collect(),
            ),
            Value::Array(items) => Value::Array(items.iter().map(strip).collect()),
            other => other.clone(),
        }
    }
    current.is_some_and(|current| strip(current) == strip(desired))
}

pub fn rfc3339_now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339(seconds)
}
fn rfc3339(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

// ---------------------------------------------------------------------------
// Diagnostics (console + metrics)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Report {
    pub require_protection: bool,
    pub client_address_preserved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_address_message: Option<String>,
    pub guard_configured: bool,
    pub guard_enforcing: bool,
    pub counts: Counts,
    pub ingresses: Vec<IngressRow>,
    pub policies: Vec<PolicyRow>,
    /// Rows omitted beyond the report bound.
    pub truncated: usize,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub protected: u64,
    pub unprotected: u64,
    pub withheld: u64,
    pub invalid_policies: u64,
    pub conflicted_policies: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct IngressRow {
    pub namespace: String,
    pub name: String,
    /// `protected`, `unprotected` or `withheld`.
    pub state: &'static str,
    /// Whether the published snapshot serves the Ingress.
    pub published: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PolicyRow {
    pub namespace: String,
    pub name: String,
    pub accepted: bool,
    pub reason: String,
}

impl Resolution {
    pub fn report(&self, admitted: &BTreeSet<ObjectKey>) -> Report {
        let mut report = Report {
            require_protection: self.require_protection,
            client_address_preserved: self.client_address.is_ok(),
            client_address_message: self.client_address.as_ref().err().cloned(),
            guard_configured: self.facts.guard_configured,
            guard_enforcing: self.facts.guard_enforcing,
            ..Report::default()
        };
        for (key, decision) in &self.decisions {
            let (state, reason, message) = match decision {
                Decision::Protected(_) => {
                    report.counts.protected += 1;
                    ("protected", None, None)
                }
                Decision::Public => {
                    report.counts.unprotected += 1;
                    ("unprotected", None, None)
                }
                Decision::Withheld(withheld) => {
                    report.counts.withheld += 1;
                    (
                        "withheld",
                        Some(withheld.reason),
                        Some(withheld.message.clone()),
                    )
                }
            };
            if report.ingresses.len() == MAX_REPORT_ROWS {
                report.truncated += 1;
                continue;
            }
            report.ingresses.push(IngressRow {
                namespace: key.0.clone(),
                name: key.1.clone(),
                state,
                published: admitted.contains(key),
                policy: self.attached.get(key).map(|p| p.1.clone()),
                reason,
                message,
            });
        }
        for (key, finding) in &self.policies {
            let conflicted = finding.targets.iter().any(|t| t.accepted.1 == "Conflicted");
            if finding.invalid.is_some() {
                report.counts.invalid_policies += 1;
            }
            if conflicted {
                report.counts.conflicted_policies += 1;
            }
            if report.policies.len() == MAX_REPORT_ROWS {
                report.truncated += 1;
                continue;
            }
            let (accepted, reason) = if finding.invalid.is_some() {
                (false, "Invalid")
            } else if conflicted {
                (false, "Conflicted")
            } else if finding.targets.iter().any(|t| t.accepted.0) {
                (true, "Accepted")
            } else {
                (false, "TargetNotFound")
            };
            report.policies.push(PolicyRow {
                namespace: key.0.clone(),
                name: key.1.clone(),
                accepted,
                reason: reason.into(),
            });
        }
        report
    }
}

/// Latest report of this process, shared with the administration API and
/// metrics. Absent when Kubernetes protection is disabled.
#[derive(Default)]
pub struct Diagnostics {
    report: std::sync::Mutex<Option<Arc<Report>>>,
}
impl Diagnostics {
    pub fn publish(&self, report: Report) {
        *self
            .report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(report));
    }
    pub fn current(&self) -> Option<Arc<Report>> {
        self.report
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub fn render(&self, out: &mut String) {
        let Some(report) = self.current() else {
            return;
        };
        for (name, help, value) in [
            (
                "kubernetes_ingresses_protected",
                "Selected Ingresses published with a ProtectionPolicy.",
                report.counts.protected,
            ),
            (
                "kubernetes_ingresses_unprotected",
                "Selected Ingresses deliberately published without protection (require_protection off).",
                report.counts.unprotected,
            ),
            (
                "kubernetes_ingresses_withheld",
                "Selected Ingresses withheld because protection is missing, ambiguous or cannot be enforced.",
                report.counts.withheld,
            ),
            (
                "kubernetes_protection_policies_invalid",
                "ProtectionPolicy objects rejected as invalid.",
                report.counts.invalid_policies,
            ),
            (
                "kubernetes_protection_policies_conflicted",
                "ProtectionPolicy objects with an ambiguous attachment.",
                report.counts.conflicted_policies,
            ),
        ] {
            out.push_str(&format!(
                "# HELP hangang_{name} {help}\n# TYPE hangang_{name} gauge\nhangang_{name} {value}\n"
            ));
        }
        out.push_str(&format!(
            "# HELP hangang_kubernetes_client_address_preserved Whether network-conditioned policies can see the real client address.\n# TYPE hangang_kubernetes_client_address_preserved gauge\nhangang_kubernetes_client_address_preserved {}\n",
            u8::from(report.client_address_preserved)
        ));
    }
}

// ---------------------------------------------------------------------------
// Release of protected scopes
// ---------------------------------------------------------------------------

/// An enforced resource scope may only disappear after a revision that keeps
/// it with `enforce: false` (see `Config::validate_transition_from`). In
/// Kubernetes mode the API objects are the authority, so deleting or moving
/// a protected Ingress is an explicit release: this builds the intermediate
/// revision that keeps each released scope as a **disabled** route with
/// `enforce: false` (it serves no traffic), to be followed immediately by
/// `next`. `None` when `next` can replace `previous` directly.
pub fn release_plan(previous: &Config, next: &Config) -> Option<Config> {
    let mut intermediate = next.clone();
    let mut ids: BTreeSet<String> = next.http.iter().map(|route| route.id.clone()).collect();
    let mut released = false;
    for old in &previous.http {
        let Some(policy) = old.resource_policy.as_ref().filter(|policy| policy.enforce) else {
            continue;
        };
        let kept = next.http.iter().any(|new| {
            new.resource_policy.as_ref().is_some_and(|next| {
                next.resource_id == policy.resource_id
                    && (!policy.has_pumgye() || next.has_pumgye())
            }) && new.host == old.host
                && new.hosts == old.hosts
                && new.path_prefix == old.path_prefix
                && new.path_match == old.path_match
                && new.path_case_insensitive() == old.path_case_insensitive()
                && crate::config::effective_public_listeners(new)
                    == crate::config::effective_public_listeners(old)
        });
        if kept {
            continue;
        }
        let mut tombstone = old.clone();
        tombstone.enabled = false;
        if let Some(policy) = tombstone.resource_policy.as_mut() {
            policy.enforce = false;
        }
        let mut id = old.id.clone();
        let mut attempt = 0u32;
        while ids.contains(&id) {
            attempt += 1;
            let stem: String = old.id.chars().take(100).collect();
            id = format!("{stem}.released{attempt}");
        }
        ids.insert(id.clone());
        tombstone.id = id;
        intermediate.http.push(tombstone);
        released = true;
    }
    if !released {
        return None;
    }
    if intermediate.pumgye_authority.is_none() {
        intermediate.pumgye_authority = previous.pumgye_authority.clone();
    }
    Some(intermediate)
}

// ---------------------------------------------------------------------------

fn bounded(message: &str) -> String {
    if message.len() <= MAX_MESSAGE {
        return message.to_owned();
    }
    let mut end = MAX_MESSAGE;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &message[..end])
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}
fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
fn dns_subdomain(value: &str) -> bool {
    !value.is_empty() && value.len() <= 253 && value.split('.').all(dns_label)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tls() -> Value {
        serde_json::json!({"server_name":"owned.example.test","ca":"/owned/ca.pem","certificate":"/owned/client.pem","key":"/owned/client.key"})
    }
    fn auth() -> Value {
        serde_json::json!({"url":"https://hopae.example.test/_hopae/verify",
            "native":{"transport":"grpc","address":"127.0.0.1:9001","tls":tls()},
            "request_headers":["authorization","cookie"],
            "response_headers":["x-forwarded-user","x-hopae-aal","x-hopae-principal-kind"],
            "static_request_headers":{"x-hopae-gateway-key":{"env":"HOPAE_GATEWAY_KEY"},"x-hopae-contract":"1"}})
    }
    fn settings_value() -> Value {
        serde_json::json!({
            "identity_profiles":{"corp":{"auth":auth()},"payroll-only":{"namespaces":["payroll"],"auth":auth()}},
            "pumgye_authority":{"transport":"grpc","decision_address":"127.0.0.1:9002","management_address":"127.0.0.1:9003",
                "tls":tls(),"decision_token_env":"PUMGYE_DECISION_TOKEN","admin_token_env":"PUMGYE_ADMIN_TOKEN"},
            "client_address":{"mode":"service_local","namespace":"edge","name":"hangang"}
        })
    }
    fn options_with(settings: Value, facts: GatewayFacts) -> Options {
        let settings: Settings = serde_json::from_value(settings).unwrap();
        settings.validate().unwrap();
        Options { settings, facts }
    }
    fn enforcing() -> GatewayFacts {
        GatewayFacts {
            guard_configured: true,
            guard_enforcing: true,
            proxy_protocol: false,
        }
    }
    fn options() -> Options {
        options_with(settings_value(), enforcing())
    }
    fn policy(namespace: &str, name: &str, targets: &[&str]) -> Value {
        let targets: Vec<Value> = targets
            .iter()
            .map(|t| serde_json::json!({"group":"networking.k8s.io","kind":"Ingress","name":t}))
            .collect();
        serde_json::json!({
            "apiVersion":"world.hangang.dev/v1alpha1","kind":"ProtectionPolicy",
            "metadata":{"namespace":namespace,"name":name,"uid":format!("uid-{name}"),"generation":3,
                "creationTimestamp":"2026-01-01T00:00:00Z","resourceVersion":"7"},
            "spec":{"targetRefs":targets,"identity":{"profileRef":{"name":"corp"}},
                "authorization":{"pumgye":{"serviceId":"orders","resource":"http:orders","actions":[{"method":"GET","action":"read"},{"method":"POST","action":"write"}]}}}
        })
    }
    fn default_policy(namespace: &str, name: &str) -> Value {
        let mut value = policy(namespace, name, &[]);
        value["spec"].as_object_mut().unwrap().remove("targetRefs");
        value["spec"]["namespaceDefault"] = true.into();
        value
    }
    fn gateway_service(kind: &str, traffic: &str) -> Value {
        serde_json::json!({"metadata":{"namespace":"edge","name":"hangang"},"spec":{"type":kind,"externalTrafficPolicy":traffic}})
    }
    fn keys(list: &[(&str, &str)]) -> BTreeSet<ObjectKey> {
        list.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }
    fn run(
        options: &Options,
        ingresses: &[(&str, &str)],
        policies: &[Value],
        service: Option<Value>,
    ) -> Resolution {
        let ingresses = keys(ingresses);
        let lookup = move |namespace: &str, name: &str| {
            service
                .as_ref()
                .filter(|_| (namespace, name) == ("edge", "hangang"))
                .map(|s| Box::leak(Box::new(s.clone())) as &Value)
        };
        resolve(
            options,
            Inputs {
                ingresses: &ingresses,
                policies: policies.iter().collect(),
                service: &lookup,
            },
        )
    }
    fn key(namespace: &str, name: &str) -> ObjectKey {
        (namespace.to_owned(), name.to_owned())
    }
    fn withheld(resolution: &Resolution, ingress: ObjectKey) -> &'static str {
        match resolution.decisions.get(&ingress) {
            Some(Decision::Withheld(w)) => w.reason,
            other => panic!("expected withheld, got {other:?}"),
        }
    }
    fn local_lb() -> Option<Value> {
        Some(gateway_service("LoadBalancer", "Local"))
    }

    #[test]
    fn settings_require_grpc_mtls_authority_and_route_capable_profiles() {
        options();
        let mut bad = settings_value();
        bad["pumgye_authority"]["transport"] = "native".into();
        assert!(
            serde_json::from_value::<Settings>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut bad = settings_value();
        bad["identity_profiles"]["corp"]["auth"]["response_headers"] =
            serde_json::json!(["x-forwarded-user"]);
        assert!(
            serde_json::from_value::<Settings>(bad)
                .unwrap()
                .validate()
                .is_err(),
            "Pumgye needs Hopae assurance evidence"
        );
        let mut bad = settings_value();
        bad["identity_profiles"]["corp"]["auth"]["terminal_response"] = true.into();
        assert!(
            serde_json::from_value::<Settings>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut bad = settings_value();
        bad["unexpected"] = true.into();
        assert!(serde_json::from_value::<Settings>(bad).is_err());
        let settings: Settings = serde_json::from_value(settings_value()).unwrap();
        assert!(
            settings.require_protection,
            "protection is required by default"
        );
        let proxy = Options {
            settings: Settings {
                client_address: ClientAddress::ProxyProtocol,
                ..settings
            },
            facts: enforcing(),
        };
        assert!(
            proxy.validate().is_err(),
            "proxy_protocol mode needs the listener"
        );
    }

    #[test]
    fn unprotected_ingresses_are_withheld_when_protection_is_required() {
        let resolution = run(&options(), &[("blue", "app")], &[], local_lb());
        assert_eq!(
            withheld(&resolution, key("blue", "app")),
            "ProtectionRequired"
        );
        let mut relaxed = settings_value();
        relaxed["require_protection"] = false.into();
        let resolution = run(
            &options_with(relaxed, enforcing()),
            &[("blue", "app")],
            &[],
            local_lb(),
        );
        assert_eq!(resolution.decisions[&key("blue", "app")], Decision::Public);
        let report = resolution.report(&BTreeSet::new());
        assert_eq!(report.counts.unprotected, 1);
    }

    #[test]
    fn targeted_policy_compiles_hopae_and_pumgye_into_every_generated_route() {
        let options = options();
        let resolution = run(
            &options,
            &[("blue", "app")],
            &[policy("blue", "p", &["app"])],
            local_lb(),
        );
        let Decision::Protected(compiled) = &resolution.decisions[&key("blue", "app")] else {
            panic!("expected protection");
        };
        assert_eq!(compiled.gate.service_id, "orders");
        let protections = resolution.protections(&options);
        let document = serde_json::json!({"items":[
            {"kind":"Service","metadata":{"name":"api","namespace":"blue"},"spec":{"ports":[{"port":80}]}},
            {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"app","namespace":"blue"},
             "spec":{"ingressClassName":"hangang","defaultBackend":{"service":{"name":"api","port":{"number":80}}},
                "rules":[{"host":"app.example.test","http":{"paths":[{"path":"/api","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}},
            {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"other","namespace":"blue"},
             "spec":{"ingressClassName":"hangang","rules":[{"host":"other.example.test","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}}
        ]});
        let (config, admitted) =
            crate::ingress::import_validated(&document, "hangang", Some(&protections)).unwrap();
        assert_eq!(
            admitted,
            keys(&[("blue", "app")]),
            "the Ingress without a decision is withheld"
        );
        assert_eq!(config.http.len(), 2);
        for route in &config.http {
            assert_eq!(route.access_mode, AccessMode::Protected);
            assert!(
                route
                    .auth
                    .as_ref()
                    .is_some_and(|auth| auth.native.is_some())
            );
            let policy = route.resource_policy.as_ref().unwrap();
            assert!(policy.enforce);
            assert_eq!(
                policy.pumgye_resource.as_ref().unwrap().resource,
                "http:orders"
            );
        }
        assert_ne!(
            config.http[0].resource_policy.as_ref().unwrap().resource_id,
            config.http[1].resource_policy.as_ref().unwrap().resource_id
        );
        assert!(config.pumgye_authority.is_some());
        config.validate().unwrap();
    }

    #[test]
    fn namespace_default_applies_only_where_no_policy_targets() {
        let mut targeted = policy("blue", "strict", &["a"]);
        targeted["spec"]["authorization"]["pumgye"]["serviceId"] = "strict".into();
        let resolution = run(
            &options(),
            &[("blue", "a"), ("blue", "b"), ("green", "c")],
            &[default_policy("blue", "default"), targeted],
            local_lb(),
        );
        let service = |ingress| match &resolution.decisions[&ingress] {
            Decision::Protected(compiled) => compiled.gate.service_id.clone(),
            other => panic!("{other:?}"),
        };
        assert_eq!(service(key("blue", "a")), "strict");
        assert_eq!(service(key("blue", "b")), "orders");
        assert_eq!(
            withheld(&resolution, key("green", "c")),
            "ProtectionRequired"
        );
        // The default's status lists the Ingress it actually applies to.
        let status = resolution
            .desired_status(&default_policy("blue", "default"), &keys(&[("blue", "b")]))
            .unwrap();
        let ancestors = status["ancestors"].as_array().unwrap();
        assert_eq!(ancestors.len(), 1);
        assert_eq!(ancestors[0]["ancestorRef"]["name"], "b");
        assert_eq!(status["conditions"][2]["status"], "True");
    }

    #[test]
    fn ambiguous_attachments_are_refused_deterministically() {
        let first = policy("blue", "first", &["app"]);
        let second = policy("blue", "second", &["app", "solo"]);
        let forward = run(
            &options(),
            &[("blue", "app"), ("blue", "solo")],
            &[first.clone(), second.clone()],
            local_lb(),
        );
        let backward = run(
            &options(),
            &[("blue", "app"), ("blue", "solo")],
            &[second.clone(), first.clone()],
            local_lb(),
        );
        assert_eq!(forward, backward, "input order must not matter");
        assert_eq!(withheld(&forward, key("blue", "app")), "Conflicted");
        assert!(matches!(
            forward.decisions[&key("blue", "solo")],
            Decision::Protected(_)
        ));
        for object in [&first, &second] {
            let status = forward
                .desired_status(object, &keys(&[("blue", "solo")]))
                .unwrap();
            assert_eq!(status["conditions"][0]["reason"], "Conflicted");
            assert_eq!(status["conditions"][0]["status"], "False");
        }
        let report = forward.report(&BTreeSet::new());
        assert_eq!(report.counts.conflicted_policies, 2);
        assert_eq!(report.counts.withheld, 1);
        // Two namespace defaults are just as ambiguous.
        let resolution = run(
            &options(),
            &[("blue", "x")],
            &[default_policy("blue", "d1"), default_policy("blue", "d2")],
            local_lb(),
        );
        assert_eq!(withheld(&resolution, key("blue", "x")), "Conflicted");
    }

    #[test]
    fn an_invalid_policy_aimed_at_an_ingress_never_fails_open() {
        let mut relaxed = settings_value();
        relaxed["require_protection"] = false.into();
        let options = options_with(relaxed, enforcing());
        for mutate in [
            |p: &mut Value| {
                p["spec"]["authorization"]["pumgye"]["actions"] =
                    serde_json::json!([{"method":"get","action":"read"}])
            },
            |p: &mut Value| {
                p["spec"]["authorization"]["pumgye"]["actions"] =
                    serde_json::json!([{"method":"GET","action":"a"},{"method":"GET","action":"b"}])
            },
            |p: &mut Value| p["spec"]["unknownField"] = true.into(),
            |p: &mut Value| p["spec"]["failureMode"] = "Open".into(),
            |p: &mut Value| p["spec"]["namespaceDefault"] = true.into(),
            |p: &mut Value| p["spec"]["targetRefs"][0]["sectionName"] = "x".into(),
        ] {
            let mut object = policy("blue", "p", &["app"]);
            mutate(&mut object);
            let resolution = run(
                &options,
                &[("blue", "app")],
                std::slice::from_ref(&object),
                local_lb(),
            );
            assert_eq!(
                withheld(&resolution, key("blue", "app")),
                "Invalid",
                "{object}"
            );
            let status = resolution
                .desired_status(&object, &BTreeSet::new())
                .unwrap();
            assert_eq!(status["conditions"][0]["reason"], "Invalid");
        }
    }

    #[test]
    fn references_are_resolved_against_operator_settings() {
        let mut unknown = policy("blue", "p", &["app"]);
        unknown["spec"]["identity"]["profileRef"]["name"] = "missing".into();
        let resolution = run(
            &options(),
            &[("blue", "app")],
            &[unknown.clone()],
            local_lb(),
        );
        assert_eq!(
            withheld(&resolution, key("blue", "app")),
            "InvalidIdentityProfile"
        );
        let status = resolution
            .desired_status(&unknown, &BTreeSet::new())
            .unwrap();
        assert_eq!(status["conditions"][1]["type"], "ResolvedRefs");
        assert_eq!(status["conditions"][1]["status"], "False");

        let mut restricted = policy("blue", "p", &["app"]);
        restricted["spec"]["identity"]["profileRef"]["name"] = "payroll-only".into();
        let resolution = run(&options(), &[("blue", "app")], &[restricted], local_lb());
        assert_eq!(withheld(&resolution, key("blue", "app")), "RefNotPermitted");

        let mut settings = settings_value();
        settings["pumgye_services"] = serde_json::json!({"orders":["green"]});
        let resolution = run(
            &options_with(settings, enforcing()),
            &[("blue", "app")],
            &[policy("blue", "p", &["app"])],
            local_lb(),
        );
        assert_eq!(withheld(&resolution, key("blue", "app")), "RefNotPermitted");
    }

    #[test]
    fn network_enforcement_requires_guard_and_a_preserved_client_address() {
        let object = policy("blue", "p", &["app"]);
        let no_guard = options_with(settings_value(), GatewayFacts::default());
        let resolution = run(
            &no_guard,
            &[("blue", "app")],
            std::slice::from_ref(&object),
            local_lb(),
        );
        assert_eq!(
            withheld(&resolution, key("blue", "app")),
            "GuardUnavailable"
        );
        let open = options_with(
            settings_value(),
            GatewayFacts {
                guard_configured: true,
                guard_enforcing: false,
                proxy_protocol: false,
            },
        );
        let resolution = run(
            &open,
            &[("blue", "app")],
            std::slice::from_ref(&object),
            local_lb(),
        );
        assert_eq!(
            withheld(&resolution, key("blue", "app")),
            "GuardUnavailable"
        );

        for service in [
            None,
            Some(gateway_service("ClusterIP", "Cluster")),
            Some(gateway_service("LoadBalancer", "Cluster")),
        ] {
            let resolution = run(
                &options(),
                &[("blue", "app")],
                std::slice::from_ref(&object),
                service,
            );
            assert_eq!(
                withheld(&resolution, key("blue", "app")),
                "ClientAddressUnavailable"
            );
            let status = resolution
                .desired_status(&object, &BTreeSet::new())
                .unwrap();
            let preserved = status["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["type"] == "ClientAddressPreserved")
                .unwrap();
            assert_eq!(preserved["status"], "False");
            assert_eq!(
                status["conditions"][2]["reason"],
                "ClientAddressUnavailable"
            );
        }
        let resolution = run(
            &options(),
            &[("blue", "app")],
            std::slice::from_ref(&object),
            Some(gateway_service("NodePort", "Local")),
        );
        assert!(matches!(
            resolution.decisions[&key("blue", "app")],
            Decision::Protected(_)
        ));

        // Identity and authorization only: no network claim, no prerequisite.
        let mut identity_only = object.clone();
        identity_only["spec"]["network"] = serde_json::json!({"enforcement":"None"});
        let resolution = run(
            &no_guard,
            &[("blue", "app")],
            &[identity_only.clone()],
            None,
        );
        assert!(matches!(
            resolution.decisions[&key("blue", "app")],
            Decision::Protected(_)
        ));
        let status = resolution
            .desired_status(&identity_only, &keys(&[("blue", "app")]))
            .unwrap();
        assert!(
            status["conditions"]
                .as_array()
                .unwrap()
                .iter()
                .all(|c| c["type"] != "ClientAddressPreserved")
        );

        let mut proxy = settings_value();
        proxy["client_address"] = serde_json::json!({"mode":"proxy_protocol"});
        let facts = GatewayFacts {
            proxy_protocol: true,
            ..enforcing()
        };
        let resolution = run(
            &options_with(proxy, facts),
            &[("blue", "app")],
            &[object],
            None,
        );
        assert!(matches!(
            resolution.decisions[&key("blue", "app")],
            Decision::Protected(_)
        ));
    }

    #[test]
    fn status_follows_gateway_api_policy_conventions() {
        let mut object = policy("blue", "p", &["app", "missing"]);
        object["spec"]["targetRefs"].as_array_mut().unwrap().push(
            serde_json::json!({"group":"gateway.networking.k8s.io","kind":"HTTPRoute","name":"web"}),
        );
        object["status"] = serde_json::json!({"ancestors":[{"ancestorRef":{"name":"gw"},"controllerName":"example.com/other","conditions":[]}]});
        let resolution = run(
            &options(),
            &[("blue", "app")],
            std::slice::from_ref(&object),
            local_lb(),
        );
        let status = resolution
            .desired_status(&object, &keys(&[("blue", "app")]))
            .unwrap();
        assert_eq!(status["observedGeneration"], 3);
        let ancestors = status["ancestors"].as_array().unwrap();
        assert_eq!(ancestors.len(), 4, "foreign ancestors are preserved");
        assert_eq!(ancestors[0]["controllerName"], "example.com/other");
        let by_name = |name: &str| {
            ancestors
                .iter()
                .find(|a| a["ancestorRef"]["name"] == name)
                .unwrap()
                .clone()
        };
        assert_eq!(by_name("app")["conditions"][2]["status"], "True");
        assert_eq!(
            by_name("missing")["conditions"][0]["reason"],
            "TargetNotFound"
        );
        assert_eq!(by_name("web")["conditions"][0]["reason"], "Unsupported");
        assert_eq!(by_name("app")["ancestorRef"]["namespace"], "blue");
        for condition in status["conditions"].as_array().unwrap() {
            assert_eq!(condition["observedGeneration"], 3);
            assert!(
                condition["lastTransitionTime"]
                    .as_str()
                    .unwrap()
                    .ends_with('Z')
            );
        }
        // Accepted for at least one target, Programmed only when all are.
        assert_eq!(status["conditions"][0]["status"], "True");
        assert_eq!(status["conditions"][2]["status"], "False");
        // Not admitted by the snapshot (ownership, TLS, budget): Pending.
        let pending = resolution
            .desired_status(&object, &BTreeSet::new())
            .unwrap();
        let app = pending["ancestors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["ancestorRef"]["name"] == "app")
            .unwrap()
            .clone();
        assert_eq!(app["conditions"][2]["reason"], "Pending");

        // Timestamps are carried while statuses are unchanged.
        let mut current = status.clone();
        current["conditions"][0]["lastTransitionTime"] = "2020-01-01T00:00:00Z".into();
        object["status"] = current.clone();
        let again = resolution
            .desired_status(&object, &keys(&[("blue", "app")]))
            .unwrap();
        assert_eq!(
            again["conditions"][0]["lastTransitionTime"],
            "2020-01-01T00:00:00Z"
        );
        assert!(same_status(Some(&current), &again));
        assert!(!same_status(Some(&current), &pending));
        assert!(!same_status(None, &again));
    }

    #[test]
    fn released_scopes_pass_through_a_disabled_unenforced_revision() {
        let options = options();
        let resolution = run(
            &options,
            &[("blue", "app")],
            &[policy("blue", "p", &["app"])],
            local_lb(),
        );
        let document = serde_json::json!({"items":[
            {"kind":"Service","metadata":{"name":"api","namespace":"blue"},"spec":{"ports":[{"port":80}]}},
            {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"app","namespace":"blue"},
             "spec":{"ingressClassName":"hangang","rules":[{"host":"app.example.test","http":{"paths":[{"path":"/api","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}}
        ]});
        let (previous, _) = crate::ingress::import_validated(
            &document,
            "hangang",
            Some(&resolution.protections(&options)),
        )
        .unwrap();
        // The Ingress is deleted: the scope must be released first.
        let next = Config::default();
        assert!(next.validate_transition_from(&previous).is_err());
        let intermediate = release_plan(&previous, &next).unwrap();
        intermediate.validate().unwrap();
        intermediate.validate_transition_from(&previous).unwrap();
        next.validate_transition_from(&intermediate).unwrap();
        assert!(intermediate.http.iter().all(|route| !route.enabled));
        assert!(release_plan(&intermediate, &next).is_none());
        // The path moves under the same route ID.
        let mut moved = document.clone();
        moved["items"][1]["spec"]["rules"][0]["http"]["paths"][0]["path"] = "/v2".into();
        let (next, _) = crate::ingress::import_validated(
            &moved,
            "hangang",
            Some(&resolution.protections(&options)),
        )
        .unwrap();
        assert!(next.validate_transition_from(&previous).is_err());
        let intermediate = release_plan(&previous, &next).unwrap();
        intermediate.validate().unwrap();
        intermediate.validate_transition_from(&previous).unwrap();
        next.validate_transition_from(&intermediate).unwrap();
        assert_eq!(intermediate.http.len(), 2);
        // An unchanged scope needs no release.
        assert!(release_plan(&previous, &previous).is_none());
    }

    #[test]
    fn shipped_settings_example_is_valid() {
        let settings: Settings = serde_json::from_str(include_str!(
            "../deploy/kubernetes/protection-settings.example.json"
        ))
        .unwrap();
        settings.validate().unwrap();
        assert!(settings.require_protection);
        assert_eq!(
            settings.client_address,
            ClientAddress::ServiceLocal {
                namespace: "hangang".into(),
                name: "hangang".into()
            }
        );
    }

    #[test]
    fn rfc3339_formats_utc() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}
