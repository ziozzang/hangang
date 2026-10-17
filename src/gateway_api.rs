//! Gateway API (`gateway.networking.k8s.io/v1`) for the Kubernetes
//! controller: `GatewayClass`, `Gateway`, `HTTPRoute` and `ReferenceGrant`
//! become generated HTTP routes, SNI certificates and spec-conformant status.
//!
//! The translation is a pure function of the cached objects, like the
//! Ingress adapter, so replicas with the same objects publish the same
//! routes. It runs in two stages: [`plan`] resolves classes, listeners,
//! attachments and references and yields the route rules that protection
//! decides ([`protection::GatewayUnit`]); [`finalize`] applies those
//! decisions and builds routes and status.
use crate::config::{AccessMode, HttpRoute, PathMatch};
use crate::protection::{self, Decision, GatewayUnit, UnitKey};
use crate::route_filters::{
    HeaderModifier, PathModifier, RedirectScheme, RouteRedirect, RouteRewrite,
};
use anyhow::Result;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const GROUP: &str = "gateway.networking.k8s.io";
pub const VERSION: &str = "v1";
/// ReferenceGrant is served as v1beta1 by every Gateway API release.
pub const GRANT_VERSION: &str = "v1beta1";
/// ADR 0022: `GatewayClass.spec.controllerName` this controller implements.
pub const CONTROLLER_NAME: &str = "hangang.dev/gateway-controller";
/// Gateway annotation that requires protection for its routes even when the
/// gateway's `require_protection` setting is off.
pub const REQUIRE_PROTECTION_ANNOTATION: &str = "world.hangang.dev/require-protection";

const MAX_LISTENERS: usize = 64;
const MAX_PARENTS: usize = 32;
const MAX_RULES: usize = 16;
const MAX_MATCHES: usize = 64;
const MAX_BACKENDS: usize = 16;
const MAX_HOSTNAMES: usize = 16;

pub type ObjectKey = (String, String);

fn key_of(object: &Value) -> Option<ObjectKey> {
    Some((
        object
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        object.pointer("/metadata/name")?.as_str()?.to_owned(),
    ))
}
fn generation(object: &Value) -> Option<i64> {
    object
        .pointer("/metadata/generation")
        .and_then(Value::as_i64)
}
type Age = (bool, String, bool, String);
fn age(object: &Value) -> Age {
    let created = object
        .pointer("/metadata/creationTimestamp")
        .and_then(Value::as_str);
    let uid = object.pointer("/metadata/uid").and_then(Value::as_str);
    (
        created.is_none(),
        created.unwrap_or_default().to_owned(),
        uid.is_none(),
        uid.unwrap_or_default().to_owned(),
    )
}
fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Condition outcome: (status, reason, message).
pub type Cond = (bool, &'static str, String);
fn ok(reason: &'static str) -> Cond {
    (true, reason, String::new())
}
fn fail(reason: &'static str, message: impl Into<String>) -> Cond {
    (false, reason, message.into())
}

/// Lookups and settings the translation needs from the controller.
pub struct Inputs<'a> {
    pub classes: Vec<&'a Value>,
    pub gateways: Vec<&'a Value>,
    pub routes: Vec<&'a Value>,
    pub grants: Vec<&'a Value>,
    pub service: &'a dyn Fn(&str, &str) -> Option<&'a Value>,
    pub secret: &'a dyn Fn(&str, &str) -> Option<&'a Value>,
    /// Validate a `kubernetes.io/tls` Secret; its DNS SANs on success.
    pub certificate: &'a dyn Fn(&Value) -> Result<Vec<String>>,
    /// The public listener terminates TLS (HTTPS listeners) instead of
    /// serving plaintext (HTTP listeners).
    pub tls: bool,
    pub publish_address: Option<&'a str>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AllowedFrom {
    Same,
    All,
    /// Namespace label selectors need Namespace reads; not supported yet.
    Selector,
}

#[derive(Clone, Debug)]
pub struct ListenerPlan {
    pub name: String,
    hostname: Option<String>,
    accepted: Cond,
    resolved: Cond,
    conflicted: Option<String>,
    allowed: AllowedFrom,
    kinds_ok: bool,
    /// SNI certificate: hosts it serves and its Secret.
    pub certificate: Option<(Vec<String>, ObjectKey)>,
}
impl ListenerPlan {
    fn usable(&self) -> bool {
        self.accepted.0 && self.resolved.0 && self.conflicted.is_none()
    }
}

#[derive(Clone, Debug)]
pub struct GatewayPlan {
    pub key: ObjectKey,
    generation: Option<i64>,
    accepted: Cond,
    pub listeners: Vec<ListenerPlan>,
    require: bool,
}

#[derive(Clone, Debug)]
struct ParentPlan {
    reference: Value,
    gateway: ObjectKey,
    /// Indexes of attached listeners of that gateway.
    listeners: Vec<usize>,
    /// Effective hostnames (None: any host).
    hosts: Vec<Option<String>>,
    accepted: Cond,
}

#[derive(Clone, Debug, Default)]
struct Filters {
    request_headers: Option<HeaderModifier>,
    redirect: Option<RouteRedirect>,
    rewrite: Option<RouteRewrite>,
    response_set: BTreeMap<String, String>,
    response_remove: Vec<String>,
}

#[derive(Clone, Debug)]
struct MatchPlan {
    path: String,
    path_match: PathMatch,
    headers: BTreeMap<String, String>,
    query: BTreeMap<String, String>,
    method: Option<String>,
}

#[derive(Clone, Debug)]
struct RulePlan {
    name: Option<String>,
    matches: Vec<MatchPlan>,
    backends: Vec<(String, u32)>,
    filters: Filters,
}

#[derive(Clone, Debug)]
struct RoutePlan {
    key: ObjectKey,
    generation: Option<i64>,
    age: Age,
    parents: Vec<ParentPlan>,
    rules: Vec<RulePlan>,
    /// Unsupported features refuse the whole route.
    refused: Option<(&'static str, String)>,
    resolved: Cond,
}

/// Stage one: everything that does not depend on protection.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    classes: Vec<(ObjectKey, Option<i64>, Cond)>,
    pub gateways: Vec<GatewayPlan>,
    routes: Vec<RoutePlan>,
    pub units: Vec<GatewayUnit>,
    publish_address: Option<String>,
}

fn granted(
    grants: &[&Value],
    from_kind: &str,
    from_namespace: &str,
    to_group: &str,
    to_kind: &str,
    to_namespace: &str,
    to_name: &str,
) -> bool {
    grants.iter().any(|grant| {
        text(grant, "/metadata/namespace") == Some(to_namespace)
            && grant
                .pointer("/spec/from")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|from| {
                    text(from, "/group") == Some(GROUP)
                        && text(from, "/kind") == Some(from_kind)
                        && text(from, "/namespace") == Some(from_namespace)
                })
            && grant
                .pointer("/spec/to")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|to| {
                    text(to, "/group").unwrap_or("") == to_group
                        && text(to, "/kind") == Some(to_kind)
                        && text(to, "/name").is_none_or(|name| name == to_name)
                })
    })
}

fn lower(host: &str) -> String {
    host.to_ascii_lowercase()
}
/// `*.example.com` covers `a.example.com` and `a.b.example.com` (any depth).
fn covers(wildcard: &str, host: &str) -> bool {
    wildcard.strip_prefix('*').is_some_and(|suffix| {
        suffix.starts_with('.') && host.len() > suffix.len() && host.ends_with(suffix)
    })
}
/// Gateway API hostname intersection of a listener and a route hostname.
fn intersect(listener: Option<&str>, route: &str) -> Option<String> {
    let route = lower(route);
    let Some(listener) = listener.map(lower) else {
        return Some(route);
    };
    if listener == route || covers(&listener, &route) {
        Some(route)
    } else if covers(&route, &listener) {
        Some(listener)
    } else {
        None
    }
}

fn valid_hostname(host: &str) -> bool {
    let body = host.strip_prefix("*.").unwrap_or(host);
    !body.is_empty()
        && host.len() <= 253
        && body.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Stage one: resolve classes, Gateways, listeners, attachments and
/// references.
pub fn plan(inputs: &Inputs<'_>) -> Plan {
    let mut plan = Plan {
        publish_address: inputs.publish_address.map(str::to_owned),
        ..Plan::default()
    };
    let mut ours: BTreeSet<String> = BTreeSet::new();
    for class in &inputs.classes {
        if text(class, "/spec/controllerName") != Some(CONTROLLER_NAME) {
            continue;
        }
        let Some(key) = key_of(class) else { continue };
        let accepted = if class.pointer("/spec/parametersRef").is_some() {
            fail(
                "InvalidParameters",
                "parametersRef is not supported by this controller",
            )
        } else {
            ours.insert(key.1.clone());
            ok("Accepted")
        };
        plan.classes.push((key, generation(class), accepted));
    }

    // Gateways of our classes, oldest first (hostname ownership).
    let mut gateways: Vec<&Value> = inputs
        .gateways
        .iter()
        .copied()
        .filter(|g| text(g, "/spec/gatewayClassName").is_some_and(|c| ours.contains(c)))
        .collect();
    gateways.sort_by(|a, b| age(a).cmp(&age(b)).then_with(|| key_of(a).cmp(&key_of(b))));
    // Hostname ("*" for none) -> owning gateway.
    let mut owners: BTreeMap<String, ObjectKey> = BTreeMap::new();
    for gateway in gateways {
        let Some(key) = key_of(gateway) else { continue };
        let require = text(
            gateway,
            &format!(
                "/metadata/annotations/{}",
                REQUIRE_PROTECTION_ANNOTATION.replace('/', "~1")
            ),
        ) == Some("true");
        let mut accepted = ok("Accepted");
        if gateway
            .pointer("/spec/addresses")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty())
        {
            accepted = fail(
                "UnsupportedAddress",
                "spec.addresses is not supported; the gateway's Service address is used",
            );
        }
        let mut listeners = Vec::new();
        let mut seen: BTreeSet<String> = BTreeSet::new();
        for listener in gateway
            .pointer("/spec/listeners")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_LISTENERS)
        {
            let name = text(listener, "/name").unwrap_or("").to_owned();
            let hostname = text(listener, "/hostname").map(lower);
            let protocol = text(listener, "/protocol").unwrap_or("");
            let mut plan_l = ListenerPlan {
                name: name.clone(),
                hostname: hostname.clone(),
                accepted: ok("Accepted"),
                resolved: ok("ResolvedRefs"),
                conflicted: None,
                allowed: AllowedFrom::Same,
                kinds_ok: true,
                certificate: None,
            };
            if hostname.as_deref().is_some_and(|h| !valid_hostname(h)) {
                plan_l.accepted = fail("UnsupportedValue", "invalid listener hostname");
            }
            match (protocol, inputs.tls) {
                ("HTTPS", true) | ("HTTP", false) => {}
                ("HTTP", true) => {
                    plan_l.accepted = fail(
                        "UnsupportedProtocol",
                        "this gateway terminates TLS; HTTP listeners are not served",
                    );
                }
                ("HTTPS", false) => {
                    plan_l.accepted = fail(
                        "UnsupportedProtocol",
                        "this gateway serves plaintext HTTP; run it with --kubernetes-tls for HTTPS listeners",
                    );
                }
                _ => {
                    plan_l.accepted = fail(
                        "UnsupportedProtocol",
                        format!("protocol {protocol} is not supported"),
                    );
                }
            }
            match text(listener, "/allowedRoutes/namespaces/from").unwrap_or("Same") {
                "Same" => {}
                "All" => plan_l.allowed = AllowedFrom::All,
                "Selector" => {
                    plan_l.allowed = AllowedFrom::Selector;
                    plan_l.accepted = fail(
                        "UnsupportedValue",
                        "allowedRoutes.namespaces.from: Selector is not supported yet",
                    );
                }
                other => {
                    plan_l.accepted = fail(
                        "UnsupportedValue",
                        format!("allowedRoutes.namespaces.from {other}"),
                    );
                }
            }
            if let Some(kinds) = listener
                .pointer("/allowedRoutes/kinds")
                .and_then(Value::as_array)
                .filter(|k| !k.is_empty())
            {
                plan_l.kinds_ok = kinds.iter().any(|k| {
                    text(k, "/group").unwrap_or(GROUP) == GROUP
                        && text(k, "/kind") == Some("HTTPRoute")
                });
                if !plan_l.kinds_ok || kinds.len() > 1 {
                    plan_l.resolved = fail(
                        "InvalidRouteKinds",
                        "only HTTPRoute (gateway.networking.k8s.io) is supported",
                    );
                }
            }
            if protocol == "HTTPS" && plan_l.accepted.0 {
                let mode = text(listener, "/tls/mode").unwrap_or("Terminate");
                let refs: Vec<&Value> = listener
                    .pointer("/tls/certificateRefs")
                    .and_then(Value::as_array)
                    .map(|r| r.iter().collect())
                    .unwrap_or_default();
                if mode != "Terminate" {
                    plan_l.accepted =
                        fail("UnsupportedValue", "only TLS mode Terminate is supported");
                } else if refs.len() != 1 {
                    plan_l.resolved = fail(
                        "InvalidCertificateRef",
                        "an HTTPS listener needs exactly one certificateRef",
                    );
                } else {
                    let reference = refs[0];
                    let namespace = text(reference, "/namespace").unwrap_or(&key.0).to_owned();
                    let secret_name = text(reference, "/name").unwrap_or("").to_owned();
                    let kind_ok = text(reference, "/group").unwrap_or("").is_empty()
                        && text(reference, "/kind").unwrap_or("Secret") == "Secret";
                    if !kind_ok {
                        plan_l.resolved = fail(
                            "InvalidCertificateRef",
                            "certificateRefs must name a core Secret",
                        );
                    } else if namespace != key.0
                        && !granted(
                            &inputs.grants,
                            "Gateway",
                            &key.0,
                            "",
                            "Secret",
                            &namespace,
                            &secret_name,
                        )
                    {
                        plan_l.resolved = fail(
                            "RefNotPermitted",
                            format!(
                                "no ReferenceGrant in {namespace} allows this Gateway to use Secret {secret_name}"
                            ),
                        );
                    } else {
                        match (inputs.secret)(&namespace, &secret_name) {
                            None => {
                                plan_l.resolved = fail(
                                    "InvalidCertificateRef",
                                    format!("Secret {namespace}/{secret_name} not found"),
                                );
                            }
                            Some(secret) => match (inputs.certificate)(secret) {
                                Err(error) => {
                                    plan_l.resolved = fail(
                                        "InvalidCertificateRef",
                                        format!("Secret {namespace}/{secret_name}: {error}"),
                                    );
                                }
                                Ok(names) => {
                                    let hosts = match &hostname {
                                        Some(host) => vec![host.clone()],
                                        None => names.into_iter().map(|n| lower(&n)).collect(),
                                    };
                                    if hosts.is_empty() {
                                        plan_l.resolved = fail(
                                            "InvalidCertificateRef",
                                            "the certificate names no DNS host and the listener has no hostname",
                                        );
                                    } else {
                                        plan_l.certificate =
                                            Some((hosts, (namespace, secret_name)));
                                    }
                                }
                            },
                        }
                    }
                }
            }
            // Hostname conflicts: within the gateway, then across gateways
            // (the oldest Gateway owns a hostname).
            let claim = hostname.clone().unwrap_or_else(|| "*".into());
            if plan_l.accepted.0 {
                if !seen.insert(claim.clone()) {
                    plan_l.conflicted =
                        Some("another listener of this Gateway serves the same hostname".into());
                } else if let Some(owner) = owners.get(&claim).filter(|owner| **owner != key) {
                    plan_l.conflicted = Some(format!(
                        "hostname {claim} is served by the older Gateway {}/{}",
                        owner.0, owner.1
                    ));
                } else {
                    owners.insert(claim, key.clone());
                }
            }
            listeners.push(plan_l);
        }
        if listeners.is_empty() || listeners.iter().all(|l| !l.accepted.0) {
            if accepted.0 {
                accepted = fail("ListenersNotValid", "no listener is valid");
            }
        }
        plan.gateways.push(GatewayPlan {
            key,
            generation: generation(gateway),
            accepted,
            listeners,
            require,
        });
    }

    for route in &inputs.routes {
        if let Some(route_plan) = plan_route(route, &plan.gateways, inputs) {
            plan.routes.push(route_plan);
        }
    }
    // Protection units: one per rule of every attached route.
    for route in &plan.routes {
        if route.refused.is_some() {
            continue;
        }
        let parents: Vec<(ObjectKey, Option<String>)> = route
            .parents
            .iter()
            .filter(|p| p.accepted.0)
            .flat_map(|p| {
                let gateway = plan.gateways.iter().find(|g| g.key == p.gateway);
                p.listeners.iter().map(move |i| {
                    (
                        p.gateway.clone(),
                        gateway.map(|g| g.listeners[*i].name.clone()),
                    )
                })
            })
            .collect();
        if parents.is_empty() {
            continue;
        }
        let require = route.parents.iter().filter(|p| p.accepted.0).any(|p| {
            plan.gateways
                .iter()
                .any(|g| g.key == p.gateway && g.require)
        });
        let hosts: Vec<Option<String>> = route
            .parents
            .iter()
            .filter(|p| p.accepted.0)
            .flat_map(|p| p.hosts.clone())
            .collect();
        for (index, rule) in route.rules.iter().enumerate() {
            let rules: Vec<Value> = hosts
                .iter()
                .map(|host| {
                    let paths: Vec<Value> = rule
                        .matches
                        .iter()
                        .map(|m| serde_json::json!({
                            "path": m.path,
                            "pathType": if m.path_match == PathMatch::Exact { "Exact" } else { "Prefix" },
                        }))
                        .collect();
                    let mut entry = serde_json::json!({"http":{"paths":paths}});
                    if let Some(host) = host {
                        entry["host"] = host.clone().into();
                    }
                    entry
                })
                .collect();
            plan.units.push(GatewayUnit {
                key: (route.key.0.clone(), route.key.1.clone(), index),
                rule_name: rule.name.clone(),
                parents: parents.clone(),
                require,
                paths: serde_json::json!({"spec":{"rules":rules}}),
            });
        }
    }
    plan
}

fn plan_route(route: &Value, gateways: &[GatewayPlan], inputs: &Inputs<'_>) -> Option<RoutePlan> {
    let key = key_of(route)?;
    let hostnames: Vec<String> = route
        .pointer("/spec/hostnames")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(lower)
        .take(MAX_HOSTNAMES)
        .collect();
    let mut parents = Vec::new();
    for reference in route
        .pointer("/spec/parentRefs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_PARENTS)
    {
        if text(reference, "/group").unwrap_or(GROUP) != GROUP
            || text(reference, "/kind").unwrap_or("Gateway") != "Gateway"
        {
            continue;
        }
        let gateway_key = (
            text(reference, "/namespace").unwrap_or(&key.0).to_owned(),
            text(reference, "/name").unwrap_or("").to_owned(),
        );
        let Some(gateway) = gateways.iter().find(|g| g.key == gateway_key) else {
            continue;
        };
        let section = text(reference, "/sectionName");
        let port = reference.pointer("/port").and_then(Value::as_u64);
        let candidates: Vec<usize> = gateway
            .listeners
            .iter()
            .enumerate()
            .filter(|(_, l)| section.is_none_or(|s| s == l.name))
            .map(|(i, _)| i)
            .collect();
        let mut accepted = ok("Accepted");
        let mut listeners = Vec::new();
        let mut hosts: Vec<Option<String>> = Vec::new();
        if candidates.is_empty() || port.is_some() {
            accepted = fail(
                "NoMatchingParent",
                if port.is_some() {
                    "parentRef port is not supported; use sectionName".to_owned()
                } else {
                    format!("Gateway has no listener {}", section.unwrap_or(""))
                },
            );
        } else {
            let mut allowed_any = false;
            for index in candidates {
                let listener = &gateway.listeners[index];
                let namespace_ok = match listener.allowed {
                    AllowedFrom::Same => key.0 == gateway.key.0,
                    AllowedFrom::All => true,
                    AllowedFrom::Selector => false,
                };
                if !(listener.usable() && namespace_ok && listener.kinds_ok) {
                    continue;
                }
                allowed_any = true;
                let matched: Vec<Option<String>> = if hostnames.is_empty() {
                    vec![listener.hostname.clone()]
                } else {
                    hostnames
                        .iter()
                        .filter_map(|h| intersect(listener.hostname.as_deref(), h))
                        .map(Some)
                        .collect()
                };
                if matched.is_empty() {
                    continue;
                }
                listeners.push(index);
                for host in matched {
                    if !hosts.contains(&host) {
                        hosts.push(host);
                    }
                }
            }
            if !allowed_any {
                accepted = fail(
                    "NotAllowedByListeners",
                    "no listener of the parent allows this route (namespace, kind, validity or conflicts)",
                );
            } else if listeners.is_empty() {
                accepted = fail(
                    "NoMatchingListenerHostname",
                    "no listener hostname intersects the route's hostnames",
                );
            }
        }
        parents.push(ParentPlan {
            reference: reference.clone(),
            gateway: gateway_key,
            listeners,
            hosts,
            accepted,
        });
    }
    if parents.is_empty() {
        return None;
    }
    let mut refused: Option<(&'static str, String)> = None;
    let mut resolved = ok("ResolvedRefs");
    let mut rules = Vec::new();
    let refuse = |slot: &mut Option<(&'static str, String)>, message: String| {
        slot.get_or_insert(("UnsupportedValue", message));
    };
    for rule in route
        .pointer("/spec/rules")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_RULES)
    {
        let mut matches = Vec::new();
        let raw: Vec<Value> = rule
            .pointer("/matches")
            .and_then(Value::as_array)
            .cloned()
            .filter(|m| !m.is_empty())
            .unwrap_or_else(|| vec![serde_json::json!({})]);
        for item in raw.iter().take(MAX_MATCHES) {
            let path_type = text(item, "/path/type").unwrap_or("PathPrefix");
            let path = text(item, "/path/value").unwrap_or("/").to_owned();
            let path_match = match path_type {
                "Exact" => PathMatch::Exact,
                "PathPrefix" => PathMatch::SegmentPrefix,
                other => {
                    refuse(
                        &mut refused,
                        format!("path match type {other} is not supported"),
                    );
                    continue;
                }
            };
            if !path.starts_with('/') {
                refuse(&mut refused, "path must start with /".into());
                continue;
            }
            let mut headers = BTreeMap::new();
            for header in item
                .pointer("/headers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if text(header, "/type").unwrap_or("Exact") != "Exact" {
                    refuse(
                        &mut refused,
                        "only Exact header matches are supported".into(),
                    );
                    continue;
                }
                let name = text(header, "/name").unwrap_or("").to_ascii_lowercase();
                let value = text(header, "/value").unwrap_or("").to_owned();
                // Gateway API: the first match of a repeated name wins.
                headers.entry(name).or_insert(value);
            }
            let mut query = BTreeMap::new();
            for param in item
                .pointer("/queryParams")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if text(param, "/type").unwrap_or("Exact") != "Exact" {
                    refuse(
                        &mut refused,
                        "only Exact query parameter matches are supported".into(),
                    );
                    continue;
                }
                query
                    .entry(text(param, "/name").unwrap_or("").to_owned())
                    .or_insert(text(param, "/value").unwrap_or("").to_owned());
            }
            matches.push(MatchPlan {
                path,
                path_match,
                headers,
                query,
                method: text(item, "/method").map(str::to_owned),
            });
        }
        let mut filters = Filters::default();
        for filter in rule
            .pointer("/filters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match text(filter, "/type").unwrap_or("") {
                "RequestHeaderModifier" => {
                    filters.request_headers =
                        Some(header_modifier(filter.pointer("/requestHeaderModifier")));
                }
                "ResponseHeaderModifier" => {
                    let modifier = header_modifier(filter.pointer("/responseHeaderModifier"));
                    filters.response_set.extend(modifier.set);
                    filters.response_set.extend(modifier.add);
                    filters.response_remove.extend(modifier.remove);
                }
                "RequestRedirect" => {
                    let spec = filter
                        .pointer("/requestRedirect")
                        .cloned()
                        .unwrap_or_default();
                    filters.redirect = Some(RouteRedirect {
                        scheme: match text(&spec, "/scheme") {
                            Some("http") => Some(RedirectScheme::Http),
                            Some("https") => Some(RedirectScheme::Https),
                            _ => None,
                        },
                        hostname: text(&spec, "/hostname").map(str::to_owned),
                        port: spec
                            .pointer("/port")
                            .and_then(Value::as_u64)
                            .map(|p| p as u16),
                        path: path_modifier(spec.pointer("/path")),
                        status_code: spec
                            .pointer("/statusCode")
                            .and_then(Value::as_u64)
                            .map(|c| c as u16)
                            .unwrap_or(302),
                    });
                }
                "URLRewrite" => {
                    let spec = filter.pointer("/urlRewrite").cloned().unwrap_or_default();
                    filters.rewrite = Some(RouteRewrite {
                        hostname: text(&spec, "/hostname").map(str::to_owned),
                        path: path_modifier(spec.pointer("/path")),
                    });
                }
                other => refuse(&mut refused, format!("filter {other} is not supported")),
            }
        }
        let mut backends = Vec::new();
        for backend in rule
            .pointer("/backendRefs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_BACKENDS)
        {
            if backend
                .pointer("/filters")
                .and_then(Value::as_array)
                .is_some_and(|f| !f.is_empty())
            {
                refuse(&mut refused, "backendRef filters are not supported".into());
                continue;
            }
            let group = text(backend, "/group").unwrap_or("");
            let kind = text(backend, "/kind").unwrap_or("Service");
            let name = text(backend, "/name").unwrap_or("");
            let namespace = text(backend, "/namespace").unwrap_or(&key.0);
            let weight = backend
                .pointer("/weight")
                .and_then(Value::as_u64)
                .unwrap_or(1) as u32;
            if !group.is_empty() || kind != "Service" {
                resolved = fail(
                    "InvalidKind",
                    format!("backend kind {group}/{kind} is not supported"),
                );
                continue;
            }
            if namespace != key.0
                && !granted(
                    &inputs.grants,
                    "HTTPRoute",
                    &key.0,
                    "",
                    "Service",
                    namespace,
                    name,
                )
            {
                resolved = fail(
                    "RefNotPermitted",
                    format!(
                        "no ReferenceGrant in {namespace} allows this route to use Service {name}"
                    ),
                );
                continue;
            }
            let Some(port) = backend.pointer("/port").and_then(Value::as_u64) else {
                resolved = fail("BackendNotFound", format!("backendRef {name} has no port"));
                continue;
            };
            let Some(service) = (inputs.service)(namespace, name) else {
                resolved = fail(
                    "BackendNotFound",
                    format!("Service {namespace}/{name} not found"),
                );
                continue;
            };
            let declared = service
                .pointer("/spec/ports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|p| p.pointer("/port").and_then(Value::as_u64) == Some(port));
            if !declared || text(service, "/spec/type") == Some("ExternalName") {
                resolved = fail(
                    "BackendNotFound",
                    format!("Service {namespace}/{name} does not declare port {port}"),
                );
                continue;
            }
            if weight > 0 {
                backends.push((format!("http://{name}.{namespace}.svc:{port}"), weight));
            }
        }
        rules.push(RulePlan {
            name: text(rule, "/name").map(str::to_owned),
            matches,
            backends,
            filters,
        });
    }
    Some(RoutePlan {
        key,
        generation: generation(route),
        age: age(route),
        parents,
        rules,
        refused,
        resolved,
    })
}

fn header_modifier(spec: Option<&Value>) -> HeaderModifier {
    let mut modifier = HeaderModifier::default();
    let Some(spec) = spec else { return modifier };
    for (field, target) in [("set", &mut modifier.set), ("add", &mut modifier.add)] {
        for header in spec
            .pointer(&format!("/{field}"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            target.insert(
                text(header, "/name").unwrap_or("").to_ascii_lowercase(),
                text(header, "/value").unwrap_or("").to_owned(),
            );
        }
    }
    modifier.remove = spec
        .pointer("/remove")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|n| n.to_ascii_lowercase())
        .collect();
    modifier
}
fn path_modifier(spec: Option<&Value>) -> Option<PathModifier> {
    let spec = spec?;
    match text(spec, "/type")? {
        "ReplaceFullPath" => Some(PathModifier::Full(
            text(spec, "/replaceFullPath")?.to_owned(),
        )),
        "ReplacePrefixMatch" => Some(PathModifier::Prefix(
            text(spec, "/replacePrefixMatch")?.to_owned(),
        )),
        _ => None,
    }
}

/// Stage two result: routes, certificates, protected hosts and desired
/// status per object.
#[derive(Clone, Debug, Default)]
pub struct Translation {
    pub routes: Vec<HttpRoute>,
    /// SNI certificates: (hosts, Secret).
    pub certificates: Vec<(Vec<String>, ObjectKey)>,
    /// Hosts served by protected Gateway routes (Ingress claims on them are
    /// refused).
    pub protected_hosts: BTreeSet<String>,
    /// Every host a Gateway route serves (`*` for any host).
    pub hosts: BTreeSet<String>,
    /// Desired status: GatewayClass (namespace ""), Gateway, HTTPRoute.
    pub classes: BTreeMap<ObjectKey, Value>,
    pub gateways: BTreeMap<ObjectKey, Value>,
    pub routes_status: BTreeMap<ObjectKey, RouteStatus>,
    pub handoff_routes: u64,
    /// HTTPRoutes whose rules are all in the routes.
    pub programmed: BTreeSet<ObjectKey>,
}

/// Our part of an HTTPRoute status: one entry per parentRef of ours.
#[derive(Clone, Debug, Default)]
pub struct RouteStatus {
    pub generation: Option<i64>,
    pub parents: Vec<(Value, Vec<Value>)>,
}

/// Gateway API precedence among rules on the same host.
#[allow(clippy::type_complexity)]
fn precedence(
    a: &(MatchPlan, Age, ObjectKey, usize),
    b: &(MatchPlan, Age, ObjectKey, usize),
) -> std::cmp::Ordering {
    let exact = |m: &MatchPlan| m.path_match == PathMatch::Exact;
    exact(&b.0)
        .cmp(&exact(&a.0))
        .then_with(|| {
            b.0.path
                .trim_end_matches('/')
                .len()
                .cmp(&a.0.path.trim_end_matches('/').len())
        })
        .then_with(|| b.0.method.is_some().cmp(&a.0.method.is_some()))
        .then_with(|| b.0.headers.len().cmp(&a.0.headers.len()))
        .then_with(|| b.0.query.len().cmp(&a.0.query.len()))
        .then_with(|| a.1.cmp(&b.1))
        .then_with(|| a.2.cmp(&b.2))
        .then_with(|| a.3.cmp(&b.3))
}

/// Budget of generated Gateway API routes within one configuration; the
/// Ingress adapter gets the remainder.
pub const MAX_GATEWAY_ROUTES: usize = crate::ingress::MAX_ROUTES / 2;
pub const MAX_GATEWAY_BYTES: usize = crate::ingress::MAX_CONFIG_BYTES / 2;
/// Wildcard hostnames become host regexes, bounded per configuration.
const MAX_GATEWAY_REGEXES: usize = 128;

/// Validate one HTTPRoute's generated routes on their own, so an invalid
/// route is withheld alone instead of failing the whole snapshot.
fn check<'a>(
    routes: impl Iterator<Item = &'a HttpRoute>,
    authority: Option<&crate::pumgye::AuthorityConfig>,
) -> Result<()> {
    let http: Vec<HttpRoute> = routes.cloned().collect();
    let protected = http.iter().any(|r| r.access_mode == AccessMode::Protected);
    let config = crate::config::Config {
        http,
        pumgye_authority: authority.filter(|_| protected).cloned(),
        ..Default::default()
    };
    config.validate()
}

struct Pending {
    route: HttpRoute,
    host: Option<String>,
    order: (MatchPlan, Age, ObjectKey, usize),
    protected: bool,
}

fn handoff_route(route: &HttpRoute) -> HttpRoute {
    let mut internal = route.clone();
    internal.id = crate::ingress::identifier(&route.id, crate::ingress::HANDOFF_SUFFIX);
    internal.path_prefix = Some(protection::HOPAE_RESERVED_PATH.into());
    internal.path_match = PathMatch::SegmentPrefix;
    internal.headers.clear();
    internal.query.clear();
    internal.methods.clear();
    internal.redirect = None;
    internal.rewrite = None;
    internal.request_headers = None;
    internal.response_set_headers.clear();
    internal.response_remove_headers.clear();
    internal
}

/// The generated routes of one HTTPRoute, or why it is withheld.
fn route_rules(
    route: &RoutePlan,
    hosts: &[Option<String>],
    decisions: Option<&BTreeMap<UnitKey, Decision>>,
) -> std::result::Result<Vec<Pending>, (&'static str, String)> {
    let mut out = Vec::new();
    for (rule_index, rule) in route.rules.iter().enumerate() {
        let unit: UnitKey = (route.key.0.clone(), route.key.1.clone(), rule_index);
        let decision = match decisions {
            Some(decisions) => decisions.get(&unit).cloned().ok_or((
                "Pending",
                "protection has not decided this rule yet".to_owned(),
            ))?,
            None => Decision::Public,
        };
        if let Decision::Withheld(reason) = &decision {
            return Err((reason.reason, reason.message.clone()));
        }
        if rule.backends.is_empty() && rule.filters.redirect.is_none() {
            // No usable backend: Gateway API answers 500 for such a rule;
            // not routing it lets the request fall through to 404.
            continue;
        }
        for (match_index, matched) in rule.matches.iter().enumerate() {
            for (host_index, host) in hosts.iter().enumerate() {
                let id = crate::ingress::identifier(
                    &format!("gw.{}.{}", route.key.0, route.key.1),
                    &format!("{rule_index}.{match_index}.{host_index}"),
                );
                let backends: Vec<String> = if rule.backends.is_empty() {
                    // A redirect-only rule answers before dispatch.
                    vec!["http://127.0.0.1:9".to_owned()]
                } else {
                    rule.backends.iter().map(|(url, _)| url.clone()).collect()
                };
                let mut http: HttpRoute = serde_json::from_value(serde_json::json!({
                    "id": id,
                    "path_prefix": matched.path,
                    "path_match": matched.path_match,
                    "preserve_host": true,
                    "backends": backends,
                }))
                .map_err(|error| {
                    (
                        "UnsupportedValue",
                        format!("route rule is invalid: {error}"),
                    )
                })?;
                match host.as_deref() {
                    Some(host) if host.starts_with("*.") => {
                        // Gateway API wildcards cover any number of labels.
                        http.host_regex =
                            Some(format!("(?:[^.]+\\.)+{}", regex::escape(&host[2..])));
                    }
                    Some(host) => http.host = Some(host.to_owned()),
                    None => {}
                }
                if rule.backends.len() > 1 {
                    http.balance.weights = scaled_weights(&rule.backends);
                }
                http.headers = matched.headers.clone();
                http.query = matched.query.clone();
                http.methods = matched.method.iter().cloned().collect();
                http.request_headers = rule.filters.request_headers.clone();
                http.redirect = rule.filters.redirect.clone();
                http.rewrite = rule.filters.rewrite.clone();
                http.response_set_headers = rule.filters.response_set.clone();
                http.response_remove_headers = rule.filters.response_remove.clone();
                let protected = match &decision {
                    Decision::Protected(compiled) => {
                        compiled.protect(&mut http);
                        true
                    }
                    _ => {
                        http.access_mode = AccessMode::Public;
                        false
                    }
                };
                out.push(Pending {
                    route: http,
                    host: host.clone(),
                    order: (
                        matched.clone(),
                        route.age.clone(),
                        route.key.clone(),
                        rule_index,
                    ),
                    protected,
                });
            }
        }
    }
    Ok(out)
}

/// Stage two: apply protection decisions and build routes and status.
pub fn finalize(
    plan: &Plan,
    decisions: Option<&BTreeMap<UnitKey, Decision>>,
    authority: Option<&crate::pumgye::AuthorityConfig>,
) -> Translation {
    let mut translation = Translation::default();
    // Per route: why it is not programmed. A route is admitted whole or not
    // at all, like an Ingress: one withheld rule withholds the route.
    let mut withheld: BTreeMap<ObjectKey, (&'static str, String)> = BTreeMap::new();
    let mut pending: Vec<Pending> = Vec::new();
    let mut handoff_hosts: BTreeSet<Option<String>> = BTreeSet::new();
    let mut handoff: BTreeMap<Option<String>, HttpRoute> = BTreeMap::new();
    let mut route_count = 0usize;
    let mut route_bytes = 0usize;
    let mut regexes = 0usize;
    // Oldest route first: budget and handoff ownership follow age.
    let mut order: Vec<&RoutePlan> = plan.routes.iter().collect();
    order.sort_by(|a, b| a.age.cmp(&b.age).then_with(|| a.key.cmp(&b.key)));
    for route in order {
        if route.refused.is_some() {
            continue;
        }
        let mut hosts: Vec<Option<String>> = Vec::new();
        for host in route
            .parents
            .iter()
            .filter(|p| p.accepted.0)
            .flat_map(|p| p.hosts.iter())
        {
            if !hosts.contains(host) {
                hosts.push(host.clone());
            }
        }
        if hosts.is_empty() {
            continue;
        }
        match route_rules(route, &hosts, decisions) {
            Err(reason) => {
                withheld.insert(route.key.clone(), reason);
            }
            Ok(rules) => {
                let mut extra: Vec<HttpRoute> = Vec::new();
                let mut claimed: Vec<Option<String>> = Vec::new();
                for item in rules.iter().filter(|item| item.protected) {
                    if !handoff_hosts.contains(&item.host) && !claimed.contains(&item.host) {
                        claimed.push(item.host.clone());
                        extra.push(handoff_route(&item.route));
                    }
                }
                let count = rules.len() + extra.len();
                let bytes: usize = rules
                    .iter()
                    .map(|item| crate::ingress::serialized_len(&item.route) + 1)
                    .chain(extra.iter().map(|r| crate::ingress::serialized_len(r) + 1))
                    .sum();
                let added_regexes = rules
                    .iter()
                    .filter(|item| item.route.host_regex.is_some())
                    .count();
                if let Err(error) = check(
                    rules.iter().map(|item| &item.route).chain(extra.iter()),
                    authority,
                ) {
                    withheld.insert(
                        route.key.clone(),
                        (
                            "UnsupportedValue",
                            format!("a generated route is invalid: {error:#}"),
                        ),
                    );
                    continue;
                }
                if route_count + count > MAX_GATEWAY_ROUTES
                    || route_bytes + bytes > MAX_GATEWAY_BYTES
                    || regexes + added_regexes > MAX_GATEWAY_REGEXES
                {
                    withheld.insert(
                        route.key.clone(),
                        (
                            "UnsupportedValue",
                            format!(
                                "admitting this route would exceed the Gateway API budget of {MAX_GATEWAY_ROUTES} generated routes and {MAX_GATEWAY_BYTES} bytes"
                            ),
                        ),
                    );
                    continue;
                }
                route_count += count;
                route_bytes += bytes;
                regexes += added_regexes;
                translation.handoff_routes += extra.len() as u64;
                for (host, route) in claimed.into_iter().zip(extra) {
                    handoff_hosts.insert(host.clone());
                    handoff.insert(host, route);
                }
                for item in &rules {
                    let host = item.host.clone().unwrap_or_else(|| "*".into());
                    translation.hosts.insert(host.clone());
                    if item.protected {
                        translation.protected_hosts.insert(host);
                    }
                }
                translation.programmed.insert(route.key.clone());
                pending.extend(rules);
            }
        }
    }
    // Precedence per host: exact path, longest prefix, method, headers,
    // query parameters, oldest route, then name and rule order.
    // Hosts: exact names, then wildcards by longest suffix, then any host.
    let rank = |host: &Option<String>| match host {
        Some(host) if host.starts_with("*.") => (1, std::cmp::Reverse(host.len())),
        Some(_) => (0, std::cmp::Reverse(0)),
        None => (2, std::cmp::Reverse(0)),
    };
    pending.sort_by(|a, b| {
        rank(&a.host)
            .cmp(&rank(&b.host))
            .then_with(|| a.host.cmp(&b.host))
            .then_with(|| precedence(&a.order, &b.order))
    });
    // The handoff route leads its host's routes: protected rules cannot
    // claim Hopae's reserved path, so it shadows nothing.
    let mut previous: Option<Option<String>> = None;
    for item in pending {
        if previous.as_ref() != Some(&item.host) {
            if let Some(route) = handoff.remove(&item.host) {
                translation.routes.push(route);
            }
            previous = Some(item.host.clone());
        }
        translation.routes.push(item.route);
    }

    // Certificates of programmed HTTPS listeners.
    for gateway in &plan.gateways {
        if !gateway.accepted.0 {
            continue;
        }
        for listener in &gateway.listeners {
            if listener.usable()
                && let Some(certificate) = &listener.certificate
            {
                translation.certificates.push(certificate.clone());
            }
        }
    }

    // Status.
    for (key, generation, accepted) in &plan.classes {
        translation.classes.insert(
            key.clone(),
            serde_json::json!({
                "conditions": [protection::condition("Accepted", accepted.0, accepted.1, &accepted.2, *generation)],
            }),
        );
    }
    let mut attached: BTreeMap<(ObjectKey, usize), usize> = BTreeMap::new();
    for route in &plan.routes {
        let programmed = translation.programmed.contains(&route.key);
        for parent in &route.parents {
            if parent.accepted.0 && programmed {
                for index in &parent.listeners {
                    *attached
                        .entry((parent.gateway.clone(), *index))
                        .or_default() += 1;
                }
            }
        }
    }
    for gateway in &plan.gateways {
        let generation = gateway.generation;
        let listeners: Vec<Value> = gateway
            .listeners
            .iter()
            .enumerate()
            .map(|(index, listener)| {
                let programmed = gateway.accepted.0 && listener.usable();
                let conflicted = match &listener.conflicted {
                    Some(message) => protection::condition("Conflicted", true, "HostnameConflict", message, generation),
                    None => protection::condition("Conflicted", false, "NoConflicts", "", generation),
                };
                serde_json::json!({
                    "name": listener.name,
                    "supportedKinds": if listener.kinds_ok { serde_json::json!([{"group": GROUP, "kind": "HTTPRoute"}]) } else { serde_json::json!([]) },
                    "attachedRoutes": attached.get(&(gateway.key.clone(), index)).copied().unwrap_or(0),
                    "conditions": [
                        protection::condition("Accepted", listener.accepted.0, listener.accepted.1, &listener.accepted.2, generation),
                        protection::condition("ResolvedRefs", listener.resolved.0, listener.resolved.1, &listener.resolved.2, generation),
                        protection::condition("Programmed", programmed, if programmed { "Programmed" } else { "Invalid" }, "", generation),
                        conflicted,
                    ],
                })
            })
            .collect();
        let programmed = gateway.accepted.0 && gateway.listeners.iter().any(ListenerPlan::usable);
        let mut status = serde_json::json!({
            "conditions": [
                protection::condition("Accepted", gateway.accepted.0, gateway.accepted.1, &gateway.accepted.2, generation),
                protection::condition("Programmed", programmed, if programmed { "Programmed" } else { "Invalid" }, "", generation),
            ],
            "listeners": listeners,
        });
        if let Some(address) = &plan.publish_address {
            let kind = if address.parse::<std::net::IpAddr>().is_ok() {
                "IPAddress"
            } else {
                "Hostname"
            };
            status["addresses"] = serde_json::json!([{"type": kind, "value": address}]);
        }
        translation.gateways.insert(gateway.key.clone(), status);
    }
    for route in &plan.routes {
        let generation = route.generation;
        let mut parents = Vec::new();
        for parent in &route.parents {
            let accepted = if let Some((reason, message)) = &route.refused {
                (false, *reason, message.clone())
            } else if !parent.accepted.0 {
                parent.accepted.clone()
            } else if let Some((reason, message)) = withheld.get(&route.key) {
                (false, *reason, message.clone())
            } else {
                ok("Accepted")
            };
            parents.push((
                parent.reference.clone(),
                vec![
                    protection::condition(
                        "Accepted",
                        accepted.0,
                        accepted.1,
                        &accepted.2,
                        generation,
                    ),
                    protection::condition(
                        "ResolvedRefs",
                        route.resolved.0,
                        route.resolved.1,
                        &route.resolved.2,
                        generation,
                    ),
                ],
            ));
        }
        translation.routes_status.insert(
            route.key.clone(),
            RouteStatus {
                generation,
                parents,
            },
        );
    }
    translation
}

/// Gateway weights (0..1,000,000) as Hangang weights (1..1,000).
fn scaled_weights(backends: &[(String, u32)]) -> Vec<u16> {
    let max = backends.iter().map(|(_, w)| *w).max().unwrap_or(1).max(1);
    backends
        .iter()
        .map(|(_, w)| {
            if max <= 1000 {
                (*w).max(1) as u16
            } else {
                ((u64::from(*w) * 1000 / u64::from(max)).max(1)) as u16
            }
        })
        .collect()
}

/// The full HTTPRoute status we want: our parents (with transition times
/// carried from the current status) plus every entry of other controllers.
pub fn route_status(current: &Value, ours: &RouteStatus) -> Value {
    let existing: Vec<Value> = current
        .pointer("/status/parents")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut parents: Vec<Value> = existing
        .iter()
        .filter(|entry| text(entry, "/controllerName") != Some(CONTROLLER_NAME))
        .cloned()
        .collect();
    for (reference, conditions) in &ours.parents {
        let previous = existing.iter().find(|entry| {
            text(entry, "/controllerName") == Some(CONTROLLER_NAME)
                && entry.get("parentRef") == Some(reference)
        });
        let mut conditions = Value::Array(conditions.clone());
        stamp(previous.and_then(|p| p.get("conditions")), &mut conditions);
        parents.push(serde_json::json!({
            "parentRef": reference,
            "controllerName": CONTROLLER_NAME,
            "conditions": conditions,
        }));
    }
    parents.truncate(32);
    serde_json::json!({ "parents": parents })
}

/// Whether an HTTPRoute carries a status entry written by this controller.
pub fn has_our_parents(route: &Value) -> bool {
    route
        .pointer("/status/parents")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| text(entry, "/controllerName") == Some(CONTROLLER_NAME))
}

/// Gateway and GatewayClass status with transition times carried.
pub fn owned_status(current: &Value, mut desired: Value) -> Value {
    let previous = current.get("status");
    stamp(
        previous.and_then(|s| s.get("conditions")),
        &mut desired["conditions"],
    );
    if let Some(listeners) = desired.get_mut("listeners").and_then(Value::as_array_mut) {
        for listener in listeners {
            let name = listener["name"].clone();
            let old = previous
                .and_then(|s| s.get("listeners"))
                .and_then(Value::as_array)
                .and_then(|l| l.iter().find(|x| x["name"] == name));
            stamp(
                old.and_then(|l| l.get("conditions")),
                &mut listener["conditions"],
            );
        }
    }
    desired
}

fn stamp(previous: Option<&Value>, desired: &mut Value) {
    let now = protection::rfc3339_now();
    for condition in desired.as_array_mut().into_iter().flatten() {
        let kind = condition["type"].clone();
        let time = previous
            .and_then(Value::as_array)
            .and_then(|list| list.iter().find(|c| c["type"] == kind))
            .filter(|c| c["status"] == condition["status"] && c["lastTransitionTime"].is_string())
            .map(|c| c["lastTransitionTime"].clone())
            .unwrap_or_else(|| Value::String(now.clone()));
        condition["lastTransitionTime"] = time;
    }
}

#[cfg(test)]
mod tests;
