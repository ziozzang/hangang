//! Offline Kubernetes Ingress adapter. Cluster access and credentials stay with
//! the operator; the resulting document uses the normal dynamic config path.
use crate::config::{Config, HttpRoute, PathMatch};
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Aggregate budgets for one generated configuration. Both are enforced while
/// each Ingress is admitted so one over-sized tenant object is withdrawn on
/// its own instead of freezing every other update behind a global failure.
pub(crate) const MAX_ROUTES: usize = 1024;
pub(crate) const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Offline adapter (`--import-ingress`): any invalid selected object fails the
/// whole conversion so an operator sees the problem with their input.
pub fn import(document: &Value, class: &str) -> Result<Config> {
    build(document, class, false).map(|result| result.0)
}

/// Live controller conversion: a single invalid selected Ingress (bad name,
/// missing/invalid Service, unsupported pathType, ...) is logged and skipped so
/// one tenant's mistake cannot withdraw every other Ingress or crash-loop the
/// controller on startup. Only a malformed document or an over-limit result
/// still fails.
pub fn import_tolerant(document: &Value, class: &str) -> Result<Config> {
    build(document, class, true).map(|result| result.0)
}

pub(crate) type IngressIdentities = BTreeSet<(String, String)>;
pub(crate) fn import_validated(
    document: &Value,
    class: &str,
) -> Result<(Config, IngressIdentities)> {
    build(document, class, true)
}
fn build(document: &Value, class: &str, tolerant: bool) -> Result<(Config, IngressIdentities)> {
    let items = document
        .as_array()
        .or_else(|| document.get("items").and_then(Value::as_array))
        .context("expected a Kubernetes List or resource array")?;
    let mut services = BTreeMap::new();
    for resource in items.iter().filter(|r| r["kind"] == "Service") {
        let namespace = resource["metadata"]["namespace"]
            .as_str()
            .unwrap_or("default");
        let Some(name) = resource["metadata"]["name"].as_str() else {
            if tolerant {
                tracing::warn!("Service without a name skipped");
                continue;
            }
            bail!("service name missing");
        };
        if !(dns_label(namespace) && dns_label(name)) {
            if tolerant {
                tracing::warn!(%namespace, %name, "Service with an invalid identity skipped");
                continue;
            }
            bail!("invalid service identity");
        }
        if services.insert((namespace, name), resource).is_some() {
            if tolerant {
                tracing::warn!(%namespace, %name, "duplicate Service ignored");
            } else {
                bail!("duplicate Service");
            }
        }
    }
    let mut accepted = BTreeSet::new();
    let mut routes = Vec::new();
    let mut defaults = Vec::new();
    // Admission is deterministic: selected Ingresses are processed in
    // namespace/name order so budget decisions do not depend on API ordering.
    let mut selected_ingresses: Vec<&Value> = items
        .iter()
        .filter(|r| r["kind"] == "Ingress")
        .filter(|resource| {
            resource["spec"]["ingressClassName"].as_str().or_else(|| {
                resource["metadata"]["annotations"]["kubernetes.io/ingress.class"].as_str()
            }) == Some(class)
        })
        .collect();
    selected_ingresses.sort_by_key(|resource| ingress_identity(resource));
    // Exact serialized size of the generated document: the empty envelope plus
    // every route plus one separating comma per additional route.
    let base_bytes = serialized_len(&Config {
        certificates: vec![],
        cache: None,
        revision: 0,
        http: Vec::new(),
        tcp: Vec::new(),
        settings: Default::default(),
        cache_generation_floor: 0,
    });
    let mut route_bytes = 0usize;
    let mut route_count = 0usize;
    for resource in selected_ingresses {
        match ingress_routes(resource, &services) {
            Ok((mut ingress_routes, default)) => {
                let added_count = ingress_routes.len() + usize::from(default.is_some());
                let added_bytes: usize = ingress_routes
                    .iter()
                    .chain(default.iter())
                    .map(serialized_len)
                    .sum();
                let total_count = route_count + added_count;
                let total_bytes =
                    base_bytes + route_bytes + added_bytes + total_count.saturating_sub(1);
                if total_count > MAX_ROUTES || total_bytes > MAX_CONFIG_BYTES {
                    let (namespace, name) = ingress_identity(resource);
                    if tolerant {
                        tracing::warn!(
                            %namespace,
                            %name,
                            routes = added_count,
                            bytes = added_bytes,
                            "Ingress withdrawn: admitting it would exceed the aggregate route or size budget"
                        );
                        continue;
                    }
                    bail!(
                        "Ingress {namespace}/{name} exceeds the aggregate budget of {MAX_ROUTES} routes and {MAX_CONFIG_BYTES} bytes"
                    );
                }
                route_count = total_count;
                route_bytes += added_bytes;
                accepted.insert(ingress_identity(resource));
                routes.append(&mut ingress_routes);
                if let Some(default) = default {
                    defaults.push(default);
                }
            }
            Err(error) => {
                if tolerant {
                    let (namespace, name) = ingress_identity(resource);
                    tracing::warn!(%namespace, %name, %error, "Ingress skipped due to an error");
                    continue;
                }
                return Err(error);
            }
        }
    }
    // Deterministic precedence follows Kubernetes host selection: the most
    // specific host wins first (exact, then one-label wildcard, then any other
    // glob, then hostless), and only among rules for equally specific hosts
    // does the longest path, then an exact path match, then the stable
    // resource identity decide. Path length must not outrank host
    // specificity: otherwise a wildcard or hostless rule with a longer path
    // would capture requests for another tenant's exact host.
    routes.sort_by(|a, b| {
        host_specificity(a.host.as_deref())
            .cmp(&host_specificity(b.host.as_deref()))
            .then_with(|| {
                b.path_prefix
                    .as_deref()
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .len()
                    .cmp(
                        &a.path_prefix
                            .as_deref()
                            .unwrap_or("")
                            .trim_end_matches('/')
                            .len(),
                    )
            })
            .then_with(|| {
                (b.path_match == PathMatch::Exact).cmp(&(a.path_match == PathMatch::Exact))
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    defaults.sort_by(|a, b| a.id.cmp(&b.id));
    if defaults.len() > 1 {
        if tolerant {
            tracing::warn!(
                "multiple class default backends; keeping the first by resource identity"
            );
            defaults.truncate(1);
        } else {
            bail!("multiple class default backends are ambiguous");
        }
    }
    routes.extend(defaults);
    let config = Config {
        certificates: vec![],
        cache: None,
        revision: 0,
        http: routes,
        tcp: Vec::new(),
        settings: Default::default(),
        cache_generation_floor: 0,
    };
    config.validate()?;
    ensure!(
        serialized_len(&config) <= MAX_CONFIG_BYTES,
        "generated configuration exceeds 1 MiB"
    );
    Ok((config, accepted))
}

/// Lower sorts first: exact host, one-label wildcard, any other glob, none.
fn host_specificity(host: Option<&str>) -> u8 {
    match host {
        Some(host) if !crate::host_match::is_glob(host) => 0,
        Some(host)
            if host
                .strip_prefix("*.")
                .is_some_and(|suffix| !crate::host_match::is_glob(suffix)) =>
        {
            1
        }
        Some(_) => 2,
        None => 3,
    }
}

/// Serialized JSON length without allocating the document.
pub(crate) fn serialized_len<T: serde::Serialize>(value: &T) -> usize {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0 += buffer.len();
            Ok(buffer.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    // Serializing an in-memory value into a counting writer cannot fail.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

fn ingress_identity(resource: &Value) -> (String, String) {
    let namespace = resource["metadata"]["namespace"]
        .as_str()
        .unwrap_or("default")
        .to_owned();
    let name = resource["metadata"]["name"]
        .as_str()
        .unwrap_or("<unknown>")
        .to_owned();
    (namespace, name)
}

/// Convert one selected Ingress into its routes and optional default backend.
/// Any error is scoped to this Ingress so the caller can skip it in tolerant
/// (controller) mode.
#[allow(clippy::type_complexity)]
fn ingress_routes(
    resource: &Value,
    services: &BTreeMap<(&str, &str), &Value>,
) -> Result<(Vec<HttpRoute>, Option<HttpRoute>)> {
    ensure!(
        resource["apiVersion"] == "networking.k8s.io/v1",
        "Ingress API must be networking.k8s.io/v1"
    );
    let namespace = resource["metadata"]["namespace"]
        .as_str()
        .unwrap_or("default");
    let name = resource["metadata"]["name"]
        .as_str()
        .context("Ingress name missing")?;
    ensure!(
        dns_label(namespace) && name.len() <= 253 && name.split('.').all(dns_label),
        "invalid Ingress identity"
    );
    let prefix = format!("k8s.{}.{}", namespace, name);
    let rules = resource["spec"]["rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut routes = Vec::new();
    for (rule_index, rule) in rules.iter().enumerate() {
        let host = rule
            .get("host")
            .and_then(Value::as_str)
            .filter(|host| !host.is_empty())
            .map(str::to_owned);
        if rule.get("http").is_none_or(Value::is_null) {
            continue;
        }
        let paths = rule["http"]["paths"]
            .as_array()
            .context("Ingress HTTP paths missing")?;
        for (path_index, path) in paths.iter().enumerate() {
            let kind = match path["pathType"].as_str() {
                Some("Exact") => PathMatch::Exact,
                Some("Prefix") => PathMatch::SegmentPrefix,
                Some("ImplementationSpecific") => PathMatch::Prefix,
                _ => bail!("missing or unsupported pathType"),
            };
            let backend = service_backend(&path["backend"], namespace, services)?;
            let route: HttpRoute = serde_json::from_value(
                serde_json::json!({"id":identifier(&prefix,&format!("{rule_index}.{path_index}")),"host":host,"path_prefix":path["path"].as_str().context("Ingress path missing")?,"path_match":kind,"backends":[backend]}),
            )?;
            routes.push(route);
        }
    }
    let default = if let Some(default) = resource["spec"].get("defaultBackend") {
        let backend = service_backend(default, namespace, services)?;
        Some(serde_json::from_value::<HttpRoute>(
            serde_json::json!({"id":identifier(&prefix,"default"),"backends":[backend]}),
        )?)
    } else {
        None
    };
    Config {
        http: routes
            .iter()
            .cloned()
            .chain(default.iter().cloned())
            .collect(),
        ..Config::default()
    }
    .validate()?;
    Ok((routes, default))
}
fn service_backend(
    backend: &Value,
    namespace: &str,
    services: &BTreeMap<(&str, &str), &Value>,
) -> Result<String> {
    ensure!(
        backend.get("resource").is_none(),
        "resource backends are unsupported"
    );
    let service = &backend["service"];
    let name = service["name"]
        .as_str()
        .context("service backend name missing")?;
    let resource = services
        .get(&(namespace, name))
        .context("referenced Service is absent from input")?;
    ensure!(
        resource["spec"]["type"] != "ExternalName",
        "ExternalName backends require explicit native route configuration"
    );
    let ports = resource["spec"]["ports"]
        .as_array()
        .context("Service ports missing")?;
    let selector = &service["port"];
    let selected = ports
        .iter()
        .find(|port| {
            if let Some(number) = selector["number"].as_u64() {
                port["port"].as_u64() == Some(number)
            } else if let Some(name) = selector["name"].as_str() {
                port["name"].as_str() == Some(name)
            } else {
                false
            }
        })
        .context("Ingress backend port is not declared by Service")?;
    ensure!(
        selected["protocol"].as_str().unwrap_or("TCP") == "TCP",
        "Ingress backend must use TCP"
    );
    let port = selected["port"]
        .as_u64()
        .filter(|p| (1..=65535).contains(p))
        .context("invalid service port")?;
    Ok(format!("http://{name}.{namespace}.svc:{port}"))
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
fn identifier(prefix: &str, suffix: &str) -> String {
    use sha2::{Digest, Sha256};
    let full = format!("{prefix}.{suffix}");
    if full.len() <= 128 {
        return full;
    }
    let digest = Sha256::digest(full.as_bytes());
    format!("{}.{:x}", &prefix[..60], digest)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input() -> Value {
        serde_json::json!({"items":[{"kind":"Service","metadata":{"name":"api","namespace":"blue"},"spec":{"ports":[{"name":"web","port":8080}]}},{"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"main","namespace":"blue"},"spec":{"ingressClassName":"hangang","rules":[{"host":"*.example.test","http":{"paths":[{"path":"/api","pathType":"Prefix","backend":{"service":{"name":"api","port":{"name":"web"}}}},{"path":"/api","pathType":"Exact","backend":{"service":{"name":"api","port":{"number":8080}}}}]}}]}}]})
    }
    #[test]
    fn projects_class_named_ports_and_precedence() {
        let config = import(&input(), "hangang").unwrap();
        assert_eq!(config.http.len(), 2);
        assert_eq!(config.http[0].path_match, PathMatch::Exact);
        assert_eq!(config.http[1].path_match, PathMatch::SegmentPrefix);
        assert_eq!(config.http[0].backends, ["http://api.blue.svc:8080"]);
        assert!(import(&input(), "other").unwrap().http.is_empty());
    }
    #[test]
    fn rejects_missing_service_and_unsupported_resources() {
        let mut document = input();
        document["items"].as_array_mut().unwrap().remove(0);
        assert!(import(&document, "hangang").is_err());
        let mut document = input();
        document["items"][1]["spec"]["rules"][0]["http"]["paths"][0]["backend"]["resource"] =
            serde_json::json!({"name":"bucket"});
        assert!(import(&document, "hangang").is_err());
    }

    #[test]
    fn tolerant_import_isolates_one_bad_ingress_and_keeps_the_valid_ones() {
        // A second Ingress that references a Service absent from the input.
        let mut document = input();
        document["items"].as_array_mut().unwrap().push(serde_json::json!({
            "apiVersion":"networking.k8s.io/v1","kind":"Ingress",
            "metadata":{"name":"broken","namespace":"blue"},
            "spec":{"ingressClassName":"hangang","rules":[{"host":"broken.example.test","http":{"paths":[
                {"path":"/","pathType":"Prefix","backend":{"service":{"name":"missing","port":{"number":80}}}}
            ]}}]}
        }));
        // Strict mode fails the whole conversion.
        assert!(import(&document, "hangang").is_err());
        // Tolerant mode skips only the broken Ingress and keeps the valid routes.
        let config = import_tolerant(&document, "hangang").unwrap();
        assert_eq!(config.http.len(), 2);
        assert!(
            config
                .http
                .iter()
                .all(|r| r.id.starts_with("k8s.blue.main."))
        );
    }
}

#[cfg(test)]
mod isolation_tests {
    use super::*;
    #[test]
    fn valid_dotted_and_long_ingress_names_are_stable_and_bounded() {
        for name in [
            "api.v2".to_owned(),
            ["a".repeat(63), "b".repeat(63), "c".repeat(63)].join("."),
        ] {
            let input = serde_json::json!({"items":[{"kind":"Service","metadata":{"name":"api"},"spec":{"ports":[{"port":80}]}},{"kind":"Ingress","apiVersion":"networking.k8s.io/v1","metadata":{"name":name},"spec":{"ingressClassName":"hangang","defaultBackend":{"service":{"name":"api","port":{"number":80}}}}}]});
            let first = import(&input, "hangang").unwrap();
            let second = import(&input, "hangang").unwrap();
            assert_eq!(first, second);
            assert_eq!(first.http.len(), 1);
            assert!(first.http[0].id.len() <= 128);
        }
    }
    #[test]
    fn native_route_validation_is_isolated_before_global_merge() {
        let good = serde_json::json!({"kind":"Ingress","apiVersion":"networking.k8s.io/v1","metadata":{"name":"good"},"spec":{"ingressClassName":"hangang","rules":[{"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}});
        let mut bad = good.clone();
        bad["metadata"]["name"] = "bad".into();
        bad["spec"]["rules"][0]["http"]["paths"][0]["path"] = "invalid-relative-path".into();
        let input = serde_json::json!({"items":[{"kind":"Service","metadata":{"name":"api"},"spec":{"ports":[{"port":80}]}},good,bad]});
        assert!(import(&input, "hangang").is_err());
        let actual = import_tolerant(&input, "hangang").unwrap();
        assert_eq!(actual.http.len(), 1);
        assert!(actual.http[0].id.contains("good"));
    }

    fn ingress_with_paths(
        namespace: &str,
        name: &str,
        host: Option<&str>,
        paths: &[&str],
    ) -> Value {
        let paths: Vec<Value> = paths
            .iter()
            .map(|path| serde_json::json!({"path":path,"pathType":"Prefix","backend":{"service":{"name":"api","port":{"number":80}}}}))
            .collect();
        let mut rule = serde_json::json!({"http":{"paths":paths}});
        if let Some(host) = host {
            rule["host"] = host.into();
        }
        serde_json::json!({"kind":"Ingress","apiVersion":"networking.k8s.io/v1","metadata":{"name":name,"namespace":namespace},"spec":{"ingressClassName":"hangang","rules":[rule]}})
    }
    fn service(namespace: &str) -> Value {
        serde_json::json!({"kind":"Service","metadata":{"name":"api","namespace":namespace},"spec":{"ports":[{"port":80}]}})
    }

    #[test]
    fn exact_host_routes_precede_wildcard_and_hostless_routes_regardless_of_path_length() {
        // A hostless or wildcard rule with a longer path must not capture a
        // request for another tenant's exact host.
        let input = serde_json::json!({"items":[
            service("alpha"), service("zulu"),
            ingress_with_paths("alpha", "catch", None, &["/api/deep"]),
            ingress_with_paths("alpha", "wild", Some("*.example.test"), &["/api"]),
            ingress_with_paths("zulu", "exact", Some("api.example.test"), &["/"]),
        ]});
        let config = import(&input, "hangang").unwrap();
        let hosts: Vec<Option<&str>> = config.http.iter().map(|r| r.host.as_deref()).collect();
        assert_eq!(
            hosts,
            [Some("api.example.test"), Some("*.example.test"), None]
        );
        // Among equally specific hosts the longest path still wins.
        let input = serde_json::json!({"items":[
            service("blue"),
            ingress_with_paths("blue", "a", Some("api.example.test"), &["/", "/api/v1"]),
        ]});
        let config = import(&input, "hangang").unwrap();
        assert_eq!(config.http[0].path_prefix.as_deref(), Some("/api/v1"));
    }

    #[test]
    fn aggregate_route_budget_withdraws_only_the_excess_ingress() {
        let many: Vec<String> = (0..MAX_ROUTES).map(|i| format!("/p{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        let input = serde_json::json!({"items":[
            service("blue"),
            ingress_with_paths("blue", "a-small", Some("small.example.test"), &["/"]),
            ingress_with_paths("blue", "z-big", Some("big.example.test"), &many),
        ]});
        // Each object is individually valid, so only the aggregate overflows.
        assert!(import(&input, "hangang").is_err());
        let (config, accepted) = import_validated(&input, "hangang").unwrap();
        assert_eq!(config.http.len(), 1);
        assert_eq!(config.http[0].host.as_deref(), Some("small.example.test"));
        assert_eq!(
            accepted,
            BTreeSet::from([("blue".to_owned(), "a-small".to_owned())])
        );
        // Whichever object sorts later by identity is the one withdrawn; the
        // budget itself is honored either way.
        let input = serde_json::json!({"items":[
            service("blue"),
            ingress_with_paths("blue", "a-big", Some("big.example.test"), &many),
            ingress_with_paths("blue", "z-small", Some("small.example.test"), &["/"]),
        ]});
        let (config, accepted) = import_validated(&input, "hangang").unwrap();
        assert_eq!(config.http.len(), MAX_ROUTES);
        assert_eq!(
            accepted,
            BTreeSet::from([("blue".to_owned(), "a-big".to_owned())])
        );
    }

    #[test]
    fn serialized_size_budget_is_enforced_per_ingress() {
        // 600 routes of ~2 KiB each stay under the route cap but exceed 1 MiB.
        let long: Vec<String> = (0..600)
            .map(|i| format!("/{}{i}", "x".repeat(2000)))
            .collect();
        let long: Vec<&str> = long.iter().map(String::as_str).collect();
        let input = serde_json::json!({"items":[
            service("blue"),
            ingress_with_paths("blue", "a-small", Some("small.example.test"), &["/"]),
            ingress_with_paths("blue", "z-large", Some("large.example.test"), &long),
        ]});
        assert!(import(&input, "hangang").is_err());
        let (config, accepted) = import_validated(&input, "hangang").unwrap();
        assert_eq!(config.http.len(), 1);
        assert_eq!(accepted.len(), 1);
        assert!(serialized_len(&config) <= MAX_CONFIG_BYTES);
        // The incremental accounting matches the real serialized document.
        let input = serde_json::json!({"items":[
            service("blue"),
            ingress_with_paths("blue", "a", Some("a.example.test"), &["/", "/x"]),
            ingress_with_paths("blue", "b", None, &["/y"]),
        ]});
        let config = import(&input, "hangang").unwrap();
        assert_eq!(
            serialized_len(&config),
            serde_json::to_vec(&config).unwrap().len()
        );
    }
}
