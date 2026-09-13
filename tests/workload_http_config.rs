use hangang::config::{Config, Snapshot};
use serde_json::{Value, json};
use std::sync::Arc;
fn document() -> Value {
    json!({"http":[{"id":"private", "host":"api.example.test", "backends":["http://127.0.0.1:9"], "access_mode":"protected",
        "workload_auth":{"listener_ids":["workloads"],"allowed_uri_sans":["spiffe://example.test/orders"],"identity_header":"x-workload-subject"},
        "resource_policy":{"resource_id":"orders","principal":{"source":"workload"},"allow":[{"subjects":["spiffe://example.test/orders"],"methods":["GET"]}]}}]})
}
fn config(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}
#[test]
fn workload_namespace_requires_protected_resource_and_accepts_long_canonical_identity() {
    config(document()).validate().unwrap();
    for field in ["resource_policy", "workload_auth"] {
        let mut value = document();
        value["http"][0].as_object_mut().unwrap().remove(field);
        assert!(config(value).validate().is_err());
    }
    let mut value = document();
    value["http"][0]["access_mode"] = json!("legacy");
    assert!(config(value).validate().is_err());
    let mut value = document();
    let uri = format!("spiffe://example.test/{}", "a".repeat(300));
    value["http"][0]["workload_auth"]["allowed_uri_sans"] = json!([uri]);
    value["http"][0]["resource_policy"]["allow"][0]["subjects"] = json!([uri]);
    config(value).validate().unwrap();
}
#[test]
fn workload_identity_names_are_reserved_across_public_routes() {
    let mut value = document();
    value["http"].as_array_mut().unwrap().push(
        json!({"id":"public","host":"public.example.test","backends":["http://127.0.0.1:9"]}),
    );
    let snapshot = Snapshot::new(config(value.clone())).unwrap();
    assert!(snapshot.http.iter().all(|route| {
        route
            .auth_reserved
            .iter()
            .any(|header| header == "x-workload-subject")
    }));
    for change in [
        json!({"request_transform":{"set_headers":{"X-Workload-Subject":"forged"}}}),
        json!({"headers":{"x-workload-subject":"forged"}}),
        json!({"auth":{"url":"http://127.0.0.1:9","response_headers":["x-workload-subject"]}}),
    ] {
        let mut changed = value.clone();
        for (key, entry) in change.as_object().unwrap() {
            changed["http"][1][key] = entry.clone();
        }
        assert!(config(changed).validate().is_err());
    }
}
#[test]
fn unchanged_workload_routes_reuse_leases_but_policy_and_disable_withdraw_them() {
    let first = Snapshot::new(config(document())).unwrap();
    let next = Snapshot::replace(first.config.clone(), &first).unwrap();
    assert!(Arc::ptr_eq(
        &first.workload_routes["private"],
        &next.workload_routes["private"]
    ));
    let mut changed = next.config.clone();
    changed.http[0]
        .resource_policy
        .as_mut()
        .unwrap()
        .allow
        .clear();
    let denied = Snapshot::replace(changed, &next).unwrap();
    assert!(!Arc::ptr_eq(
        &next.workload_routes["private"],
        &denied.workload_routes["private"]
    ));
    let mut disabled = denied.config.clone();
    disabled.http[0].enabled = false;
    let disabled = Snapshot::replace(disabled, &denied).unwrap();
    assert!(disabled.workload_routes.is_empty());
}
#[test]
fn listener_role_change_requires_a_separate_retirement_revision() {
    let old = config(
        json!({"tcp":[{"id":"opaque","listen":"127.0.0.1:9443","backends":["127.0.0.1:9"]}]}),
    );
    let new = config(
        json!({"workload_http":[{"id":"workloads","listen":"127.0.0.1:9443","tls":{"cert_file":"/etc/hangang/server.pem","key_file":"/etc/hangang/server.key","client_ca_file":"/etc/hangang/ca.pem","allowed_uri_sans":["spiffe://example.test/orders"]}}]}),
    );
    old.validate().unwrap();
    new.validate().unwrap();
    assert!(new.validate_transition_from(&old).is_err());
    assert!(old.validate_transition_from(&new).is_err());
    new.validate_transition_from(&Config::default()).unwrap();
    let mut disabled = new;
    disabled.workload_http[0].enabled = false;
    assert!(
        Snapshot::new(disabled)
            .unwrap()
            .http_workload_tls
            .is_empty()
    );
}

#[test]
fn published_workload_http_example_passes_structural_validation() {
    let example: Config =
        serde_json::from_str(include_str!("../examples/http-workload-mtls.json")).unwrap();
    example.validate().unwrap();
}
