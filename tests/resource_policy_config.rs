use hangang::config::{Config, Snapshot};
use serde_json::json;

fn config() -> Config {
    serde_json::from_value(json!({"http":[{
        "id":"protected", "host":"app.test", "path_prefix":"/admin", "path_match":"segment_prefix",
        "access_mode":"protected", "backends":["http://127.0.0.1:9"],
        "auth":{"url":"http://127.0.0.1:9/check", "response_headers":["x-subject"]},
        "resource_policy":{"resource_id":"admin", "principal":{"source":"external", "subject_header":"x-subject"},
            "allow":[{"subjects":["alice"],"methods":["GET"]}]}
    }]})).unwrap()
}

#[test]
fn policy_binding_and_shared_resource_authenticators_are_validated() {
    let original = config();
    original.validate().unwrap();
    let mut next = original.clone();
    next.http[0].auth.as_mut().unwrap().terminal_response = true;
    assert!(next.validate().is_err());
    next = original.clone();
    next.http[0].auth.as_mut().unwrap().response_headers.clear();
    assert!(next.validate().is_err());
    next = original.clone();
    let mut alias = next.http[0].clone();
    alias.id = "alias".into();
    alias.host = Some("www.app.test".into());
    next.http.push(alias);
    next.validate().unwrap();
    next.http[1].auth.as_mut().unwrap().url = "http://127.0.0.1:8/check".into();
    assert!(
        next.validate().is_err(),
        "same resource cannot silently use another identity authority"
    );
    next = original.clone();
    let mut alias = next.http[0].clone();
    alias.id = "alias".into();
    alias.resource_policy.as_mut().unwrap().allow.clear();
    next.http.push(alias);
    assert!(
        next.validate().is_err(),
        "same resource cannot carry a weaker/different permission policy"
    );
}

#[test]
fn namespace_removal_requires_an_explicit_prior_release() {
    let original = config();
    let mut next = original.clone();
    next.http.clear();
    assert!(next.validate_transition_from(&original).is_err());
    next = original.clone();
    next.http[0].resource_policy = None;
    assert!(next.validate_transition_from(&original).is_err());
    for field in ["host", "path_prefix", "path_match"] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["http"][0][field] = match field {
            "host" => json!("elsewhere.test"),
            "path_prefix" => json!("/admin/private"),
            _ => json!("exact"),
        };
        let modified: Config = serde_json::from_value(value).unwrap();
        assert!(
            modified.validate_transition_from(&original).is_err(),
            "{field}"
        );
    }
    // Merely renaming a route does not release its independently identified scope.
    next = original.clone();
    next.http[0].id = "renamed".into();
    next.validate_transition_from(&original).unwrap();
    next.http[0].enabled = false;
    next.validate_transition_from(&original).unwrap();
    assert_eq!(
        Snapshot::new(next.clone()).unwrap().resource_guards.len(),
        1
    );
    next.http[0].resource_policy.as_mut().unwrap().enforce = false;
    next.validate_transition_from(&original).unwrap();
    assert!(
        Snapshot::new(next.clone())
            .unwrap()
            .resource_guards
            .is_empty()
    );
    let mut released = next.clone();
    released.http.clear();
    released.validate_transition_from(&next).unwrap();
}

#[test]
fn configuration_paths_are_canonical_and_legacy_output_remains_compatible() {
    for path in [
        "/ad%6din",
        "/admin/..",
        "/admin//a",
        "/admin;a",
        "/admin%2fa",
    ] {
        let mut bad = config();
        bad.http[0].path_prefix = Some(path.into());
        assert!(bad.validate().is_err(), "{path}");
    }
    let legacy: Config = serde_json::from_value(
        json!({"http":[{"id":"public", "backends":["http://127.0.0.1:9"]}]}),
    )
    .unwrap();
    assert!(
        serde_json::to_value(legacy).unwrap()["http"][0]
            .get("resource_policy")
            .is_none()
    );
}

#[test]
fn published_resource_example_is_a_valid_protected_configuration() {
    let example: Config =
        serde_json::from_str(include_str!("../examples/resource-policy.json")).unwrap();
    example.validate().unwrap();
    let snapshot = Snapshot::new(example).unwrap();
    assert_eq!(snapshot.resource_guards.len(), 1);
    assert_eq!(snapshot.http[0].route.hosts.len(), 2);
    assert!(snapshot.http[0].route.lua.is_some());
}

#[test]
fn adding_and_reordering_aliases_does_not_require_releasing_protection() {
    let original = config();
    let mut expanded = original.clone();
    expanded.http[0].host = None;
    expanded.http[0].hosts = vec!["www.app.test".into(), "APP.TEST".into()];
    expanded.validate().unwrap();
    expanded.validate_transition_from(&original).unwrap();
    let mut reordered = expanded.clone();
    reordered.http[0].hosts.reverse();
    reordered.validate_transition_from(&expanded).unwrap();
    assert!(
        original.validate_transition_from(&expanded).is_err(),
        "removing an alias needs explicit release"
    );
    let mut changed = expanded.clone();
    changed.http[0].hosts = vec!["*.test".into()];
    assert!(
        changed.validate_transition_from(&expanded).is_err(),
        "do not guess glob containment"
    );
}
