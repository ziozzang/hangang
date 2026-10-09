use hangang::config::{Config, Snapshot};
use serde_json::json;

#[test]
fn regex_validation_limits_and_mutually_exclusive_http_fields() {
    for route in [
        json!({"id":"a","host":"*.foo.com","host_regex":".*","backends":["http://localhost"]}),
        json!({"id":"a","host_regex":"(?=foo)","backends":["http://localhost"]}),
        json!({"id":"a","host_regex":"foo)|(?:.*","backends":["http://localhost"]}),
        json!({"id":"a","host_regex":"a{1000000}","backends":["http://localhost"]}),
    ] {
        let config: Config = serde_json::from_value(json!({"http":[route]})).unwrap();
        assert!(Snapshot::new(config).is_err());
    }
    let routes: Vec<_> = (0..257)
        .map(|i| json!({"id":format!("r{i}"),"host_regex":".*","backends":["http://localhost"]}))
        .collect();
    let config: Config = serde_json::from_value(json!({"http":routes})).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn http_host_aliases_validate_as_one_bounded_mutually_exclusive_condition() {
    let route = json!({"id":"group","hosts":["foo.com","www.foo.com","*.alias.test"],"backends":["http://localhost"]});
    let config: Config = serde_json::from_value(json!({"http":[route]})).unwrap();
    assert!(Snapshot::new(config.clone()).is_ok());
    assert_eq!(
        serde_json::to_value(&config).unwrap()["http"][0]["hosts"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let legacy: Config = serde_json::from_value(
        json!({"http":[{"id":"legacy","host":"foo.com","backends":["http://localhost"]}]}),
    )
    .unwrap();
    assert!(
        serde_json::to_value(&legacy).unwrap()["http"][0]
            .get("hosts")
            .is_none()
    );

    for aliases in [
        json!([]),
        json!(["FOO.com", "foo.COM"]),
        json!(["*.foo.com", "*.FOO.COM"]),
        json!(["*.bad_name.test"]),
        json!(
            (0..33)
                .map(|index| format!("host{index}.test"))
                .collect::<Vec<_>>()
        ),
    ] {
        let parsed = serde_json::from_value::<Config>(
            json!({"http":[{"id":"bad","hosts":aliases,"backends":["http://localhost"]}]}),
        );
        assert!(parsed.is_err() || parsed.unwrap().validate().is_err());
    }
    for extra in [json!({"host":"foo.com"}), json!({"host_regex":"foo[.]com"})] {
        let mut route = json!({"id":"bad","hosts":["foo.com"],"backends":["http://localhost"]});
        route
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let config: Config = serde_json::from_value(json!({"http":[route]})).unwrap();
        assert!(config.validate().is_err());
    }
}
#[test]
fn tcp_glob_and_regex_limits_are_separate_from_certificate_names() {
    let route = |i: usize, priority: i32| json!({"id":format!("r{i}"),"listen":"127.0.0.1:9443","priority":priority,"backends":["localhost:80"],"sni":{"hosts":["f??.bar.com"]}});
    let config: Config = serde_json::from_value(json!({"tcp":[route(1,0),route(2,1)]})).unwrap();
    assert!(Snapshot::new(config).is_ok());
    let config: Config = serde_json::from_value(json!({"tcp":[route(1,0),route(2,0)]})).unwrap();
    assert!(config.validate().is_err());
    let config:Config=serde_json::from_value(json!({"tcp":[{"id":"regex-only","listen":"127.0.0.1:9443","backends":["localhost:80"],"sni":{"host_regexes":["f[a-z]{2}[.]bar[.]com"]}}]})).unwrap();
    assert!(Snapshot::new(config).is_ok());
    let routes:Vec<_>=(0..257).map(|i|json!({"id":format!("r{i}"),"listen":"127.0.0.1:9443","backends":["localhost:80"],"sni":{"hosts":[format!("f??.r{i}.com")]}})).collect();
    let config: Config = serde_json::from_value(json!({"tcp":routes})).unwrap();
    assert!(config.validate().is_err());
    let config:Config=serde_json::from_value(json!({"certificates":[{"id":"cert","hosts":["f??.bar.com"],"cert_file":"/tmp/cert.pem","key_file":"/tmp/key.pem"}]})).unwrap();
    assert!(config.validate().is_err());
}

fn case_config(routes: serde_json::Value) -> anyhow::Result<()> {
    let config: Config = serde_json::from_value(json!({"http": routes}))?;
    config.validate()
}

fn basic() -> serde_json::Value {
    json!({"realm":"r","credentials":["u:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000"]})
}

#[test]
fn path_case_round_trips_and_rejects_unknown_values() {
    let config: Config = serde_json::from_value(json!({"http":[
        {"id":"a","path_prefix":"/a","path_case":"insensitive","backends":["http://localhost"]}]}))
    .unwrap();
    assert_eq!(
        serde_json::to_value(&config).unwrap()["http"][0]["path_case"],
        "insensitive"
    );
    let absent: Config = serde_json::from_value(json!({"http":[
        {"id":"a","backends":["http://localhost"]}]}))
    .unwrap();
    assert!(
        serde_json::to_value(&absent).unwrap()["http"][0]
            .get("path_case")
            .is_none()
    );
    assert!(
        serde_json::from_value::<Config>(json!({"http":[
        {"id":"a","path_case":"fold","backends":["http://localhost"]}]}))
        .is_err()
    );
}

#[test]
fn mixed_case_sensitivity_on_same_prefix_and_host_is_rejected() {
    let protected = json!({"id":"p","host":"a.test","path_prefix":"/admin","basic_auth":basic(),"backends":["http://localhost"]});
    let public_variant = json!({"id":"q","host":"A.test","path_prefix":"/ADMIN/open","backends":["http://localhost"]});
    // /ADMIN/open differs from /admin by more than case: no conflict.
    case_config(json!([protected, public_variant])).unwrap();
    let same =
        json!({"id":"q","host":"A.test","path_prefix":"/Admin","backends":["http://localhost"]});
    let error = case_config(json!([protected, same]))
        .unwrap_err()
        .to_string();
    assert!(error.contains("path_case"), "{error}");
    // Different hosts do not overlap; explicit insensitive on both is consistent.
    let other_host =
        json!({"id":"q","host":"b.test","path_prefix":"/Admin","backends":["http://localhost"]});
    case_config(json!([protected, other_host])).unwrap();
    let both = json!({"id":"q","host":"a.test","path_prefix":"/Admin","path_case":"insensitive","backends":["http://localhost"]});
    case_config(json!([protected, both])).unwrap();
}

#[test]
fn explicit_sensitive_protected_prefix_is_accepted_with_a_named_warning() {
    let sensitive = json!({"id":"p","path_prefix":"/admin","path_case":"sensitive","access_mode":"protected","basic_auth":basic(),"backends":["http://localhost"]});
    let config: Config = serde_json::from_value(json!({"http":[sensitive]})).unwrap();
    config.validate().unwrap();
    let warnings = config.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("p") && warnings[0].contains("case variant"));
    let default: Config = serde_json::from_value(json!({"http":[
        {"id":"p","path_prefix":"/admin","basic_auth":basic(),"backends":["http://localhost"]}]}))
    .unwrap();
    assert!(default.warnings().is_empty());
}
