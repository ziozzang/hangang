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
