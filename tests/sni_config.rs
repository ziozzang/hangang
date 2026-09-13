use hangang::config::Config;
use serde_json::{Value, json};
fn route(id: &str, host: &str) -> Value {
    json!({"id":id,"listen":"127.0.0.1:19443","backends":["127.0.0.1:20443"],"sni":{"hosts":[host]}})
}
#[test]
fn shared_sni_listener_requires_unambiguous_hosts_and_uniform_limits() {
    let a = route("a", "one.example.test");
    let b = route("b", "*.example.test");
    let config: Config = serde_json::from_value(json!({"tcp":[a,b]})).unwrap();
    config.validate().unwrap();
    for mutation in ["duplicate", "raw", "size", "time"] {
        let mut a = route("a", "one.example.test");
        let mut b = route("b", "*.example.test");
        match mutation {
            "duplicate" => b["sni"]["hosts"] = json!(["one.example.test"]),
            "raw" => a["sni"] = Value::Null,
            "size" => b["sni"]["max_client_hello_bytes"] = json!(4096),
            "time" => b["sni"]["hello_timeout_ms"] = json!(100),
            _ => unreachable!(),
        };
        let c: Config = serde_json::from_value(json!({"tcp":[a,b]})).unwrap();
        assert!(c.validate().is_err(), "{mutation}");
    }
}
#[test]
fn sni_settings_and_certificate_metadata_roundtrip_without_secret_material() {
    let config:Config=serde_json::from_value(json!({"tcp":[route("a","*.example.test")],"certificates":[{"id":"web","hosts":["web.example.test"],"cert_file":"/run/certs/web.pem","key_file":"/run/certs/web.key"}]})).unwrap();
    config.validate().unwrap();
    let serialized = serde_json::to_value(&config).unwrap();
    assert_eq!(serialized["tcp"][0]["sni"]["max_client_hello_bytes"], 65536);
    assert_eq!(serialized["tcp"][0]["sni"]["hello_timeout_ms"], 3000);
    assert_eq!(
        serde_json::from_value::<Config>(serialized).unwrap(),
        config
    );
}
