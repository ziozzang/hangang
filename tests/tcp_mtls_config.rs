use hangang::config::Config;
use serde_json::Value;

fn example() -> Value {
    serde_json::from_str(include_str!("../examples/tcp-mtls.json")).unwrap()
}

#[test]
fn published_mtls_policy_validates_without_reading_private_files() {
    let config: Config = serde_json::from_value(example()).unwrap();
    config.validate().unwrap();
    let mut incompatible = example();
    incompatible["tcp"][0]["sni"] = serde_json::json!({"hosts":["example.test"]});
    let config: Config = serde_json::from_value(incompatible).unwrap();
    assert!(config.validate().is_err());
}

#[test]
fn distinct_workload_policies_have_a_preparation_budget() {
    let mut document = example();
    let route = document["tcp"][0].clone();
    let routes = document["tcp"].as_array_mut().unwrap();
    routes.clear();
    for index in 0..65 {
        let mut route = route.clone();
        route["id"] = format!("workload-{index}").into();
        route["listen"] = format!("127.0.0.1:{}", 10_000 + index).into();
        route["inbound_tls"]["handshake_timeout_ms"] = (index + 1).into();
        routes.push(route);
    }
    let config: Config = serde_json::from_value(document.clone()).unwrap();
    assert!(config.validate().is_err());
    document["tcp"].as_array_mut().unwrap().pop();
    let config: Config = serde_json::from_value(document).unwrap();
    config.validate().unwrap();
}
