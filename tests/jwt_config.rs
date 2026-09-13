use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hangang::config::{Config, Snapshot};
use serde_json::{Value, json};
use std::sync::Arc;

fn document() -> Value {
    let key = ed25519_dalek::SigningKey::from_bytes(&[73; 32]).verifying_key();
    json!({"http":[{"id":"private", "host":"jwt.test", "access_mode":"protected",
        "backends":["http://127.0.0.1:9"], "jwt_auth":{
            "verification":{"issuer":"https://issuer.example/", "audiences":["api"], "profile":"rfc9068", "algorithms":["EdDSA"]},
            "keys":{"source":"local", "jwks":{"keys":[{"kty":"OKP", "crv":"Ed25519", "alg":"EdDSA", "kid":"test-key", "use":"sig", "x":URL_SAFE_NO_PAD.encode(key.to_bytes())}]}},
            "identity_header":"x-jwt-subject"},
        "resource_policy":{"resource_id":"private", "principal":{"source":"jwt"}, "allow":[{"subjects":["alice"],"methods":["GET"]}]}
    }]})
}
fn parse(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}

#[test]
fn local_jwks_supports_normal_json_and_rejects_duplicate_members_before_maps() {
    let text = serde_json::to_string(&document()).unwrap();
    let config: Config = serde_json::from_str(&text).unwrap();
    config.validate().unwrap();
    parse(document()).validate().unwrap();
    let duplicate = text.replace(
        "\"kid\":\"test-key\"",
        "\"kid\":\"other\",\"kid\":\"test-key\"",
    );
    assert_ne!(duplicate, text);
    assert!(serde_json::from_str::<Config>(&duplicate).is_err());
    let mut private = document();
    private["http"][0]["jwt_auth"]["keys"]["jwks"]["keys"][0]["d"] = json!("not-public");
    assert!(parse(private).validate().is_err());
}

#[test]
fn jwt_identity_headers_cannot_replace_transport_or_credentials() {
    for name in [
        "host",
        "authorization",
        "cookie",
        "content-length",
        "x-real-ip",
        "x-forwarded-host",
        "x-original-uri",
        "sec-websocket-key",
        "x-hangang-auth-terminal",
    ] {
        let mut value = document();
        value["http"][0]["jwt_auth"]["identity_header"] = json!(name);
        assert!(parse(value).validate().is_err(), "{name}");
    }
    let mut value = document();
    value["http"][0]["request_transform"] = json!({"set_headers":{"x-jwt-subject":"mallory"}});
    assert!(parse(value).validate().is_err());
    let mut value = document();
    value["http"][0]["auth"] =
        json!({"url":"http://127.0.0.1:9/check", "response_headers":["X-JWT-SUBJECT"]});
    assert!(parse(value).validate().is_err());
}

#[test]
fn jwt_source_is_bound_to_resource_and_cache_eligibility() {
    let mut value = document();
    value["http"][0]["jwt_auth"] = Value::Null;
    value["http"][0]["auth"] = json!({"url":"http://127.0.0.1:9/check"});
    assert!(parse(value).validate().is_err());
    let mut value = document();
    let mut alias = value["http"][0].clone();
    alias["id"] = json!("alias");
    alias["host"] = json!("www.jwt.test");
    alias["jwt_auth"]["verification"]["audiences"] = json!(["other-api"]);
    value["http"].as_array_mut().unwrap().push(alias);
    assert!(parse(value).validate().is_err());
    let mut config = parse(document());
    config.http[0].resource_policy = None;
    config.http[0].access_mode = hangang::config::AccessMode::Legacy;
    config.http[0].cache = Some(hangang::cache_policy::RouteCache {
        ttl_seconds: 10,
        max_ttl_seconds: 10,
    });
    assert!(!hangang::cache_policy::route_eligible(&config.http[0]));
}

#[test]
fn unchanged_jwt_policies_share_runtime_and_replacements_get_a_fresh_generation() {
    let mut value = document();
    let mut alias = value["http"][0].clone();
    alias["id"] = json!("alias");
    alias["host"] = json!("www.jwt.test");
    value["http"].as_array_mut().unwrap().push(alias);
    let snapshot = Snapshot::new(parse(value)).unwrap();
    assert!(Arc::ptr_eq(
        snapshot.http[0].jwt_auth.as_ref().unwrap(),
        snapshot.http[1].jwt_auth.as_ref().unwrap()
    ));
    let mut changed = snapshot.config.clone();
    changed.http[0].priority = 5;
    let next = Snapshot::replace(changed, &snapshot).unwrap();
    assert!(Arc::ptr_eq(
        snapshot.http[0].jwt_auth.as_ref().unwrap(),
        next.http[0].jwt_auth.as_ref().unwrap()
    ));
    let mut changed = next.config.clone();
    for route in &mut changed.http {
        route.jwt_auth.as_mut().unwrap().verification.audiences = vec!["replacement-api".into()];
    }
    let final_snapshot = Snapshot::replace(changed, &next).unwrap();
    assert!(!Arc::ptr_eq(
        next.http[0].jwt_auth.as_ref().unwrap(),
        final_snapshot.http[0].jwt_auth.as_ref().unwrap()
    ));
}

#[test]
fn published_oidc_example_validates_without_network_access() {
    let config: Config = serde_json::from_str(include_str!("../examples/jwt-auth.json")).unwrap();
    config.validate().unwrap();
    Snapshot::new(config).unwrap();
}
