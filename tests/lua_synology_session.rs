//! Product policy stays in an example and runs through the ordinary Lua worker.
use hangang::{
    country_observation::Observation,
    policy::{PolicyPool, TransformInput},
};
use serde_json::{Value, json};
use std::sync::Arc;
const SCRIPT: &str = include_str!("../examples/lua/synology-session-redact.lua");
const PREFIX: &str = "if (typeof(SYNO) === 'undefined') {SYNO = {};}\nSYNO.SDS = SYNO.SDS || {};\nSYNO.SDS.Session = ";
fn fixture(logged_in: bool) -> Value {
    json!({"isLogined":logged_in,"enable_syno_token":"yes","hostname":"private-fixture","fullversion":"fixture-full","version":"fixture-version","buildphase":"fixture-phase","dsm_http_port":5000,"dsm_https_port":5001,"dsm_upgrade_pgsql_status":"fixture-status","login_welcome_title":"Welcome","login_background_enable":true,"cas_sso_enable":false,"oidc_sso_enable":false,"saml_sso_enable":false,"enable_http_negotiate":false,"sso_name":"private-fixture-provider","sso_server":"https://private.invalid/","cas_service_ids":[],"optional":null})
}
fn encoded(value: &Value) -> Vec<u8> {
    format!("{PREFIX}{value}\n;\n").into_bytes()
}
async fn apply(pool: &Arc<PolicyPool>, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    pool.transform(TransformInput {
        script: SCRIPT.into(),
        body,
        phase: "response".into(),
        geoip: Observation::default(),
    })
    .await
}
#[tokio::test]
async fn anonymous_metadata_removed_without_evaluating_js_or_changing_login_guards() {
    let pool = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let source = fixture(false);
    let output = apply(&pool, encoded(&source)).await.unwrap();
    let text = String::from_utf8(output).unwrap();
    let output: Value = serde_json::from_str(
        text.strip_prefix(PREFIX)
            .unwrap()
            .trim()
            .strip_suffix(';')
            .unwrap(),
    )
    .unwrap();
    for key in [
        "hostname",
        "fullversion",
        "version",
        "buildphase",
        "dsm_http_port",
        "dsm_https_port",
        "dsm_upgrade_pgsql_status",
        "sso_name",
        "sso_server",
        "cas_service_ids",
    ] {
        assert!(output.get(key).is_none(), "{key}");
    }
    for key in [
        "isLogined",
        "enable_syno_token",
        "login_welcome_title",
        "login_background_enable",
        "cas_sso_enable",
        "oidc_sso_enable",
        "saml_sso_enable",
        "enable_http_negotiate",
        "optional",
    ] {
        assert_eq!(output[key], source[key], "{key}");
    }
    let authenticated = encoded(&fixture(true));
    assert_eq!(
        apply(&pool, authenticated.clone()).await.unwrap(),
        authenticated
    );
    let mut active = fixture(false);
    active["saml_sso_enable"] = json!(true);
    let output = apply(&pool, encoded(&active)).await.unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("private-fixture-provider")
    );
    for unrelated in [
        b"{\"error\":{\"code\":103},\"success\":false}".to_vec(),
        b"binary\0\xff".to_vec(),
    ] {
        assert_eq!(apply(&pool, unrelated.clone()).await.unwrap(), unrelated);
    }
    pool.shutdown().await;
}
#[tokio::test]
async fn malformed_selected_wrappers_and_required_schema_fail_closed() {
    let pool = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 1));
    let mut missing = fixture(false);
    missing.as_object_mut().unwrap().remove("enable_syno_token");
    let mut wrong = fixture(false);
    wrong["isLogined"] = json!("false");
    for body in [
        encoded(&missing),
        encoded(&wrong),
        format!("{PREFIX}{{invalid}};\n").into_bytes(),
        format!("{PREFIX}{}; alert('not-executed');", fixture(false)).into_bytes(),
        format!("{PREFIX}{}", fixture(false)).into_bytes(),
        b"SYNO.SDS.Session = {};".to_vec(),
    ] {
        assert!(apply(&pool, body).await.is_err());
    }
    assert!(
        apply(&pool, encoded(&fixture(false))).await.is_ok(),
        "malformed input must not poison the next worker operation"
    );
    pool.shutdown().await;
}
