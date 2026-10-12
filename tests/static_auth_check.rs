use std::process::Command;

fn check(env: Option<(&str, &str)>, enabled: bool) -> std::process::Output {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    let config = serde_json::json!({"revision":0,"tcp":[],"http":[{
        "id":"web","path_prefix":"/","enabled":enabled,"backends":["http://127.0.0.1:9"],
        "auth":{"url":"http://127.0.0.1:9/check",
            "static_request_headers":{"x-key":{"env":"HANGANG_HC3_CHECK_KEY"}}}
    }]});
    std::fs::write(&path, config.to_string()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_hangang"));
    command
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .env_remove("HANGANG_HC3_CHECK_KEY");
    if let Some((name, value)) = env {
        command.env(name, value);
    }
    command.output().unwrap()
}

#[test]
fn check_resolves_static_header_variables_and_reports_names_only() {
    let output = check(None, true);
    assert!(
        !output.status.success(),
        "missing variable must fail --check"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("HANGANG_HC3_CHECK_KEY"), "{stderr}");
    assert!(stderr.contains("web"), "{stderr}");

    let output = check(Some(("HANGANG_HC3_CHECK_KEY", "")), true);
    assert!(!output.status.success(), "empty variable must fail --check");
    assert!(String::from_utf8_lossy(&output.stderr).contains("HANGANG_HC3_CHECK_KEY"));

    // An invalid header value is rejected by variable name, never by value.
    let output = check(
        Some(("HANGANG_HC3_CHECK_KEY", "bad\nsecret-value-xyz")),
        true,
    );
    assert!(!output.status.success(), "invalid value must fail --check");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(all.contains("HANGANG_HC3_CHECK_KEY"), "{all}");
    assert!(!all.contains("secret-value-xyz"), "{all}");

    let output = check(Some(("HANGANG_HC3_CHECK_KEY", "ok-value-xyz")), true);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("configuration valid") && !stdout.contains("ok-value-xyz"));

    // A disabled route is never selected, so it needs no variable.
    assert!(check(None, false).status.success());
}

#[test]
fn check_prints_path_case_warning_for_sensitive_protected_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.json");
    let config = serde_json::json!({"revision":0,"tcp":[],"http":[{
        "id":"admin","path_prefix":"/admin","path_case":"sensitive",
        "basic_auth":{"realm":"r","credentials":["u:00000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000"]},
        "backends":["http://127.0.0.1:9"]
    }]});
    std::fs::write(&path, config.to_string()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hangang"))
        .arg("--config")
        .arg(&path)
        .arg("--check")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        all.contains("warning") && all.contains("admin") && all.contains("case"),
        "{all}"
    );
}
