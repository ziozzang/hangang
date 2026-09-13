//! Owned gateway process exercising the configuration/API certificate boundary.
use serde_json::json;
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn material(dir: &Path, id: &str, host: &str) -> (serde_json::Value, String) {
    let pair = rcgen::generate_simple_self_signed(vec![host.into()]).unwrap();
    let cert = dir.join(format!("{id}.pem"));
    let key = dir.join(format!("{id}.key"));
    std::fs::write(&cert, pair.cert.pem()).unwrap();
    std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
    (
        json!({"id":id,"hosts":[host],"cert_file":cert,"key_file":key}),
        pair.cert.pem(),
    )
}
fn client(public: u16, roots: &[&str]) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2));
    for host in ["first.test", "one.second.test", "missing.test"] {
        b = b.resolve(host, format!("127.0.0.1:{public}").parse().unwrap());
    }
    for root in roots {
        b = b.add_root_certificate(reqwest::Certificate::from_pem(root.as_bytes()).unwrap());
    }
    b.build().unwrap()
}
#[tokio::test]
async fn config_tls_api_updates_rotate_and_remove_certificates_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let (first, root1) = material(dir.path(), "first", "first.test");
    let (second, root2) = material(dir.path(), "second", "*.second.test");
    let config = dir.path().join("config.json");
    std::fs::write(&config, json!({"certificates":[first,second]}).to_string()).unwrap();
    let public = port();
    let mut admin = port();
    while admin == public {
        admin = port();
    }
    let token = "test-config-tls-token";
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_hangang"))
            .args([
                "--config",
                config.to_str().unwrap(),
                "--config-tls",
                "--listen",
                &format!("127.0.0.1:{public}"),
                "--admin",
                &format!("127.0.0.1:{admin}"),
                "--threads",
                "2",
                "--lua-workers",
                "1",
            ])
            .env("HANGANG_ADMIN_TOKEN", token)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let admin_client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let base = format!("http://127.0.0.1:{admin}");
    let mut ready = false;
    for _ in 0..100 {
        assert!(process.0.try_wait().unwrap().is_none());
        if admin_client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .is_ok()
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(ready);
    let tls = client(public, &[&root1, &root2]);
    for host in ["first.test", "one.second.test"] {
        assert_eq!(
            tls.get(format!("https://{host}:{public}/"))
                .send()
                .await
                .unwrap()
                .status(),
            404
        );
    }
    let connections = (0..64).map(|index| {
        let fresh = client(public, &[&root1, &root2]);
        async move {
            let host = if index % 2 == 0 {
                "first.test"
            } else {
                "one.second.test"
            };
            fresh
                .get(format!("https://{host}:{public}/"))
                .send()
                .await
                .unwrap()
                .status()
        }
    });
    for status in futures_util::future::join_all(connections).await {
        assert_eq!(status, 404);
    }
    assert!(
        tls.get(format!("https://missing.test:{public}/"))
            .send()
            .await
            .is_err()
    );
    let reply = admin_client
        .get(format!("{base}/v1/config"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    let etag = reply.headers()["etag"].to_str().unwrap().to_owned();
    let mut document: serde_json::Value = reply.json().await.unwrap();
    assert!(!document.to_string().contains("BEGIN"));
    let mut invalid = document.clone();
    invalid["certificates"][0]["key_file"] = json!(dir.path().join("missing.key"));
    for endpoint in ["/v1/config/validate", "/v1/config"] {
        let req = if endpoint.ends_with("validate") {
            admin_client.post(format!("{base}{endpoint}"))
        } else {
            admin_client.put(format!("{base}{endpoint}"))
        };
        assert_eq!(
            req.bearer_auth(token)
                .header("if-match", &etag)
                .json(&invalid)
                .send()
                .await
                .unwrap()
                .status(),
            422
        );
    }
    assert_eq!(
        client(public, &[&root1])
            .get(format!("https://first.test:{public}/"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    // A broken pair on disk preserves the last working TLS configuration.
    std::fs::write(dir.path().join("first.pem"), "invalid PEM").unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert_eq!(
        client(public, &[&root1])
            .get(format!("https://first.test:{public}/"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let (_, rotated) = material(dir.path(), "first", "first.test");
    let mut changed = false;
    for _ in 0..100 {
        if client(public, &[&rotated])
            .get(format!("https://first.test:{public}/"))
            .send()
            .await
            .is_ok()
        {
            changed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(changed, "certificate files must hot reload");
    document["certificates"] = json!([second]);
    let reply = admin_client
        .put(format!("{base}/v1/config"))
        .bearer_auth(token)
        .header("if-match", &etag)
        .json(&document)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert!(
        client(public, &[&rotated])
            .get(format!("https://first.test:{public}/"))
            .send()
            .await
            .is_err()
    );
    assert_eq!(
        client(public, &[&root2])
            .get(format!("https://one.second.test:{public}/"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    let etag = reply.headers()["etag"].to_str().unwrap().to_owned();
    document = reply.json().await.unwrap();
    document["certificates"] = json!([]);
    assert_eq!(
        admin_client
            .put(format!("{base}/v1/config"))
            .bearer_auth(token)
            .header("if-match", etag)
            .json(&document)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert!(
        client(public, &[&root2])
            .get(format!("https://one.second.test:{public}/"))
            .send()
            .await
            .is_err()
    );
    // Empty certificate sets do not silently turn the public listener into plaintext.
    assert!(
        admin_client
            .get(format!("http://127.0.0.1:{public}/"))
            .send()
            .await
            .is_err()
    );
}

#[test]
fn configuration_tls_rejects_competing_certificate_authorities() {
    for args in [
        vec!["--kubernetes-controller"],
        vec!["--acme-config", "/unused/acme.json"],
        vec![
            "--tls-cert",
            "/unused/cert.pem",
            "--tls-key",
            "/unused/key.pem",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_hangang"))
            .arg("--config-tls")
            .args(args)
            .arg("--check")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be used with"));
    }
}
