//! Owned loopback sockets only: public handshake capacity must not pin admin TLS.
use std::{process::Stdio, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpStream};

const TOKEN: &str = "test-token-for-handshake-admission";

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ports() -> [u16; 3] {
    // Keep all reservations alive together to obtain distinct ephemeral ports.
    let reservations: Vec<_> = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|index| reservations[index].local_addr().unwrap().port())
}

async fn status(client: &reqwest::Client, admin: u16) -> anyhow::Result<serde_json::Value> {
    Ok(client
        .get(format!("https://localhost:{admin}/v1/status"))
        .bearer_auth(TOKEN)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn assert_rejected_before_handshake_deadline(port: u16) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut byte = [0u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("an excess public handshake waited instead of being rejected");
    assert!(
        matches!(read, Ok(0))
            || matches!(read, Err(ref error) if error.kind() == std::io::ErrorKind::ConnectionReset),
        "unexpected excess-handshake result: {read:?}"
    );
}

#[tokio::test]
async fn cli_and_named_tls_share_capacity_without_starving_admin_tls() {
    let directory = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = directory.path().join("server.pem");
    let key = directory.path().join("server.key");
    std::fs::write(&cert, pair.cert.pem()).unwrap();
    std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
    let [public, named, admin] = ports();
    let config = directory.path().join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
            "revision":0,"http":[],"tcp":[],
            "public_http":[{
                "id":"edge","listen":format!("127.0.0.1:{named}"),
                "certificates":[{"id":"localhost","hosts":[],"default":true,
                    "cert_file":cert,"key_file":key}]
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let mut child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_hangang"))
            .arg("--config")
            .arg(&config)
            .args([
                "--listen",
                &format!("127.0.0.1:{public}"),
                "--admin",
                &format!("127.0.0.1:{admin}"),
                "--threads",
                "2",
                "--lua-workers",
                "1",
                "--max-connections",
                "128",
            ])
            .arg("--tls-cert")
            .arg(&cert)
            .arg("--tls-key")
            .arg(&key)
            .arg("--admin-tls-cert")
            .arg(&cert)
            .arg("--admin-tls-key")
            .arg(&key)
            .env("HANGANG_ADMIN_TOKEN", TOKEN)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    // Disable pooling: every status read performs a fresh administrator TLS
    // handshake, so an already-established admin socket cannot mask starvation.
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(1))
        .add_root_certificate(reqwest::Certificate::from_pem(pair.cert.pem().as_bytes()).unwrap())
        .build()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "server exited before readiness"
            );
            if status(&client, admin).await.is_ok() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut stalled = Vec::with_capacity(64);
    for index in 0..64 {
        let target = if index % 2 == 0 { public } else { named };
        stalled.push(TcpStream::connect(("127.0.0.1", target)).await.unwrap());
    }
    // Observe the actual accepted sockets through the independent admin
    // listener rather than assuming they were accepted after a fixed sleep.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = status(&client, admin).await.unwrap();
            assert_eq!(
                snapshot["metrics"]["rejected_connections_total"], 0,
                "the initial 64 public handshakes should fit their shared budget"
            );
            if snapshot["metrics"]["active_connections"].as_u64().unwrap() >= 65 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Both public listeners must reject immediately while the shared budget
    // is full; independent per-listener pools would wrongly admit these.
    assert_rejected_before_handshake_deadline(public).await;
    assert_rejected_before_handshake_deadline(named).await;
    let saturated = status(&client, admin)
        .await
        .expect("public saturation blocked fresh admin TLS");
    assert!(
        saturated["metrics"]["rejected_connections_total"]
            .as_u64()
            .unwrap()
            >= 2
    );

    drop(stalled);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = status(&client, admin).await.unwrap();
            if snapshot["metrics"]["active_connections"].as_u64().unwrap() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    for port in [public, named] {
        let response = client
            .get(format!("https://localhost:{port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            404,
            "public TLS capacity did not recover"
        );
    }
}
