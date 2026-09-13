#![cfg(unix)]

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use std::{
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::net::UnixStream;

const TOKEN: &str = "0123456789abcdef";

struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn request(socket: &Path, path: &str, authorized: bool) -> (u16, hyper::body::Incoming) {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut builder = Request::builder().uri(path).header("host", "admin.local");
    if authorized {
        builder = builder.header("authorization", format!("Bearer {TOKEN}"));
    }
    let response = sender
        .send_request(builder.body(Empty::<Bytes>::new()).unwrap())
        .await
        .unwrap();
    (response.status().as_u16(), response.into_body())
}

#[tokio::test]
async fn unix_admin_serves_authenticated_api_and_streams_then_unlinks_on_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = directory.path().join("config.json");
    std::fs::write(&config, b"{}").unwrap();
    let socket = directory.path().join("admin.sock");
    let child = Command::new(env!("CARGO_BIN_EXE_hangang"))
        .args([
            "--config",
            config.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--admin-socket",
            socket.to_str().unwrap(),
            "--threads",
            "2",
            "--lua-workers",
            "1",
            "--lame-duck-seconds",
            "0",
            "--drain-seconds",
            "0",
        ])
        .env("HANGANG_ADMIN_TOKEN", TOKEN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = Worker(child);
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            if socket.exists() && UnixStream::connect(&socket).await.is_ok() {
                break;
            }
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "UDS worker exited during startup"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::symlink_metadata(&socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let (status, body) = request(&socket, "/v1/status", false).await;
    assert_eq!(status, 401);
    drop(body);
    let (status, body) = request(&socket, "/v1/status", true).await;
    assert_eq!(status, 200);
    let bytes = body.collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["revision"],
        0
    );
    let (status, mut body) = request(&socket, "/v1/events", true).await;
    assert_eq!(status, 200);
    let frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let data = frame.into_data().unwrap();
    assert!(
        std::str::from_utf8(&data)
            .unwrap()
            .contains("event: status")
    );
    drop(body);
    let result = unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) };
    assert_eq!(result, 0);
    tokio::time::timeout(Duration::from_secs(5), async {
        while child.0.try_wait().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        !socket.exists(),
        "worker left its owned admin socket behind"
    );
}

#[test]
fn unix_admin_rejects_supervised_mode_and_explicit_tcp_admin_flag() {
    let binary = env!("CARGO_BIN_EXE_hangang");
    let supervised = Command::new(binary)
        .args(["--admin-socket", "/tmp/private/admin.sock", "--supervised"])
        .env("HANGANG_ADMIN_TOKEN", TOKEN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!supervised.success());
    let both = Command::new(binary)
        .args([
            "--admin-socket",
            "/tmp/private/admin.sock",
            "--admin",
            "127.0.0.1:9000",
        ])
        .env("HANGANG_ADMIN_TOKEN", TOKEN)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(!both.success());
}
