//! Wire-level checks for the separate, bearer-transparent management relay.
//! All sockets and processes are owned by this test.
use std::{
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixListener, UnixStream},
    task::JoinHandle,
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        // The native gateway can spawn Lua workers; retire its owned process
        // group instead of leaving children behind after the fixture ends.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGTERM);
        }
        let _ = self.0.wait();
    }
}

struct FakeAdmin {
    path: PathBuf,
    task: JoinHandle<()>,
    hits: Arc<AtomicUsize>,
}
impl Drop for FakeAdmin {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn fake_admin(path: PathBuf) -> FakeAdmin {
    let listener = UnixListener::bind(&path).unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let seen = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(serve_fake(stream));
        }
    });
    FakeAdmin { path, task, hits }
}

async fn serve_fake(mut stream: UnixStream) {
    let mut input = Vec::new();
    let headers_end = loop {
        let mut bytes = [0u8; 4096];
        let Ok(count) = stream.read(&mut bytes).await else {
            return;
        };
        if count == 0 || input.len() + count > 32768 {
            return;
        }
        input.extend_from_slice(&bytes[..count]);
        if let Some(position) = input.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = String::from_utf8_lossy(&input[..headers_end]).to_ascii_lowercase();
    let path = headers.split_whitespace().nth(1).unwrap_or("");
    if path == "/events" {
        let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n").await;
        let first = b"data: first\n\n";
        let _ = stream
            .write_all(format!("{:x}\r\n", first.len()).as_bytes())
            .await;
        let _ = stream.write_all(first).await;
        let _ = stream.write_all(b"\r\n").await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let second = b"data: second\n\n";
        let _ = stream
            .write_all(format!("{:x}\r\n", second.len()).as_bytes())
            .await;
        let _ = stream.write_all(second).await;
        let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
        return;
    }
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    while input.len() - headers_end < length {
        let mut bytes = [0u8; 4096];
        let Ok(count) = stream.read(&mut bytes).await else {
            return;
        };
        if count == 0 {
            return;
        }
        input.extend_from_slice(&bytes[..count]);
    }
    let value = |name: &str| {
        headers
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .unwrap_or("")
            .trim()
    };
    let body = format!(
        "host={};origin={};authorization={};body={}",
        value("host: "),
        value("origin: "),
        value("authorization: "),
        String::from_utf8_lossy(&input[headers_end..headers_end + length]),
    );
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nCache-Control: no-store\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body,
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn start_relay(socket: &Path, max_requests: usize) -> (ChildGuard, u16) {
    let child = Command::new(env!("CARGO_BIN_EXE_hangang-admin-gateway"))
        .args([
            "--listen",
            "127.0.0.1:0",
            "--admin-socket",
            socket.to_str().unwrap(),
            "--max-requests",
            &max_requests.to_string(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let stdout = child.0.stdout.take().unwrap();
    let line = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).map(|_| line)
        }),
    )
    .await
    .expect("owned management relay did not report its bound address")
    .unwrap()
    .unwrap();
    let address = line
        .trim()
        .strip_prefix("HANGANG_ADMIN_GATEWAY_LISTEN ")
        .and_then(|address| address.parse::<SocketAddr>().ok());
    let status = child.0.try_wait().unwrap();
    if address.is_none() || status.is_some() {
        let mut detail = String::new();
        if status.is_some() {
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut detail)
                .unwrap();
        }
        panic!(
            "owned management relay startup failed: status={status:?}, line={line:?}, stderr={detail}"
        );
    }
    let address = address.unwrap();
    assert!(address.ip().is_loopback() && address.port() != 0);
    (child, address.port())
}

async fn exchange(port: u16, raw: &[u8]) -> String {
    let head = raw.starts_with(b"HEAD ");
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream.write_all(raw).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let mut bytes = [0u8; 4096];
            let count = stream.read(&mut bytes).await.unwrap();
            if count == 0 {
                break;
            }
            response.extend_from_slice(&bytes[..count]);
            if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
                let end = end + 4;
                if head {
                    break;
                }
                let headers = String::from_utf8_lossy(&response[..end]).to_ascii_lowercase();
                if let Some(length) = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    && response.len() >= end + length
                {
                    break;
                }
                if headers.contains("transfer-encoding: chunked")
                    && response[end..].ends_with(b"0\r\n\r\n")
                {
                    break;
                }
            }
        }
    })
    .await
    .unwrap();
    String::from_utf8(response).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn preserves_authority_and_origin_but_rejects_ambiguous_framing() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("admin.sock");
    let fake = fake_admin(socket.clone()).await;
    let (_relay, port) = start_relay(&socket, 2).await;

    let response = exchange(port, b"POST /echo HTTP/1.1\r\nHost: console.example.test\r\nOrigin: https://console.example.test\r\nAuthorization: Bearer owned-test\r\nContent-Length: 4\r\nConnection: close\r\n\r\nping").await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.contains("host=console.example.test;origin=https://console.example.test;authorization=bearer owned-test;body=ping"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("cache-control: no-store")
    );
    let before = fake.hits.load(Ordering::SeqCst);
    for raw in [
        "POST /echo HTTP/1.1\r\nHost: console.example.test\r\nContent-Length: 4\r\nContent-Length: 5\r\nConnection: close\r\n\r\nping!",
        "POST /echo HTTP/1.1\r\nHost: console.example.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nping\r\n0\r\n\r\n",
        "GET /echo HTTP/1.1\r\nHost: console.example.test\r\nConnection: authorization\r\nAuthorization: Bearer owned-test\r\n\r\n",
        "GET http://elsewhere.invalid/echo HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    ] {
        let response = exchange(port, raw.as_bytes()).await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
    }
    assert_eq!(fake.hits.load(Ordering::SeqCst), before);
    let too_large = exchange(port, b"POST /echo HTTP/1.1\r\nHost: console.example.test\r\nContent-Length: 2097153\r\nConnection: close\r\n\r\n").await;
    assert!(too_large.starts_with("HTTP/1.1 413"), "{too_large}");
    drop(fake);
    let ui = exchange(
        port,
        b"GET /ui/ HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(ui.starts_with("HTTP/1.1 200"), "{ui}");
    assert!(ui.contains("HANGANG"));
    assert!(ui.to_ascii_lowercase().contains("content-security-policy:"));
    assert!(ui.to_ascii_lowercase().contains("cache-control: no-store"));
    let head = exchange(
        port,
        b"HEAD /ui/ HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(head.to_ascii_lowercase().contains("content-length:"));
    assert_eq!(head.split_once("\r\n\r\n").unwrap().1, "");
    let method = exchange(
        port,
        b"POST /ui/ HTTP/1.1\r\nHost: console.example.test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(method.starts_with("HTTP/1.1 405"), "{method}");
    assert!(method.to_ascii_lowercase().contains("allow: get, head"));
    let unavailable = exchange(
        port,
        b"GET /echo HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(unavailable.starts_with("HTTP/1.1 502"), "{unavailable}");
    assert!(unavailable.contains("management backend unavailable"));
    assert!(!unavailable.contains(socket.to_str().unwrap()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn streams_sse_immediately_and_bounds_active_requests() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("admin.sock");
    let _fake = fake_admin(socket.clone()).await;
    let (mut relay, port) = start_relay(&socket, 1).await;
    let mut stream = match TcpStream::connect(("127.0.0.1", port)).await {
        Ok(stream) => stream,
        Err(error) => {
            let status = relay.0.try_wait().unwrap();
            let mut detail = String::new();
            if status.is_some() {
                relay
                    .0
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut detail)
                    .unwrap();
            }
            panic!(
                "owned relay refused its reported listener: {error}; child status={status:?}; stderr={detail}"
            );
        }
    };
    stream
        .write_all(b"GET /events HTTP/1.1\r\nHost: console.example.test\r\n\r\n")
        .await
        .unwrap();
    let mut first = Vec::new();
    tokio::time::timeout(Duration::from_millis(250), async {
        while !first
            .windows(b"data: first".len())
            .any(|window| window == b"data: first")
        {
            let mut bytes = [0u8; 1024];
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            first.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .expect("the first SSE frame must arrive before the second is produced");
    assert!(!String::from_utf8_lossy(&first).contains("data: second"));
    let busy = exchange(
        port,
        b"GET /echo HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(busy.starts_with("HTTP/1.1 503"), "{busy}");
    let mut rest = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !rest
            .windows(b"data: second".len())
            .any(|window| window == b"data: second")
        {
            let mut bytes = [0u8; 1024];
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            rest.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8_lossy(&rest).contains("data: second"));
    drop(stream);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let recovered = exchange(
        port,
        b"GET /echo HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(recovered.starts_with("HTTP/1.1 200"), "{recovered}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_admin_auth_and_status_stream_survive_the_separate_relay() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("admin.sock");
    let config = directory.path().join("config.json");
    std::fs::write(&config, r#"{"http":[],"tcp":[]}"#).unwrap();
    let token = "owned-native-admin-token";
    let mut native = Command::new(env!("CARGO_BIN_EXE_hangang"));
    native
        .args([
            "--config",
            config.to_str().unwrap(),
            "--listen",
            "127.0.0.1:0",
            "--admin-socket",
            socket.to_str().unwrap(),
            "--admin-users-db",
            directory.path().join("users.sqlite3").to_str().unwrap(),
            "--threads",
            "2",
            "--lua-workers",
            "1",
        ])
        .env("HANGANG_ADMIN_TOKEN", token)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .process_group(0);
    let mut native = ChildGuard(native.spawn().unwrap());
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        if native.0.try_wait().unwrap().is_some() {
            use std::io::Read;
            let mut detail = String::new();
            native
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut detail)
                .unwrap();
            panic!(
                "owned native gateway exited before its admin socket was ready: {}",
                detail.replace(token, "[redacted]")
            );
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(socket.exists(), "owned native admin socket was not created");
    let (_relay, relay_port) = start_relay(&socket, 4).await;

    let unauthenticated = exchange(
        relay_port,
        b"GET /v1/status HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(
        unauthenticated.starts_with("HTTP/1.1 401"),
        "{unauthenticated}"
    );
    let status = exchange(relay_port, format!("GET /v1/status HTTP/1.1\r\nHost: console.example.test\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes()).await;
    assert!(status.starts_with("HTTP/1.1 200"), "{status}");
    assert!(status.contains("\"revision\":"));
    let ui = exchange(
        relay_port,
        b"GET /ui/ HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(ui.starts_with("HTTP/1.1 200"), "{ui}");
    assert!(ui.to_ascii_lowercase().contains("content-security-policy:"));
    assert!(ui.contains("HANGANG"));

    let mut stream = TcpStream::connect(("127.0.0.1", relay_port)).await.unwrap();
    stream.write_all(format!("GET /v1/events HTTP/1.1\r\nHost: console.example.test\r\nAuthorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !response
            .windows(b"event: status".len())
            .any(|window| window == b"event: status")
        {
            let mut bytes = [0u8; 4096];
            let count = stream.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            response.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .expect("native SSE status must pass through the management relay without buffering");
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
}
