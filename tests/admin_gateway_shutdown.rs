//! Owned-process signal and drain checks for the standalone admin relay.
use std::{
    io::{BufRead, BufReader},
    net::SocketAddr,
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixListener, UnixStream},
    sync::Notify,
};

struct Relay(Child);

impl Drop for Relay {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

async fn start_relay(socket: &Path) -> (Relay, u16) {
    let mut child = Relay(
        Command::new(env!("CARGO_BIN_EXE_hangang-admin-gateway"))
            .args([
                "--listen",
                "127.0.0.1:0",
                "--admin-socket",
                socket.to_str().unwrap(),
                "--shutdown-grace-seconds",
                "1",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let line = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).map(|_| line)
        }),
    )
    .await
    .expect("relay readiness timeout")
    .unwrap()
    .unwrap();
    let address: SocketAddr = line
        .trim()
        .strip_prefix("HANGANG_ADMIN_GATEWAY_LISTEN ")
        .expect("relay readiness line")
        .parse()
        .unwrap();
    assert!(address.ip().is_loopback());
    assert!(child.0.try_wait().unwrap().is_none());
    (child, address.port())
}

async fn fake_admin(socket: &Path, slow_started: std::sync::Arc<Notify>) {
    let listener = UnixListener::bind(socket).unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let slow_started = slow_started.clone();
            tokio::spawn(async move { serve_admin(stream, slow_started).await });
        }
    });
}

async fn serve_admin(mut stream: UnixStream, slow_started: std::sync::Arc<Notify>) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        let mut bytes = [0; 1024];
        let Ok(count) = stream.read(&mut bytes).await else {
            return;
        };
        if count == 0 || request.len() + count > 8192 {
            return;
        }
        request.extend_from_slice(&bytes[..count]);
        if request.windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    let request = String::from_utf8_lossy(&request);
    if request.starts_with("GET /slow ") {
        slow_started.notify_one();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await;
    } else if request.starts_with("GET /events ") {
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\ndata: first\n\n\r\n")
            .await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    } else {
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
    }
}

async fn request(port: u16, path: &str) -> TcpStream {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {path} HTTP/1.1\r\nHost: console.example.test\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream
}

async fn read_to_end(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8(response).unwrap()
}

async fn clean_exit(relay: &mut Relay) -> Duration {
    let start = Instant::now();
    let status = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(status) = relay.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("relay did not exit within its drain deadline");
    assert!(status.success(), "relay exited with {status:?}");
    assert_eq!(status.signal(), None, "relay was killed by a signal");
    start.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigterm_finishes_in_flight_response_then_exits() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("admin.sock");
    let slow_started = std::sync::Arc::new(Notify::new());
    fake_admin(&socket, slow_started.clone()).await;
    let (mut relay, port) = start_relay(&socket).await;

    let ordinary = read_to_end(&mut request(port, "/fast").await).await;
    assert!(ordinary.starts_with("HTTP/1.1 200"), "{ordinary}");
    assert!(ordinary.ends_with("ok"), "{ordinary}");

    let mut slow = request(port, "/slow").await;
    tokio::time::timeout(Duration::from_secs(2), slow_started.notified())
        .await
        .unwrap();
    assert_eq!(unsafe { libc::kill(relay.0.id() as i32, libc::SIGTERM) }, 0);
    let response = read_to_end(&mut slow).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("done"), "{response}");
    assert!(clean_exit(&mut relay).await < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sigint_closes_hanging_sse_at_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("admin.sock");
    fake_admin(&socket, std::sync::Arc::new(Notify::new())).await;
    let (mut relay, port) = start_relay(&socket).await;
    let mut events = request(port, "/events").await;
    let mut first = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !first.windows(11).any(|part| part == b"data: first") {
            let mut bytes = [0; 1024];
            let count = events.read(&mut bytes).await.unwrap();
            assert!(count > 0);
            first.extend_from_slice(&bytes[..count]);
        }
    })
    .await
    .unwrap();
    assert_eq!(unsafe { libc::kill(relay.0.id() as i32, libc::SIGINT) }, 0);
    let started = Instant::now();
    assert!(clean_exit(&mut relay).await < Duration::from_secs(2));
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), events.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
}
