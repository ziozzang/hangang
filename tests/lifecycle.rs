//! Process-level shutdown ordering: readiness is withdrawn before the
//! listeners close, and a lame-duck window keeps accepting in between so an
//! external load balancer can observe the 503 and stop routing.
use std::{
    os::unix::fs::PermissionsExt,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
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
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
}

async fn spawn(dir: &std::path::Path, lame_duck: u64) -> (Process, u16, u16) {
    spawn_with(dir, lame_duck, false).await
}

async fn spawn_with(
    dir: &std::path::Path,
    lame_duck: u64,
    supervised: bool,
) -> (Process, u16, u16) {
    // A normal configuration directory may be group-writable. The default
    // account store must create its own private child directory.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    let config = dir.join(format!("config-{lame_duck}-{supervised}.json"));
    std::fs::write(&config, r#"{"http":[]}"#).unwrap();
    let public = port();
    let mut admin = port();
    while admin == public {
        admin = port();
    }
    let mut command = Command::new(env!("CARGO_BIN_EXE_hangang"));
    if supervised {
        command.arg("--supervised");
    }
    let process = Process(
        command
            .args([
                "--config",
                config.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{public}"),
                "--admin",
                &format!("127.0.0.1:{admin}"),
                "--health-path",
                "/-/ready",
                "--lame-duck-seconds",
                &lame_duck.to_string(),
                "--drain-seconds",
                "1",
                "--threads",
                "2",
                "--lua-workers",
                "1",
            ])
            .env("HANGANG_ADMIN_TOKEN", "test-lifecycle-token")
            .stdout(Stdio::null())
            .stderr(std::fs::File::create(dir.join("server-stderr.log")).unwrap())
            .spawn()
            .unwrap(),
    );
    let http = client();
    let started = Instant::now();
    loop {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "server did not start (stderr: {})",
            std::fs::read_to_string(dir.join("server-stderr.log")).unwrap_or_default(),
        );
        if let Ok(response) = http
            .get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            && response.status() == 200
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut directory_name = config.file_name().unwrap().to_os_string();
    directory_name.push(".admin");
    let account_dir = dir.join(directory_name);
    assert_eq!(
        std::fs::metadata(account_dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    (process, public, admin)
}

fn terminate(process: &Process) {
    // SAFETY: plain signal delivery to a child this test owns.
    unsafe {
        libc::kill(process.0.id() as i32, libc::SIGTERM);
    }
}

#[tokio::test]
async fn lame_duck_withdraws_readiness_before_the_listener_closes() {
    let dir = tempfile::tempdir().unwrap();
    let (mut process, public, admin) = spawn(dir.path(), 2).await;
    let http = client();
    let sent = Instant::now();
    terminate(&process);

    // Inside the lame-duck window the listener still answers, with 503.
    let mut withdrawn = false;
    while sent.elapsed() < Duration::from_millis(1500) {
        let response = http
            .get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            .expect("listener must keep accepting during the lame-duck window");
        if response.status() == 503 {
            withdrawn = true;
            break;
        }
        assert_eq!(response.status(), 200);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        withdrawn,
        "readiness must be withdrawn as soon as the signal arrives"
    );
    let response = http
        .get(format!("http://127.0.0.1:{admin}/healthz"))
        .bearer_auth("test-lifecycle-token")
        .send()
        .await
        .expect("admin listener stays open during the lame-duck window");
    assert_eq!(response.status(), 503);
    assert!(
        process.0.try_wait().unwrap().is_none(),
        "the process must not exit before the lame-duck window elapses"
    );

    // After the window the listener is closed and the process exits.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let refused = Instant::now();
    loop {
        if http
            .get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            .is_err()
        {
            break;
        }
        assert!(
            refused.elapsed() < Duration::from_secs(3),
            "listener must close after the lame-duck window"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let exited = Instant::now();
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "clean exit expected: {status:?}");
            break;
        }
        assert!(
            exited.elapsed() < Duration::from_secs(5),
            "process did not exit"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        sent.elapsed() >= Duration::from_secs(2),
        "lame duck must last its window"
    );
}

#[tokio::test]
async fn zero_lame_duck_closes_the_listener_immediately() {
    let dir = tempfile::tempdir().unwrap();
    let (mut process, public, _admin) = spawn(dir.path(), 0).await;
    let http = client();
    let sent = Instant::now();
    terminate(&process);
    loop {
        if http
            .get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            .is_err()
        {
            break;
        }
        assert!(
            sent.elapsed() < Duration::from_millis(1500),
            "without a lame-duck window the listener must close at once"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(sent.elapsed() < Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn supervised_shutdown_withdraws_then_drains_within_the_lame_duck_budget() {
    let dir = tempfile::tempdir().unwrap();
    let (mut process, public, _admin) = spawn_with(dir.path(), 2, true).await;
    let http = client();
    let sent = Instant::now();
    terminate(&process);
    // Phase one (Withdraw): the generation answers 503 but keeps accepting.
    let mut withdrawn = false;
    while sent.elapsed() < Duration::from_millis(1500) {
        let response = http
            .get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            .expect("listener must keep accepting during the lame-duck window");
        if response.status() == 503 {
            withdrawn = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(withdrawn, "the supervisor must withdraw readiness first");
    assert!(process.0.try_wait().unwrap().is_none());
    // Phase two (Drain) after the window: listener closed, supervisor exits.
    let exited = Instant::now();
    loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "clean exit expected: {status:?}");
            break;
        }
        assert!(
            exited.elapsed() < Duration::from_secs(8),
            "supervisor did not exit within lame duck + drain"
        );
        assert!(
            sent.elapsed() < Duration::from_millis(4500),
            "the generation must not sleep the lame-duck window a second time"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        sent.elapsed() >= Duration::from_secs(2),
        "the supervisor must not kill the generation before the lame-duck window"
    );
    assert!(
        http.get(format!("http://127.0.0.1:{public}/-/ready"))
            .send()
            .await
            .is_err()
    );
}
