#![cfg(target_os = "linux")]
//! Owned process/supervisor qualification; no operating configuration is read.
use hangang_route_grpc::v1::{RouteRequest, route_ownership_client::RouteOwnershipClient};
use std::{
    os::unix::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
const ADMIN: &str = "owned-route-lifecycle-admin-token";
const CALLER: &str = "owned-route-lifecycle-decision-token-00001";
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        // This process group contains only this fixture and its descendants.
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGTERM);
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if self.0.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        unsafe {
            libc::kill(-(self.0.id() as i32), libc::SIGKILL);
        }
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
fn certificates(root: &Path) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    let mut parameters = CertificateParams::new(vec![]).unwrap();
    parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(parameters, KeyPair::generate().unwrap()).unwrap();
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    for (name, usage, names) in [
        (
            "server",
            ExtendedKeyUsagePurpose::ServerAuth,
            vec!["route.example.test".into()],
        ),
        ("client", ExtendedKeyUsagePurpose::ClientAuth, vec![]),
    ] {
        let mut parameters = CertificateParams::new(names).unwrap();
        parameters.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let certificate = parameters.signed_by(&key, &ca).unwrap();
        std::fs::write(root.join(format!("{name}.pem")), certificate.pem()).unwrap();
        std::fs::write(root.join(format!("{name}.key")), key.serialize_pem()).unwrap();
    }
}
fn configuration(root: &Path, route: u16) -> serde_json::Value {
    serde_json::json!({"listen":format!("127.0.0.1:{route}"),"certificate":root.join("server.pem"),"key":root.join("server.key"),"client_ca":root.join("ca.pem"),"token_env":"OWNED_ROUTE_TOKEN"})
}
fn command(root: &Path, public: u16, admin: u16) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_hangang"));
    command
        .args([
            "--config",
            root.join("config.json").to_str().unwrap(),
            "--route-owner-config",
            root.join("route.json").to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{public}"),
            "--admin",
            &format!("127.0.0.1:{admin}"),
            "--threads",
            "2",
            "--lua-workers",
            "1",
            "--drain-seconds",
            "1",
        ])
        .env("HANGANG_ADMIN_TOKEN", ADMIN)
        .env("OWNED_ROUTE_TOKEN", CALLER)
        .env("RUST_LOG", "info");
    command
}
async fn query(root: &Path, route: u16) {
    let tls = ClientTlsConfig::new()
        .domain_name("route.example.test")
        .ca_certificate(Certificate::from_pem(
            std::fs::read(root.join("ca.pem")).unwrap(),
        ))
        .identity(Identity::from_pem(
            std::fs::read(root.join("client.pem")).unwrap(),
            std::fs::read(root.join("client.key")).unwrap(),
        ));
    let channel = Endpoint::from_shared(format!("https://127.0.0.1:{route}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(2))
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = RouteOwnershipClient::new(channel);
    let mut request = tonic::Request::new(RouteRequest {
        request_id: 1,
        reference: vec![1; 32],
        request_sha256: vec![2; 32],
        destination_sha256: vec![3; 32],
    });
    request
        .metadata_mut()
        .insert("authorization", format!("Bearer {CALLER}").parse().unwrap());
    request.set_timeout(Duration::from_secs(2));
    let refusal = client.observe(request).await.unwrap_err();
    assert_eq!(refusal.code(), tonic::Code::Unavailable);
    assert_eq!(refusal.message(), "route owner unavailable");
}
async fn status(client: &reqwest::Client, admin: u16) -> Option<serde_json::Value> {
    client
        .get(format!("http://127.0.0.1:{admin}/v1/status"))
        .bearer_auth(ADMIN)
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()
}
#[tokio::test]
async fn check_validates_private_resources_without_binding_the_route_socket() {
    let root = tempfile::tempdir().unwrap();
    certificates(root.path());
    std::fs::write(root.path().join("config.json"), b"{\"http\":[]}").unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let document = configuration(root.path(), occupied.local_addr().unwrap().port());
    std::fs::write(
        root.path().join("route.json"),
        serde_json::to_vec(&document).unwrap(),
    )
    .unwrap();
    let result = command(root.path(), port(), port())
        .arg("--check")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "check must not bind the already occupied route socket"
    );
    assert!(
        !command(root.path(), port(), port())
            .arg("--check")
            .env("OWNED_ROUTE_TOKEN", ADMIN)
            .output()
            .unwrap()
            .status
            .success()
    );
    let route = occupied.local_addr().unwrap().port();
    assert!(
        !command(root.path(), route, port())
            .arg("--check")
            .output()
            .unwrap()
            .status
            .success()
    );
    std::fs::remove_file(root.path().join("ca.pem")).unwrap();
    assert!(
        !command(root.path(), port(), port())
            .arg("--check")
            .output()
            .unwrap()
            .status
            .success()
    );
}
#[tokio::test]
async fn standalone_starts_the_route_listener_and_closes_it_on_shutdown() {
    let root = tempfile::tempdir().unwrap();
    certificates(root.path());
    std::fs::write(root.path().join("config.json"), b"{\"http\":[]}").unwrap();
    let mut ports = std::collections::HashSet::new();
    while ports.len() < 3 {
        ports.insert(port());
    }
    let mut ports = ports.into_iter();
    let (public, admin, route) = (
        ports.next().unwrap(),
        ports.next().unwrap(),
        ports.next().unwrap(),
    );
    std::fs::write(
        root.path().join("route.json"),
        serde_json::to_vec(&configuration(root.path(), route)).unwrap(),
    )
    .unwrap();
    let mut process = Process(
        command(root.path(), public, admin)
            .process_group(0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "owned standalone exited"
        );
        if status(&client, admin).await.is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "standalone route owner did not start"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    query(root.path(), route).await;
    drop(process);
    assert!(
        std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{route}").parse().unwrap(),
            Duration::from_millis(200)
        )
        .is_err()
    );
}
#[tokio::test]
async fn supervised_handoff_and_rejected_candidate_preserve_the_route_listener() {
    let root = tempfile::tempdir().unwrap();
    certificates(root.path());
    std::fs::write(root.path().join("config.json"), b"{\"http\":[]}").unwrap();
    let mut ports = std::collections::HashSet::new();
    while ports.len() < 3 {
        ports.insert(port());
    }
    let mut ports = ports.into_iter();
    let (public, admin, route) = (
        ports.next().unwrap(),
        ports.next().unwrap(),
        ports.next().unwrap(),
    );
    let document = configuration(root.path(), route);
    let route_file = root.path().join("route.json");
    std::fs::write(&route_file, serde_json::to_vec(&document).unwrap()).unwrap();
    let log = root.path().join("process.log");
    let output = std::fs::File::create(&log).unwrap();
    let mut process = Process(
        command(root.path(), public, admin)
            .arg("--supervised")
            .process_group(0)
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let mut current = None;
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "owned gateway exited"
        );
        if let Some(value) = status(&client, admin).await {
            current = Some(value);
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let original = current.expect("owned gateway did not become ready")["process_id"]
        .as_u64()
        .unwrap();
    query(root.path(), route).await;
    unsafe {
        libc::kill(process.0.id() as i32, libc::SIGHUP);
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut successor = None;
    while Instant::now() < deadline {
        if let Some(value) = status(&client, admin).await
            && value["process_id"].as_u64() != Some(original)
        {
            successor = value["process_id"].as_u64();
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let successor = successor.expect("route descriptor handoff did not activate a successor");
    query(root.path(), route).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let children =
            std::fs::read_to_string(format!("/proc/{0}/task/{0}/children", process.0.id()))
                .unwrap();
        if children.split_whitespace().collect::<Vec<_>>() == vec![successor.to_string().as_str()] {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "old owned generation did not drain"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let mut invalid = document.clone();
    invalid["token_env"] = "HANGANG_ADMIN_TOKEN".into();
    std::fs::write(&route_file, serde_json::to_vec(&invalid).unwrap()).unwrap();
    unsafe {
        libc::kill(process.0.id() as i32, libc::SIGHUP);
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while !std::fs::read_to_string(&log)
        .unwrap()
        .contains("replacement rejected; retaining active generation")
    {
        assert!(
            Instant::now() < deadline,
            "bad route candidate was not rejected: {}",
            std::fs::read_to_string(&log).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(
        status(&client, admin).await.unwrap()["process_id"].as_u64(),
        Some(successor)
    );
    query(root.path(), route).await;
    std::fs::write(&route_file, serde_json::to_vec(&document).unwrap()).unwrap();
    drop(process);
    assert!(
        std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{route}").parse().unwrap(),
            Duration::from_millis(200)
        )
        .is_err()
    );
}
