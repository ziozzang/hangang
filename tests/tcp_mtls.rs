#![cfg(unix)]

//! Real TCP inbound-mTLS admission. All sockets and certificate files belong
//! to this test; the backend deliberately speaks plaintext after termination.
use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::{
    io::Cursor,
    net::Ipv4Addr,
    os::{fd::OwnedFd, unix::fs::PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

const GOOD_ID: &str = "spiffe://example.org/ns/test/sa/allowed";
const OTHER_ID: &str = "spiffe://example.org/ns/test/sa/other";

struct Material {
    _directory: tempfile::TempDir,
    server_cert: PathBuf,
    server_key: PathBuf,
    ca_file: PathBuf,
    ca_pem: String,
    ca_der: rustls::pki_types::CertificateDer<'static>,
    good_cert: String,
    good_key: String,
    other_cert: String,
    other_key: String,
    wrong_cert: String,
    wrong_key: String,
    issuer: CertifiedIssuer<'static, KeyPair>,
}

fn ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn client_certificate(issuer: &CertifiedIssuer<'_, KeyPair>, uri: &str) -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    if uri == GOOD_ID {
        // A stable leaf serial lets the owned CRL fixture revoke exactly this
        // certificate without relying on PEM parser representation details.
        params.serial_number = Some(42u64.into());
    }
    params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn crl_versions(material: &Material) -> (PathBuf, String, String, String) {
    let path = material._directory.path().join("clients.crl");
    let mut params = rcgen::CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2020, 1, 1),
        next_update: rcgen::date_time_ymd(2035, 1, 1),
        crl_number: 1u64.into(),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let empty = params.signed_by(&material.issuer).unwrap().pem().unwrap();
    params.revoked_certs.push(rcgen::RevokedCertParams {
        serial_number: 42u64.into(),
        revocation_time: rcgen::date_time_ymd(2021, 1, 1),
        reason_code: Some(rcgen::RevocationReason::KeyCompromise),
        invalidity_date: None,
    });
    params.crl_number = 2u64.into();
    let revoked = params.signed_by(&material.issuer).unwrap().pem().unwrap();
    params.revoked_certs.clear();
    params.crl_number = 3u64.into();
    let restored = params.signed_by(&material.issuer).unwrap().pem().unwrap();
    (path, empty, revoked, restored)
}

fn short_lived_client_certificate(
    issuer: &CertifiedIssuer<'_, KeyPair>,
    uri: &str,
) -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.not_before = (SystemTime::now() - Duration::from_secs(5)).into();
    params.not_after = (SystemTime::now() + Duration::from_secs(5)).into();
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, issuer).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn write_private(path: &Path, contents: &str) {
    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn material() -> Material {
    let directory = tempfile::tempdir().unwrap();
    let trusted_ca = ca();
    let untrusted_ca = ca();
    let mut server_params = CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_keypair = KeyPair::generate().unwrap();
    let server = server_params
        .signed_by(&server_keypair, &trusted_ca)
        .unwrap();
    let server_cert = directory.path().join("server.pem");
    let server_key = directory.path().join("server.key");
    let ca_file = directory.path().join("clients-ca.pem");
    std::fs::write(&server_cert, server.pem()).unwrap();
    write_private(&server_key, &server_keypair.serialize_pem());
    let ca_pem = trusted_ca.pem();
    std::fs::write(&ca_file, &ca_pem).unwrap();
    let (good_cert, good_key) = client_certificate(&trusted_ca, GOOD_ID);
    let (other_cert, other_key) = client_certificate(&trusted_ca, OTHER_ID);
    let (wrong_cert, wrong_key) = client_certificate(&untrusted_ca, GOOD_ID);
    Material {
        _directory: directory,
        server_cert,
        server_key,
        ca_file,
        ca_pem,
        ca_der: trusted_ca.der().clone(),
        good_cert,
        good_key,
        other_cert,
        other_key,
        wrong_cert,
        wrong_key,
        issuer: trusted_ca,
    }
}

fn connector(material: &Material, identity: Option<(&str, &str)>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(material.ca_der.clone()).unwrap();
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots);
    let config = if let Some((cert, key)) = identity {
        let certs = rustls_pemfile::certs(&mut Cursor::new(cert))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut Cursor::new(key))
            .unwrap()
            .unwrap();
        builder.with_client_auth_cert(certs, key).unwrap()
    } else {
        builder.with_no_client_auth()
    };
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn config(
    listen: std::net::SocketAddr,
    backend: std::net::SocketAddr,
    material: &Material,
    allowed: &[&str],
) -> Config {
    serde_json::from_value(serde_json::json!({"tcp":[{
        "id":"workload", "listen":listen, "backends":[backend.to_string()],
        "inbound_tls":{
            "cert_file":material.server_cert,
            "key_file":material.server_key,
            "client_ca_file":material.ca_file,
            "allowed_uri_sans":allowed,
            "handshake_timeout_ms":1000
        }
    }]}))
    .unwrap()
}

async fn exchange(connector: &tokio_rustls::TlsConnector, listen: std::net::SocketAddr) -> bool {
    tokio::time::timeout(Duration::from_secs(3), async {
        let socket = TcpStream::connect(listen).await.ok()?;
        let mut tls = connector
            .connect("localhost".try_into().unwrap(), socket)
            .await
            .ok()?;
        tls.write_all(b"ping").await.ok()?;
        let mut reply = [0; 4];
        tls.read_exact(&mut reply).await.ok()?;
        (reply == *b"ping").then_some(())
    })
    .await
    .ok()
    .flatten()
    .is_some()
}

async fn wait_material(
    active: &Arc<ArcSwap<Snapshot>>,
    ready: bool,
) -> Option<Arc<hangang::workload_tls::Prepared>> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let current = active.load().tcp_inbound_tls["workload"].load();
            if current.is_some() == ready {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TCP workload material did not reach the requested state")
}

async fn wait_new_generation(
    active: &Arc<ArcSwap<Snapshot>>,
    previous: &Arc<hangang::workload_tls::Prepared>,
) -> Arc<hangang::workload_tls::Prepared> {
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if let Some(current) = active.load().tcp_inbound_tls["workload"].load()
                && !Arc::ptr_eq(&current, previous)
            {
                return current;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("TCP CRL change did not publish a new material generation")
}

#[test]
fn active_mtls_listener_requires_a_separate_retirement_revision_before_plaintext() {
    let material = material();
    let listen = "127.0.0.1:19001".parse().unwrap();
    let backend = "127.0.0.1:19002".parse().unwrap();
    let old = config(listen, backend, &material, &[GOOD_ID]);
    let mut replacement = serde_json::to_value(&old).unwrap();
    replacement["tcp"][0]
        .as_object_mut()
        .unwrap()
        .remove("inbound_tls");
    let mut direct: Config = serde_json::from_value(replacement).unwrap();
    assert!(direct.validate_transition_from(&old).is_err());
    direct.tcp[0].id = "renamed-plaintext".into();
    assert!(direct.validate_transition_from(&old).is_err());
    let mut disabled = direct.clone();
    disabled.tcp[0].enabled = false;
    disabled.validate_transition_from(&old).unwrap();
    direct.validate_transition_from(&disabled).unwrap();
    let mut removed = old.clone();
    removed.tcp.clear();
    removed.validate_transition_from(&old).unwrap();
    direct.validate_transition_from(&removed).unwrap();
}

#[test]
fn damaged_material_does_not_prevent_disabling_an_existing_mtls_route() {
    let material = material();
    let listen = "127.0.0.1:19003".parse().unwrap();
    let backend = "127.0.0.1:19004".parse().unwrap();
    let old = config(listen, backend, &material, &[GOOD_ID]);
    let active = Snapshot::new(old.clone()).unwrap();
    std::fs::remove_file(&material.ca_file).unwrap();

    let mut disabled = old.clone();
    disabled.tcp[0].enabled = false;
    let retired = Snapshot::replace(disabled.clone(), &active).unwrap();
    assert!(retired.tcp_inbound_tls.is_empty());
    assert!(Snapshot::replace(old, &retired).is_err());
}

#[tokio::test]
async fn tcp_mtls_verifies_certificate_identity_before_backend_and_fences_reloads() {
    let material = material();
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let backend_accepted = accepted.clone();
    let backend_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = backend.accept().await.unwrap();
            backend_accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                while let Ok(size) = stream.read(&mut buf).await {
                    if size == 0 || stream.write_all(&buf[..size]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    // Preserve the reserved port-zero socket until TCP publication.
    let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held.local_addr().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let watch_cancel = CancellationToken::new();
    let watcher = tokio::spawn(hangang::workload_material::watch(
        active.clone(),
        watch_cancel.clone(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 16);
    let first = config(listen, backend_address, &material, &[GOOD_ID]);
    let prepared = manager
        .prepare_with_inherited(&first, vec![(listen, OwnedFd::from(held))])
        .await
        .unwrap();
    active.store(Arc::new(
        Snapshot::replace(first, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    wait_material(&active, true).await;

    let good = connector(&material, Some((&material.good_cert, &material.good_key)));
    let no_certificate = connector(&material, None);
    let wrong_ca = connector(&material, Some((&material.wrong_cert, &material.wrong_key)));
    let wrong_uri = connector(&material, Some((&material.other_cert, &material.other_key)));
    assert!(!exchange(&no_certificate, listen).await);
    assert!(!exchange(&wrong_ca, listen).await);
    assert!(!exchange(&wrong_uri, listen).await);
    let mut plain = TcpStream::connect(listen).await.unwrap();
    plain
        .write_all(b"plaintext is not a TLS record")
        .await
        .unwrap();
    let mut alert = [0; 1024];
    // rustls may send a fatal TLS alert before closing a plaintext client.
    // Its exact alert bytes are not an application response or backend dial.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), plain.read(&mut alert))
            .await
            .is_ok()
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 0);

    assert!(exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    let (short_cert, short_key) = short_lived_client_certificate(&material.issuer, GOOD_ID);
    let short = connector(&material, Some((&short_cert, &short_key)));
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut expiring = short
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    expiring.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    expiring.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(8), expiring.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "expired identity stream remained active: {closed:?}"
    );

    // Keep a verified stream open across publication. It must not continue
    // forwarding under an allowlist that no longer admits its SAN URI.
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut held = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    held.write_all(b"ping").await.unwrap();
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);

    // A no-op publication preserves the exact prepared verifier and a live
    // authenticated stream. Replacing CA bytes at the same path must fence
    // that stream even though the route JSON is unchanged.
    let slot_before = active.load_full().tcp_inbound_tls["workload"].clone();
    let prepared_before = slot_before.load().unwrap();
    let same = config(listen, backend_address, &material, &[GOOD_ID]);
    let prepared = manager.prepare(&same).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(same.clone(), &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    assert!(Arc::ptr_eq(
        &slot_before,
        &active.load_full().tcp_inbound_tls["workload"]
    ));
    held.write_all(b"ping").await.unwrap();
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 3);

    // No config revision is published: the file watcher invalidates this
    // same Slot when a CA file becomes malformed, closing existing streams
    // and denying new handshakes rather than retaining stale trust.
    std::fs::write(&material.ca_file, b"invalid CA material").unwrap();
    wait_material(&active, false).await;
    assert!(Arc::ptr_eq(
        &slot_before,
        &active.load_full().tcp_inbound_tls["workload"]
    ));
    let closed = tokio::time::timeout(Duration::from_secs(3), held.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "old CA stream stayed active: {closed:?}"
    );
    assert!(!exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 3);

    std::fs::write(&material.ca_file, &material.ca_pem).unwrap();
    let restored = wait_material(&active, true).await.unwrap();
    assert!(!Arc::ptr_eq(&prepared_before, &restored));
    assert!(exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 4);

    let socket = TcpStream::connect(listen).await.unwrap();
    let mut held = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    held.write_all(b"ping").await.unwrap();
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 5);

    let next = config(listen, backend_address, &material, &[OTHER_ID]);
    let prepared = manager.prepare(&next).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(next, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    wait_material(&active, true).await;
    let closed = tokio::time::timeout(Duration::from_secs(3), held.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "old identity stream remained active: {closed:?}"
    );
    assert!(!exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 5);
    assert!(exchange(&wrong_uri, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 6);

    let socket = TcpStream::connect(listen).await.unwrap();
    let mut remaining = wrong_uri
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    remaining.write_all(b"ping").await.unwrap();
    remaining.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 7);

    let empty = Config::default();
    let prepared = manager.prepare(&empty).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(empty, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    let closed = tokio::time::timeout(Duration::from_secs(3), remaining.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "removed route kept authenticated stream active: {closed:?}"
    );
    assert!(!exchange(&wrong_uri, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 7);
    watch_cancel.cancel();
    watcher.await.unwrap();
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn signed_crl_rotation_revokes_and_restores_tcp_identity_without_config_revision() {
    let material = material();
    let (crl_file, empty_crl, revoked_crl, restored_crl) = crl_versions(&material);
    std::fs::write(&crl_file, empty_crl).unwrap();
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let accepted = Arc::new(AtomicUsize::new(0));
    let backend_accepted = accepted.clone();
    let backend_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = backend.accept().await {
            backend_accepted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let bound = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = bound.local_addr().unwrap();
    let mut document = config(listen, backend_address, &material, &[GOOD_ID]);
    document.tcp[0]
        .inbound_tls
        .as_mut()
        .unwrap()
        .client_crl_file = Some(crl_file.clone());
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(document.clone()).unwrap(),
    ));
    let unchanged_snapshot = active.load_full();
    let watch_cancel = CancellationToken::new();
    let watcher = tokio::spawn(hangang::workload_material::watch(
        active.clone(),
        watch_cancel.clone(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active.clone(), metrics.clone(), 16);
    let prepared = manager
        .prepare_with_inherited(&document, vec![(listen, OwnedFd::from(bound))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    let initial = wait_material(&active, true).await.unwrap();

    let good = connector(&material, Some((&material.good_cert, &material.good_key)));
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut held = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    held.write_all(b"ping").await.unwrap();
    let mut reply = [0u8; 4];
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // The CRL remains valid and correctly signed, but now revokes the exact
    // leaf serial. The watcher must replace Prepared without a CAS revision.
    std::fs::write(&crl_file, revoked_crl).unwrap();
    let revoked = wait_new_generation(&active, &initial).await;
    assert!(Arc::ptr_eq(&unchanged_snapshot, &active.load_full()));
    let mut byte = [0u8];
    let closed = tokio::time::timeout(Duration::from_secs(3), held.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "revoked CRL left established stream active: {closed:?}"
    );
    assert!(
        !exchange(&good, listen).await,
        "revoked client reached the backend"
    );
    assert_eq!(accepted.load(Ordering::SeqCst), 1);

    // A newer empty CRL restores admission through the same watched path.
    std::fs::write(&crl_file, restored_crl).unwrap();
    let restored = wait_new_generation(&active, &revoked).await;
    assert!(!Arc::ptr_eq(&initial, &restored));
    assert!(Arc::ptr_eq(&unchanged_snapshot, &active.load_full()));
    assert!(exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
    watch_cancel.cancel();
    watcher.await.unwrap();
    manager.shutdown(Duration::from_secs(1)).await;
    let history = serde_json::to_value(metrics.tcp_history.recent(None, 128)).unwrap();
    let rows = history["records"].as_array().unwrap();
    let revoked = rows
        .iter()
        .find(|row| row["outcome"] == "identity_revoked")
        .expect("revocation has its own TCP outcome");
    assert_eq!(revoked["bytes_upstream"], "4");
    assert_eq!(revoked["bytes_downstream"], "4");
    assert!(rows.iter().any(|row| row["outcome"] == "mtls_rejected"));
    backend_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "owned throughput diagnostic; run release explicitly"]
async fn tcp_mtls_owned_echo_throughput() {
    let material = material();
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let backend_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = backend.accept().await.unwrap();
            stream.set_nodelay(true).unwrap();
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 65536];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held.local_addr().unwrap();
    let document = config(listen, backend_address, &material, &[GOOD_ID]);
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(document.clone()).unwrap(),
    ));
    let watch_cancel = CancellationToken::new();
    let watcher = tokio::spawn(hangang::workload_material::watch(
        active.clone(),
        watch_cancel.clone(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 32);
    let prepared = manager
        .prepare_with_inherited(&document, vec![(listen, OwnedFd::from(held))])
        .await
        .unwrap();
    manager.commit(prepared).await;
    wait_material(&active, true).await;
    let connector = connector(&material, Some((&material.good_cert, &material.good_key)));
    let concurrency = std::thread::available_parallelism()
        .map_or(1, |count| count.get())
        .clamp(1, 8);
    let started = std::time::Instant::now();
    let mut clients = tokio::task::JoinSet::new();
    for client in 0..concurrency {
        let connector = connector.clone();
        clients.spawn(async move {
            let socket = TcpStream::connect(listen).await.unwrap();
            socket.set_nodelay(true).unwrap();
            let mut stream = connector
                .connect("localhost".try_into().unwrap(), socket)
                .await
                .unwrap();
            let payload = vec![client as u8; 65536];
            let mut reply = vec![0u8; payload.len()];
            for _ in 0..128 {
                stream.write_all(&payload).await.unwrap();
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(reply, payload);
            }
            stream.shutdown().await.unwrap();
        });
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
    })
    .await
    .unwrap();
    let elapsed = started.elapsed().as_secs_f64();
    eprintln!(
        "TCP mTLS echo: {concurrency} clients, {} MiB payload plus equal replies, {elapsed:.3}s, {:.1} payload MiB/s; includes TLS handshakes",
        concurrency * 8,
        (concurrency * 8) as f64 / elapsed
    );
    watch_cancel.cancel();
    watcher.await.unwrap();
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}
