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
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

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
}

fn ca() -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

fn client_certificate(issuer: &CertifiedIssuer<'_, KeyPair>, uri: &str) -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(uri.try_into().unwrap())];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
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

    // Keep a verified stream open across publication. It must not continue
    // forwarding under an allowlist that no longer admits its SAN URI.
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut held = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    held.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    // A no-op publication preserves the exact prepared verifier and a live
    // authenticated stream. Replacing CA bytes at the same path must fence
    // that stream even though the route JSON is unchanged.
    let prepared_before = active.load_full().tcp_inbound_tls["workload"].clone();
    let same = config(listen, backend_address, &material, &[GOOD_ID]);
    let prepared = manager.prepare(&same).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(same.clone(), &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    assert!(Arc::ptr_eq(
        &prepared_before,
        &active.load_full().tcp_inbound_tls["workload"]
    ));
    held.write_all(b"ping").await.unwrap();
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    std::fs::write(&material.ca_file, ca().pem()).unwrap();
    let prepared = manager.prepare(&same).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(same.clone(), &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    assert!(!Arc::ptr_eq(
        &prepared_before,
        &active.load_full().tcp_inbound_tls["workload"]
    ));
    let mut byte = [0];
    let closed = tokio::time::timeout(Duration::from_secs(3), held.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "old CA stream stayed active: {closed:?}"
    );
    assert!(!exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 2);

    std::fs::write(&material.ca_file, &material.ca_pem).unwrap();
    let prepared = manager.prepare(&same).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(same, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    assert!(exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 3);

    let socket = TcpStream::connect(listen).await.unwrap();
    let mut held = good
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    held.write_all(b"ping").await.unwrap();
    held.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 4);

    let next = config(listen, backend_address, &material, &[OTHER_ID]);
    let prepared = manager.prepare(&next).await.unwrap();
    active.store(Arc::new(
        Snapshot::replace(next, &active.load_full()).unwrap(),
    ));
    manager.commit(prepared).await;
    let closed = tokio::time::timeout(Duration::from_secs(3), held.read(&mut byte)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "old identity stream remained active: {closed:?}"
    );
    assert!(!exchange(&good, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 4);
    assert!(exchange(&wrong_uri, listen).await);
    assert_eq!(accepted.load(Ordering::SeqCst), 5);

    let socket = TcpStream::connect(listen).await.unwrap();
    let mut remaining = wrong_uri
        .connect("localhost".try_into().unwrap(), socket)
        .await
        .unwrap();
    remaining.write_all(b"ping").await.unwrap();
    remaining.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert_eq!(accepted.load(Ordering::SeqCst), 6);

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
    assert_eq!(accepted.load(Ordering::SeqCst), 6);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}
