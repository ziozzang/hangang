use arc_swap::ArcSwap;
use hangang::{
    certificates::{CertificateFiles, load, validate_set, watch},
    config::{Config, Snapshot},
};
use rustls::RootCertStore;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};

fn files(
    directory: &Path,
    id: &str,
    hosts: &[&str],
    pair: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> CertificateFiles {
    let cert_file = directory.join(format!("{id}.crt.pem"));
    let key_file = directory.join(format!("{id}.key.pem"));
    std::fs::write(&cert_file, pair.cert.pem()).unwrap();
    std::fs::write(&key_file, pair.signing_key.serialize_pem()).unwrap();
    CertificateFiles {
        id: id.to_owned(),
        hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
        default: false,
        enabled: true,
        cert_file,
        key_file,
        issuer_status_file: None,
    }
}

#[test]
fn disabled_certificate_keeps_metadata_but_requires_no_files_until_enabled() {
    let directory = tempfile::tempdir().unwrap();
    let mut entry = CertificateFiles {
        id: "inactive".into(),
        hosts: vec!["inactive.example.test".into()],
        default: false,
        enabled: false,
        cert_file: directory.path().join("absent.cert.pem"),
        key_file: directory.path().join("absent.key.pem"),
        issuer_status_file: None,
    };
    assert!(load(&[entry.clone()]).is_ok());
    let serialized = serde_json::to_value(&entry).unwrap();
    assert_eq!(serialized["enabled"], false);
    entry.enabled = true;
    assert!(
        serde_json::to_value(&entry)
            .unwrap()
            .get("enabled")
            .is_none()
    );
    assert!(load(&[entry]).is_err());
}

#[test]
fn inactive_certificates_do_not_reserve_hosts_or_default_fallback() {
    let directory = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["same.example.test".into()]).unwrap();
    let active = files(directory.path(), "active", &["same.example.test"], &pair);
    let mut inactive = CertificateFiles {
        id: "replacement".into(),
        hosts: vec!["SAME.example.test".into()],
        default: false,
        enabled: false,
        cert_file: directory.path().join("missing.cert.pem"),
        key_file: directory.path().join("missing.key.pem"),
        issuer_status_file: None,
    };
    assert!(load(&[active.clone(), inactive.clone()]).is_ok());
    inactive.enabled = true;
    assert!(validate_set(&[active.clone(), inactive.clone()]).is_err());

    let mut fallback = active;
    fallback.default = true;
    fallback.hosts.clear();
    let mut inactive_fallback = inactive;
    inactive_fallback.enabled = false;
    inactive_fallback.default = true;
    inactive_fallback.hosts.clear();
    assert!(validate_set(&[fallback.clone(), inactive_fallback.clone()]).is_ok());
    inactive_fallback.enabled = true;
    assert!(validate_set(&[fallback, inactive_fallback]).is_err());
}

fn client(roots: RootCertStore) -> Arc<rustls::ClientConfig> {
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

async fn accepts(
    server: rustls::ServerConfig,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> bool {
    accepts_shared(Arc::new(server), client, name).await
}

async fn accepts_shared(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(server);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        acceptor.accept(stream).await.is_ok()
    });
    let connector = tokio_rustls::TlsConnector::from(client);
    let connected = tokio::time::timeout(
        Duration::from_secs(2),
        connector.connect(
            name.to_owned().try_into().unwrap(),
            TcpStream::connect(address).await.unwrap(),
        ),
    )
    .await
    .is_ok_and(|result| result.is_ok());
    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
    connected
}

fn padded_material(
    pair: &rcgen::CertifiedKey<rcgen::KeyPair>,
    cert_len: usize,
    key_len: usize,
) -> (Vec<u8>, Vec<u8>) {
    let mut cert = pair.cert.pem().into_bytes();
    let mut key = pair.signing_key.serialize_pem().into_bytes();
    assert!(cert.len() <= cert_len);
    assert!(key.len() <= key_len);
    cert.resize(cert_len, b'\n');
    key.resize(key_len, b'\n');
    (cert, key)
}

fn rename_over(path: &Path, bytes: &[u8]) {
    let replacement = path.with_extension("replacement");
    std::fs::write(&replacement, bytes).unwrap();
    assert_eq!(std::fs::metadata(path).unwrap().len(), bytes.len() as u64);
    std::fs::rename(replacement, path).unwrap();
}

#[tokio::test]
async fn exact_and_single_label_wildcard_hosts_are_selected_and_removal_is_complete() {
    let directory = tempfile::tempdir().unwrap();
    let exact = rcgen::generate_simple_self_signed(vec!["first.test".into()]).unwrap();
    let wildcard = rcgen::generate_simple_self_signed(vec!["*.second.test".into()]).unwrap();
    let exact_files = files(directory.path(), "exact", &["first.test"], &exact);
    let wildcard_files = files(directory.path(), "wildcard", &["*.second.test"], &wildcard);
    let mut roots = RootCertStore::empty();
    roots.add(exact.cert.der().clone()).unwrap();
    roots.add(wildcard.cert.der().clone()).unwrap();
    let client = client(roots);

    assert!(
        accepts(
            load(&[exact_files.clone(), wildcard_files.clone()]).unwrap(),
            client.clone(),
            "first.test"
        )
        .await
    );
    assert!(
        accepts(
            load(&[exact_files.clone(), wildcard_files.clone()]).unwrap(),
            client.clone(),
            "one.second.test"
        )
        .await
    );
    assert!(
        !accepts(
            load(&[exact_files.clone(), wildcard_files.clone()]).unwrap(),
            client.clone(),
            "two.one.second.test"
        )
        .await
    );
    assert!(
        !accepts(
            load(std::slice::from_ref(&wildcard_files)).unwrap(),
            client.clone(),
            "first.test"
        )
        .await,
        "a removed exact name must not remain in the replacement resolver"
    );
    assert!(
        !accepts(
            load(std::slice::from_ref(&wildcard_files)).unwrap(),
            client,
            "unknown.test"
        )
        .await
    );
}

#[tokio::test]
async fn default_pair_serves_unknown_and_absent_sni_without_replacing_named_pair() {
    let directory = tempfile::tempdir().unwrap();
    let exact = rcgen::generate_simple_self_signed(vec!["known.test".into()]).unwrap();
    // rustls omits the SNI extension when the client uses an IP ServerName.
    let fallback =
        rcgen::generate_simple_self_signed(vec!["fallback.test".into(), "127.0.0.1".into()])
            .unwrap();
    let exact_files = files(directory.path(), "exact", &["known.test"], &exact);
    let mut default_files = files(directory.path(), "default", &[], &fallback);
    default_files.default = true;
    let mut roots = RootCertStore::empty();
    roots.add(exact.cert.der().clone()).unwrap();
    roots.add(fallback.cert.der().clone()).unwrap();
    let client = client(roots);
    assert!(
        accepts(
            load(&[exact_files.clone(), default_files.clone()]).unwrap(),
            client.clone(),
            "known.test"
        )
        .await,
        "a named certificate must win over the default"
    );
    assert!(
        accepts(
            load(&[exact_files.clone(), default_files.clone()]).unwrap(),
            client.clone(),
            "fallback.test"
        )
        .await,
        "unknown SNI must receive the default certificate"
    );
    assert!(
        accepts(
            load(&[exact_files.clone(), default_files.clone()]).unwrap(),
            client.clone(),
            "127.0.0.1"
        )
        .await,
        "absent SNI must receive the default certificate"
    );
    assert!(
        !accepts(load(&[exact_files]).unwrap(), client, "fallback.test").await,
        "default=false must preserve rejection of unknown SNI"
    );
    assert!(validate_set(&[default_files.clone(), default_files.clone()]).is_err());
    let mut another_default = default_files.clone();
    another_default.id = "other-default".into();
    assert!(validate_set(&[default_files.clone(), another_default]).is_err());
    let mut invalid = default_files.clone();
    invalid.hosts = vec!["fallback.test".into()];
    assert!(validate_set(&[invalid]).is_err());
    let mut missing_flag = default_files;
    missing_flag.default = false;
    assert!(validate_set(&[missing_flag]).is_err());
}

#[test]
fn default_pair_may_have_no_san_like_the_existing_kong_default() {
    let directory = tempfile::tempdir().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_file = directory.path().join("default.crt.pem");
    let key_file = directory.path().join("default.key.pem");
    std::fs::write(&cert_file, cert.pem()).unwrap();
    std::fs::write(&key_file, key.serialize_pem()).unwrap();
    let entry = CertificateFiles {
        id: "default".into(),
        hosts: Vec::new(),
        default: true,
        enabled: true,
        cert_file,
        key_file,
        issuer_status_file: None,
    };
    assert!(load(&[entry]).is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn watcher_catches_same_length_rename_and_retains_last_good_pair() {
    let directory = tempfile::tempdir().unwrap();
    let first = rcgen::generate_simple_self_signed(vec!["rotate.test".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["rotate.test".into()]).unwrap();
    let entry = files(directory.path(), "rotate", &["rotate.test"], &first);
    let cert_len = first.cert.pem().len().max(second.cert.pem().len());
    let key_len = first
        .signing_key
        .serialize_pem()
        .len()
        .max(second.signing_key.serialize_pem().len());
    let first_material = padded_material(&first, cert_len, key_len);
    let second_material = padded_material(&second, cert_len, key_len);
    std::fs::write(&entry.cert_file, &first_material.0).unwrap();
    std::fs::write(&entry.key_file, &first_material.1).unwrap();

    let mut first_roots = RootCertStore::empty();
    first_roots.add(first.cert.der().clone()).unwrap();
    let first_client = client(first_roots);
    let mut second_roots = RootCertStore::empty();
    second_roots.add(second.cert.der().clone()).unwrap();
    let second_client = client(second_roots);

    let snapshot = Snapshot::new(Config {
        certificates: vec![entry.clone()],
        ..Config::default()
    })
    .unwrap();
    let resolver = snapshot.certificates.as_ref().unwrap().clone();
    let active = Arc::new(ArcSwap::from_pointee(snapshot));
    let cancel = tokio_util::sync::CancellationToken::new();
    let watcher = tokio::spawn(watch(active, cancel.clone()));
    assert!(
        accepts_shared(resolver.load_full(), first_client, "rotate.test").await,
        "initial certificate should be served"
    );

    rename_over(&entry.cert_file, &second_material.0);
    rename_over(&entry.key_file, &second_material.1);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if accepts_shared(resolver.load_full(), second_client.clone(), "rotate.test").await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("renamed same-length material should be detected");

    // A mismatched key is a changed, readable pair but must not replace the
    // successfully published second certificate.
    rename_over(&entry.key_file, &first_material.1);
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(
        accepts_shared(resolver.load_full(), second_client, "rotate.test").await,
        "invalid rotation must retain the last good resolver"
    );
    cancel.cancel();
    watcher.await.unwrap();
}

#[test]
fn rejects_a_certificate_paired_with_the_wrong_private_key() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = rcgen::generate_simple_self_signed(vec!["wrong-key.test".into()]).unwrap();
    let wrong = rcgen::generate_simple_self_signed(vec!["wrong-key.test".into()]).unwrap();
    let entry = files(
        directory.path(),
        "wrong-key",
        &["wrong-key.test"],
        &certificate,
    );
    std::fs::write(&entry.key_file, wrong.signing_key.serialize_pem()).unwrap();
    assert!(load(&[entry]).is_err());
}

#[test]
fn rejects_oversized_or_non_regular_material() {
    let directory = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["bounded.test".into()]).unwrap();
    let entry = files(directory.path(), "bounded", &["bounded.test"], &pair);
    std::fs::write(&entry.cert_file, vec![b'x'; 1024 * 1024 + 1]).unwrap();
    let error = load(&[entry]).unwrap_err().to_string();
    assert!(error.contains("exceeds 1 MiB"), "{error}");

    let directory_entry = CertificateFiles {
        id: "directory".into(),
        hosts: vec!["directory.test".into()],
        default: false,
        enabled: true,
        cert_file: directory.path().to_owned(),
        key_file: directory.path().join("bounded.key.pem"),
        issuer_status_file: None,
    };
    assert!(load(&[directory_entry]).is_err());
}

#[test]
fn structural_validation_is_case_insensitive_and_requires_safe_absolute_paths() {
    let directory = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["duplicate.test".into()]).unwrap();
    let first = files(directory.path(), "first", &["duplicate.test"], &pair);
    let mut duplicate = first.clone();
    duplicate.id = "second".into();
    duplicate.hosts = vec!["DUPLICATE.TEST".into()];
    assert!(validate_set(&[first.clone(), duplicate]).is_err());

    let mut relative = first;
    relative.cert_file = "certificate.pem".into();
    assert!(validate_set(&[relative]).is_err());
}

#[cfg(unix)]
#[test]
fn rejects_a_fifo_without_waiting_for_a_writer() {
    use std::os::unix::ffi::OsStrExt;
    let directory = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["fifo.test".into()]).unwrap();
    let entry = files(directory.path(), "fifo", &["fifo.test"], &pair);
    std::fs::remove_file(&entry.cert_file).unwrap();
    let fifo = std::ffi::CString::new(entry.cert_file.as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is a live NUL-terminated pathname in the owned temporary directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let (sent, received) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sent.send(load(&[entry]));
    });
    let result = received
        .recv_timeout(Duration::from_secs(1))
        .expect("FIFO certificate rejection must not wait for a writer");
    assert!(result.is_err());
}
