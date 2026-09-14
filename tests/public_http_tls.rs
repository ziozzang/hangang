use arc_swap::ArcSwap;
use hangang::{
    certificates::{CertificateFiles, load, load_public, watch_public},
    config::{Config, Snapshot},
    public_listener_config::Listener,
};
use rustls::RootCertStore;
use std::{path::Path, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

fn cert(
    directory: &Path,
    id: &str,
    pair: &rcgen::CertifiedKey<rcgen::KeyPair>,
) -> CertificateFiles {
    let cert_file = directory.join(format!("{id}.crt.pem"));
    let key_file = directory.join(format!("{id}.key.pem"));
    std::fs::write(&cert_file, pair.cert.pem()).unwrap();
    std::fs::write(&key_file, pair.signing_key.serialize_pem()).unwrap();
    CertificateFiles {
        id: id.into(),
        hosts: vec![format!("{id}.test")],
        default: false,
        enabled: true,
        cert_file,
        key_file,
        issuer_status_file: None,
    }
}

fn listener(id: &str, port: u16, certificates: Vec<CertificateFiles>) -> Listener {
    Listener {
        id: id.into(),
        listen: ([127, 0, 0, 1], port).into(),
        enabled: true,
        certificates,
        trusted_proxy_cidrs: vec![],
    }
}

fn client(pairs: &[&rcgen::CertifiedKey<rcgen::KeyPair>]) -> Arc<rustls::ClientConfig> {
    let mut roots = RootCertStore::empty();
    for pair in pairs {
        roots.add(pair.cert.der().clone()).unwrap();
    }
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

async fn handshake(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: &str,
) -> bool {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio_rustls::TlsAcceptor::from(server)
            .accept(stream)
            .await
            .is_ok()
    });
    let connected = tokio::time::timeout(Duration::from_secs(2), async {
        tokio_rustls::TlsConnector::from(client)
            .connect(
                name.to_owned().try_into().unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
    })
    .await
    .is_ok_and(|result| result.is_ok());
    let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
    connected
}

#[tokio::test]
async fn named_https_resolvers_isolate_sni_and_default_certificates() {
    let dir = tempfile::tempdir().unwrap();
    let alpha = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let beta = rcgen::generate_simple_self_signed(vec!["beta.test".into()]).unwrap();
    let fallback = rcgen::generate_simple_self_signed(vec!["fallback.test".into()]).unwrap();
    let mut fallback_file = cert(dir.path(), "fallback", &fallback);
    fallback_file.hosts.clear();
    fallback_file.default = true;
    let mut config = Config::default();
    config.public_http = vec![
        listener(
            "one",
            28001,
            vec![cert(dir.path(), "alpha", &alpha), fallback_file],
        ),
        listener("two", 28002, vec![cert(dir.path(), "beta", &beta)]),
    ];
    let snapshot = Snapshot::new(config).unwrap();
    let client = client(&[&alpha, &beta, &fallback]);
    assert!(
        handshake(
            snapshot.public_http_tls["one"].load_full(),
            client.clone(),
            "alpha.test"
        )
        .await
    );
    assert!(
        handshake(
            snapshot.public_http_tls["one"].load_full(),
            client.clone(),
            "fallback.test"
        )
        .await
    );
    assert!(
        !handshake(
            snapshot.public_http_tls["one"].load_full(),
            client.clone(),
            "beta.test"
        )
        .await
    );
    assert!(
        handshake(
            snapshot.public_http_tls["two"].load_full(),
            client.clone(),
            "beta.test"
        )
        .await
    );
    assert!(
        !handshake(
            snapshot.public_http_tls["two"].load_full(),
            client,
            "alpha.test"
        )
        .await
    );
}

#[tokio::test]
async fn invalid_material_refuses_snapshot_and_disabled_all_stays_https() {
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let mut config = Config::default();
    let mut missing = cert(dir.path(), "alpha", &pair);
    let initial = Snapshot::new({
        let mut valid = config.clone();
        valid
            .public_http
            .push(listener("edge", 28003, vec![missing.clone()]));
        valid
    })
    .unwrap();
    missing.key_file = dir.path().join("missing.key.pem");
    config
        .public_http
        .push(listener("edge", 28003, vec![missing.clone()]));
    assert!(Snapshot::new(config.clone()).is_err());
    assert!(Snapshot::replace(config.clone(), &initial).is_err());
    let pair = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    missing = cert(dir.path(), "alpha", &pair);
    missing.enabled = false;
    config.public_http[0].certificates = vec![missing];
    let snapshot = Snapshot::new(config).unwrap();
    assert!(
        snapshot.public_http_tls.contains_key("edge"),
        "disabled certificate metadata must retain an HTTPS resolver"
    );
    assert!(
        !handshake(
            snapshot.public_http_tls["edge"].load_full(),
            client(&[&pair]),
            "alpha.test"
        )
        .await
    );
}

#[tokio::test]
async fn named_watcher_rotates_one_listener_and_keeps_last_good_on_invalid_files() {
    let dir = tempfile::tempdir().unwrap();
    let old = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let new = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["beta.test".into()]).unwrap();
    let alpha = cert(dir.path(), "alpha", &old);
    let beta = cert(dir.path(), "beta", &other);
    let mut config = Config::default();
    config.public_http = vec![
        listener("one", 28004, vec![alpha.clone()]),
        listener("two", 28005, vec![beta]),
    ];
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(watch_public(active.clone(), cancel.clone()));
    let new_client = client(&[&new]);
    std::fs::write(&alpha.key_file, b"invalid key").unwrap();
    tokio::time::sleep(Duration::from_millis(750)).await;
    let unchanged = active.load().public_http_tls["two"].load_full();
    assert!(
        !handshake(
            active.load().public_http_tls["one"].load_full(),
            new_client.clone(),
            "alpha.test"
        )
        .await
    );
    assert!(
        handshake(
            active.load().public_http_tls["one"].load_full(),
            client(&[&old]),
            "alpha.test"
        )
        .await,
        "invalid replacement must keep the last verified certificate"
    );
    std::fs::write(&alpha.cert_file, new.cert.pem()).unwrap();
    std::fs::write(&alpha.key_file, new.signing_key.serialize_pem()).unwrap();
    let rotated = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if handshake(
                active.load().public_http_tls["one"].load_full(),
                new_client.clone(),
                "alpha.test",
            )
            .await
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(rotated.is_ok());
    assert!(Arc::ptr_eq(
        &unchanged,
        &active.load().public_http_tls["two"].load_full()
    ));
    cancel.cancel();
    watcher.await.unwrap();
}

#[tokio::test]
async fn named_material_budget_rejects_actual_bytes_and_keeps_last_good() {
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let alpha = cert(dir.path(), "alpha", &pair);
    let mut config = Config::default();
    config
        .public_http
        .push(listener("edge", 28006, vec![alpha.clone()]));
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let cancel = CancellationToken::new();
    let watcher = tokio::spawn(watch_public(active.clone(), cancel.clone()));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let last_good = active.load().public_http_tls["edge"].load_full();
    let mut padded = pair.cert.pem().into_bytes();
    padded.resize(1024 * 1024, b'\n');
    std::fs::write(&alpha.cert_file, padded).unwrap();
    assert!(load_public(&[alpha.clone()]).is_err());
    assert!(
        load(&[alpha]).is_ok(),
        "legacy global TLS retains its 16 MiB budget"
    );
    tokio::time::sleep(Duration::from_millis(750)).await;
    assert!(Arc::ptr_eq(
        &last_good,
        &active.load().public_http_tls["edge"].load_full()
    ));
    assert!(
        handshake(
            active.load().public_http_tls["edge"].load_full(),
            client(&[&pair]),
            "alpha.test"
        )
        .await
    );
    cancel.cancel();
    watcher.await.unwrap();
}

#[test]
fn named_certificate_count_is_aggregate_across_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["alpha.test".into()]).unwrap();
    let base = cert(dir.path(), "base", &pair);
    let certificates = |prefix: &str| {
        (0..513)
            .map(|i| {
                let mut entry = base.clone();
                entry.id = format!("{prefix}{i}");
                entry.default = true;
                entry.enabled = false;
                entry.hosts.clear();
                entry
            })
            .collect()
    };
    let mut config = Config::default();
    config.public_http = vec![
        listener("one", 28007, certificates("a")),
        listener("two", 28008, certificates("b")),
    ];
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("1024 named public TLS certificates")
    );
}
