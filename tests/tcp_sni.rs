#![cfg(unix)]

use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
};
use std::{net::Ipv4Addr, os::fd::OwnedFd, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};

#[tokio::test]
async fn named_sni_stream_counts_only_its_selected_member_until_tls_closes() {
    let pair = rcgen::generate_simple_self_signed(vec!["a.example.test".into()]).unwrap();
    let server = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let backend_a = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address_a = backend_a.local_addr().unwrap();
    // The second route shares the listener but must never receive this stream.
    let backend_b = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address_b = backend_b.local_addr().unwrap();
    let (release_tx, release_rx) = oneshot::channel();
    let origin = tokio::spawn(async move {
        let (socket, _) = backend_a.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.unwrap();
        stream.write_all(b"A").await.unwrap();
        release_rx.await.unwrap();
        stream.shutdown().await.unwrap();
    });

    // Hold the port-zero reservation through publication so another fixture
    // cannot claim the public listener between selection and bind.
    let held = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let listen = held.local_addr().unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "tcp": [
            {"id":"sni-a", "listen":listen,
             "backends":[{"id":"origin-a", "address":address_a.to_string()}],
             "sni":{"hosts":["a.example.test"],
                    "max_client_hello_bytes":4096, "hello_timeout_ms":1000}},
            {"id":"sni-b", "listen":listen,
             "backends":[{"id":"origin-b", "address":address_b.to_string()}],
             "sni":{"hosts":["b.example.test"],
                    "max_client_hello_bytes":4096, "hello_timeout_ms":1000}}
        ]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let manager = TcpManager::new(active.clone(), Arc::new(Metrics::default()), 8);
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, OwnedFd::from(held))])
        .await
        .unwrap();
    let snapshot = Snapshot::replace(config, &active.load_full()).unwrap();
    active.store(Arc::new(snapshot));
    manager.commit(prepared).await;
    let current = active.load_full();
    let a = current.tcp_member_activity["sni-a"].node(0).unwrap();
    let b = current.tcp_member_activity["sni-b"].node(0).unwrap();
    assert_eq!((a.active(), b.active()), (0, 0));

    let mut roots = rustls::RootCertStore::empty();
    roots.add(pair.cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    // A syntactically valid but unmatched SNI is rejected before selecting a
    // route or acquiring a member stream lease.
    let unknown = TcpStream::connect(listen).await.unwrap();
    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        connector.connect(
            "unknown.example.test".to_owned().try_into().unwrap(),
            unknown,
        ),
    )
    .await
    .expect("unknown SNI must close promptly");
    assert!(rejected.is_err());
    assert_eq!((a.active(), b.active()), (0, 0));

    let selected = TcpStream::connect(listen).await.unwrap();
    let mut selected = tokio::time::timeout(
        Duration::from_secs(2),
        connector.connect("a.example.test".to_owned().try_into().unwrap(), selected),
    )
    .await
    .expect("selected TLS handshake timed out")
    .unwrap();
    let mut tag = [0];
    selected.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag, [b'A']);
    assert_eq!((a.active(), b.active()), (1, 0));

    release_tx.send(()).unwrap();
    origin.await.unwrap();
    selected.shutdown().await.unwrap();
    drop(selected);
    tokio::time::timeout(Duration::from_secs(2), async {
        while a.active() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("stream lease must release after TLS close");
    assert_eq!(b.active(), 0);
    manager.shutdown(Duration::from_secs(1)).await;
}
