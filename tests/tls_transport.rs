use hangang::tls::ReloadingTls;
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn certificate_reload_is_atomic_and_retains_last_good_pair() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert, first.cert.pem()).unwrap();
    std::fs::write(&key, first.signing_key.serialize_pem()).unwrap();
    let tls = Arc::new(ReloadingTls::new(cert.clone(), key.clone()).unwrap());
    let cancel = CancellationToken::new();
    let task = tokio::spawn(tls.clone().watch(cancel.clone()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let good = tls.current.load_full();
    std::fs::write(&cert, "incomplete PEM").unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(Arc::ptr_eq(&good, &tls.current.load_full()));
    let second = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert, second.cert.pem()).unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(Arc::ptr_eq(&good, &tls.current.load_full()));
    std::fs::write(&key, second.signing_key.serialize_pem()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while Arc::ptr_eq(&good, &tls.current.load_full()) {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    cancel.cancel();
    task.await.unwrap();
}

#[tokio::test]
async fn identical_rejected_material_is_parsed_once() {
    // The legacy watcher polls every 500 ms. Bad material must be parsed once
    // (off the executor) and then skipped by digest until it changes, rather
    // than re-parsed on every tick.
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert, first.cert.pem()).unwrap();
    std::fs::write(&key, first.signing_key.serialize_pem()).unwrap();
    let tls = Arc::new(ReloadingTls::new(cert.clone(), key.clone()).unwrap());
    let good = tls.current.load_full();
    let cancel = CancellationToken::new();
    let task = tokio::spawn(tls.clone().watch(cancel.clone()));
    // Unchanged material never replaces the config published at start.
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(Arc::ptr_eq(&good, &tls.current.load_full()));
    assert_eq!(tls.rejected_reloads(), 0);
    // A large chain paired with the wrong key: rejected exactly once.
    let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut chain = String::new();
    for _ in 0..64 {
        chain.push_str(&first.cert.pem());
    }
    std::fs::write(&cert, &chain).unwrap();
    std::fs::write(&key, wrong.signing_key.serialize_pem()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while tls.rejected_reloads() == 0 {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    // Several more ticks pass with the same bad bytes on disk.
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(
        tls.rejected_reloads(),
        1,
        "identical bad material was re-parsed"
    );
    assert!(Arc::ptr_eq(&good, &tls.current.load_full()));
    // Different bad material is parsed (and rejected) again, once.
    std::fs::write(&cert, "still not a certificate").unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while tls.rejected_reloads() < 2 {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    assert_eq!(tls.rejected_reloads(), 2);
    // Valid material still replaces the configuration.
    std::fs::write(&cert, wrong.cert.pem()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while Arc::ptr_eq(&good, &tls.current.load_full()) {
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(tls.rejected_reloads(), 2);
    cancel.cancel();
    task.await.unwrap();
}

struct Child(std::process::Child);
impl Drop for Child {
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

#[tokio::test]
async fn public_and_admin_tls_negotiate_h2_and_cleartext_h2_is_supported() {
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    std::fs::write(&cert, pair.cert.pem()).unwrap();
    std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
    for tls in [true, false] {
        let public = port();
        let mut admin = port();
        while admin == public {
            admin = port();
        }
        let state = dir.path().join(format!("state-{tls}.json"));
        std::fs::write(&state, r#"{"revision":0,"http":[],"tcp":[]}"#).unwrap();
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_hangang"));
        cmd.args([
            "--config",
            state.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{public}"),
            "--admin",
            &format!("127.0.0.1:{admin}"),
            "--threads",
            "2",
            "--lua-workers",
            "1",
        ])
        .env("HANGANG_ADMIN_TOKEN", "test-token-for-tls-transport")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
        if tls {
            cmd.arg("--tls-cert")
                .arg(&cert)
                .arg("--tls-key")
                .arg(&key)
                .arg("--admin-tls-cert")
                .arg(&cert)
                .arg("--admin-tls-key")
                .arg(&key);
        }
        let mut child = Child(cmd.spawn().unwrap());
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy();
        if tls {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(pair.cert.pem().as_bytes()).unwrap(),
            );
        } else {
            builder = builder.http2_prior_knowledge();
        }
        let client = builder.build().unwrap();
        let scheme = if tls { "https" } else { "http" };
        let url = format!("{scheme}://localhost:{admin}/v1/status");
        let response = tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                assert!(child.0.try_wait().unwrap().is_none(), "server exited");
                if let Ok(response) = client
                    .get(&url)
                    .bearer_auth("test-token-for-tls-transport")
                    .send()
                    .await
                {
                    break response;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        let response = client
            .get(format!("{scheme}://localhost:{public}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
        assert_eq!(response.version(), reqwest::Version::HTTP_2);
        if tls {
            assert!(
                reqwest::Client::builder()
                    .no_proxy()
                    .build()
                    .unwrap()
                    .get(&url)
                    .send()
                    .await
                    .is_err(),
                "untrusted certificate accepted"
            );
        }
    }
}

#[tokio::test]
async fn https_upstream_is_verified_and_forwarded() {
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Request, Response, service::service_fn};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    let dir = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = dir.path().join("root.pem");
    std::fs::write(&cert, pair.cert.pem()).unwrap();
    let tls = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_: Request<hyper::body::Incoming>| async {
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"secure upstream",
                    ))))
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    let public = port();
    let mut admin = port();
    while admin == public {
        admin = port();
    }
    let state = dir.path().join("state.json");
    std::fs::write(
        &state,
        format!(r#"{{"http":[{{"id":"secure","backends":["https://localhost:{upstream}"]}}]}}"#),
    )
    .unwrap();
    let mut child = Child(
        std::process::Command::new(env!("CARGO_BIN_EXE_hangang"))
            .args([
                "--config",
                state.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{public}"),
                "--admin",
                &format!("127.0.0.1:{admin}"),
                "--threads",
                "2",
                "--lua-workers",
                "1",
                "--upstream-ca",
                cert.to_str().unwrap(),
            ])
            .env("HANGANG_ADMIN_TOKEN", "test-token-for-tls-transport")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            assert!(child.0.try_wait().unwrap().is_none());
            if let Ok(response) = client
                .get(format!("http://127.0.0.1:{public}/"))
                .send()
                .await
            {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "secure upstream");
    task.abort();
}

#[tokio::test]
async fn dynamic_sni_serves_multiple_secrets_and_removes_deleted_names() {
    use tokio::net::{TcpListener, TcpStream};
    let first = rcgen::generate_simple_self_signed(vec!["first.test".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["*.second.test".into()]).unwrap();
    let material = || {
        vec![
            hangang::tls::SniCertificate {
                hosts: vec!["first.test".into()],
                default: false,
                cert_pem: first.cert.pem().into_bytes(),
                key_pem: first.signing_key.serialize_pem().into_bytes(),
            },
            hangang::tls::SniCertificate {
                hosts: vec!["*.second.test".into()],
                default: false,
                cert_pem: second.cert.pem().into_bytes(),
                key_pem: second.signing_key.serialize_pem().into_bytes(),
            },
        ]
    };
    let tls = Arc::new(ReloadingTls::dynamic(
        hangang::tls::sni_server_config(material()).unwrap(),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn({
        let tls = tls.clone();
        async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(tls.current.load_full());
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        }
    });
    let mut roots = rustls::RootCertStore::empty();
    roots.add(first.cert.der().clone()).unwrap();
    roots.add(second.cert.der().clone()).unwrap();
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
    for name in ["first.test", "one.second.test"] {
        assert!(
            connector
                .connect(
                    name.to_owned().try_into().unwrap(),
                    TcpStream::connect(address).await.unwrap()
                )
                .await
                .is_ok()
        );
    }
    assert!(
        connector
            .connect(
                "two.one.second.test".to_owned().try_into().unwrap(),
                TcpStream::connect(address).await.unwrap()
            )
            .await
            .is_err()
    );
    let mut replacement = material();
    replacement.remove(0);
    tls.current.store(Arc::new(
        hangang::tls::sni_server_config(replacement).unwrap(),
    ));
    assert!(
        connector
            .connect(
                "first.test".to_owned().try_into().unwrap(),
                TcpStream::connect(address).await.unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        connector
            .connect(
                "one.second.test".to_owned().try_into().unwrap(),
                TcpStream::connect(address).await.unwrap()
            )
            .await
            .is_ok()
    );
    server.abort();
}
