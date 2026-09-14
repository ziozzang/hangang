#![cfg(unix)]

use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
    tcp::TcpManager,
};
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, os::fd::OwnedFd, sync::Arc, time::Duration};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn named_https_h2_forwards_only_routes_in_its_scope() {
    let bound = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen = bound.local_addr().unwrap();
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = origin.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|_request: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"origin-ok"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let material = tempfile::tempdir().unwrap();
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_file = material.path().join("server.pem");
    let key_file = material.path().join("server.key");
    std::fs::write(&cert_file, pair.cert.pem()).unwrap();
    std::fs::write(&key_file, pair.signing_key.serialize_pem()).unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "public_http": [{"id":"edge","listen":listen,"certificates":[{"id":"localhost","hosts":[],"default":true,"cert_file":cert_file,"key_file":key_file}]}],
        "http": [
            {"id":"edge-route","path_prefix":"/edge","listener_ids":["edge"],"backends":[format!("http://{backend}")]},
            {"id":"default-route","path_prefix":"/default","backends":[format!("http://{backend}")]}
        ]
    })).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(config.clone()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Arc::new(Proxy::new(active.clone(), policy.clone(), metrics.clone()));
    let manager = TcpManager::new(active, metrics, 32).with_gate_closed();
    manager.set_workload_http(proxy.clone(), 32 * 1024).unwrap();
    let inherited: OwnedFd = bound.into_std().unwrap().into();
    let prepared = manager
        .prepare_with_inherited(&config, vec![(listen, inherited)])
        .await
        .unwrap();
    manager.commit(prepared).await;
    manager.open_gate();

    let mut roots = rustls::RootCertStore::empty();
    roots.add(pair.cert.der().clone()).unwrap();
    let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec()];
    let tls = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(
            "localhost".try_into().unwrap(),
            TcpStream::connect(listen).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(tls))
        .await
        .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    for (path, expected) in [("/edge", 200), ("/default", 404)] {
        let response = tokio::time::timeout(
            Duration::from_secs(3),
            sender.send_request(
                Request::builder()
                    .uri(format!("https://localhost{path}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response.status().as_u16(), expected, "{path}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        if expected == 200 {
            assert_eq!(body, "origin-ok");
        }
    }
    connection_task.abort();
    manager.shutdown(Duration::ZERO).await;
    proxy.shutdown(Duration::ZERO).await;
    policy.shutdown().await;
    origin_task.abort();
}
