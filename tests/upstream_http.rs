use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, task::JoinHandle};

async fn origin(tls: Option<rustls::ServerConfig>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let acceptor = tls.map(|c| tokio_rustls::TlsAcceptor::from(Arc::new(c)));
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let connection = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let (stream, sni): (hangang::upstream::BoxIo, String) =
                    if let Some(acceptor) = acceptor {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let name = tls.get_ref().1.server_name().unwrap_or("").to_owned();
                        (Box::new(tls), name)
                    } else {
                        (Box::new(stream), String::new())
                    };
                let service = service_fn(move |req: Request<Incoming>| {
                    let sni = sni.clone();
                    async move {
                        let value = serde_json::json!({"connection":connection,"host":req.headers().get("host").and_then(|h|h.to_str().ok()),"authority":req.uri().authority().map(|a|a.as_str()),"sni":sni,"version":format!("{:?}",req.version()),"path":req.uri().path()});
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                            value.to_string(),
                        ))))
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (addr, task)
}
#[cfg(unix)]
async fn unix_origin(path: &std::path::Path, tls: Option<rustls::ServerConfig>) -> JoinHandle<()> {
    let listener = tokio::net::UnixListener::bind(path).unwrap();
    let acceptor = tls.map(|c| tokio_rustls::TlsAcceptor::from(Arc::new(c)));
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let (stream, sni): (hangang::upstream::BoxIo, String) =
                    if let Some(acceptor) = acceptor {
                        let Ok(tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let name = tls.get_ref().1.server_name().unwrap_or("").to_owned();
                        (Box::new(tls), name)
                    } else {
                        (Box::new(stream), String::new())
                    };
                let service = service_fn(move |req: Request<Incoming>| {
                    let sni = sni.clone();
                    async move {
                        let value = serde_json::json!({"host": req.headers().get("host").and_then(|h| h.to_str().ok()), "authority": req.uri().authority().map(|a| a.as_str()), "sni": sni, "path": req.uri().path()});
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                            value.to_string(),
                        ))))
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    })
}
async fn gateway(config: Config) -> (SocketAddr, Arc<ArcSwap<Snapshot>>, JoinHandle<()>) {
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let proxy = Proxy::new(
        active.clone(),
        Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1)),
        Arc::new(Metrics::default()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, peer) = listener.accept().await.unwrap();
            let p = proxy.clone();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(stream),
                        service_fn(move |r| {
                            let p = p.clone();
                            async move { p.handle(r, peer).await }
                        }),
                    )
                    .await;
            });
        }
    });
    (addr, active, task)
}
#[cfg(unix)]
#[tokio::test]
async fn http_routes_use_unix_socket_without_changing_host_or_tls_name() {
    let pair = rcgen::generate_simple_self_signed(vec!["relay.example".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let plain_socket = directory.path().join("plain.sock");
    let tls_socket = directory.path().join("tls.sock");
    let ca = directory.path().join("ca.pem");
    std::fs::write(&ca, pair.cert.pem()).unwrap();
    let plain_server = unix_origin(&plain_socket, None).await;
    let tls_server = unix_origin(
        &tls_socket,
        Some(
            hangang::tls::server_config(
                pair.cert.pem().as_bytes(),
                pair.signing_key.serialize_pem().as_bytes(),
            )
            .unwrap(),
        ),
    )
    .await;
    let config: Config = serde_json::from_value(serde_json::json!({"http": [
        {"id":"plain-uds","path_prefix":"/plain","backends":["http://logical.invalid"],"upstream":{"unix_socket":plain_socket}},
        {"id":"tls-uds","path_prefix":"/tls","backends":["https://logical.invalid"],"upstream":{"unix_socket":tls_socket,"tls":{"server_name":"relay.example","ca_file":ca}}}
    ]})).unwrap();
    let (address, _, gateway_task) = gateway(config).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (path, expected_sni) in [("plain", ""), ("tls", "relay.example")] {
        let result: serde_json::Value = client
            .get(format!("http://{address}/{path}"))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            result["host"]
                .as_str()
                .or_else(|| result["authority"].as_str()),
            Some("logical.invalid")
        );
        assert_eq!(result["sni"], expected_sni);
        assert_eq!(result["path"], format!("/{path}"));
    }
    gateway_task.abort();
    plain_server.abort();
    tls_server.abort();
}
#[tokio::test]
async fn dial_host_sni_and_verification_are_independent_and_reload_isolates_pools() {
    let pair = rcgen::generate_simple_self_signed(vec!["foo.bar".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.pem");
    std::fs::write(&ca, pair.cert.pem()).unwrap();
    let tls = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let (backend, bt) = origin(Some(tls)).await;
    let config:Config=serde_json::from_value(serde_json::json!({"http":[
        {"id":"verified","path_prefix":"/verified","backends":["https://logical.invalid"],"upstream_host":"http.name","upstream":{"connect_address":backend.to_string(),"tls":{"server_name":"foo.bar","ca_file":ca,"max_fragment_size":128}}},
        {"id":"insecure","path_prefix":"/insecure","backends":["https://logical.invalid"],"upstream":{"connect_address":backend.to_string(),"tls":{"server_name":"foo.bar","insecure_skip_verify":true}}},
        {"id":"strict","path_prefix":"/strict","backends":["https://logical.invalid"],"upstream":{"connect_address":backend.to_string(),"tls":{"server_name":"foo.bar"}}},
        {"id":"wrong-name","path_prefix":"/wrong-name","backends":["https://logical.invalid"],"upstream":{"connect_address":backend.to_string(),"tls":{"server_name":"wrong.name","ca_file":ca}}}
    ]})).unwrap();
    let (addr, active, gt) = gateway(config.clone()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let result: serde_json::Value = client
        .get(format!("http://{addr}/verified"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["sni"], "foo.bar");
    assert_eq!(result["authority"], "http.name");
    assert_eq!(result["version"], "HTTP/2.0");
    assert_eq!(
        client
            .get(format!("http://{addr}/insecure"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    for path in ["strict", "wrong-name"] {
        assert_eq!(
            client
                .get(format!("http://{addr}/{path}"))
                .send()
                .await
                .unwrap()
                .status(),
            502
        );
    }
    let results = futures_util::future::join_all(
        (0..64).map(|_| client.get(format!("http://{addr}/verified")).send()),
    )
    .await;
    assert!(
        results
            .iter()
            .all(|r| r.as_ref().is_ok_and(|r| r.status() == 200))
    );
    // Existing insecure pool must not survive into a newly strict route generation.
    let mut next = config;
    next.http[1]
        .upstream
        .tls
        .as_mut()
        .unwrap()
        .insecure_skip_verify = false;
    let old = active.load_full();
    active.store(Arc::new(Snapshot::replace(next, &old).unwrap()));
    assert_eq!(
        client
            .get(format!("http://{addr}/insecure"))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    gt.abort();
    bt.abort();
}
#[tokio::test]
async fn fixed_and_preserved_http_host_do_not_change_the_socket_destination() {
    let (backend, bt) = origin(None).await;
    let config=serde_json::from_value(serde_json::json!({"http":[
        {"id":"fixed","path_prefix":"/fixed","backends":[format!("http://{backend}")],"upstream_host":"foo.bar:8080"},
        {"id":"preserve","path_prefix":"/preserve","backends":[format!("http://{backend}")],"preserve_host":true}
    ]})).unwrap();
    let (addr, _, gt) = gateway(config).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (path, expected) in [("fixed", "foo.bar:8080"), ("preserve", "original.name")] {
        let result: serde_json::Value = client
            .get(format!("http://{addr}/{path}"))
            .header("host", "original.name")
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(result["host"], expected);
    }
    let first: serde_json::Value = client
        .get(format!("http://{addr}/preserve"))
        .header("host", "another.name")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let second: serde_json::Value = client
        .get(format!("http://{addr}/preserve"))
        .header("host", "another.name")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        first["connection"], second["connection"],
        "unbounded incoming authorities must not accumulate idle pools"
    );
    gt.abort();
    bt.abort();
}
#[test]
fn invalid_transport_config_is_rejected_before_publication() {
    for route in [
        serde_json::json!({"id":"a","backends":["http://localhost"],"upstream":{"tls":{"insecure_skip_verify":true}}}),
        serde_json::json!({"id":"a","backends":["https://localhost"],"upstream":{"tls":{"max_fragment_size":1}}}),
        serde_json::json!({"id":"a","backends":["https://localhost"],"upstream":{"tls":{"ca_file":"/nonexistent/hangang-ca.pem"}}}),
        serde_json::json!({"id":"a","backends":["http://localhost"],"upstream_host":"foo.bar","preserve_host":true}),
    ] {
        let c: Config = serde_json::from_value(serde_json::json!({"http":[route]})).unwrap();
        assert!(Snapshot::new(c).is_err());
    }
}

#[tokio::test]
async fn socks5_applies_only_to_selected_route_and_failure_never_dials_direct() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (backend, bt) = origin(None).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let socks = listener.local_addr().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    let st = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await.unwrap();
                let mut header = [0; 5];
                stream.read_exact(&mut header).await.unwrap();
                assert_eq!(&header[..4], &[5, 1, 0, 3]);
                let mut name = vec![0; header[4] as usize];
                stream.read_exact(&mut name).await.unwrap();
                let port = stream.read_u16().await.unwrap();
                tx.send((String::from_utf8(name).unwrap(), port))
                    .await
                    .unwrap();
                stream
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                    .await
                    .unwrap();
                let mut target = tokio::net::TcpStream::connect(backend).await.unwrap();
                let _ = tokio::io::copy_bidirectional(&mut stream, &mut target).await;
            });
        }
    });
    let refused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad = refused.local_addr().unwrap();
    let rt = tokio::spawn(async move {
        loop {
            let (mut s, _) = refused.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0; 3];
                s.read_exact(&mut b).await.unwrap();
                s.write_all(&[5, 255]).await.unwrap();
            });
        }
    });
    let config=serde_json::from_value(serde_json::json!({"http":[
        {"id":"via","path_prefix":"/via","backends":["http://remote-name.test:8088"],"upstream":{"socks5":{"address":socks.to_string()}}},
        {"id":"direct","path_prefix":"/direct","backends":[format!("http://{backend}")]},
        {"id":"denied","path_prefix":"/denied","backends":[format!("http://{backend}")],"upstream":{"socks5":{"address":bad.to_string()}}}
    ]})).unwrap();
    let (addr, _, gt) = gateway(config).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(
        client
            .get(format!("http://{addr}/via"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(rx.recv().await.unwrap(), ("remote-name.test".into(), 8088));
    assert_eq!(
        client
            .get(format!("http://{addr}/direct"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(format!("http://{addr}/denied"))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert!(rx.try_recv().is_err());
    gt.abort();
    bt.abort();
    st.abort();
    rt.abort();
}

#[tokio::test]
async fn host_patterns_regex_and_priority_choose_routes_and_reload_atomically() {
    let (backend, bt) = origin(None).await;
    let mut config: Config = serde_json::from_value(serde_json::json!({"http":[
        {"id":"wild","host":"*.foo.com","priority":0,"upstream_host":"wild.selected","backends":[format!("http://{backend}")]},
        {"id":"first","host":"f??.bar.com","priority":20,"upstream_host":"first.selected","backends":[format!("http://{backend}")]},
        {"id":"second","host_regex":"f[a-z]{2}[.]bar[.]com","priority":20,"upstream_host":"second.selected","backends":[format!("http://{backend}")]},
        {"id":"regex","host_regex":"api[0-9]+[.]foo[.]com","priority":10,"upstream_host":"regex.selected","backends":[format!("http://{backend}")]},
        {"id":"exact","host":"api1.foo.com","priority":5,"upstream_host":"exact.selected","backends":[format!("http://{backend}")]},
        {"id":"fallback","priority":-1,"upstream_host":"fallback.selected","backends":[format!("http://{backend}")]}
    ]})).unwrap();
    let (addr, active, gt) = gateway(config.clone()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    for (host, expected) in [
        ("api1.foo.com", "regex.selected"),
        ("a.foo.com", "wild.selected"),
        ("FOO.BAR.COM:8080", "first.selected"),
        ("fooo.bar.com", "fallback.selected"),
        ("a.b.foo.com", "fallback.selected"),
    ] {
        let result: serde_json::Value = client
            .get(format!("http://{addr}/"))
            .header("host", host)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(result["host"], expected, "{host}");
    }
    config.http[2].priority = 21;
    let old = active.load_full();
    active.store(Arc::new(Snapshot::replace(config.clone(), &old).unwrap()));
    let result: serde_json::Value = client
        .get(format!("http://{addr}/"))
        .header("host", "foo.bar.com")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(result["host"], "second.selected");
    config.http[2].host_regex = Some("foo)|(?:.*".into());
    let before = active.load_full();
    assert!(Snapshot::replace(config, &before).is_err());
    assert!(Arc::ptr_eq(&before, &active.load_full()));
    gt.abort();
    bt.abort();
}
