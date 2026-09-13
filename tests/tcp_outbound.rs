use arc_swap::ArcSwap;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    tcp::TcpManager,
};
use serde_json::{Value, json};
use std::{
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
};

fn reserve_address() -> SocketAddr {
    StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
}

fn config(listen: SocketAddr, backend: impl Into<String>, upstream: Value) -> Config {
    serde_json::from_value(json!({
        "tcp": [{
            "id": "outbound",
            "listen": listen,
            "backends": [backend.into()],
            "upstream": upstream
        }]
    }))
    .unwrap()
}

fn manager() -> (Arc<ArcSwap<Snapshot>>, Arc<Metrics>, TcpManager) {
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active.clone(), metrics.clone(), 32);
    (active, metrics, manager)
}

async fn publish(manager: &TcpManager, active: &Arc<ArcSwap<Snapshot>>, next: Config) {
    let prepared = manager.prepare(&next).await.unwrap();
    let snapshot = Snapshot::replace(next, &active.load_full()).unwrap();
    active.store(Arc::new(snapshot));
    manager.commit(prepared).await;
}

async fn exchange(address: SocketAddr, message: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(message).await?;
    let mut response = vec![0; message.len()];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

async fn assert_closed(address: SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"probe").await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .expect("failed outbound connection must close promptly");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected upstream bytes"
    );
}

async fn spawn_tls_echo(
    hostname: &str,
) -> (
    SocketAddr,
    rcgen::CertifiedKey<rcgen::KeyPair>,
    JoinHandle<()>,
) {
    let pair = rcgen::generate_simple_self_signed(vec![hostname.to_owned()]).unwrap();
    let server = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0; 1024];
                if let Ok(count) = stream.read(&mut buffer).await
                    && count != 0
                {
                    let _ = stream.write_all(&buffer[..count]).await;
                }
            });
        }
    });
    (address, pair, task)
}

fn write_ca(pair: &rcgen::CertifiedKey<rcgen::KeyPair>) -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    std::fs::write(&path, pair.cert.pem()).unwrap();
    (directory, path.to_string_lossy().into_owned())
}

fn tls_connector(pair: &rcgen::CertifiedKey<rcgen::KeyPair>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(pair.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn tls_verification_is_default_and_server_name_override_is_explicit() {
    let (backend, pair, backend_task) = spawn_tls_echo("backend.test").await;
    let (_ca_directory, ca_file) = write_ca(&pair);
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    publish(
        &manager,
        &active,
        config(
            listen,
            "wrong-name.test:443",
            json!({
                "connect_address": backend.to_string(),
                "tls": {"ca_file": ca_file}
            }),
        ),
    )
    .await;
    assert_closed(listen).await;

    publish(
        &manager,
        &active,
        config(
            listen,
            "wrong-name.test:443",
            json!({
                "connect_address": backend.to_string(),
                "tls": {"ca_file": ca_file, "server_name": "backend.test"}
            }),
        ),
    )
    .await;
    assert_eq!(exchange(listen, b"verified").await.unwrap(), b"verified");

    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn insecure_tls_requires_the_explicit_route_option() {
    let (backend, _pair, backend_task) = spawn_tls_echo("untrusted.test").await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    publish(
        &manager,
        &active,
        config(
            listen,
            "different.test:443",
            json!({
                "connect_address": backend.to_string(),
                "tls": {"insecure_skip_verify": true}
            }),
        ),
    )
    .await;
    assert_eq!(exchange(listen, b"insecure").await.unwrap(), b"insecure");

    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

async fn spawn_double_tls_echo() -> (
    SocketAddr,
    rcgen::CertifiedKey<rcgen::KeyPair>,
    rcgen::CertifiedKey<rcgen::KeyPair>,
    JoinHandle<()>,
) {
    let outer_pair = rcgen::generate_simple_self_signed(vec!["outer.test".into()]).unwrap();
    let inner_pair = rcgen::generate_simple_self_signed(vec!["inner.test".into()]).unwrap();
    let outer = hangang::tls::server_config(
        outer_pair.cert.pem().as_bytes(),
        outer_pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let inner = hangang::tls::server_config(
        inner_pair.cert.pem().as_bytes(),
        inner_pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let outer_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(outer));
    let inner_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(inner));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let outer_acceptor = outer_acceptor.clone();
            let inner_acceptor = inner_acceptor.clone();
            tokio::spawn(async move {
                let Ok(outer) = outer_acceptor.accept(stream).await else {
                    return;
                };
                let Ok(mut inner) = inner_acceptor.accept(outer).await else {
                    return;
                };
                let mut buffer = [0; 1024];
                if let Ok(count) = inner.read(&mut buffer).await
                    && count != 0
                {
                    let _ = inner.write_all(&buffer[..count]).await;
                }
            });
        }
    });
    (address, outer_pair, inner_pair, task)
}

#[tokio::test]
async fn sni_passthrough_can_explicitly_use_an_outer_tls_session() {
    let (backend, outer_pair, inner_pair, backend_task) = spawn_double_tls_echo().await;
    let (_outer_ca_directory, outer_ca) = write_ca(&outer_pair);
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    let next: Config = serde_json::from_value(json!({
        "tcp": [{
            "id": "outbound",
            "listen": listen,
            "backends": ["outer.test:443"],
            "sni": {"hosts": ["inner.test"]},
            "upstream": {
                "connect_address": backend.to_string(),
                "tls": {"ca_file": outer_ca}
            }
        }]
    }))
    .unwrap();
    publish(&manager, &active, next).await;

    let stream = TcpStream::connect(listen).await.unwrap();
    let mut stream = tls_connector(&inner_pair)
        .connect("inner.test".to_owned().try_into().unwrap(), stream)
        .await
        .unwrap();
    stream.write_all(b"nested").await.unwrap();
    let mut response = [0; 6];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"nested");

    drop(stream);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

async fn spawn_plain_echo(accepted: Arc<AtomicUsize>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            accepted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(async move {
                let mut buffer = [0; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            if stream.write_all(&buffer[..count]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    (address, task)
}

async fn spawn_loopback_dns() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut packet = [0; 512];
        loop {
            let (length, peer) = socket.recv_from(&mut packet).await.unwrap();
            if length < 17 {
                continue;
            }
            let mut question_end = 12;
            while question_end < length && packet[question_end] != 0 {
                question_end += 1 + packet[question_end] as usize;
            }
            question_end += 5;
            if question_end > length {
                continue;
            }
            let query_type =
                u16::from_be_bytes([packet[question_end - 4], packet[question_end - 3]]);
            let answer_count = u8::from(query_type == 1);
            let mut response = Vec::with_capacity(question_end + 16);
            response.extend_from_slice(&packet[..2]);
            response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, answer_count, 0, 0, 0, 0]);
            response.extend_from_slice(&packet[12..question_end]);
            if query_type == 1 {
                response
                    .extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    (address, task)
}

#[tokio::test]
async fn tcp_route_uses_only_its_configured_dns_server() {
    let accepted = Arc::new(AtomicUsize::new(0));
    let (backend, backend_task) = spawn_plain_echo(accepted.clone()).await;
    let (dns, dns_task) = spawn_loopback_dns().await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    let resolved = hangang::upstream_dns::resolve("route-only.test", &[dns])
        .await
        .unwrap();
    assert_eq!(resolved, vec![std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)]);

    publish(
        &manager,
        &active,
        config(
            listen,
            format!("route-only.test:{}", backend.port()),
            json!({"dns_servers": [dns.to_string()]}),
        ),
    )
    .await;
    assert_eq!(exchange(listen, b"dns").await.unwrap(), b"dns");
    assert_eq!(accepted.load(Ordering::Relaxed), 1);

    manager.shutdown(Duration::from_secs(1)).await;
    dns_task.abort();
    backend_task.abort();
}

async fn read_socks_target(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut greeting = [0; 3];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [5, 1, 0]);
    stream.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    assert_eq!(&header[..3], &[5, 1, 0]);
    let host = match header[3] {
        1 => {
            let mut address = [0; 4];
            stream.read_exact(&mut address).await?;
            std::net::Ipv4Addr::from(address).to_string()
        }
        3 => {
            let length = stream.read_u8().await? as usize;
            let mut name = vec![0; length];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).unwrap()
        }
        4 => {
            let mut address = [0; 16];
            stream.read_exact(&mut address).await?;
            std::net::Ipv6Addr::from(address).to_string()
        }
        atyp => panic!("unexpected SOCKS address type {atyp}"),
    };
    let port = stream.read_u16().await?;
    Ok(format!("{host}:{port}"))
}

async fn spawn_socks(
    destination: Option<SocketAddr>,
) -> (SocketAddr, mpsc::UnboundedReceiver<String>, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (targets_tx, targets_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let targets_tx = targets_tx.clone();
            tokio::spawn(async move {
                let Ok(target) = read_socks_target(&mut client).await else {
                    return;
                };
                let _ = targets_tx.send(target);
                let Some(destination) = destination else {
                    let _ = client.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect(destination).await else {
                    return;
                };
                if client
                    .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                    .await
                    .is_ok()
                {
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                }
            });
        }
    });
    (address, targets_rx, task)
}

#[tokio::test]
async fn socks_routes_the_logical_target_and_never_falls_back_directly() {
    let accepted = Arc::new(AtomicUsize::new(0));
    let (backend, backend_task) = spawn_plain_echo(accepted.clone()).await;
    let (socks, mut targets, socks_task) = spawn_socks(Some(backend)).await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    publish(
        &manager,
        &active,
        config(
            listen,
            "private.service.test:5432",
            json!({"socks5": {"address": socks.to_string()}}),
        ),
    )
    .await;
    assert_eq!(exchange(listen, b"proxied").await.unwrap(), b"proxied");
    assert_eq!(targets.recv().await.unwrap(), "private.service.test:5432");

    let (rejecting_socks, mut rejected_targets, rejecting_task) = spawn_socks(None).await;
    publish(
        &manager,
        &active,
        config(
            listen,
            backend.to_string(),
            json!({"socks5": {"address": rejecting_socks.to_string()}}),
        ),
    )
    .await;
    assert_closed(listen).await;
    assert_eq!(rejected_targets.recv().await.unwrap(), backend.to_string());
    assert_eq!(
        accepted.load(Ordering::Relaxed),
        1,
        "a rejected SOCKS request must not retry the target directly"
    );

    manager.shutdown(Duration::from_secs(1)).await;
    socks_task.abort();
    rejecting_task.abort();
    backend_task.abort();
}

async fn spawn_tagged_echo(tag: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = stream.write_all(&[tag]).await;
                let mut buffer = [0; 1024];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(count) => {
                            let _ = stream.write_all(&buffer[..count]).await;
                        }
                    }
                }
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn route_reload_changes_outbound_address_without_cutting_existing_streams() {
    let (backend_a, task_a) = spawn_tagged_echo(b'A').await;
    let (backend_b, task_b) = spawn_tagged_echo(b'B').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    publish(
        &manager,
        &active,
        config(
            listen,
            "logical.service.test:9000",
            json!({"connect_address": backend_a.to_string()}),
        ),
    )
    .await;
    let mut established = TcpStream::connect(listen).await.unwrap();
    assert_eq!(established.read_u8().await.unwrap(), b'A');

    publish(
        &manager,
        &active,
        config(
            listen,
            "logical.service.test:9000",
            json!({"connect_address": backend_b.to_string()}),
        ),
    )
    .await;
    let mut fresh = TcpStream::connect(listen).await.unwrap();
    assert_eq!(fresh.read_u8().await.unwrap(), b'B');
    established.write_all(b"old").await.unwrap();
    let mut response = [0; 3];
    established.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"old");

    drop(established);
    drop(fresh);
    manager.shutdown(Duration::from_secs(1)).await;
    task_a.abort();
    task_b.abort();
}

async fn spawn_recording_relay(
    destination: SocketAddr,
) -> (
    SocketAddr,
    mpsc::UnboundedReceiver<(u8, usize)>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (records_tx, records_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(destination).await.unwrap();
        let (mut client_read, mut client_write) = client.into_split();
        let (mut server_read, mut server_write) = server.into_split();
        let inspect = async move {
            let mut pending = Vec::new();
            let mut buffer = [0; 4096];
            loop {
                let count = client_read.read(&mut buffer).await?;
                if count == 0 {
                    server_write.shutdown().await?;
                    return Ok::<_, std::io::Error>(());
                }
                pending.extend_from_slice(&buffer[..count]);
                while pending.len() >= 5 {
                    let length = u16::from_be_bytes([pending[3], pending[4]]) as usize;
                    if pending.len() < 5 + length {
                        break;
                    }
                    let _ = records_tx.send((pending[0], length));
                    pending.drain(..5 + length);
                }
                server_write.write_all(&buffer[..count]).await?;
            }
        };
        let return_path = tokio::io::copy(&mut server_read, &mut client_write);
        let _ = tokio::join!(inspect, return_path);
    });
    (address, records_rx, task)
}

#[tokio::test]
async fn tls_max_fragment_size_splits_client_hello_records_and_still_connects() {
    let (backend, pair, backend_task) = spawn_tls_echo("fragment.test").await;
    let (_ca_directory, ca_file) = write_ca(&pair);
    let (relay, mut records, relay_task) = spawn_recording_relay(backend).await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    publish(
        &manager,
        &active,
        config(
            listen,
            "fragment.test:443",
            json!({
                "connect_address": relay.to_string(),
                "tls": {"ca_file": ca_file, "max_fragment_size": 128}
            }),
        ),
    )
    .await;
    assert_eq!(
        exchange(listen, b"fragmented").await.unwrap(),
        b"fragmented"
    );

    let mut handshake_lengths = Vec::new();
    while handshake_lengths.len() < 2 {
        let (kind, length) = tokio::time::timeout(Duration::from_secs(2), records.recv())
            .await
            .unwrap()
            .unwrap();
        if kind == 22 {
            handshake_lengths.push(length);
        }
    }
    assert!(handshake_lengths.iter().all(|length| *length <= 128));

    manager.shutdown(Duration::from_secs(1)).await;
    relay_task.abort();
    backend_task.abort();
}
