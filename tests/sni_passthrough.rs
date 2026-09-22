use arc_swap::ArcSwap;
use hangang::{
    client_hello::{SniMatch, read_client_hello},
    config::{Config, Snapshot, TcpRoute},
    metrics::Metrics,
    tcp::TcpManager,
};
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
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

// Retain real sockets until first publication. Dropping a port-zero probe
// before prepare lets another parallel fixture or outbound ephemeral socket
// claim that port. Use the existing socket-handoff API, without bind retries.
#[cfg(unix)]
static RESERVED_LISTENERS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<SocketAddr, StdTcpListener>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

fn reserve_address() -> SocketAddr {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let address = listener.local_addr().unwrap();
    #[cfg(unix)]
    assert!(
        RESERVED_LISTENERS
            .lock()
            .unwrap()
            .insert(address, listener)
            .is_none()
    );
    address
}

fn route(
    id: &str,
    listen: SocketAddr,
    backend: SocketAddr,
    hosts: &[&str],
    max_bytes: usize,
    timeout_ms: u64,
) -> TcpRoute {
    TcpRoute {
        country_policy: None,
        enabled: true,
        upstream: Default::default(),
        health: None,
        inbound_tls: None,
        id: id.to_owned(),
        priority: 0,
        sni: Some(SniMatch {
            hosts: hosts.iter().map(|host| (*host).to_owned()).collect(),
            host_regexes: Vec::new(),
            max_client_hello_bytes: max_bytes,
            hello_timeout_ms: timeout_ms,
        }),
        max_connections: None,
        listen,
        backends: vec![backend.to_string().into()],
        deny_cidrs: Vec::new(),
    }
}

fn regex_route(
    id: &str,
    listen: SocketAddr,
    backend: SocketAddr,
    patterns: &[&str],
    priority: i32,
) -> TcpRoute {
    let mut route = route(id, listen, backend, &[], 4096, 1000);
    route.priority = priority;
    route.sni.as_mut().unwrap().host_regexes = patterns
        .iter()
        .map(|pattern| (*pattern).to_owned())
        .collect();
    route
}

fn config(routes: Vec<TcpRoute>) -> Config {
    Config {
        geoip_database: None,
        revision: 0,
        cache: None,
        certificates: Vec::new(),
        http: Vec::new(),
        tcp: routes,
        workload_http: Vec::new(),
        udp: Vec::new(),
        public_http: Vec::new(),
        settings: Default::default(),
        cache_generation_floor: 0,
    }
}

fn manager() -> (Arc<ArcSwap<Snapshot>>, Arc<Metrics>, TcpManager) {
    manager_with_limit(32)
}

fn manager_with_limit(
    max_connections: usize,
) -> (Arc<ArcSwap<Snapshot>>, Arc<Metrics>, TcpManager) {
    let active = Arc::new(ArcSwap::from_pointee(
        Snapshot::new(Config::default()).unwrap(),
    ));
    let metrics = Arc::new(Metrics::default());
    let manager = TcpManager::new(active.clone(), metrics.clone(), max_connections);
    (active, metrics, manager)
}

async fn publish(manager: &TcpManager, active: &Arc<ArcSwap<Snapshot>>, next: Config) {
    #[cfg(unix)]
    let prepared = if active.load().config.tcp.is_empty() {
        let inherited = {
            let mut reserved = RESERVED_LISTENERS.lock().unwrap();
            next.tcp
                .iter()
                .filter(|route| route.enabled)
                .map(|route| route.listen)
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .map(|address| {
                    let listener = reserved
                        .remove(&address)
                        .expect("owned listener reservation");
                    (address, std::os::fd::OwnedFd::from(listener))
                })
                .collect()
        };
        manager
            .prepare_with_inherited(&next, inherited)
            .await
            .unwrap()
    } else {
        manager.prepare(&next).await.unwrap()
    };
    #[cfg(not(unix))]
    let prepared = manager.prepare(&next).await.unwrap();
    let snapshot = Snapshot::replace(next, &active.load_full()).unwrap();
    active.store(Arc::new(snapshot));
    manager.commit(prepared).await;
}

async fn spawn_tls_backend(
    hostname: &str,
    tag: u8,
) -> (
    SocketAddr,
    rcgen::CertifiedKey<rcgen::KeyPair>,
    JoinHandle<()>,
) {
    spawn_tls_backend_names(&[hostname], tag).await
}

async fn spawn_tls_backend_names(
    hostnames: &[&str],
    tag: u8,
) -> (
    SocketAddr,
    rcgen::CertifiedKey<rcgen::KeyPair>,
    JoinHandle<()>,
) {
    let pair = rcgen::generate_simple_self_signed(
        hostnames
            .iter()
            .map(|hostname| (*hostname).to_owned())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let tls = hangang::tls::server_config(
        pair.cert.pem().as_bytes(),
        pair.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut stream) = acceptor.accept(stream).await {
                    let _ = stream.write_all(&[tag]).await;
                    let _ = stream.shutdown().await;
                }
            });
        }
    });
    (address, pair, task)
}

fn tls_connector(pairs: &[&rcgen::CertifiedKey<rcgen::KeyPair>]) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    for pair in pairs {
        roots.add(pair.cert.der().clone()).unwrap();
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

async fn tls_tag(
    connector: &tokio_rustls::TlsConnector,
    address: SocketAddr,
    hostname: &str,
) -> u8 {
    let stream = TcpStream::connect(address).await.unwrap();
    let mut stream = connector
        .connect(hostname.to_owned().try_into().unwrap(), stream)
        .await
        .unwrap();
    let mut tag = [0];
    stream.read_exact(&mut tag).await.unwrap();
    tag[0]
}

#[tokio::test]
async fn real_tls_routes_exact_before_one_label_wildcard() {
    let (exact_backend, exact_pair, exact_task) = spawn_tls_backend("api.example.test", b'E').await;
    let (wild_backend, wild_pair, wild_task) = spawn_tls_backend("*.example.test", b'W').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    // Put the wildcard first to prove an exact match still has priority.
    publish(
        &manager,
        &active,
        config(vec![
            route(
                "wildcard",
                listen,
                wild_backend,
                &["*.example.test"],
                65_536,
                3_000,
            ),
            route(
                "exact",
                listen,
                exact_backend,
                &["api.example.test"],
                65_536,
                3_000,
            ),
        ]),
    )
    .await;
    let connector = tls_connector(&[&exact_pair, &wild_pair]);
    assert_eq!(tls_tag(&connector, listen, "api.example.test").await, b'E');
    assert_eq!(tls_tag(&connector, listen, "web.example.test").await, b'W');

    manager.shutdown(Duration::from_secs(1)).await;
    exact_task.abort();
    wild_task.abort();
}

#[tokio::test]
async fn real_tls_routes_question_and_leading_star_patterns() {
    let (question_backend, question_pair, question_task) =
        spawn_tls_backend_names(&["foo.bar.com", "fab.bar.com"], b'Q').await;
    let (star_backend, star_pair, star_task) = spawn_tls_backend("*.foo.com", b'W').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    publish(
        &manager,
        &active,
        config(vec![
            route(
                "question",
                listen,
                question_backend,
                &["f??.bar.com"],
                65_536,
                3_000,
            ),
            route("star", listen, star_backend, &["*.foo.com"], 65_536, 3_000),
        ]),
    )
    .await;
    let connector = tls_connector(&[&question_pair, &star_pair]);
    assert_eq!(tls_tag(&connector, listen, "foo.bar.com").await, b'Q');
    assert_eq!(tls_tag(&connector, listen, "fab.bar.com").await, b'Q');
    assert_eq!(tls_tag(&connector, listen, "api.foo.com").await, b'W');

    let unknown = TcpStream::connect(listen).await.unwrap();
    let rejected = tokio::time::timeout(
        Duration::from_secs(1),
        connector.connect("unknown.test".to_owned().try_into().unwrap(), unknown),
    )
    .await
    .expect("unknown glob SNI remained open");
    assert!(rejected.is_err());

    manager.shutdown(Duration::from_secs(1)).await;
    question_task.abort();
    star_task.abort();
}

fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut extensions = Vec::new();
    extensions.extend_from_slice(&0_u16.to_be_bytes());
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[11; 32]);
    body.push(0);
    body.extend_from_slice(&2_u16.to_be_bytes());
    body.extend_from_slice(&0x1301_u16.to_be_bytes());
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    let length = body.len();
    let mut handshake = vec![
        1,
        ((length >> 16) & 0xff) as u8,
        ((length >> 8) & 0xff) as u8,
        (length & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn fragmented_client_hello(host: &str) -> Vec<u8> {
    let original = client_hello(host);
    let handshake = &original[5..];
    let split = 13;
    let mut records = vec![22, 3, 1];
    records.extend_from_slice(&(split as u16).to_be_bytes());
    records.extend_from_slice(&handshake[..split]);
    records.extend_from_slice(&[22, 3, 3]);
    records.extend_from_slice(&((handshake.len() - split) as u16).to_be_bytes());
    records.extend_from_slice(&handshake[split..]);
    records
}

async fn hello_tag(address: SocketAddr, hostname: &str) -> u8 {
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(&client_hello(hostname)).await.unwrap();
    let mut tag = [0];
    stream.read_exact(&mut tag).await.unwrap();
    tag[0]
}

#[tokio::test]
async fn exact_then_simple_wildcard_then_ordered_glob_precedence() {
    let (general_backend, general_task) = spawn_immediate_backend(b'G').await;
    let (second_backend, second_task) = spawn_immediate_backend(b'B').await;
    let (wildcard_backend, wildcard_task) = spawn_immediate_backend(b'W').await;
    let (exact_backend, exact_task) = spawn_immediate_backend(b'E').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    // General globs come first to prove the indexed exact and simple wildcard
    // classes have priority. The two overlap globs retain configuration order.
    publish(
        &manager,
        &active,
        config(vec![
            route(
                "general",
                listen,
                general_backend,
                &["f*.exact.com", "f??.wild.com", "f*.overlap.com"],
                4096,
                1000,
            ),
            route(
                "second",
                listen,
                second_backend,
                &["*b.overlap.com"],
                4096,
                1000,
            ),
            route(
                "wildcard",
                listen,
                wildcard_backend,
                &["*.wild.com"],
                4096,
                1000,
            ),
            route(
                "exact",
                listen,
                exact_backend,
                &["fab.exact.com"],
                4096,
                1000,
            ),
        ]),
    )
    .await;

    assert_eq!(hello_tag(listen, "fab.exact.com").await, b'E');
    assert_eq!(hello_tag(listen, "foo.wild.com").await, b'W');
    assert_eq!(hello_tag(listen, "fob.overlap.com").await, b'G');

    manager.shutdown(Duration::from_secs(1)).await;
    general_task.abort();
    second_task.abort();
    wildcard_task.abort();
    exact_task.abort();
}

#[tokio::test]
async fn priority_precedes_match_class_and_regex_ties_keep_config_order() {
    let (exact_backend, exact_task) = spawn_immediate_backend(b'E').await;
    let (regex_backend, regex_task) = spawn_immediate_backend(b'R').await;
    let (first_backend, first_task) = spawn_immediate_backend(b'A').await;
    let (second_backend, second_task) = spawn_immediate_backend(b'B').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();

    let mut lower_exact = route(
        "lower-exact",
        listen,
        exact_backend,
        &["higher.test"],
        4096,
        1000,
    );
    lower_exact.priority = 1;
    let higher_regex = regex_route(
        "higher-regex",
        listen,
        regex_backend,
        &[r"higher[.]test"],
        2,
    );
    let same_regex = regex_route("same-regex", listen, regex_backend, &[r"same[.]test"], 3);
    let mut same_exact = route(
        "same-exact",
        listen,
        exact_backend,
        &["same.test"],
        4096,
        1000,
    );
    same_exact.priority = 3;
    let first_regex = regex_route("first-regex", listen, first_backend, &[r"tie[.]test"], 4);
    let second_regex = regex_route("second-regex", listen, second_backend, &[r"tie\.test"], 4);
    publish(
        &manager,
        &active,
        config(vec![
            lower_exact,
            higher_regex,
            same_regex,
            same_exact,
            first_regex,
            second_regex,
        ]),
    )
    .await;

    assert_eq!(hello_tag(listen, "higher.test").await, b'R');
    assert_eq!(hello_tag(listen, "same.test").await, b'E');
    assert_eq!(hello_tag(listen, "tie.test").await, b'A');

    manager.shutdown(Duration::from_secs(1)).await;
    exact_task.abort();
    regex_task.abort();
    first_task.abort();
    second_task.abort();
}

async fn spawn_capture_backend(expected: Vec<u8>) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        stream.write_all(b"F").await.unwrap();
    });
    (address, task)
}

#[tokio::test]
async fn fragmented_records_and_tcp_writes_are_forwarded_byte_for_byte() {
    let hello = fragmented_client_hello("fragment.example.test");
    let (backend, backend_task) = spawn_capture_backend(hello.clone()).await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    publish(
        &manager,
        &active,
        config(vec![route(
            "fragment",
            listen,
            backend,
            &["fragment.example.test"],
            1024,
            1000,
        )]),
    )
    .await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    for piece in hello.chunks(3) {
        client.write_all(piece).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut tag = [0];
    client.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag, [b'F']);

    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.await.unwrap();
}

#[tokio::test]
async fn fragmented_client_hello_routes_through_general_glob_unchanged() {
    let hello = fragmented_client_hello("fzz.fragment.com");
    let (backend, backend_task) = spawn_capture_backend(hello.clone()).await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    publish(
        &manager,
        &active,
        config(vec![route(
            "fragment-glob",
            listen,
            backend,
            &["f??.fragment.com"],
            1024,
            1000,
        )]),
    )
    .await;
    let mut client = TcpStream::connect(listen).await.unwrap();
    for piece in hello.chunks(2) {
        client.write_all(piece).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut tag = [0];
    client.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag, [b'F']);

    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.await.unwrap();
}

async fn assert_closed(mut stream: TcpStream) {
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .expect("rejected SNI connection remained open");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected data: {result:?}"
    );
}

async fn spawn_immediate_backend(tag: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = stream.write_all(&[tag]).await;
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn listener_wide_cidr_denial_precedes_hello_and_global_admission() {
    let denied_listen = reserve_address();
    let mut allowed_listen = reserve_address();
    while allowed_listen == denied_listen {
        allowed_listen = reserve_address();
    }
    let (allowed_backend, backend_task) = spawn_immediate_backend(b'P').await;
    let mut denied_exact = route(
        "denied-exact",
        denied_listen,
        allowed_backend,
        &["one.denied.test"],
        4096,
        1000,
    );
    denied_exact.deny_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    let mut denied_wildcard = route(
        "denied-wildcard",
        denied_listen,
        allowed_backend,
        &["*.denied.test"],
        4096,
        1000,
    );
    denied_wildcard.deny_cidrs = vec!["127.0.0.0/8".parse().unwrap()];
    let allowed = TcpRoute {
        country_policy: None,
        enabled: true,
        upstream: Default::default(),
        health: None,
        inbound_tls: None,
        id: "allowed-legacy".into(),
        priority: 0,
        sni: None,
        max_connections: None,
        listen: allowed_listen,
        backends: vec![allowed_backend.to_string().into()],
        deny_cidrs: Vec::new(),
    };
    let (active, metrics, manager) = manager_with_limit(1);
    publish(
        &manager,
        &active,
        config(vec![denied_exact, denied_wildcard, allowed]),
    )
    .await;

    // Send no bytes. Without the listener-wide precheck this connection would
    // hold the only global permit in ClientHello inspection for one second.
    let denied = TcpStream::connect(denied_listen).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let mut permitted = TcpStream::connect(allowed_listen).await.unwrap();
    let mut tag = [0];
    tokio::time::timeout(Duration::from_millis(250), permitted.read_exact(&mut tag))
        .await
        .expect("denied SNI peer consumed global admission")
        .unwrap();
    assert_eq!(tag, [b'P']);
    assert_closed(denied).await;
    assert!(metrics.rejected_connections.load(Ordering::Relaxed) >= 1);

    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

#[tokio::test]
async fn oversized_missing_unknown_and_timed_out_sni_never_reach_backend() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let accepts = Arc::new(AtomicUsize::new(0));
    let backend_task = tokio::spawn({
        let accepts = accepts.clone();
        async move {
            while let Ok((_stream, _)) = backend.accept().await {
                accepts.fetch_add(1, Ordering::Relaxed);
            }
        }
    });
    let listen = reserve_address();
    let (active, metrics, manager) = manager();
    publish(
        &manager,
        &active,
        config(vec![route(
            "bounded",
            listen,
            backend_address,
            &["known.example.test"],
            4096,
            30,
        )]),
    )
    .await;

    let mut oversized = TcpStream::connect(listen).await.unwrap();
    oversized.write_all(&[22, 3, 1, 32, 0]).await.unwrap();
    assert_closed(oversized).await;

    let mut too_many_records = TcpStream::connect(listen).await.unwrap();
    let prefix = [1, 0, 3, 232];
    let mut records = Vec::new();
    for index in 0..=256 {
        records.extend_from_slice(&[22, 3, 1, 0, 1]);
        records.push(prefix.get(index).copied().unwrap_or(0));
    }
    too_many_records.write_all(&records).await.unwrap();
    assert_closed(too_many_records).await;

    let mut missing = TcpStream::connect(listen).await.unwrap();
    let mut no_sni = client_hello("ignored.example.test");
    // Change server_name(0) to max_fragment_length(1); its body remains opaque here.
    no_sni[52..54].copy_from_slice(&1_u16.to_be_bytes());
    missing.write_all(&no_sni).await.unwrap();
    assert_closed(missing).await;

    let mut unknown = TcpStream::connect(listen).await.unwrap();
    unknown
        .write_all(&client_hello("unknown.example.test"))
        .await
        .unwrap();
    assert_closed(unknown).await;

    let timed_out = TcpStream::connect(listen).await.unwrap();
    assert_closed(timed_out).await;

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(accepts.load(Ordering::Relaxed), 0);
    assert!(metrics.rejected_connections.load(Ordering::Relaxed) >= 5);
    manager.shutdown(Duration::from_secs(1)).await;
    backend_task.abort();
}

async fn spawn_raw_tagged_backend(tag: u8) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                if read_client_hello(&mut stream, 4096).await.is_err() {
                    return;
                }
                if stream.write_all(&[tag]).await.is_err() {
                    return;
                }
                let mut buffer = [0; 128];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(amount) => {
                            if stream.write_all(&buffer[..amount]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (address, task)
}

#[tokio::test]
async fn reload_changes_new_sni_connections_and_drains_existing_streams() {
    let (backend_a, task_a) = spawn_raw_tagged_backend(b'A').await;
    let (backend_b, task_b) = spawn_raw_tagged_backend(b'B').await;
    let listen = reserve_address();
    let (active, _metrics, manager) = manager();
    let make = |backend| {
        config(vec![route(
            "reload",
            listen,
            backend,
            &["reload.example.test"],
            4096,
            1000,
        )])
    };
    publish(&manager, &active, make(backend_a)).await;
    let hello = client_hello("reload.example.test");
    let mut established = TcpStream::connect(listen).await.unwrap();
    established.write_all(&hello).await.unwrap();
    let mut tag = [0];
    established.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag, [b'A']);

    let mut next = make(backend_b);
    next.revision = 1;
    publish(&manager, &active, next).await;
    let mut fresh = TcpStream::connect(listen).await.unwrap();
    fresh.write_all(&hello).await.unwrap();
    fresh.read_exact(&mut tag).await.unwrap();
    assert_eq!(tag, [b'B']);

    established.write_all(b"old").await.unwrap();
    let mut echoed = [0; 3];
    established.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"old");

    manager.shutdown(Duration::from_secs(1)).await;
    task_a.abort();
    task_b.abort();
}

#[tokio::test]
async fn disabling_one_sni_route_preserves_shared_listener_and_reactivation() {
    let (a, pair_a, task_a) = spawn_tls_backend("a.example.test", b'A').await;
    let (b, pair_b, task_b) = spawn_tls_backend("b.example.test", b'B').await;
    let listen = reserve_address();
    let (active, _, manager) = manager();
    let mut first = route("a", listen, a, &["a.example.test"], 4096, 1000);
    let second = route("b", listen, b, &["b.example.test"], 4096, 1000);
    let connector = tls_connector(&[&pair_a, &pair_b]);
    for enabled in [true, false, true] {
        first.enabled = enabled;
        publish(
            &manager,
            &active,
            config(vec![first.clone(), second.clone()]),
        )
        .await;
        assert_eq!(tls_tag(&connector, listen, "b.example.test").await, b'B');
        if enabled {
            assert_eq!(tls_tag(&connector, listen, "a.example.test").await, b'A');
        } else {
            let socket = TcpStream::connect(listen).await.unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                connector.connect("a.example.test".to_owned().try_into().unwrap(), socket),
            )
            .await
            .unwrap();
            assert!(result.is_err());
        }
    }
    manager.shutdown(Duration::from_secs(1)).await;
    task_a.abort();
    task_b.abort();
}
