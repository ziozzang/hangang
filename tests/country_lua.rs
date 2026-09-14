use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::stream;
use hangang::{
    config::{Config, Snapshot},
    geoip_runtime::{self, Published, Slot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    Request, Response, body::Frame, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use tokio_util::sync::CancellationToken;

struct Front {
    url: String,
    active: Arc<ArcSwap<Snapshot>>,
    policy: Arc<PolicyPool>,
    task: JoinHandle<()>,
}

impl Front {
    async fn close(self) {
        self.task.abort();
        self.policy.shutdown().await;
    }
}

async fn start_front(config: Config) -> Front {
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Front {
        url,
        active,
        policy,
        task,
    }
}

fn fresh_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    const MARKER: &[u8] = b"build_epoch\x04\x02";
    let offsets = bytes
        .windows(MARKER.len())
        .enumerate()
        .filter_map(|(index, part)| (part == MARKER).then_some(index + MARKER.len()))
        .collect::<Vec<_>>();
    assert_eq!(offsets.len(), 1);
    let epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3_600;
    bytes[offsets[0]..offsets[0] + 4].copy_from_slice(&u32::try_from(epoch).unwrap().to_be_bytes());
    bytes
}

fn config(file: &std::path::Path, origin: SocketAddr, trusted: bool) -> Config {
    let script = r#"
        local g = hangang.geoip()
        hangang.set_header("x-observed-state", g.state)
        hangang.set_header("x-observed-country", g.country or "-")
        hangang.set_header("x-observed-generation", g.generation_sha256 or "-")
        hangang.set_header("x-observed-error", g.error_code or "-")
    "#;
    serde_json::from_value(json!({
        "geoip_database":{"file":file,"max_age_days":1,"reload_interval_seconds":1},
        "settings":{"trusted_proxy_cidrs":if trusted { vec!["127.0.0.0/8"] } else { vec![] }},
        "http":[
            {"id":"passive","access_mode":"public","path_prefix":"/passive",
             "backends":[format!("http://{origin}")],"lua":script},
            {"id":"enforced","access_mode":"public","path_prefix":"/enforced",
             "backends":[format!("http://{origin}")],"lua":"hangang.reject(418)",
             "country_policy":{"allow":["GB"],"on_unknown":"deny"}},
            {"id":"readonly","access_mode":"public","path_prefix":"/readonly",
             "backends":[format!("http://{origin}")],
             "lua":"local g = hangang.geoip(); g.country = 'ZZ'"}
        ]
    }))
    .unwrap()
}

fn start_watcher(
    active: &Arc<ArcSwap<Snapshot>>,
) -> (Arc<Slot>, CancellationToken, JoinHandle<()>) {
    let slot = active.load().geoip.as_ref().unwrap().clone();
    let current = active.clone();
    let published: Arc<Published> = Arc::new(move |candidate| {
        current
            .load()
            .geoip
            .as_ref()
            .is_some_and(|live| Arc::ptr_eq(live, candidate))
    });
    let cancel = CancellationToken::new();
    let task = tokio::spawn(geoip_runtime::watch(
        slot.clone(),
        published,
        cancel.clone(),
    ));
    (slot, cancel, task)
}

async fn wait_for(mut condition: impl FnMut() -> bool, label: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

async fn request(client: &reqwest::Client, front: &Front, path: &str, xff: &str) -> (u16, String) {
    let response = client
        .get(format!("{}{path}", front.url))
        .header("x-forwarded-for", xff)
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.text().await.unwrap())
}

async fn echo_origin() -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let value = |name: &str| {
                        request
                            .headers()
                            .get(name)
                            .and_then(|value| value.to_str().ok())
                            .unwrap_or("-")
                            .to_owned()
                    };
                    let line = format!(
                        "{}|{}|{}|{}",
                        value("x-observed-state"),
                        value("x-observed-country"),
                        value("x-observed-generation"),
                        value("x-observed-error")
                    );
                    async move { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(line)))) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, hits, task)
}

#[tokio::test]
async fn lua_sees_trusted_known_unknown_and_passive_unavailable_without_native_bypass() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    let (origin, hits, origin_task) = echo_origin().await;
    let front = start_front(config(&file, origin, true)).await;
    let (slot, cancel, watcher) = start_watcher(&front.active);
    wait_for(|| slot.load().is_some(), "country database").await;
    let client = client();

    let (status, known) = request(&client, &front, "/passive", "81.2.69.160").await;
    assert_eq!(status, 200);
    let known: Vec<_> = known.split('|').collect();
    assert_eq!(&known[..2], &["known", "GB"]);
    assert_eq!(known[2].len(), 64);
    assert_eq!(known[3], "-");
    let (status, unknown) = request(&client, &front, "/passive", "127.0.0.1").await;
    assert_eq!(status, 200);
    assert_eq!(unknown, format!("unknown|-|{}|-", known[2]));

    // A native denial happens before the route's Lua reject(418) and origin.
    let before = hits.load(Ordering::SeqCst);
    assert_eq!(
        request(&client, &front, "/enforced", "2001:220::1").await.0,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), before);
    assert_eq!(
        request(&client, &front, "/readonly", "81.2.69.160").await.0,
        503
    );
    assert_eq!(hits.load(Ordering::SeqCst), before);
    assert_eq!(
        request(&client, &front, "/passive", "81.2.69.160").await.0,
        200
    );

    let replacement = dir.path().join("damaged.mmdb");
    std::fs::write(&replacement, b"damaged database").unwrap();
    std::fs::rename(replacement, &file).unwrap();
    wait_for(
        || slot.status().error_code == Some("invalid_database"),
        "failed database reload",
    )
    .await;
    let (status, passive) = request(&client, &front, "/passive", "81.2.69.160").await;
    assert_eq!(status, 200);
    assert_eq!(passive, "unavailable|-|-|invalid_database");
    let before = hits.load(Ordering::SeqCst);
    assert_eq!(
        request(&client, &front, "/enforced", "81.2.69.160").await.0,
        503
    );
    assert_eq!(hits.load(Ordering::SeqCst), before);

    cancel.cancel();
    watcher.await.unwrap();
    front.close().await;
    origin_task.abort();

    // An untrusted socket peer cannot fabricate a public-country observation.
    std::fs::write(&file, fresh_fixture()).unwrap();
    let (origin, _hits, origin_task) = echo_origin().await;
    let untrusted = start_front(config(&file, origin, false)).await;
    let (slot, cancel, watcher) = start_watcher(&untrusted.active);
    wait_for(|| slot.load().is_some(), "untrusted fixture database").await;
    let (status, body) = request(&client, &untrusted, "/passive", "81.2.69.160").await;
    assert_eq!(status, 200);
    assert!(body.starts_with("unknown|-|"), "{body}");
    cancel.cancel();
    watcher.await.unwrap();
    untrusted.close().await;
    origin_task.abort();
}

async fn gated_ndjson_origin() -> (SocketAddr, Arc<Notify>, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let gate = Arc::new(Notify::new());
    let requests = Arc::new(AtomicUsize::new(0));
    let task_gate = gate.clone();
    let task_requests = requests.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let gate = task_gate.clone();
            let requests = task_requests.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    let index = requests.fetch_add(1, Ordering::SeqCst);
                    let gate = gate.clone();
                    async move {
                        let records = if index == 0 {
                            vec![b"{\"n\":1}\n".to_vec(), b"{\"n\":2}\n".to_vec()]
                        } else {
                            vec![b"{\"n\":3}\n".to_vec()]
                        };
                        let stream = stream::unfold(
                            (records, 0, gate),
                            |(records, index, gate)| async move {
                                if index >= records.len() {
                                    return None;
                                }
                                if index == 1 {
                                    gate.notified().await;
                                }
                                let part = Bytes::from(records[index].clone());
                                Some((
                                    Ok::<_, Infallible>(Frame::data(part)),
                                    (records, index + 1, gate),
                                ))
                            },
                        );
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/x-ndjson")
                                .body(StreamBody::new(stream).boxed_unsync())
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, gate, requests, task)
}

fn ndjson_config(file: &std::path::Path, origin: SocketAddr) -> Config {
    serde_json::from_value(json!({
        "geoip_database":{"file":file,"max_age_days":1,"reload_interval_seconds":1},
        "settings":{"trusted_proxy_cidrs":["127.0.0.0/8"]},
        "http":[{"id":"stream","access_mode":"public","backends":[format!("http://{origin}")],
            "response_transform":{"mode":"ndjson","max_buffer_bytes":16384,
                "max_output_bytes":16384,"lua":
                "local g = hangang.geoip(); local v = hangang.json_decode(hangang.body()); v.country = g.country; v.generation = g.generation_sha256; return hangang.json_encode(v)"}}]
    })).unwrap()
}

#[tokio::test]
async fn ndjson_response_keeps_one_observation_across_database_generation_switch() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    let original = fresh_fixture();
    assert_eq!(&original[12097..12099], b"GB");
    std::fs::write(&file, &original).unwrap();
    let (origin, gate, requests, origin_task) = gated_ndjson_origin().await;
    let front = start_front(ndjson_config(&file, origin)).await;
    let (slot, cancel, watcher) = start_watcher(&front.active);
    wait_for(|| slot.load().is_some(), "first database generation").await;
    let client = client();
    let mut response = client
        .get(&front.url)
        .header("x-forwarded-for", "81.2.69.160")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let first: Value =
        serde_json::from_slice(response.chunk().await.unwrap().unwrap().trim_ascii()).unwrap();
    assert_eq!(first["n"], 1);
    assert_eq!(first["country"], "GB");
    let old_digest = first["generation"].as_str().unwrap().to_owned();
    assert_eq!(old_digest.len(), 64);

    let mut replacement = original;
    replacement[12097..12099].copy_from_slice(b"KR");
    let replacement_path = dir.path().join("replacement.mmdb");
    std::fs::write(&replacement_path, replacement).unwrap();
    std::fs::rename(replacement_path, &file).unwrap();
    wait_for(
        || {
            slot.load()
                .is_some_and(|db| db.status().generation_sha256 != old_digest)
        },
        "replacement database generation",
    )
    .await;

    gate.notify_one();
    let second: Value =
        serde_json::from_slice(response.chunk().await.unwrap().unwrap().trim_ascii()).unwrap();
    assert_eq!(second["n"], 2);
    assert_eq!(second["country"], "GB");
    assert_eq!(second["generation"], old_digest);
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    let next = client
        .get(&front.url)
        .header("x-forwarded-for", "81.2.69.160")
        .send()
        .await
        .unwrap();
    assert_eq!(next.status().as_u16(), 200);
    let third: Value = serde_json::from_slice(next.bytes().await.unwrap().trim_ascii()).unwrap();
    assert_eq!(third["n"], 3);
    assert_eq!(third["country"], "KR");
    assert_ne!(third["generation"], old_digest);

    cancel.cancel();
    watcher.await.unwrap();
    front.close().await;
    origin_task.abort();
}
