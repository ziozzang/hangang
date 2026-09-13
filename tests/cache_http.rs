use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};
type OriginBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;
fn full(bytes: impl Into<Bytes>) -> OriginBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}
struct Fixture {
    url: String,
    origin: Arc<AtomicUsize>,
    active: Arc<ArcSwap<Snapshot>>,
    tasks: Vec<JoinHandle<()>>,
    _dir: tempfile::TempDir,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
/// A second gateway front-end serving the same configuration through its own
/// snapshot (and therefore its own cache runtime), i.e. another fleet member.
struct Peer {
    url: String,
    active: Arc<ArcSwap<Snapshot>>,
    task: JoinHandle<()>,
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn front(active: Arc<ArcSwap<Snapshot>>) -> (String, JoinHandle<()>) {
    let proxy = Proxy::new(
        active,
        Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2)),
        Arc::new(Metrics::default()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(req, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (format!("http://{address}"), task)
}
async fn peer(config: Config) -> Peer {
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let (url, task) = front(active.clone()).await;
    Peer { url, active, task }
}
async fn fixture(disk: bool, route_extra: Value) -> Fixture {
    let origin = Arc::new(AtomicUsize::new(0));
    let count = origin.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let count = count.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let count = count.clone();
                    async move {
                        let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                        let path = request.uri().path();
                        let text = format!(
                            "{}:{}:{}",
                            n,
                            request.uri(),
                            request
                                .headers()
                                .get("x-variant")
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("none")
                        );
                        let mut response = Response::new(match path {
                            "/large" => full("x".repeat(8192)),
                            "/json" | "/private-json" => {
                                full(format!("{{\"n\":{n},\"secret\":true}}"))
                            }
                            "/slow" => {
                                let chunks = vec![b"first".as_slice(), b"last".as_slice()];
                                let stream = futures_util::stream::unfold(
                                    chunks.into_iter(),
                                    |mut chunks| async move {
                                        let data = chunks.next()?;
                                        tokio::time::sleep(Duration::from_millis(60)).await;
                                        Some((
                                            Ok::<_, std::io::Error>(Frame::data(
                                                Bytes::from_static(data),
                                            )),
                                            chunks,
                                        ))
                                    },
                                );
                                StreamBody::new(stream).boxed_unsync()
                            }
                            "/broken" => {
                                let frames = vec![
                                    Ok(Frame::data(Bytes::from_static(b"prefix"))),
                                    Err(std::io::Error::other("owned fixture truncation")),
                                ];
                                StreamBody::new(futures_util::stream::iter(frames)).boxed_unsync()
                            }
                            _ => full(text),
                        });
                        let cc = match path {
                            "/private" | "/private-json" => "private, max-age=60",
                            "/no-store" => "no-store",
                            "/no-cache" => "no-cache",
                            "/ttl" => "max-age=1",
                            _ => "public, max-age=60",
                        };
                        response
                            .headers_mut()
                            .insert("cache-control", cc.parse().unwrap());
                        // A header the document's settings may later remove.
                        response
                            .headers_mut()
                            .insert("x-internal-info", "origin-detail".parse().unwrap());
                        if path == "/cookie" {
                            response
                                .headers_mut()
                                .insert("set-cookie", "sid=secret".parse().unwrap());
                        }
                        if path == "/vary" {
                            response
                                .headers_mut()
                                .insert("vary", "x-variant".parse().unwrap());
                        }
                        if path == "/vary-star" {
                            response.headers_mut().insert("vary", "*".parse().unwrap());
                        }
                        if path == "/sse" {
                            response
                                .headers_mut()
                                .insert("content-type", "text/event-stream".parse().unwrap());
                        }
                        if path == "/partial" {
                            *response.status_mut() = hyper::StatusCode::PARTIAL_CONTENT;
                            response
                                .headers_mut()
                                .insert("content-range", "bytes 0-2/10".parse().unwrap());
                        }
                        Ok::<_, Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut settings = json!({"memory":{"max_bytes":65536,"max_entries":16,"eviction":"lru"},"max_object_bytes":4096});
    if disk {
        settings["memory"]["max_bytes"] = json!(0);
        settings["disk"] = json!({"directory":dir.path().join("cache"),"max_bytes":1048576,"max_entries":16,"eviction":"lru"});
    }
    let mut route = json!({"id":"cache","backends":[format!("http://{upstream}")],"cache":{"ttl_seconds":30,"max_ttl_seconds":60}});
    for (k, v) in route_extra.as_object().unwrap() {
        route[k] = v.clone();
    }
    let config: Config = serde_json::from_value(json!({"cache":settings,"http":[route]})).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let (url, front) = front(active.clone()).await;
    Fixture {
        url,
        origin,
        active,
        tasks: vec![task, front],
        _dir: dir,
    }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}
async fn text(c: &reqwest::Client, f: &Fixture, path: &str) -> String {
    c.get(format!("{}{path}", f.url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}
async fn published(f: &Fixture) {
    for _ in 0..200 {
        if f.active.load().cache.as_ref().unwrap().active_fills() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("cache fill did not finish")
}

#[tokio::test]
async fn memory_and_disk_hits_preserve_body_and_report_age() {
    for disk in [false, true] {
        let f = fixture(disk, json!({})).await;
        let c = client();
        let first = text(&c, &f, "/public").await;
        published(&f).await;
        let hit = c.get(format!("{}/public", f.url)).send().await.unwrap();
        assert!(
            hit.headers().contains_key("age"),
            "disk={disk} stats={:?}",
            serde_json::to_value(f.active.load().cache.as_ref().unwrap().store.stats().await)
                .unwrap()
        );
        assert_eq!(hit.text().await.unwrap(), first);
        assert_eq!(f.origin.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn sensitive_requests_and_noncacheable_responses_always_reach_origin() {
    let f = fixture(false, json!({})).await;
    let c = client();
    for path in [
        "/private",
        "/no-store",
        "/no-cache",
        "/cookie",
        "/vary-star",
        "/sse",
        "/partial",
    ] {
        let before = f.origin.load(Ordering::SeqCst);
        text(&c, &f, path).await;
        text(&c, &f, path).await;
        assert_eq!(f.origin.load(Ordering::SeqCst) - before, 2, "{path}");
    }
    for (header, value) in [
        ("authorization", "Bearer private"),
        ("cookie", "user=private"),
        ("range", "bytes=0-2"),
        ("cache-control", "no-cache"),
        ("if-none-match", "old"),
    ] {
        let before = f.origin.load(Ordering::SeqCst);
        for _ in 0..2 {
            let _ = c
                .get(format!("{}/public", f.url))
                .header(header, value)
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
        }
        assert_eq!(f.origin.load(Ordering::SeqCst) - before, 2, "{header}");
    }
}

#[tokio::test]
async fn all_request_headers_query_and_host_partition_responses() {
    let f = fixture(false, json!({})).await;
    let c = client();
    for query in ["?a=1&b=2", "?b=2&a=1"] {
        for variant in ["a", "b"] {
            for host in ["one.test", "two.test"] {
                let url = format!("{}/vary{query}", f.url);
                let first = c
                    .get(&url)
                    .header("x-variant", variant)
                    .header("host", host)
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                published(&f).await;
                let second = c
                    .get(&url)
                    .header("x-variant", variant)
                    .header("host", host)
                    .send()
                    .await
                    .unwrap()
                    .text()
                    .await
                    .unwrap();
                assert_eq!(first, second);
            }
        }
    }
    assert_eq!(f.origin.load(Ordering::SeqCst), 8);
}

#[tokio::test]
async fn oversize_and_truncated_responses_are_not_stored() {
    let f = fixture(false, json!({})).await;
    let c = client();
    assert_eq!(text(&c, &f, "/large").await.len(), 8192);
    assert_eq!(text(&c, &f, "/large").await.len(), 8192);
    for _ in 0..2 {
        if let Ok(reply) = c.get(format!("{}/broken", f.url)).send().await
            && reply.status() != reqwest::StatusCode::BAD_GATEWAY
        {
            assert!(reply.bytes().await.is_err());
        }
    }
    assert_eq!(f.origin.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn concurrent_misses_coalesce_and_purge_invalidates() {
    let f = fixture(false, json!({})).await;
    let c = client();
    let (a, b) = tokio::join!(text(&c, &f, "/slow"), text(&c, &f, "/slow"));
    assert_eq!(a, "firstlast");
    assert_eq!(a, b);
    published(&f).await;
    assert_eq!(f.origin.load(Ordering::SeqCst), 1);
    f.active
        .load_full()
        .cache
        .as_ref()
        .unwrap()
        .purge()
        .await
        .unwrap();
    assert_eq!(text(&c, &f, "/slow").await, "firstlast");
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn ttl_expiry_and_route_change_do_not_reuse_old_entries() {
    let f = fixture(false, json!({})).await;
    let c = client();
    let old = text(&c, &f, "/ttl").await;
    published(&f).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_ne!(text(&c, &f, "/ttl").await, old);
    let old = text(&c, &f, "/public").await;
    published(&f).await;
    let previous = f.active.load_full();
    let mut config = previous.config.clone();
    config.revision += 1;
    config.http[0].cache.as_mut().unwrap().ttl_seconds = 10;
    f.active
        .store(Arc::new(Snapshot::replace(config, &previous).unwrap()));
    assert_ne!(text(&c, &f, "/public").await, old);
}

#[tokio::test]
async fn native_transforms_cache_final_bytes_but_cannot_override_origin_privacy() {
    let f=fixture(false,json!({"response_transform":{"operations":[{"op":"json_remove","pointer":"/secret"}],"remove_headers":["cache-control"]}})).await;
    let c = client();
    let first = text(&c, &f, "/json").await;
    assert!(!first.contains("secret"));
    published(&f).await;
    assert_eq!(text(&c, &f, "/json").await, first);
    let before = f.origin.load(Ordering::SeqCst);
    text(&c, &f, "/private-json").await;
    text(&c, &f, "/private-json").await;
    assert_eq!(f.origin.load(Ordering::SeqCst) - before, 2);
}

#[tokio::test]
async fn lua_policy_routes_bypass_and_only_if_cached_does_not_contact_origin() {
    let f = fixture(false, json!({"lua":"hangang.set_header('x-policy','yes')"})).await;
    let c = client();
    text(&c, &f, "/public").await;
    text(&c, &f, "/public").await;
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);
    let reply = c
        .get(format!("{}/public", f.url))
        .header("cache-control", "only-if-cached")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 504);
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);
}

async fn text_at(c: &reqwest::Client, url: &str, path: &str) -> String {
    c.get(format!("{url}{path}"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap()
}
/// Installs `config` on `active` the way a poll of the shared store does:
/// rebuilt from the previous snapshot so reusable runtimes are kept.
fn install(active: &ArcSwap<Snapshot>, config: Config) {
    let previous = active.load_full();
    let next = Arc::new(Snapshot::replace(config, &previous).unwrap());
    // Publication-time side effects (generation adoption) run before the
    // snapshot becomes visible, as the manager does.
    next.activated();
    active.store(next);
}
async fn stats(active: &ArcSwap<Snapshot>) -> hangang::cache_store::CacheStats {
    active.load().cache.as_ref().unwrap().store.stats().await
}

#[tokio::test]
async fn generation_bump_invalidates_every_runtime_and_keeps_them() {
    // Two fleet members serve the same configuration through their own
    // runtimes. A local purge only reaches one of them; bumping the
    // configuration generation (what the admin purge does in shared-store
    // mode) reaches both through the ordinary configuration update, without
    // rebuilding either runtime.
    let f = fixture(false, json!({})).await;
    let other = peer(f.active.load().config.clone()).await;
    let c = client();
    let a = text(&c, &f, "/public").await;
    published(&f).await;
    let b = text_at(&c, &other.url, "/public").await;
    assert_ne!(a, b, "separate runtimes fill separately");
    assert_eq!(text(&c, &f, "/public").await, a);
    assert_eq!(text_at(&c, &other.url, "/public").await, b);
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);

    // Local purge: this member only.
    f.active
        .load_full()
        .cache
        .as_ref()
        .unwrap()
        .purge()
        .await
        .unwrap();
    let a2 = text(&c, &f, "/public").await;
    published(&f).await;
    assert_ne!(a2, a);
    assert_eq!(text_at(&c, &other.url, "/public").await, b);
    assert_eq!(f.origin.load(Ordering::SeqCst), 3);

    // Fleet purge: the same document with the next generation, applied to
    // both members as a configuration update.
    let before_a = f.active.load().cache.clone().unwrap();
    let before_b = other.active.load().cache.clone().unwrap();
    let mut bumped = f.active.load().config.clone();
    bumped.revision += 1;
    bumped.cache = Some(bumped.cache.as_ref().unwrap().bumped().unwrap());
    assert_eq!(bumped.cache.as_ref().unwrap().generation, 1);
    install(&f.active, bumped.clone());
    install(&other.active, bumped);
    for active in [&f.active, &other.active] {
        let snapshot = active.load();
        let runtime = snapshot.cache.as_ref().unwrap();
        assert_eq!(runtime.generation(), 1);
        assert_eq!(snapshot.config.cache.as_ref().unwrap().generation, 1);
        assert_eq!(stats(active).await.memory_entries, 0);
    }
    assert!(Arc::ptr_eq(
        &before_a,
        f.active.load().cache.as_ref().unwrap()
    ));
    assert!(Arc::ptr_eq(
        &before_b,
        other.active.load().cache.as_ref().unwrap()
    ));
    assert_ne!(text(&c, &f, "/public").await, a2);
    assert_ne!(text_at(&c, &other.url, "/public").await, b);
    assert_eq!(f.origin.load(Ordering::SeqCst), 5);
    published(&f).await;
    // The new generation caches normally.
    let before = f.origin.load(Ordering::SeqCst);
    text(&c, &f, "/public").await;
    assert_eq!(f.origin.load(Ordering::SeqCst), before);

    // Any other cache change still builds a fresh runtime.
    let mut retuned = f.active.load().config.clone();
    retuned.revision += 1;
    retuned.cache.as_mut().unwrap().max_fills += 1;
    install(&f.active, retuned);
    assert!(!Arc::ptr_eq(
        &before_a,
        f.active.load().cache.as_ref().unwrap()
    ));
    assert_eq!(f.active.load().cache.as_ref().unwrap().generation(), 1);
}

#[tokio::test]
async fn route_rollback_after_a_generation_bump_cannot_reach_pre_bump_entries() {
    let f = fixture(false, json!({})).await;
    let c = client();
    let first = text(&c, &f, "/public").await;
    published(&f).await;
    let change_ttl = |config: &mut Config, ttl: u64| {
        config.revision += 1;
        config.http[0].cache.as_mut().unwrap().ttl_seconds = ttl;
    };
    // Editing the route moves it to another key namespace; reverting the
    // edit alone restores the previous namespace and its still-fresh entry.
    // That is not an invalidation: the route is byte-identical to the one the
    // entry was stored under.
    let mut edited = f.active.load().config.clone();
    change_ttl(&mut edited, 10);
    install(&f.active, edited);
    let second = text(&c, &f, "/public").await;
    published(&f).await;
    assert_ne!(second, first);
    let mut reverted = f.active.load().config.clone();
    change_ttl(&mut reverted, 30);
    install(&f.active, reverted);
    assert_eq!(text(&c, &f, "/public").await, first);
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);

    // After a generation bump the pre-bump entry must stay unreachable even
    // when the route is rolled back to the exact form it was stored under.
    let mut edited = f.active.load().config.clone();
    change_ttl(&mut edited, 10);
    edited.cache = Some(edited.cache.as_ref().unwrap().bumped().unwrap());
    install(&f.active, edited);
    let third = text(&c, &f, "/public").await;
    published(&f).await;
    assert_ne!(third, first);
    assert_ne!(third, second);
    let mut reverted = f.active.load().config.clone();
    change_ttl(&mut reverted, 30);
    install(&f.active, reverted);
    let fourth = text(&c, &f, "/public").await;
    assert_ne!(
        fourth, first,
        "pre-bump entry resurrected by route rollback"
    );
    assert_ne!(fourth, second);
    assert_eq!(f.origin.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn generation_bump_reclaims_disk_rows_and_a_restart_keeps_the_generation() {
    let f = fixture(true, json!({})).await;
    let c = client();
    let first = text(&c, &f, "/public").await;
    published(&f).await;
    assert_eq!(text(&c, &f, "/public").await, first);
    assert_eq!(stats(&f.active).await.disk_entries, 1);
    let runtime = f.active.load().cache.clone().unwrap();
    let mut bumped = f.active.load().config.clone();
    bumped.revision += 1;
    bumped.cache = Some(bumped.cache.as_ref().unwrap().bumped().unwrap());
    install(&f.active, bumped.clone());
    assert!(Arc::ptr_eq(
        &runtime,
        f.active.load().cache.as_ref().unwrap()
    ));
    assert_eq!(stats(&f.active).await.disk_entries, 0);
    let second = text(&c, &f, "/public").await;
    published(&f).await;
    assert_ne!(second, first);
    assert_eq!(stats(&f.active).await.disk_entries, 1);
    assert_eq!(stats(&f.active).await.errors, 0);

    // A restart under the bumped configuration reopens the same database and
    // keeps the entry written after the bump.
    drop(runtime);
    let previous = f.active.load_full();
    f.active
        .store(Arc::new(Snapshot::new(previous.config.clone()).unwrap()));
    drop(previous);
    assert_eq!(text(&c, &f, "/public").await, second);
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);
    assert_eq!(stats(&f.active).await.errors, 0);
}

#[tokio::test]
async fn global_header_removals_are_part_of_the_cache_identity() {
    // Entries are captured after the document's header rules ran; changing
    // the global removals in either direction moves to a fresh namespace, so
    // a hit never exposes a header the current rules remove, and relaxing the
    // rules brings the header back (by refilling) instead of serving the
    // stripped copy.
    let f = fixture(false, json!({})).await;
    let c = client();
    let first = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert_eq!(first.headers()["x-internal-info"], "origin-detail");
    published(&f).await;
    let hit = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert_eq!(hit.headers()["x-internal-info"], "origin-detail");
    assert_eq!(f.origin.load(Ordering::SeqCst), 1);

    let mut stricter = f.active.load().config.clone();
    stricter.revision += 1;
    stricter.settings.remove_response_headers = Some(vec!["x-internal-info".into()]);
    install(&f.active, stricter);
    let refilled = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert!(!refilled.headers().contains_key("x-internal-info"));
    assert_eq!(
        f.origin.load(Ordering::SeqCst),
        2,
        "new rules: new namespace"
    );
    published(&f).await;
    let hit = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert!(!hit.headers().contains_key("x-internal-info"));
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);

    // Relaxing the rule again must not serve the stripped copy: the original
    // namespace (captured with the header) is still fresh and serves instead.
    let mut relaxed = f.active.load().config.clone();
    relaxed.revision += 1;
    relaxed.settings.remove_response_headers = None;
    install(&f.active, relaxed);
    let back = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert_eq!(back.headers()["x-internal-info"], "origin-detail");
    assert_eq!(f.origin.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn cache_hits_keep_transform_set_headers_over_route_rules() {
    // A buffered response transform runs after the route's header rules on a
    // miss; the cached entry holds the transformed headers and a hit must not
    // re-apply route rules over them.
    let f = fixture(
        false,
        json!({
            "response_set_headers": {"content-type": "text/html"},
            "response_transform": {"mode": "buffered", "set_headers": {"content-type": "application/json"}}
        }),
    )
    .await;
    let c = client();
    let miss = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert_eq!(miss.headers()["content-type"], "application/json");
    published(&f).await;
    let hit = c.get(format!("{}/public", f.url)).send().await.unwrap();
    assert_eq!(hit.headers()["content-type"], "application/json");
    assert_eq!(f.origin.load(Ordering::SeqCst), 1);
}
