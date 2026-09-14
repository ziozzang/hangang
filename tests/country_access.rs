use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::Full;
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};

struct Fixture {
    metrics: Arc<Metrics>,
    traffic: Arc<hangang::traffic::TrafficHistory>,
    front: String,
    origin_hits: Arc<AtomicUsize>,
    active: Arc<ArcSwap<Snapshot>>,
    policy: Arc<PolicyPool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

impl Fixture {
    async fn close(self) {
        self.policy.shutdown().await;
    }
}

async fn fixture(
    route_builder: impl FnOnce(std::net::SocketAddr) -> Value,
    file: &std::path::Path,
    trusted: bool,
) -> Fixture {
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_address = origin.local_addr().unwrap();
    let origin_hits = Arc::new(AtomicUsize::new(0));
    let hits = origin_hits.clone();
    let origin_task = tokio::spawn(async move {
        while let Ok((stream, _)) = origin.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    hits.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"origin"))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let mut document = json!({"http": route_builder(origin_address), "cache": {
        "memory":{"max_bytes":65536,"max_entries":16,"eviction":"lru"},"max_object_bytes":4096
    }});
    document["geoip_database"] = json!({"file":file,"reload_interval_seconds":1});
    document["settings"] =
        json!({"trusted_proxy_cidrs": if trusted { vec!["127.0.0.0/8"] } else { vec![] }});
    let config: Config = serde_json::from_value(document).unwrap();
    let snapshot = Snapshot::new(config).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(snapshot));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let metrics = Arc::new(Metrics::default());
    let traffic = Arc::new(hangang::traffic::TrafficHistory::default());
    let proxy = Proxy::new(active.clone(), policy.clone(), metrics.clone())
        .with_traffic_history(traffic.clone());
    let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let front = format!("http://{}", front_listener.local_addr().unwrap());
    let front_task = tokio::spawn(async move {
        while let Ok((stream, peer)) = front_listener.accept().await {
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
    Fixture {
        metrics,
        traffic,
        front,
        origin_hits,
        active,
        policy,
        tasks: vec![origin_task, front_task],
    }
}

fn fresh_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    let marker = b"build_epoch";
    let offset = bytes
        .windows(marker.len())
        .rposition(|part| part == marker)
        .unwrap()
        + marker.len();
    // Synthetic fixture: extended uint64, four encoded bytes. Only the test
    // copy changes; preserve the checked-in upstream fixture and provenance.
    assert_eq!(&bytes[offset..offset + 2], &[4, 2]);
    let now: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    bytes[offset + 2..offset + 6].copy_from_slice(&now.to_be_bytes());
    bytes
}

async fn status(fixture: &Fixture, ip: &str) -> u16 {
    request_status(fixture, "/", ip, &[]).await
}

async fn request_status(fixture: &Fixture, path: &str, ip: &str, headers: &[(&str, &str)]) -> u16 {
    let mut request = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .get(format!("{}{path}", fixture.front))
        .header("x-forwarded-for", ip);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let response = request.send().await.unwrap();
    let code = response.status().as_u16();
    response.bytes().await.unwrap();
    code
}

fn start_watcher(
    fixture: &Fixture,
    slot: Arc<hangang::geoip_runtime::Slot>,
) -> (tokio_util::sync::CancellationToken, JoinHandle<()>) {
    let active = fixture.active.clone();
    let published: Arc<hangang::geoip_runtime::Published> = Arc::new(move |candidate| {
        active
            .load()
            .geoip
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, candidate))
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    let task = tokio::spawn(hangang::geoip_runtime::watch(
        slot,
        published,
        cancel.clone(),
    ));
    (cancel, task)
}

async fn wait_ready(slot: &hangang::geoip_runtime::Slot) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !slot.status().ready {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("GeoIP slot should become ready");
}

fn basic_credential() -> String {
    let salt = b"0123456789abcdef";
    let mut digest = Sha256::new();
    digest.update(salt);
    digest.update(b"secret");
    let hex = |value: &[u8]| {
        value
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!("alice:{}:{}", hex(salt), hex(&digest.finalize()))
}

#[tokio::test]
async fn observation_records_and_counters_use_the_admission_result_without_blocking_passive_errors()
{
    use hangang::country_observation::State;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    let fixture = fixture(
        |origin| {
            json!([{
                "id":"observed", "access_mode":"public", "backends":[format!("http://{origin}")],
                "country_policy":{"allow":["GB"],"on_unknown":"deny"}
            }])
        },
        &file,
        true,
    )
    .await;
    assert_eq!(status(&fixture, "81.2.69.160").await, 503);
    let slot = fixture.active.load().geoip.clone().unwrap();
    let (cancel, worker) = start_watcher(&fixture, slot.clone());
    wait_ready(&slot).await;
    let digest = slot.load().unwrap().status().generation_sha256.clone();
    assert_eq!(status(&fixture, "81.2.69.160").await, 200);
    assert_eq!(status(&fixture, "2001:220::1").await, 403);
    assert_eq!(status(&fixture, "127.0.0.1").await, 403);
    let current = fixture.active.load_full();
    let mut config = current.config.clone();
    config.http[0].country_policy = None;
    config.revision += 1;
    let next = Snapshot::replace(config, &current).unwrap();
    next.activated();
    fixture.active.store(Arc::new(next));
    std::fs::write(&file, b"invalid").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while slot.status().error_code != Some("invalid_database") {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status(&fixture, "81.2.69.160").await, 200);
    let rows = fixture.traffic.snapshot_since(None, 128).records;
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0].geoip.state, State::Unavailable);
    assert_eq!(rows[0].geoip.error_code.as_deref(), Some("pending"));
    assert_eq!(rows[1].geoip.country.as_deref(), Some("GB"));
    assert_eq!(rows[2].geoip.country.as_deref(), Some("KR"));
    assert_eq!(rows[3].geoip.state, State::Unknown);
    for row in &rows[1..4] {
        assert_eq!(
            row.geoip.generation_sha256.as_deref(),
            Some(digest.as_str())
        );
    }
    assert_eq!(rows[4].geoip.state, State::Unavailable);
    assert_eq!(
        rows[4].geoip.error_code.as_deref(),
        Some("invalid_database")
    );
    assert_eq!(
        rows[4].status, 200,
        "passive observation is not an access policy"
    );
    let counts = fixture.metrics.geoip.snapshot();
    assert_eq!(
        (
            counts.http.known,
            counts.http.unknown,
            counts.http.unavailable
        ),
        (2, 1, 2)
    );
    assert_eq!(
        (
            counts.http.allowed,
            counts.http.denied,
            counts.http.admission_unavailable
        ),
        (1, 2, 1)
    );
    assert_eq!(counts.http.countries.len(), 3);
    let text = fixture.metrics.render();
    assert!(
        text.contains("hangang_geoip_lookups_total{protocol=\"http\",result=\"unavailable\"} 2")
    );
    assert!(
        text.contains(
            "hangang_geoip_admission_total{protocol=\"http\",decision=\"unavailable\"} 1"
        )
    );
    assert!(!text.contains(&digest));
    assert!(!text.contains("81.2.69.160"));
    cancel.cancel();
    worker.await.unwrap();
    fixture.close().await;
}

fn protected_route(origin: std::net::SocketAddr, allow: &str) -> Value {
    json!({
        "id":"protected", "host":"foo.test", "path_prefix":"/secure",
        "path_match":"segment_prefix", "access_mode":"protected",
        "backends":[format!("http://{origin}")],
        "basic_auth":{"credentials":[basic_credential()]},
        "resource_policy":{"resource_id":"records", "principal":{"source":"basic"},
            "allow":[{"subjects":["alice"],"methods":["GET"]}]},
        "country_policy":{"allow":[allow],"on_unknown":"deny"}
    })
}

#[tokio::test]
async fn country_admission_uses_trusted_ip_and_fails_closed_on_database_damage() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    for trusted in [true, false] {
        let fixture = fixture(
            |origin| {
                json!([{
                    "id":"country", "access_mode":"public", "backends":[format!("http://{origin}")],
                    "cache":{"ttl_seconds":30,"max_ttl_seconds":60},
            "country_policy":{"allow":["GB"],"on_unknown":"deny"}
                }])
            },
            &file,
            trusted,
        )
        .await;
        assert_eq!(status(&fixture, "81.2.69.160").await, 503);
        assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);
        let slot = fixture.active.load().geoip.clone().unwrap();
        let active = fixture.active.clone();
        let published: Arc<hangang::geoip_runtime::Published> = Arc::new(move |slot| {
            active
                .load()
                .geoip
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, slot))
        });
        let cancel = tokio_util::sync::CancellationToken::new();
        let watcher = tokio::spawn(hangang::geoip_runtime::watch(
            slot.clone(),
            published,
            cancel.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while !slot.status().ready {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            status(&fixture, "81.2.69.160").await,
            if trusted { 200 } else { 403 }
        );
        assert_eq!(
            status(&fixture, "::ffff:81.2.69.160").await,
            if trusted { 200 } else { 403 }
        );
        assert_eq!(status(&fixture, "2001:220::1").await, 403);
        assert_eq!(status(&fixture, "127.0.0.1").await, 403);
        assert_eq!(
            fixture.origin_hits.load(Ordering::SeqCst),
            if trusted { 2 } else { 0 }
        );
        if trusted {
            let current = fixture.active.load_full();
            let mut config = current.config.clone();
            config.revision += 1;
            config.http[0].country_policy.as_mut().unwrap().allow = vec!["KR".into()];
            let next = Snapshot::replace(config, &current).unwrap();
            assert!(Arc::ptr_eq(next.geoip.as_ref().unwrap(), &slot));
            assert!(Arc::ptr_eq(
                next.cache.as_ref().unwrap(),
                current.cache.as_ref().unwrap()
            ));
            next.activated();
            fixture.active.store(Arc::new(next));
            assert_eq!(status(&fixture, "81.2.69.160").await, 403);
            assert_eq!(status(&fixture, "2001:220::1").await, 200);
            assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 3);
        }
        let hits = fixture.origin_hits.load(Ordering::SeqCst);
        let replacement = dir.path().join("replacement.mmdb");
        std::fs::write(&replacement, b"damaged").unwrap();
        std::fs::rename(&replacement, &file).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while slot.status().ready {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(status(&fixture, "81.2.69.160").await, 503);
        assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), hits);
        cancel.cancel();
        watcher.await.unwrap();
        fixture.close().await;
        std::fs::write(&file, fresh_fixture()).unwrap();
    }
}

#[tokio::test]
async fn protected_resource_shadow_cannot_skip_country_policy() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    let fixture = fixture(
        |origin| {
            json!([
                protected_route(origin, "GB"),
                {"id":"public-shadow", "host":"foo.test", "path_prefix":"/secure",
                 "path_match":"segment_prefix", "priority":100, "access_mode":"public",
                 "headers":{"x-mode":"public"}, "backends":[format!("http://{origin}")]}
            ])
        },
        &file,
        true,
    )
    .await;
    let slot = fixture.active.load().geoip.clone().unwrap();
    let (cancel, watcher) = start_watcher(&fixture, slot.clone());
    wait_ready(&slot).await;

    // The public route would otherwise win priority and ignore country rules.
    assert_eq!(
        request_status(
            &fixture,
            "/secure/records",
            "81.2.69.160",
            &[("host", "foo.test"), ("x-mode", "public")],
        )
        .await,
        403
    );
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);

    // Two routes claiming one resource ID cannot publish different country
    // policies, even when their authentication and resource rules agree.
    let current = fixture.active.load_full();
    let mut mismatch = current.config.clone();
    let mut second = mismatch.http[0].clone();
    second.id = "other-protected".into();
    second.country_policy.as_mut().unwrap().allow = vec!["KR".into()];
    mismatch.http.push(second);
    assert!(mismatch.validate().is_err());

    cancel.cancel();
    watcher.await.unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn changed_country_source_is_pending_until_its_own_verification() {
    let dir = tempfile::tempdir().unwrap();
    let first_file = dir.path().join("first.mmdb");
    let next_file = dir.path().join("next.mmdb");
    let bytes = fresh_fixture();
    std::fs::write(&first_file, &bytes).unwrap();
    std::fs::write(&next_file, &bytes).unwrap();
    let fixture = fixture(
        |origin| {
            json!([{"id":"country", "access_mode":"public",
                "backends":[format!("http://{origin}")],
                "country_policy":{"allow":["GB"],"on_unknown":"deny"}}])
        },
        &first_file,
        true,
    )
    .await;
    let old_slot = fixture.active.load().geoip.clone().unwrap();
    let (old_cancel, old_watcher) = start_watcher(&fixture, old_slot.clone());
    wait_ready(&old_slot).await;
    assert_eq!(status(&fixture, "81.2.69.160").await, 200);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 1);

    let current = fixture.active.load_full();
    let mut config = current.config.clone();
    config.revision += 1;
    config.geoip_database.as_mut().unwrap().file = next_file;
    let next = Arc::new(Snapshot::replace(config, &current).unwrap());
    let next_slot = next.geoip.clone().unwrap();
    assert!(!Arc::ptr_eq(&old_slot, &next_slot));
    assert!(next_slot.load().is_none());
    next.activated();
    fixture.active.store(next);
    assert_eq!(status(&fixture, "81.2.69.160").await, 503);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 1);

    let (next_cancel, next_watcher) = start_watcher(&fixture, next_slot.clone());
    wait_ready(&next_slot).await;
    assert_eq!(status(&fixture, "81.2.69.160").await, 200);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 2);
    old_cancel.cancel();
    next_cancel.cancel();
    old_watcher.await.unwrap();
    next_watcher.await.unwrap();
    fixture.close().await;
}

#[tokio::test]
async fn country_denial_precedes_only_if_cached_shortcut() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    let fixture = fixture(
        |origin| {
            json!([{"id":"country", "access_mode":"public",
                "backends":[format!("http://{origin}")],
                "cache":{"ttl_seconds":30,"max_ttl_seconds":60},
                "country_policy":{"allow":["GB"],"on_unknown":"deny"}}])
        },
        &file,
        true,
    )
    .await;
    let slot = fixture.active.load().geoip.clone().unwrap();
    let (cancel, watcher) = start_watcher(&fixture, slot.clone());
    wait_ready(&slot).await;
    assert_eq!(
        request_status(
            &fixture,
            "/",
            "2001:220::1",
            &[("cache-control", "only-if-cached")],
        )
        .await,
        403
    );
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);

    cancel.cancel();
    watcher.await.unwrap();
    fixture.close().await;
}
