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
    let proxy = Proxy::new(active.clone(), policy.clone(), Arc::new(Metrics::default()));
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
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
        .get(&fixture.front)
        .header("x-forwarded-for", ip)
        .send()
        .await
        .unwrap();
    let code = response.status().as_u16();
    response.bytes().await.unwrap();
    code
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
