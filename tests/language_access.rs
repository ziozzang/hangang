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
    cache: bool,
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

    let mut document = json!({"http": route_builder(origin_address)});
    if cache {
        document["cache"] = json!({
            "memory":{"max_bytes":65536,"max_entries":16,"eviction":"lru"},
            "max_object_bytes":4096
        });
    }
    let config: Config = serde_json::from_value(document).unwrap();
    let snapshot = Snapshot::new(config).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(snapshot));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
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
        policy,
        tasks: vec![origin_task, front_task],
    }
}

fn route(id: &str, origin: std::net::SocketAddr, policy: Value) -> Value {
    json!({
        "id":id,
        "access_mode":"public",
        "backends":[format!("http://{origin}")],
        "language_policy":policy
    })
}

fn language(mode: &str, allow: &[&str], deny: &[&str], on_missing: &str) -> Value {
    json!({"mode":mode,"allow":allow,"deny":deny,"on_missing":on_missing})
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

async fn status(fixture: &Fixture, headers: &[(&str, &str)]) -> u16 {
    status_path(fixture, "/secure/item", headers).await
}

async fn status_path(fixture: &Fixture, path: &str, headers: &[(&str, &str)]) -> u16 {
    let mut request = client()
        .get(format!("{}{path}", fixture.front))
        .header("host", "foo.test");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn language_header_parsing_is_scoped_to_selected_policy_route() {
    let fixture = fixture(
        |origin| {
            let mut restricted = route("restricted", origin, language("any", &["en"], &[], "deny"));
            restricted["path_prefix"] = json!("/secure");
            let open = json!({
                "id":"open", "access_mode":"public", "path_prefix":"/open",
                "backends":[format!("http://{origin}")]
            });
            json!([restricted, open])
        },
        false,
    )
    .await;
    let malformed = &[("accept-language", "not a valid range")];
    assert_eq!(status_path(&fixture, "/open/item", malformed).await, 200);
    assert_eq!(status(&fixture, malformed).await, 400);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test]
async fn preferred_language_is_admission_after_selection_without_fallback() {
    let fixture = fixture(
        |origin| {
            let mut selected = route(
                "selected",
                origin,
                language("preferred", &["fr"], &[], "deny"),
            );
            selected["priority"] = json!(100);
            let fallback = json!({
                "id":"fallback", "access_mode":"public", "priority":0,
                "backends":[format!("http://{origin}")]
            });
            json!([selected, fallback])
        },
        false,
    )
    .await;
    assert_eq!(
        status(&fixture, &[("accept-language", "en;q=1, fr;q=0.5")]).await,
        403
    );
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        status(&fixture, &[("accept-language", "fr-CA;q=1, en;q=0.5")]).await,
        200
    );
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test]
async fn absent_empty_zero_quality_and_malformed_signals_do_not_open_deny_only_route() {
    let fixture = fixture(
        |origin| json!([route("deny", origin, language("any", &[], &["en"], "deny"))]),
        false,
    )
    .await;
    assert_eq!(status(&fixture, &[]).await, 403);
    assert_eq!(status(&fixture, &[("accept-language", "")]).await, 403);
    assert_eq!(
        status(&fixture, &[("accept-language", "fr;q=0")]).await,
        403
    );
    assert_eq!(
        status(&fixture, &[("accept-language", "en;q=0,fr;q=0")]).await,
        403
    );
    assert_eq!(
        status(&fixture, &[("accept-language", "fr;q=bogus")]).await,
        400
    );
    assert_eq!(
        status(
            &fixture,
            &[("accept-language", "fr"), ("accept-language", "FR")]
        )
        .await,
        400
    );
    assert_eq!(status(&fixture, &[("accept-language", "fr")]).await, 200);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 1);
    fixture.close().await;
}

#[tokio::test]
async fn oversized_accept_language_is_rejected_before_origin() {
    let fixture = fixture(
        |origin| {
            json!([route(
                "bounded",
                origin,
                language("any", &["en"], &[], "allow")
            )])
        },
        false,
    )
    .await;
    let oversized = "a".repeat(hangang::language_policy::MAX_HEADER_BYTES + 1);
    assert_eq!(
        status(&fixture, &[("accept-language", &oversized)]).await,
        400
    );
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);
    fixture.close().await;
}

#[test]
#[ignore = "owned release diagnostic: parser and policy evaluation only, not HTTP throughput"]
fn language_parser_and_policy_release_diagnostic() {
    use hangang::language_policy::{
        AcceptLanguage, CompiledLanguagePolicy, MatchMode, MissingAction,
    };
    let typical = b"en-US,en;q=0.7".as_slice();
    let max_header = (0..32)
        .map(|index| {
            let first = char::from(b'a' + (index / 26) as u8);
            let second = char::from(b'a' + (index % 26) as u8);
            format!("l{first}{second};q=0.9")
        })
        .collect::<Vec<_>>()
        .join(",");
    let cases: [(&str, &[u8], &str); 2] = [
        ("typical", typical, "en"),
        ("max_32_ranges", max_header.as_bytes(), "lbf"),
    ];
    const ITERATIONS: usize = 100_000;
    for (name, header, allow) in cases {
        let policy = CompiledLanguagePolicy::new(
            MatchMode::Any,
            MissingAction::Deny,
            true,
            [allow],
            std::iter::empty::<&str>(),
        )
        .unwrap();
        let started = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            let parsed = AcceptLanguage::parse_values([std::hint::black_box(header)]).unwrap();
            assert!(std::hint::black_box(
                policy.allows(std::hint::black_box(&parsed))
            ));
        }
        let elapsed = started.elapsed();
        println!(
            "language_parse_evaluate case={name} header_bytes={} iterations={ITERATIONS} elapsed_ms={:.3} ns_per_iteration={:.1}",
            header.len(),
            elapsed.as_secs_f64() * 1000.0,
            elapsed.as_nanos() as f64 / ITERATIONS as f64
        );
    }
}

#[tokio::test]
async fn language_denial_precedes_cache_only_and_lua_policy() {
    let cached = fixture(
        |origin| {
            let mut selected = route("localized", origin, language("any", &["en"], &[], "deny"));
            selected["cache"] = json!({"ttl_seconds":30,"max_ttl_seconds":60});
            json!([selected])
        },
        true,
    )
    .await;
    assert_eq!(status(&cached, &[("accept-language", "en")]).await, 200);
    assert_eq!(
        status(
            &cached,
            &[
                ("accept-language", "fr"),
                ("cache-control", "only-if-cached")
            ]
        )
        .await,
        403
    );
    assert_eq!(cached.origin_hits.load(Ordering::SeqCst), 1);
    cached.close().await;

    let fixture = fixture(
        |origin| {
            let mut selected = route("lua", origin, language("any", &["en"], &[], "deny"));
            selected["lua"] = json!("hangang.reject(418)");
            json!([selected])
        },
        false,
    )
    .await;
    assert_eq!(status(&fixture, &[("accept-language", "fr")]).await, 403);
    assert_eq!(status(&fixture, &[("accept-language", "en")]).await, 418);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);
    fixture.close().await;
}

#[tokio::test]
async fn public_shadow_cannot_escape_protected_resource_or_relax_shared_policy() {
    let config = |origin| {
        let protected = json!({
            "id":"protected", "access_mode":"protected", "priority":0,
            "host":"foo.test", "path_prefix":"/secure", "path_match":"segment_prefix",
            "backends":[format!("http://{origin}")],
            "basic_auth":{"credentials":[hangang::basic_auth::hash_credential("alice", "secret").unwrap()]},
            "resource_policy":{"resource_id":"records","principal":{"source":"basic"},"allow":[{"subjects":["alice"],"methods":["GET"]}]},
            "language_policy":language("any", &["en"], &[], "deny")
        });
        let mut shadow = route("shadow", origin, language("any", &["fr"], &[], "allow"));
        shadow["priority"] = json!(100);
        json!([protected, shadow])
    };
    let fixture = fixture(config, false).await;
    assert_eq!(status(&fixture, &[("accept-language", "fr")]).await, 403);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 0);
    fixture.close().await;
}

#[tokio::test]
async fn shared_resource_id_cannot_have_different_language_admission() {
    let origin = "http://127.0.0.1:9";
    let credential = hangang::basic_auth::hash_credential("alice", "secret").unwrap();
    let make_route = |id: &str, path: &str, language_policy: Value| {
        json!({
            "id":id, "access_mode":"protected", "host":"foo.test",
            "path_prefix":path, "backends":[origin],
            "basic_auth":{"credentials":[credential]},
            "resource_policy":{"resource_id":"records", "principal":{"source":"basic"},
                "allow":[{"subjects":["alice"],"methods":["GET"]}]},
            "language_policy":language_policy
        })
    };
    let mut document = json!({"http":[
        make_route("one", "/one", language("any", &["en"], &[], "deny")),
        make_route("two", "/two", language("any", &["fr"], &[], "deny"))
    ]});
    let mismatched: Config = serde_json::from_value(document.clone()).unwrap();
    let mismatch = Snapshot::new(mismatched)
        .err()
        .expect("different language policy must fail");
    assert!(mismatch.to_string().contains("share policy"), "{mismatch}");
    let same_policy = document["http"][0]["language_policy"].clone();
    document["http"][1]["language_policy"] = same_policy;
    let config: Config = serde_json::from_value(document).unwrap();
    Snapshot::new(config).expect("identical policies and authenticators may share resource ID");
}

#[tokio::test]
async fn deliberately_disabled_language_policy_does_not_filter_or_parse_header() {
    let fixture = fixture(
        |origin| {
            let mut selected = route("disabled", origin, language("any", &["en"], &[], "deny"));
            selected["language_policy"]["enforce"] = json!(false);
            json!([selected])
        },
        false,
    )
    .await;
    assert_eq!(
        status(&fixture, &[("accept-language", "not a valid range")]).await,
        200
    );
    assert_eq!(status(&fixture, &[]).await, 200);
    assert_eq!(fixture.origin_hits.load(Ordering::SeqCst), 2);
    fixture.close().await;
}
