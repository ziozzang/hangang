use arc_swap::ArcSwap;
use base64::Engine;
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
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};

fn credential(username: &str, password: &str) -> String {
    let salt = b"0123456789abcdef";
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    format!("{username}:{}:{}", hex(salt), hex(&hasher.finalize()))
}

fn protected_route(origin: SocketAddr) -> Value {
    json!({
        "id":"protected", "access_mode":"protected", "priority":0,
        "host":"foo.test", "path_prefix":"/secure", "path_match":"segment_prefix",
        "backends":[format!("http://{origin}")],
        "basic_auth":{
            "credentials":[credential("alice", "secret"), credential("bob", "secret")],
            "hide_credentials":true, "identity_header":"x-verified-user"
        },
        "resource_policy":{
            "resource_id":"records", "principal":{"source":"basic"},
            "allow":[{"subjects":["alice"],"methods":["GET"]}]
        }
    })
}

async fn origin(label: &'static str) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let counter = counter.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<Incoming>| {
                    counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                            label.as_bytes(),
                        ))))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, hits, task)
}

async fn gateway(routes: Vec<Value>) -> (SocketAddr, Arc<PolicyPool>, JoinHandle<()>) {
    let config: Config = serde_json::from_value(json!({"http":routes})).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, policy, task)
}

async fn request(
    front: SocketAddr,
    method: &str,
    path: &str,
    user: Option<&str>,
    extra: &[(&str, &str)],
    body: Option<&str>,
) -> u16 {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut request = client
        .request(method.parse().unwrap(), format!("http://{front}{path}"))
        .header("host", "foo.test");
    if let Some(user) = user {
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:secret"));
        request = request.header("authorization", format!("Basic {encoded}"));
    }
    for (name, value) in extra {
        request = request.header(*name, *value);
    }
    if let Some(body) = body {
        request = request.body(body.to_owned());
    }
    request.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn basic_principal_and_method_allowlist_are_verified_before_origin() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let (front, policy, front_task) = gateway(vec![protected_route(upstream)]).await;
    assert_eq!(
        request(front, "GET", "/secure/records?view=all", None, &[], None).await,
        401
    );
    assert_eq!(
        request(front, "GET", "/secure/records", Some("bob"), &[], None).await,
        403
    );
    assert_eq!(
        request(front, "POST", "/secure/records", Some("alice"), &[], None).await,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        request(
            front,
            "GET",
            "/secure/records?view=all",
            Some("alice"),
            &[("x-verified-user", "bob")],
            None
        )
        .await,
        200
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn priority_header_and_json_shadow_routes_cannot_escape_resource_guard() {
    let (private, private_hits, private_task) = origin("private").await;
    let (public, public_hits, public_task) = origin("public").await;
    let header_shadow = json!({
        "id":"header-shadow", "access_mode":"public", "priority":100,
        "host_regex":".*", "path_prefix":"/secure", "headers":{"x-mode":"public"},
        "backends":[format!("http://{public}")]
    });
    let json_shadow = json!({
        "id":"json-shadow", "access_mode":"public", "priority":200,
        "host":"foo.test", "path_prefix":"/secure", "json":{"/bypass":true},
        "backends":[format!("http://{public}")]
    });
    let mut protected = protected_route(private);
    protected["resource_policy"]["allow"][0]["methods"] = json!(["GET", "POST"]);
    let (front, policy, front_task) = gateway(vec![protected, header_shadow, json_shadow]).await;
    assert_eq!(
        request(
            front,
            "GET",
            "/secure/records",
            None,
            &[("x-mode", "public")],
            None
        )
        .await,
        403
    );
    assert_eq!(
        request(
            front,
            "POST",
            "/secure/records",
            Some("alice"),
            &[("content-type", "application/json")],
            Some(r#"{"bypass":true}"#)
        )
        .await,
        403
    );
    assert_eq!(public_hits.load(Ordering::SeqCst), 0);
    assert_eq!(private_hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        request(front, "GET", "/secure/records", Some("alice"), &[], None).await,
        200
    );
    assert_eq!(private_hits.load(Ordering::SeqCst), 1);
    front_task.abort();
    private_task.abort();
    public_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn cache_only_request_cannot_skip_resource_auth_or_serve_origin_content() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let (front, policy, front_task) = gateway(vec![protected_route(upstream)]).await;
    let cache_only = &[("cache-control", "only-if-cached")];
    assert_eq!(
        request(front, "GET", "/secure?query=public", None, cache_only, None).await,
        401
    );
    assert_eq!(
        request(front, "GET", "/secure", Some("bob"), cache_only, None).await,
        403
    );
    assert_eq!(
        request(front, "GET", "/secure", Some("alice"), cache_only, None).await,
        504
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn guarded_host_uses_canonical_path_and_rejects_ambiguous_escapes() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let (front, policy, front_task) = gateway(vec![protected_route(upstream)]).await;
    // Unreserved letters decode once for guard and route matching. The
    // request remains protected even when the wire spelling differs.
    assert_eq!(
        request(front, "GET", "/s%65cure/records", None, &[], None).await,
        401
    );
    assert_eq!(
        request(front, "GET", "/s%65cure/records", Some("alice"), &[], None).await,
        200
    );
    let permitted_hits = hits.load(Ordering::SeqCst);
    for path in [
        "/secure%2fhidden",
        "/secure%5chidden",
        "/secure/%252e%252e",
        "/secure/%2e%2e",
        "/secure/%3fprivate",
        "/secure/%3bprivate",
    ] {
        assert_eq!(
            request(front, "GET", path, Some("alice"), &[], None).await,
            400,
            "{path}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), permitted_hits);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}
