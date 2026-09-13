use arc_swap::ArcSwap;
use base64::Engine;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::Proxy,
};
use http_body_util::{BodyExt, Full};
use hyper::{
    HeaderMap, Request, Response, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

async fn capture_origin() -> (SocketAddr, Arc<Mutex<Vec<HeaderMap>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let records = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let records = records.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let records = records.clone();
                    async move {
                        let headers = request.headers().clone();
                        let _ = request.into_body().collect().await;
                        records.lock().unwrap().push(headers);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::new())))
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    (address, seen, task)
}

async fn gateway(routes: Vec<Value>) -> (SocketAddr, Arc<PolicyPool>, JoinHandle<()>) {
    gateway_document(json!({"http":routes})).await
}

async fn gateway_document(document: Value) -> (SocketAddr, Arc<PolicyPool>, JoinHandle<()>) {
    let config: Config = serde_json::from_value(document).unwrap();
    serve_snapshot(Snapshot::new(config).unwrap()).await
}

async fn serve_snapshot(snapshot: Snapshot) -> (SocketAddr, Arc<PolicyPool>, JoinHandle<()>) {
    let active = Arc::new(ArcSwap::from_pointee(snapshot));
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

async fn raw_status(front: SocketAddr, request: &str) -> u16 {
    let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    String::from_utf8_lossy(&response)
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
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
        "host_regex":"[a-z.]+", "path_prefix":"/secure", "headers":{"x-mode":"public"},
        "backends":[format!("http://{public}")]
    });
    let json_shadow = json!({
        "id":"json-shadow", "access_mode":"public", "priority":200,
        "host":"foo.test", "path_prefix":"/secure", "headers":{"content-type":"application/json"},
        "json":{"/bypass":true},
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
    let credential = base64::engine::general_purpose::STANDARD.encode("alice:secret");
    for path in [
        "/secure%2fhidden",
        "/secure%5chidden",
        "/secure/%252e%252e",
        "/secure/%2e%2e",
        "/secure/%3fprivate",
        "/secure/%3bprivate",
    ] {
        let wire = format!(
            "GET {path} HTTP/1.1\r\nHost: foo.test\r\nAuthorization: Basic {credential}\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(raw_status(front, &wire).await, 400, "{path}");
    }
    assert_eq!(hits.load(Ordering::SeqCst), permitted_hits);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn external_subject_must_be_single_verified_response_value() {
    let auth_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_address = auth_listener.local_addr().unwrap();
    let auth_task = tokio::spawn(async move {
        while let Ok((stream, _)) = auth_listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| async move {
                    let case = request
                        .headers()
                        .get("x-case")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("good");
                    let mut reply = Response::new(Full::new(Bytes::new()));
                    match case {
                        "missing" => {}
                        "duplicate" => {
                            reply
                                .headers_mut()
                                .append("x-auth-subject", "alice".parse().unwrap());
                            reply
                                .headers_mut()
                                .append("x-auth-subject", "bob".parse().unwrap());
                        }
                        "comma" => {
                            reply
                                .headers_mut()
                                .insert("x-auth-subject", "alice,bob".parse().unwrap());
                        }
                        "blank" => {
                            reply
                                .headers_mut()
                                .insert("x-auth-subject", "".parse().unwrap());
                        }
                        "hop" => {
                            reply
                                .headers_mut()
                                .insert("connection", "x-auth-subject".parse().unwrap());
                            reply
                                .headers_mut()
                                .insert("x-auth-subject", "alice".parse().unwrap());
                        }
                        _ => {
                            reply
                                .headers_mut()
                                .insert("x-auth-subject", "alice".parse().unwrap());
                        }
                    }
                    Ok::<_, Infallible>(reply)
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let (upstream, hits, upstream_task) = origin("private").await;
    let route = json!({
        "id":"external", "access_mode":"protected", "host":"foo.test",
        "path_prefix":"/secure", "path_match":"segment_prefix",
        "backends":[format!("http://{upstream}")],
        "auth":{"url":format!("http://{auth_address}/verify"),
            "request_headers":["x-case"], "response_headers":["x-auth-subject"]},
        "resource_policy":{"resource_id":"records",
            "principal":{"source":"external","subject_header":"x-auth-subject"},
            "allow":[{"subjects":["alice"],"methods":["GET"]}]}
    });
    let (front, policy, front_task) = gateway(vec![route]).await;
    for case in ["missing", "duplicate", "comma", "blank", "hop"] {
        assert_eq!(
            request(
                front,
                "GET",
                "/secure/records",
                None,
                &[("x-case", case), ("x-auth-subject", "alice")],
                None
            )
            .await,
            403,
            "{case}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert_eq!(
        request(
            front,
            "GET",
            "/secure/records",
            None,
            &[("x-case", "good"), ("x-auth-subject", "client-forged")],
            None
        )
        .await,
        200
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    front_task.abort();
    upstream_task.abort();
    auth_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn guarded_host_rejects_forwarded_absolute_and_trailing_dot_mismatch() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let (front, policy, front_task) = gateway_document(json!({
        "settings":{"trusted_proxy_cidrs":["127.0.0.0/8"]},
        "http":[protected_route(upstream)]
    }))
    .await;
    assert_eq!(
        request(
            front,
            "GET",
            "/secure",
            None,
            &[("x-forwarded-host", "evil.test")],
            None
        )
        .await,
        400
    );
    assert_eq!(
        raw_status(
            front,
            "GET http://evil.test/secure HTTP/1.1\r\nHost: foo.test\r\nConnection: close\r\n\r\n"
        )
        .await,
        400
    );
    assert_eq!(
        raw_status(
            front,
            "GET /secure HTTP/1.1\r\nHost: foo.test.\r\nConnection: close\r\n\r\n"
        )
        .await,
        400
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn disabled_guard_and_overlapping_resource_ids_fail_closed() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let mut disabled = protected_route(upstream);
    disabled["enabled"] = json!(false);
    let public = json!({"id":"public", "access_mode":"public", "priority":100,
        "host":"foo.test", "path_prefix":"/secure", "backends":[format!("http://{upstream}")]});
    let (front, policy, front_task) = gateway(vec![disabled, public]).await;
    assert_eq!(
        request(front, "GET", "/secure/records", Some("alice"), &[], None).await,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    front_task.abort();
    policy.shutdown().await;

    let mut other = protected_route(upstream);
    other["id"] = json!("other");
    other["priority"] = json!(100);
    other["resource_policy"]["resource_id"] = json!("other-records");
    let (front, policy, front_task) = gateway(vec![protected_route(upstream), other]).await;
    assert_eq!(
        request(front, "GET", "/secure/records", Some("alice"), &[], None).await,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_cannot_replace_verified_resource_principal_or_origin_identity() {
    let (upstream, seen, upstream_task) = capture_origin().await;
    let mut route = protected_route(upstream);
    route["lua"] = json!("hangang.set_header('x-app-mutated', 'yes')");
    let (front, policy, front_task) = gateway(vec![route]).await;
    assert_eq!(
        request(
            front,
            "GET",
            "/secure/records",
            Some("bob"),
            &[("x-verified-user", "alice")],
            None
        )
        .await,
        403
    );
    assert!(
        seen.lock().unwrap().is_empty(),
        "Bob cannot become Alice through a request header or Lua"
    );
    assert_eq!(
        request(
            front,
            "GET",
            "/secure/records",
            Some("alice"),
            &[("x-verified-user", "bob")],
            None
        )
        .await,
        200
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].get_all("x-verified-user").iter().count(), 1);
        assert_eq!(seen[0]["x-verified-user"], "alice");
        assert_eq!(
            seen[0]["x-app-mutated"], "yes",
            "Lua application mutation actually ran"
        );
    }
    front_task.abort();
    policy.shutdown().await;

    let mut rejected = protected_route(upstream);
    rejected["lua"] = json!("hangang.set_header('x-verified-user', 'bob')");
    let (front, policy, front_task) = gateway(vec![rejected]).await;
    assert_eq!(
        request(front, "GET", "/secure/records", Some("alice"), &[], None).await,
        503
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "reserved Lua identity mutation must not reach origin"
    );
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn resource_policy_rejects_native_identity_transform_and_defensively_reasserts() {
    let (upstream, seen, upstream_task) = capture_origin().await;
    let mut document = json!({"http":[protected_route(upstream)]});
    document["http"][0]["resource_policy"]["allow"][0]["methods"] = json!(["GET", "POST"]);
    let valid: Config = serde_json::from_value(document).unwrap();
    let mut transform = hangang::transform::BodyTransform::default();
    transform
        .set_headers
        .insert("X-Verified-User".into(), "bob".into());
    let mut rejected = valid.clone();
    rejected.http[0].request_transform = Some(transform.clone());
    assert!(
        rejected.validate().is_err(),
        "configuration cannot publish an identity rewrite"
    );

    // The active document remains valid. A test-only forged runtime exercises
    // defense in depth if a lower layer ever bypasses configuration validation.
    let mut snapshot = Snapshot::new(valid).unwrap();
    let previous = snapshot.http[0].clone();
    let mut route = previous.route.clone();
    route.request_transform = Some(transform.clone());
    let runtime = hangang::config::HttpRuntime {
        host_regex: previous.host_regex.clone(),
        admission: previous.admission.clone(),
        balancer: previous.balancer.clone(),
        cache_fingerprint: previous.cache_fingerprint.clone(),
        request_transform: Some(Arc::new(transform)),
        response_transform: previous.response_transform.clone(),
        basic_auth: Some(hangang::basic_auth::prepare(route.basic_auth.as_ref().unwrap()).unwrap()),
        route,
    };
    snapshot.http = vec![Arc::new(runtime)];
    let (front, policy, front_task) = serve_snapshot(snapshot).await;
    assert_eq!(
        request(
            front,
            "POST",
            "/secure/records",
            Some("bob"),
            &[("x-verified-user", "alice")],
            Some("payload")
        )
        .await,
        403
    );
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(
        request(
            front,
            "POST",
            "/secure/records",
            Some("alice"),
            &[("x-verified-user", "mallory")],
            Some("payload")
        )
        .await,
        200
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].get_all("x-verified-user").iter().count(), 1);
        assert_eq!(seen[0]["x-verified-user"], "alice");
    }
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}
