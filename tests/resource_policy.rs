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
        language_policy: None,
        country_policy: None,
        auth_reserved: Vec::new(),
        auth_static_headers: Vec::new(),
        auth_native: None,
        auth_unavailable: None,
        jwt_auth: None,
        workload_auth: None,
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

#[tokio::test]
async fn concurrent_subjects_cannot_share_resource_permission() {
    let (upstream, hits, upstream_task) = origin("private").await;
    let (front, policy, front_task) = gateway(vec![protected_route(upstream)]).await;
    let mut requests = tokio::task::JoinSet::new();
    for index in 0..96 {
        requests.spawn(async move {
            let (user, expected) = match index % 3 {
                0 => (Some("alice"), 200),
                1 => (Some("bob"), 403),
                _ => (None, 401),
            };
            let status = request(
                front,
                "GET",
                "/secure/records",
                user,
                &[("x-verified-user", "alice")],
                None,
            )
            .await;
            assert_eq!(status, expected);
        });
    }
    while let Some(result) = requests.join_next().await {
        result.unwrap();
    }
    assert_eq!(hits.load(Ordering::SeqCst), 32);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

async fn pumgye_identity() -> (SocketAddr, Arc<Mutex<String>>, JoinHandle<()>) {
    pumgye_identity_with(None, b"2").await
}
async fn pumgye_identity_with(
    kind: Option<&'static str>,
    aal: &'static [u8],
) -> (SocketAddr, Arc<Mutex<String>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let subject = Arc::new(Mutex::new("u_reader".to_owned()));
    let selected = subject.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let selected = selected.clone();
            tokio::spawn(async move {
                let mut header = [0u8; 16];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let (id, n) = hangang::hopae_wire::parse_header(header).unwrap();
                assert_eq!(id, 0);
                let mut key = vec![0; n];
                stream.read_exact(&mut key).await.unwrap();
                assert_eq!(key, b"fixture-native-key-0123456789");
                stream
                    .write_all(&hangang::hopae_wire::frame_header(0, 1).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&[1]).await.unwrap();
                while stream.read_exact(&mut header).await.is_ok() {
                    let (id, n) = hangang::hopae_wire::parse_header(header).unwrap();
                    let mut body = vec![0; n];
                    stream.read_exact(&mut body).await.unwrap();
                    let subject = selected.lock().unwrap().clone();
                    let mut identity = vec![
                        ("x-forwarded-user".into(), subject.clone().into_bytes()),
                        ("x-hopae-aal".into(), aal.to_vec()),
                    ];
                    if let Some(kind) = kind {
                        identity.push(("x-hopae-principal-kind".into(), kind.as_bytes().to_vec()));
                        identity.push(("x-hopae-service-id".into(), b"orders".to_vec()));
                        identity.push((
                            "x-hopae-evidence-ttl-ms".into(),
                            if subject == "expired" {
                                b"1".to_vec()
                            } else {
                                b"1000".to_vec()
                            },
                        ));
                    }
                    let reply = hangang::hopae_wire::Reply {
                        status: if subject == "revoked" {
                            401
                        } else if subject == "outage" {
                            503
                        } else {
                            200
                        },
                        headers: identity,
                        body: vec![],
                    };
                    let data = hangang::hopae_wire::encode_reply(&reply).unwrap();
                    stream
                        .write_all(&hangang::hopae_wire::frame_header(id, data.len()).unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&data).await.unwrap();
                }
            });
        }
    });
    (address, subject, task)
}
fn pumgye_document(origin: SocketAddr, native: SocketAddr, require_guard: bool) -> Value {
    json!({"http":[{
        "id":"pumgye","host":"foo.test","path_prefix":"/secure","path_match":"segment_prefix","access_mode":"protected","backends":[format!("http://{origin}")],
        "auth":{"url":"http://127.0.0.1:8701/_hopae/verify","native":{"address":native.to_string()},"response_headers":["x-forwarded-user","x-hopae-aal"],"static_request_headers":{"x-hopae-gateway-key":"fixture-native-key-0123456789"}},
        "resource_policy":{"resource_id":"orders","principal":{"source":"external","subject_header":"x-forwarded-user"},"allow":[],"pumgye":{"service_id":"orders","information_class":"internal","permissions":{"GET":["read"],"POST":["write"]}}}
    }],"pumgye":{"version":1,"information_classes":["internal"],"services":{"orders":{"permissions":["read","write"],"require_guard":require_guard,
    "roles":{"reader":{"permissions":["read"],"information_classes":["internal"]}},"users":{"u_reader":["reader"]},"networks":[{"cidr":"127.0.0.1/32","roles":["reader"]}]}}}})
}
#[tokio::test]
async fn native_pumgye_guest_method_network_and_guard_gates() {
    let (origin, hits, origin_task) = origin("allowed").await;
    let (native, subject, native_task) = pumgye_identity().await;
    let (front, policy, task) = gateway_document(pumgye_document(origin, native, false)).await;
    assert_eq!(request(front, "GET", "/secure", None, &[], None).await, 200);
    assert_eq!(
        request(front, "POST", "/secure", None, &[], None).await,
        403
    );
    *subject.lock().unwrap() = "unassigned".into();
    assert_eq!(
        request(
            front,
            "GET",
            "/secure",
            None,
            &[("x-forwarded-user", "u_reader"), ("x-hopae-aal", "3")],
            None
        )
        .await,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    *subject.lock().unwrap() = "u_reader".into();
    let mut document = pumgye_document(origin, native, false);
    document["pumgye"]["services"]["orders"]["networks"] = json!([]);
    let (no_network, p2, t2) = gateway_document(document).await;
    assert_eq!(
        request(no_network, "GET", "/secure", None, &[], None).await,
        403
    );
    let (mandatory, p3, t3) = gateway_document(pumgye_document(origin, native, true)).await;
    assert_eq!(
        request(mandatory, "GET", "/secure", None, &[], None).await,
        403
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    task.abort();
    t2.abort();
    t3.abort();
    native_task.abort();
    origin_task.abort();
    policy.shutdown().await;
    p2.shutdown().await;
    p3.shutdown().await;
}

#[test]
fn pumgye_scope_cannot_be_silently_downgraded() {
    let old: Config = serde_json::from_value(pumgye_document(
        "127.0.0.1:19000".parse().unwrap(),
        "127.0.0.1:19001".parse().unwrap(),
        true,
    ))
    .unwrap();
    old.validate().unwrap();
    let mut new = old.clone();
    new.http[0].resource_policy.as_mut().unwrap().pumgye = None;
    assert!(new.validate_transition_from(&old).is_err());
    let mut disabled = old.clone();
    disabled.http[0].resource_policy.as_mut().unwrap().enforce = false;
    assert!(disabled.validate_transition_from(&old).is_ok());
    assert!(new.validate_transition_from(&disabled).is_ok());
    let mut missing = old.clone();
    missing.pumgye = None;
    assert!(missing.validate().is_err());
}

#[tokio::test]
async fn service_principal_requires_explicit_matrix_and_never_exports_api_credential() {
    qualify_nonhuman_principal("service").await;
}
#[tokio::test]
async fn workload_principal_requires_explicit_matrix_and_never_exports_client_credential() {
    qualify_nonhuman_principal("workload").await;
}
async fn qualify_nonhuman_principal(kind: &'static str) {
    let (origin, seen, origin_task) = capture_origin().await;
    let (native, subject, native_task) = pumgye_identity_with(Some(kind), b"0").await;
    let service = format!("s_{}", "a".repeat(48));
    *subject.lock().unwrap() = service.clone();
    let mut document = pumgye_document(origin, native, false);
    document["http"][0]["auth"]["request_headers"] = json!(["authorization"]);
    document["http"][0]["auth"]["response_headers"] =
        json!(["x-forwarded-user", "x-hopae-aal", "x-hopae-principal-kind"]);
    document["pumgye"]["services"]["orders"]["users"] = json!({service.clone():["reader"]});
    document["pumgye"]["services"]["orders"]["roles"]["reader"]["minimum_aal"] = json!(0);
    document["http"][0]["request_transform"] =
        json!({"set_headers":{"authorization":"Bearer late-transform-credential"}});
    let (front, policy, task) = gateway_document(document.clone()).await;
    let credential = [("authorization", "Bearer consumed-service-credential")];
    assert_eq!(
        request(front, "GET", "/secure", None, &credential, None).await,
        200
    );
    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].get("authorization").is_none());
        assert_eq!(seen[0]["x-forwarded-user"], service);
        assert_eq!(seen[0]["x-hopae-aal"], "0");
    }
    assert_eq!(
        request(front, "POST", "/secure", None, &credential, None).await,
        403
    );
    *subject.lock().unwrap() = format!("s_{}", "b".repeat(48));
    assert_eq!(
        request(front, "GET", "/secure", None, &credential, None).await,
        403
    );
    *subject.lock().unwrap() = service;
    let mut unguarded = document.clone();
    unguarded["http"][0]
        .as_object_mut()
        .unwrap()
        .remove("access_mode");
    unguarded["http"][0]
        .as_object_mut()
        .unwrap()
        .remove("resource_policy");
    let (open, p2, t2) = gateway_document(unguarded).await;
    assert_eq!(
        request(open, "GET", "/secure", None, &credential, None).await,
        403
    );
    for condition in ["assurance", "network", "class", "service"] {
        let mut denied = document.clone();
        match condition {
            "assurance" => {
                denied["pumgye"]["services"]["orders"]["roles"]["reader"]["minimum_aal"] = json!(1)
            }
            "network" => denied["pumgye"]["services"]["orders"]["networks"] = json!([]),
            "service" => {
                denied["pumgye"]["services"]["other"] =
                    denied["pumgye"]["services"]["orders"].clone();
                denied["http"][0]["resource_policy"]["pumgye"]["service_id"] = json!("other");
            }
            _ => {
                denied["pumgye"]["information_classes"] = json!(["internal", "restricted"]);
                denied["http"][0]["resource_policy"]["pumgye"]["information_class"] =
                    json!("restricted");
            }
        }
        let (front, p, t) = gateway_document(denied).await;
        assert_eq!(
            request(front, "GET", "/secure", None, &credential, None).await,
            403,
            "{condition} must independently deny service access"
        );
        t.abort();
        p.shutdown().await;
    }
    assert_eq!(seen.lock().unwrap().len(), 1);
    task.abort();
    t2.abort();
    native_task.abort();
    origin_task.abort();
    policy.shutdown().await;
    p2.shutdown().await;
}

#[tokio::test]
async fn idle_native_workload_stream_retires_without_policy_or_origin_changes() {
    qualify_machine_stream(None).await;
}

#[tokio::test]
async fn renewed_workload_stream_survives_and_retires_on_denial_outage_identity_or_expiry() {
    for cause in [
        "revoked",
        "outage",
        "expired",
        "s_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ] {
        qualify_machine_stream(Some(cause)).await;
    }
}
async fn qualify_machine_stream(renewal_failure: Option<&str>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let origin_task = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(connection.read_u8().await.unwrap());
        }
        connection
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nopen\n\r\n")
            .await
            .unwrap();
        std::future::pending::<()>().await;
    });
    let (native, subject, native_task) = pumgye_identity_with(Some("workload"), b"0").await;
    let identity = format!("s_{}", "a".repeat(48));
    *subject.lock().unwrap() = identity.clone();
    let mut document = pumgye_document(origin, native, false);
    document["http"][0]["auth"]["renew_native_evidence"] = json!(renewal_failure.is_some());
    document["http"][0]["auth"]["response_headers"] =
        json!(["x-forwarded-user", "x-hopae-aal", "x-hopae-principal-kind"]);
    document["pumgye"]["services"]["orders"]["users"] = json!({identity:["reader"]});
    document["pumgye"]["services"]["orders"]["roles"]["reader"]["minimum_aal"] = json!(0);
    let (front, policy, front_task) = gateway_document(document).await;
    let mut client = tokio::net::TcpStream::connect(front).await.unwrap();
    let started = std::time::Instant::now();
    client
        .write_all(b"GET /secure HTTP/1.1\r\nHost: foo.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !head.ends_with(b"open\n\r\n") {
            head.push(client.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(head.starts_with(b"HTTP/1.1 200"));
    if let Some(cause) = renewal_failure {
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.read_u8())
                .await
                .is_err(),
            "valid renewed stream closed early"
        );
        *subject.lock().unwrap() = cause.to_owned();
    }
    let revoked_at = std::time::Instant::now();
    let mut remainder = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_millis(1500),
        client.read_to_end(&mut remainder),
    )
    .await
    .expect("idle stream survived native evidence expiry");
    assert!(revoked_at.elapsed() < Duration::from_millis(1500));
    if renewal_failure.is_none() {
        assert!(started.elapsed() < Duration::from_millis(1500));
    }
    front_task.abort();
    native_task.abort();
    origin_task.abort();
    policy.shutdown().await;
}

#[test]
fn machine_evidence_renewal_requires_a_native_transport() {
    let mut document = pumgye_document(
        "127.0.0.1:12345".parse().unwrap(),
        "127.0.0.1:12346".parse().unwrap(),
        false,
    );
    document["http"][0]["auth"]["renew_native_evidence"] = json!(true);
    document["http"][0]["auth"]
        .as_object_mut()
        .unwrap()
        .remove("native");
    let config: Config = serde_json::from_value(document).unwrap();
    assert!(Snapshot::new(config).is_err());
}
