use arc_swap::ArcSwap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use ed25519_dalek::{Signer, SigningKey};
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
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
};

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[37; 32])
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn claims() -> Value {
    let now = now();
    json!({"iss":"https://issuer.example.test/", "aud":"hangang-api", "sub":"alice",
        "client_id":"client-1", "iat":now - 30, "exp":now + 600, "jti":"fixture-1",
        "scope":"read write", "groups":["operators"]})
}

fn token(header: Value, claims: Value) -> String {
    let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{encoded_header}.{encoded_claims}");
    let signature = signing_key().sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn good_token() -> String {
    token(
        json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"fixture-key"}),
        claims(),
    )
}

fn basic_credential() -> String {
    let salt = b"0123456789abcdef";
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(b"secret");
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    format!("alice:{}:{}", hex(salt), hex(&hasher.finalize()))
}

fn jwt_route(origin: SocketAddr) -> Value {
    let key = signing_key().verifying_key();
    json!({"id":"secured", "host":"jwt.test", "path_prefix":"/secure",
        "path_match":"segment_prefix", "access_mode":"protected",
        "backends":[format!("http://{origin}")],
        "jwt_auth":{
            "verification":{"issuer":"https://issuer.example.test/", "audiences":["hangang-api"],
                "profile":"rfc9068", "algorithms":["EdDSA"], "leeway_seconds":0,
                "max_lifetime_seconds":3600, "scope_claim":"scope", "groups_claim":"groups",
                "required_scopes":["read"], "required_groups":["operators"]},
            "keys":{"source":"local", "jwks":{"keys":[{"kty":"OKP", "crv":"Ed25519",
                "alg":"EdDSA", "use":"sig", "kid":"fixture-key",
                "x":URL_SAFE_NO_PAD.encode(key.to_bytes())}]}},
            "hide_credentials":true, "identity_header":"x-verified-user"},
        "resource_policy":{"resource_id":"private-data", "principal":{"source":"jwt"},
            "allow":[{"subjects":["alice"],"methods":["GET"]}]}
    })
}

async fn origin() -> (SocketAddr, Arc<Mutex<Vec<HeaderMap>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let captured = captured.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let captured = captured.clone();
                    async move {
                        let headers = request.headers().clone();
                        let _ = request.into_body().collect().await;
                        captured.lock().unwrap().push(headers);
                        Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"origin"))))
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

async fn authorization_service() -> (SocketAddr, Arc<Mutex<Vec<HeaderMap>>>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let captured = seen.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let captured = captured.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let captured = captured.clone();
                    async move {
                        captured.lock().unwrap().push(request.headers().clone());
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
    let config: Config = serde_json::from_value(json!({"http":routes})).unwrap();
    let snapshot = Snapshot::new(config).unwrap();
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

async fn request(
    front: SocketAddr,
    path: &str,
    bearer: Option<&str>,
    headers: &[(&str, &str)],
) -> u16 {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let mut request = client
        .get(format!("http://{front}{path}"))
        .header("host", "jwt.test");
    if let Some(bearer) = bearer {
        request = request.bearer_auth(bearer);
    }
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn signed_access_token_is_the_only_resource_identity_and_bearer_is_hidden() {
    let (upstream, seen, upstream_task) = origin().await;
    let (front, policy, front_task) = gateway(vec![jwt_route(upstream)]).await;
    assert_eq!(request(front, "/secure/records", None, &[],).await, 401);
    assert!(seen.lock().unwrap().is_empty());
    let bearer = good_token();
    assert_eq!(
        request(
            front,
            "/secure/records",
            Some(&bearer),
            &[("x-verified-user", "mallory")]
        )
        .await,
        200
    );
    {
        let records = seen.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert!(
            records[0].get("authorization").is_none(),
            "Bearer stays away from origin"
        );
        assert_eq!(records[0].get_all("x-verified-user").iter().count(), 1);
        assert_eq!(records[0]["x-verified-user"], "alice");
    }
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn invalid_signature_type_claims_and_time_fail_before_origin() {
    let (upstream, seen, upstream_task) = origin().await;
    let (front, policy, front_task) = gateway(vec![jwt_route(upstream)]).await;
    let mut invalid = Vec::new();
    let bearer = good_token();
    let signature_offset = bearer.rfind('.').unwrap() + 1;
    let replacement = if bearer.as_bytes()[signature_offset] == b'A' {
        'B'
    } else {
        'A'
    };
    invalid.push(format!(
        "{}{replacement}{}",
        &bearer[..signature_offset],
        &bearer[signature_offset + 1..]
    ));
    for typ in ["JWT", "id+jwt"] {
        invalid.push(token(
            json!({"typ":typ,"alg":"EdDSA","kid":"fixture-key"}),
            claims(),
        ));
    }
    for field in ["iss", "aud", "sub", "client_id", "iat", "exp", "jti"] {
        let mut payload = claims();
        payload.as_object_mut().unwrap().remove(field);
        invalid.push(token(
            json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
            payload,
        ));
    }
    let mut wrong = claims();
    wrong["iss"] = json!("https://other.example.test/");
    invalid.push(token(
        json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
        wrong,
    ));
    let mut wrong = claims();
    wrong["aud"] = json!("other-api");
    invalid.push(token(
        json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
        wrong,
    ));
    let mut expired = claims();
    expired["exp"] = json!(now() - 1);
    invalid.push(token(
        json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
        expired,
    ));
    let mut future = claims();
    future["iat"] = json!(now() + 60);
    invalid.push(token(
        json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
        future,
    ));
    for bearer in &invalid {
        assert_eq!(
            request(front, "/secure/records", Some(bearer), &[]).await,
            401
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    let mixed_case = token(
        json!({"typ":"at+JWT","alg":"EdDSA","kid":"fixture-key"}),
        claims(),
    );
    assert_eq!(
        request(front, "/secure/records", Some(&mixed_case), &[]).await,
        200,
        "typ media type is ASCII case insensitive"
    );
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn required_scope_group_and_resource_subject_are_distinct_denials() {
    let (upstream, seen, upstream_task) = origin().await;
    let (front, policy, front_task) = gateway(vec![jwt_route(upstream)]).await;
    for field in ["scope", "groups"] {
        let mut payload = claims();
        payload.as_object_mut().unwrap().remove(field);
        let bearer = token(
            json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
            payload,
        );
        assert_eq!(
            request(front, "/secure/records", Some(&bearer), &[]).await,
            403,
            "{field}"
        );
    }
    let mut payload = claims();
    payload["sub"] = json!("bob");
    let bearer = token(
        json!({"typ":"at+jwt","alg":"EdDSA","kid":"fixture-key"}),
        payload,
    );
    assert_eq!(
        request(front, "/secure/records", Some(&bearer), &[]).await,
        403
    );
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn public_shadow_and_cache_only_cannot_skip_jwt() {
    let (upstream, seen, upstream_task) = origin().await;
    let public = json!({"id":"public-shadow", "priority":100, "access_mode":"public",
        "host":"jwt.test", "path_prefix":"/secure", "backends":[format!("http://{upstream}")]});
    let (front, policy, front_task) = gateway(vec![public, jwt_route(upstream)]).await;
    assert_eq!(
        request(front, "/secure/records", Some(&good_token()), &[]).await,
        403
    );
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    policy.shutdown().await;

    let (front, policy, front_task) = gateway(vec![jwt_route(upstream)]).await;
    assert_eq!(
        request(
            front,
            "/secure/records",
            None,
            &[("cache-control", "only-if-cached")]
        )
        .await,
        401
    );
    assert_eq!(
        request(
            front,
            "/secure/records",
            Some(&good_token()),
            &[("cache-control", "only-if-cached")]
        )
        .await,
        504
    );
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn lua_application_mutation_cannot_override_jwt_identity() {
    let (upstream, seen, upstream_task) = origin().await;
    let mut route = jwt_route(upstream);
    route["lua"] = json!("hangang.set_header('x-app-mutated', 'yes')");
    let (front, policy, front_task) = gateway(vec![route]).await;
    assert_eq!(
        request(
            front,
            "/secure/records",
            Some(&good_token()),
            &[("x-verified-user", "mallory")]
        )
        .await,
        200
    );
    {
        let records = seen.lock().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["x-verified-user"], "alice");
        assert_eq!(records[0]["x-app-mutated"], "yes");
    }
    front_task.abort();
    policy.shutdown().await;
    let mut route = jwt_route(upstream);
    route["lua"] = json!("hangang.set_header('x-verified-user', 'mallory')");
    let (front, policy, front_task) = gateway(vec![route]).await;
    assert_eq!(
        request(front, "/secure/records", Some(&good_token()), &[]).await,
        503
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn jwt_precedes_external_authorization_and_origin_hides_bearer() {
    let (upstream, origin_seen, upstream_task) = origin().await;
    let (auth_address, auth_seen, auth_task) = authorization_service().await;
    let mut route = jwt_route(upstream);
    route["auth"] = json!({"url":format!("http://{auth_address}/check"),
        "request_headers":["authorization"], "response_headers":[]});
    let (front, policy, front_task) = gateway(vec![route]).await;
    assert_eq!(
        request(front, "/secure/records", Some("invalid"), &[]).await,
        401
    );
    assert!(
        auth_seen.lock().unwrap().is_empty(),
        "bad JWT cannot reach external auth"
    );
    assert_eq!(
        request(front, "/secure/records", Some(&good_token()), &[]).await,
        200
    );
    {
        let auth = auth_seen.lock().unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(auth[0]["authorization"], format!("Bearer {}", good_token()));
        let origin = origin_seen.lock().unwrap();
        assert_eq!(origin.len(), 1);
        assert!(origin[0].get("authorization").is_none());
    }
    front_task.abort();
    upstream_task.abort();
    auth_task.abort();
    policy.shutdown().await;
}

#[test]
fn jwt_and_basic_cannot_compete_for_one_authorization_header() {
    let mut route = jwt_route("127.0.0.1:9".parse().unwrap());
    route["basic_auth"] = json!({"credentials":[basic_credential()]});
    let config: Config = serde_json::from_value(json!({"http":[route]})).unwrap();
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn alternate_and_duplicate_credentials_do_not_authenticate() {
    let (upstream, seen, upstream_task) = origin().await;
    let (front, policy, front_task) = gateway(vec![jwt_route(upstream)]).await;
    let bearer = good_token();
    let authorization = format!("Bearer {bearer}");
    for headers in [
        vec![("cookie", authorization.as_str())],
        vec![("proxy-authorization", authorization.as_str())],
        vec![
            ("authorization", authorization.as_str()),
            ("authorization", authorization.as_str()),
        ],
    ] {
        assert_eq!(request(front, "/secure/records", None, &headers).await, 401);
    }
    assert_eq!(
        request(
            front,
            &format!("/secure/records?access_token={bearer}"),
            None,
            &[]
        )
        .await,
        401
    );
    assert!(seen.lock().unwrap().is_empty());
    front_task.abort();
    upstream_task.abort();
    policy.shutdown().await;
}

struct LeaseGateway {
    address: SocketAddr,
    active: Arc<ArcSwap<Snapshot>>,
    proxy: Arc<Proxy>,
    policy: Arc<PolicyPool>,
    task: JoinHandle<()>,
}

impl LeaseGateway {
    fn publish(&self, routes: Vec<Value>) {
        let previous = self.active.load_full();
        let config: Config = serde_json::from_value(json!({
            "revision": previous.config.revision + 1, "http": routes
        }))
        .unwrap();
        let candidate = Arc::new(Snapshot::replace(config, &previous).unwrap());
        candidate.activated();
        self.active.store(candidate);
    }

    async fn shutdown(self) {
        self.proxy.shutdown(Duration::ZERO).await;
        self.task.abort();
        self.policy.shutdown().await;
    }
}

async fn lease_gateway(routes: Vec<Value>) -> LeaseGateway {
    let config: Config = serde_json::from_value(json!({"http": routes})).unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 2));
    let proxy = Arc::new(Proxy::new(
        active.clone(),
        policy.clone(),
        Arc::new(Metrics::default()),
    ));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let serve_proxy = proxy.clone();
    let task = tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
            let proxy = serve_proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let _ = builder
                    .serve_connection_with_upgrades(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    LeaseGateway {
        address,
        active,
        proxy,
        policy,
        task,
    }
}

async fn held_event_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut chunk = [0u8; 2048];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&chunk[..count]);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n7\r\ndata:x\n\r\n").await.unwrap();
        std::future::pending::<()>().await;
    });
    (address, task)
}

async fn held_upload_origin() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<bool>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (events, observed) = tokio::sync::mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let service = service_fn(move |request: Request<Incoming>| {
            let events = events.clone();
            async move {
                let mut body = request.into_body();
                let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
                events.send(first.as_ref() == b"ping").unwrap();
                let ended = match body.frame().await {
                    None | Some(Err(_)) => true,
                    Some(Ok(_)) => false,
                };
                events.send(ended).unwrap();
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"done"))))
            }
        });
        let _ = http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    (address, observed, task)
}

async fn websocket_echo_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|mut request: Request<Incoming>| async move {
                    let upgrade = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = upgrade.await {
                            let mut upgraded = TokioIo::new(upgraded);
                            let mut message = [0u8; 4];
                            while upgraded.read_exact(&mut message).await.is_ok() {
                                if upgraded.write_all(&message).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(101)
                            .header("connection", "upgrade")
                            .header("upgrade", "websocket")
                            .header("sec-websocket-accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    (address, task)
}

async fn websocket_client(front: SocketAddr, bearer: &str) -> TcpStream {
    let mut stream = TcpStream::connect(front).await.unwrap();
    stream.write_all(format!("GET /secure/socket HTTP/1.1\r\nHost: jwt.test\r\nAuthorization: Bearer {bearer}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n").as_bytes()).await.unwrap(); // gitleaks:allow -- WebSocket protocol fixture
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(3), async {
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            assert!(head.len() < 8192);
        }
    })
    .await
    .unwrap();
    assert!(
        head.starts_with(b"HTTP/1.1 101"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    stream.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping");
    stream
}

async fn expect_closed(stream: &mut TcpStream, label: &str) {
    let mut byte = [0u8];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match stream.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} remained open"));
}

#[tokio::test]
async fn held_sse_expires_at_the_verified_jwt_deadline_without_leeway() {
    let (upstream, upstream_task) = held_event_origin().await;
    let gateway = lease_gateway(vec![jwt_route(upstream)]).await;
    let mut payload = claims();
    let expires_at = now() + 3;
    payload["exp"] = json!(expires_at);
    let bearer = token(
        json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"fixture-key"}),
        payload,
    );
    let mut stream = TcpStream::connect(gateway.address).await.unwrap();
    stream.write_all(format!("GET /secure/events HTTP/1.1\r\nHost: jwt.test\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    let mut chunk = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(2), async {
        while !response
            .windows(b"data:x\n".len())
            .any(|part| part == b"data:x\n")
        {
            let count = stream.read(&mut chunk).await.unwrap();
            assert!(count > 0, "SSE closed before its first event");
            response.extend_from_slice(&chunk[..count]);
            assert!(response.len() < 8192);
        }
    })
    .await
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    expect_closed(&mut stream, "expired JWT SSE response").await;
    assert!(now() >= expires_at, "SSE closed before JWT expiry");
    gateway.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn authenticated_chunked_upload_stops_at_jwt_expiry_while_client_holds_body_open() {
    let (upstream, mut observed, upstream_task) = held_upload_origin().await;
    let mut route = jwt_route(upstream);
    route["resource_policy"]["allow"][0]["methods"] = json!(["POST"]);
    let gateway = lease_gateway(vec![route]).await;
    let mut payload = claims();
    let expires_at = now() + 3;
    payload["exp"] = json!(expires_at);
    let bearer = token(
        json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"fixture-key"}),
        payload,
    );
    let mut client = TcpStream::connect(gateway.address).await.unwrap();
    client.write_all(format!("POST /secure/upload HTTP/1.1\r\nHost: jwt.test\r\nAuthorization: Bearer {bearer}\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nping\r\n").as_bytes()).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap(),
        "origin did not receive the first authenticated upload chunk"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), observed.recv())
            .await
            .expect("origin upload body remained open after JWT expiry")
            .unwrap(),
        "origin received more upload data after the first chunk"
    );
    assert!(now() >= expires_at, "upload ended before JWT expiry");
    gateway.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn websocket_tunnel_closes_on_jwt_expiry_and_on_route_policy_withdrawal() {
    let (upstream, upstream_task) = websocket_echo_origin().await;
    let gateway = lease_gateway(vec![jwt_route(upstream)]).await;
    let mut payload = claims();
    let expires_at = now() + 3;
    payload["exp"] = json!(expires_at);
    let short = token(
        json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"fixture-key"}),
        payload,
    );
    let mut expiring = websocket_client(gateway.address, &short).await;
    expect_closed(&mut expiring, "expired JWT WebSocket tunnel").await;
    assert!(now() >= expires_at, "WebSocket closed before JWT expiry");

    let long = good_token();
    let mut withdrawn = websocket_client(gateway.address, &long).await;
    let mut changed = jwt_route(upstream);
    changed["resource_policy"]["allow"][0]["subjects"] = json!(["bob"]);
    gateway.publish(vec![changed]);
    expect_closed(
        &mut withdrawn,
        "withdrawn JWT route-policy WebSocket tunnel",
    )
    .await;
    assert_eq!(
        request(gateway.address, "/secure/socket", Some(&long), &[]).await,
        403
    );
    gateway.shutdown().await;
    upstream_task.abort();
}

#[tokio::test]
async fn retiring_one_jwt_route_does_not_close_an_unrelated_http2_stream() {
    let (stream_upstream, stream_task) = held_event_origin().await;
    let (other_upstream, seen, other_task) = origin().await;
    let route_a = jwt_route(stream_upstream);
    let mut route_b = jwt_route(other_upstream);
    route_b["id"] = json!("other");
    route_b["path_prefix"] = json!("/other");
    route_b["resource_policy"]["resource_id"] = json!("other-data");
    let gateway = lease_gateway(vec![route_a.clone(), route_b.clone()]).await;
    let bearer = good_token();
    let socket = TcpStream::connect(gateway.address).await.unwrap();
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake::<_, Full<Bytes>>(TokioIo::new(socket))
        .await
        .unwrap();
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let first = sender
        .send_request(
            Request::builder()
                .uri("http://jwt.test/secure/events")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let mut body = first.into_body();
    let event = tokio::time::timeout(Duration::from_secs(3), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        event
            .into_data()
            .unwrap()
            .windows(b"data:x\n".len())
            .any(|part| part == b"data:x\n")
    );

    let mut changed_a = route_a;
    changed_a["resource_policy"]["allow"][0]["subjects"] = json!(["bob"]);
    gateway.publish(vec![changed_a, route_b]);
    let retired_frame = tokio::time::timeout(Duration::from_secs(3), body.frame())
        .await
        .expect("retired JWT route left its HTTP/2 event stream open");
    assert!(
        retired_frame.is_none() || retired_frame.is_some_and(|frame| frame.is_err()),
        "retired JWT route continued delivering HTTP/2 body data"
    );
    let other = sender
        .send_request(
            Request::builder()
                .uri("http://jwt.test/other/records")
                .header("authorization", format!("Bearer {bearer}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .expect("unrelated JWT route lost its HTTP/2 connection");
    assert_eq!(other.status(), 200);
    assert_eq!(
        other.into_body().collect().await.unwrap().to_bytes(),
        "origin"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);
    connection_task.abort();
    gateway.shutdown().await;
    stream_task.abort();
    other_task.abort();
}
