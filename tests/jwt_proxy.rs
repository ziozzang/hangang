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
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, task::JoinHandle};

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
