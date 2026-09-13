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
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

struct Idp {
    issuer: String,
    ca_pem: String,
    current: Arc<Mutex<(String, String)>>,
    empty_keys: Arc<AtomicBool>,
    unavailable: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

async fn idp(signing: &SigningKey) -> Idp {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut tls = hangang::tls::server_config(
        certificate.cert.pem().as_bytes(),
        certificate.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let current = Arc::new(Mutex::new(("old".into(), public_x(signing))));
    let empty_keys = Arc::new(AtomicBool::new(false));
    let unavailable = Arc::new(AtomicBool::new(false));
    let requests = Arc::new(AtomicUsize::new(0));
    let task = {
        let issuer = issuer.clone();
        let current = current.clone();
        let empty_keys = empty_keys.clone();
        let unavailable = unavailable.clone();
        let requests = requests.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    let Ok(count) = stream.read(&mut chunk).await else {
                        break;
                    };
                    if count == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..count]);
                    if request.windows(4).any(|part| part == b"\r\n\r\n") || request.len() > 4096 {
                        break;
                    }
                }
                requests.fetch_add(1, Ordering::SeqCst);
                let discovery = request.starts_with(b"GET /.well-known/openid-configuration");
                let (kid, x) = current.lock().unwrap().clone();
                let body = if discovery {
                    format!(r#"{{"issuer":"{issuer}","jwks_uri":"{issuer}/keys"}}"#)
                } else if empty_keys.load(Ordering::SeqCst) {
                    r#"{"keys":[]}"#.to_owned()
                } else {
                    format!(
                        r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{kid}","alg":"EdDSA","use":"sig","x":"{x}"}}]}}"#
                    )
                };
                let status = if unavailable.load(Ordering::SeqCst) {
                    "503 Service Unavailable"
                } else {
                    "200 OK"
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        })
    };
    Idp {
        issuer,
        ca_pem: certificate.cert.pem(),
        current,
        empty_keys,
        unavailable,
        requests,
        task,
    }
}

fn public_x(signing: &SigningKey) -> String {
    URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes())
}

fn signed(
    signing: &SigningKey,
    kid: &str,
    subject: &str,
    issuer: &str,
    extra_header: bool,
) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = json!({"alg":"EdDSA", "kid":kid, "typ":"at+jwt"});
    if extra_header {
        header["jku"] = json!("https://untrusted.invalid/keys");
    }
    let claims = json!({
        "iss":issuer, "aud":"api://gateway", "sub":subject, "client_id":"client-1",
        "jti":"token-1", "iat":now.saturating_sub(1), "exp":now+120,
        "scope":"records:read"
    });
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = signing.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

async fn origin() -> (
    SocketAddr,
    Arc<Mutex<Vec<(bool, Option<String>)>>>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let task = {
        let seen = seen.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let seen = seen.clone();
                        async move {
                            seen.lock().unwrap().push((
                                request.headers().contains_key("authorization"),
                                request
                                    .headers()
                                    .get("x-jwt-subject")
                                    .and_then(|v| v.to_str().ok())
                                    .map(str::to_owned),
                            ));
                            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                                b"origin",
                            ))))
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        })
    };
    (addr, seen, task)
}

async fn streaming_origin() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                    let mut buffer = [0u8; 1024];
                    let count = stream.read(&mut buffer).await.unwrap();
                    assert!(count > 0);
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 8192);
                }
                if request.starts_with(b"GET /events ") {
                    stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n7\r\ndata:x\n\r\n").await.unwrap();
                    std::future::pending::<()>().await;
                } else {
                    stream.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 6\r\nconnection: close\r\n\r\norigin").await.unwrap();
                }
            });
        }
    });
    (address, task)
}

async fn held_event(front: SocketAddr, bearer: &str) -> tokio::net::TcpStream {
    let mut stream = tokio::net::TcpStream::connect(front).await.unwrap();
    stream.write_all(format!("GET /events HTTP/1.1\r\nHost: jwt.test\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), async {
        while !response.windows(7).any(|part| part == b"data:x\n") {
            let mut buffer = [0u8; 1024];
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "held response ended before first SSE event");
            response.extend_from_slice(&buffer[..count]);
            assert!(response.len() < 8192);
        }
    })
    .await
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    stream
}

async fn assert_held_event_closes(stream: &mut tokio::net::TcpStream, reason: &str) {
    let mut buffer = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{reason} left the held SSE stream open"));
}

async fn frontend(proxy: Proxy) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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
    (addr, task)
}

async fn request(front: SocketAddr, token: Option<&str>, method: Method) -> StatusCode {
    let client: Client<HttpConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{front}/records"))
        .header("host", "jwt.test");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let request = builder.body(Full::new(Bytes::new())).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), client.request(request))
        .await
        .unwrap()
        .unwrap();
    let status = response.status();
    response.into_body().collect().await.unwrap();
    status
}

#[tokio::test]
async fn remote_oidc_jwks_jwt_proxy_rotates_and_fails_closed_after_hard_expiry() {
    let old_signing = SigningKey::from_bytes(&[31; 32]);
    let new_signing = SigningKey::from_bytes(&[32; 32]);
    let idp = idp(&old_signing).await;
    let (origin_addr, seen, origin_task) = origin().await;
    let document: Value = json!({"http":[{
        "id":"jwt", "host":"jwt.test", "access_mode":"protected",
        "backends":[format!("http://{origin_addr}")],
        "jwt_auth": {
            "verification":{"issuer":idp.issuer,"audiences":["api://gateway"],"profile":"rfc9068", "algorithms":["EdDSA"],"required_scopes":["records:read"]},
            "keys":{"source":"remote","config":{"endpoint":{"kind":"oidc"},"cache_ttl_seconds":2,"refresh_cooldown_seconds":1,"timeout_ms":3000,"ca_pem":idp.ca_pem}},
            "identity_header":"x-jwt-subject"
        },
        "resource_policy":{"resource_id":"records","principal":{"source":"jwt"},"allow":[{"subjects":["alice"],"methods":["GET"]}]}
    }]});
    let config: Config = serde_json::from_value(document).unwrap();
    config.validate().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task) = frontend(proxy).await;

    let old = signed(&old_signing, "old", "alice", &idp.issuer, false);
    assert_eq!(
        request(front, None, Method::GET).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        idp.requests.load(Ordering::SeqCst),
        0,
        "missing Bearer token causes no IdP fetch"
    );
    assert_eq!(
        request(front, Some(&old), Method::GET).await,
        StatusCode::OK
    );
    assert_eq!(
        idp.requests.load(Ordering::SeqCst),
        2,
        "one discovery and one JWKS request"
    );
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        &[(false, Some("alice".into()))]
    );

    let disallowed = signed(&old_signing, "old", "bob", &idp.issuer, false);
    assert_eq!(
        request(front, Some(&disallowed), Method::GET).await,
        StatusCode::FORBIDDEN
    );
    let before_injected = idp.requests.load(Ordering::SeqCst);
    let injected_url = signed(&old_signing, "old", "alice", &idp.issuer, true);
    assert_eq!(
        request(front, Some(&injected_url), Method::GET).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        idp.requests.load(Ordering::SeqCst),
        before_injected,
        "token-supplied jku must never fetch"
    );
    assert_eq!(seen.lock().unwrap().len(), 1);

    *idp.current.lock().unwrap() = ("new".into(), public_x(&new_signing));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let new = signed(&new_signing, "new", "alice", &idp.issuer, false);
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::OK
    );
    assert_eq!(seen.lock().unwrap().len(), 2);
    assert_eq!(
        request(front, Some(&old), Method::GET).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "removed key cannot reach origin"
    );

    idp.unavailable.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "hard expiry cannot use stale signing key"
    );

    idp.unavailable.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::OK
    );
    assert_eq!(seen.lock().unwrap().len(), 3);
    front_task.abort();
    origin_task.abort();
    idp.task.abort();
    policy.shutdown().await;
}

#[tokio::test]
async fn remote_key_withdrawal_and_hard_expiry_close_existing_event_streams() {
    let old_signing = SigningKey::from_bytes(&[41; 32]);
    let new_signing = SigningKey::from_bytes(&[42; 32]);
    let idp = idp(&old_signing).await;
    let (origin_address, origin_task) = streaming_origin().await;
    let document: Value = json!({"http":[{
        "id":"jwt-events", "host":"jwt.test", "access_mode":"protected",
        "backends":[format!("http://{origin_address}")],
        "jwt_auth": {
            "verification":{"issuer":idp.issuer,"audiences":["api://gateway"],"profile":"rfc9068","algorithms":["EdDSA"]},
            "keys":{"source":"remote","config":{"endpoint":{"kind":"oidc"},"cache_ttl_seconds":2,"refresh_cooldown_seconds":1,"timeout_ms":3000,"ca_pem":idp.ca_pem}}
        },
        "resource_policy":{"resource_id":"events","principal":{"source":"jwt"},"allow":[{"subjects":["alice"],"methods":["GET"]}]}
    }]});
    let config: Config = serde_json::from_value(document).unwrap();
    config.validate().unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()));
    let (front, front_task) = frontend(proxy).await;

    let old = signed(&old_signing, "old", "alice", &idp.issuer, false);
    let mut old_stream = held_event(front, &old).await;
    // The same public key refreshes after the midpoint without revoking a valid session.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        request(front, Some(&old), Method::GET).await,
        StatusCode::OK
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), old_stream.read_u8())
            .await
            .is_err(),
        "unchanged JWKS refresh ended a valid held session"
    );

    *idp.current.lock().unwrap() = ("new".into(), public_x(&new_signing));
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let new = signed(&new_signing, "new", "alice", &idp.issuer, false);
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::OK
    );
    assert_held_event_closes(&mut old_stream, "removed signing key").await;

    let mut new_stream = held_event(front, &new).await;
    idp.empty_keys.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::UNAUTHORIZED,
        "a valid empty JWKS must withdraw the final signing key"
    );
    assert_held_event_closes(&mut new_stream, "empty JWKS key withdrawal").await;

    idp.empty_keys.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::OK
    );
    let mut restored_stream = held_event(front, &new).await;
    idp.unavailable.store(true, Ordering::SeqCst);
    // Once the last successfully fetched keys pass their hard TTL, outage must not
    // let the already admitted SSE response continue indefinitely.
    assert_held_event_closes(&mut restored_stream, "expired JWKS during IdP outage").await;
    assert_eq!(
        request(front, Some(&new), Method::GET).await,
        StatusCode::SERVICE_UNAVAILABLE
    );

    front_task.abort();
    origin_task.abort();
    idp.task.abort();
    policy.shutdown().await;
}
