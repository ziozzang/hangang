//! End-to-end decision events through the real proxy: protected requests are
//! recorded with stable reasons, unprotected traffic is not, and no header,
//! cookie, body, query string, raw path or credential reaches the exporter.

use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::config::{Config, Snapshot};
use hangang::decision::{self, schema};
use hangang::metrics::Metrics;
use hangang::policy::PolicyPool;
use hangang::proxy::Proxy;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

const SECRETS: &[&str] = &[
    "SECRETQUERY",
    "SECRETCOOKIE",
    "SECRETHEADER",
    "SECRETBODY",
    "s3cret-password",
    "wrong-password",
    "secret-path",
    "Basic ",
    "alice",
];

async fn origin() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let _ = request.into_body().collect().await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    address
}

async fn frontend(proxy: Proxy) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, peer)) = listener.accept().await {
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
    address
}

#[tokio::test]
async fn protected_decisions_are_recorded_without_request_content() {
    let dir = tempfile::tempdir().unwrap();
    let backend = origin().await;
    let credential = hangang::basic_auth::hash_credential("alice", "s3cret-password").unwrap();
    let config: Config = serde_json::from_value(serde_json::json!({
        "revision": 11,
        "http": [
            {"id": "app", "hosts": ["app.example"], "path_prefix": "/", "priority": 10,
             "backends": [format!("http://{backend}")], "access_mode": "protected",
             "basic_auth": {"realm": "app", "credentials": [credential]}},
            {"id": "site", "hosts": ["public.example"], "path_prefix": "/",
             "backends": [format!("http://{backend}")]}
        ]
    }))
    .unwrap();
    let active = Arc::new(ArcSwap::from_pointee(Snapshot::new(config).unwrap()));
    let policy = Arc::new(PolicyPool::new(std::env::current_exe().unwrap(), 1));
    let decisions: decision::Config = serde_json::from_value(serde_json::json!({
        "profile": "standard",
        "exporter_socket": dir.path().join("ingest.sock"),
        "key_file": dir.path().join("keys.json"),
        "manage_keys": true,
        "routes": {"app": {"audit_all": true}},
        "rings": {"shards": 2},
    }))
    .unwrap();
    let emitter = decision::Emitter::new(decisions).unwrap().unwrap();
    let rng = ring::rand::SystemRandom::new();
    decision::drain::KeyKeeper::new().tick(&emitter, &rng, true);
    let proxy = Proxy::new(active, policy.clone(), Arc::new(Metrics::default()))
        .with_decision_events(Some(emitter.clone()));
    let front = frontend(proxy).await;
    let client = hyper_util::client::legacy::Client::builder(TokioExecutor::new())
        .build(hyper_util::client::legacy::connect::HttpConnector::new());
    let send = |host: &'static str, authorization: Option<String>| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "http://{front}/secret-path/item?token=SECRETQUERY&x=1"
            ))
            .header("host", host)
            .header("cookie", "session=SECRETCOOKIE")
            .header("x-api-key", "SECRETHEADER");
        if let Some(value) = authorization {
            request = request.header("authorization", value);
        }
        let request = request
            .body(Full::new(Bytes::from_static(b"SECRETBODY")))
            .unwrap();
        let client = client.clone();
        async move {
            let response = client.request(request).await.unwrap();
            let status = response.status().as_u16();
            let _ = response.into_body().collect().await;
            status
        }
    };
    use base64::Engine;
    let basic = |user: &str, password: &str| {
        Some(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
        ))
    };
    assert_eq!(send("app.example", None).await, 401);
    assert_eq!(
        send("app.example", basic("alice", "wrong-password")).await,
        401
    );
    assert_eq!(
        send("app.example", basic("alice", "s3cret-password")).await,
        200
    );
    // Unprotected traffic produces no decision event.
    assert_eq!(send("public.example", None).await, 200);

    let listener = tokio::net::UnixListener::bind(dir.path().join("ingest.sock")).unwrap();
    let keys = emitter.keys.load_full();
    let cx = decision::drain::Context {
        keys: &keys,
        profile: emitter.profile(),
        instance: "gw-test",
        build: "test",
        rng: &rng,
    };
    let mut connection = decision::drain::ConnectionState::new();
    let (accepted, ()) = tokio::join!(listener.accept(), async {
        decision::drain::drain_once(&emitter, &cx, &mut connection).await;
    });
    let (mut stream, _) = accepted.unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let mut payload = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut payload).await.unwrap();

    // Nothing from the request survives in the exported bytes.
    let text = String::from_utf8_lossy(&payload);
    for secret in SECRETS {
        assert!(!text.contains(secret), "exported bytes contain {secret}");
    }
    assert!(!payload.windows(4).any(|w| w == [127, 0, 0, 1]));

    let mut events: Vec<_> = schema::split_payload(&payload)
        .unwrap()
        .into_iter()
        .map(|bytes| schema::decode(bytes).unwrap())
        .collect();
    events.sort_by_key(|e| e.time_unix_ms);
    assert_eq!(events.len(), 3, "public traffic must not be recorded");
    let reasons: Vec<_> = events
        .iter()
        .map(|e| e.outcome.as_ref().unwrap().reason.clone())
        .collect();
    assert_eq!(
        reasons
            .iter()
            .filter(|r| *r == "hangang.basic_denied")
            .count(),
        2
    );
    assert!(reasons.contains(&"hangang.allowed".to_owned()));
    for event in &events {
        let json = schema::to_json(event);
        let rendered = json.to_string();
        for secret in SECRETS {
            assert!(!rendered.contains(secret), "projection contains {secret}");
        }
        assert_eq!(json["route"]["route_id"], "app");
        assert_eq!(json["route"]["path_template"], "/");
        assert_eq!(json["route"]["method"], "POST");
        assert_eq!(json["revisions"]["hangang"], 11);
        assert_eq!(json["emitter"]["instance"], "gw-test");
        assert!(
            json["stages"][0]["client"]["ip_ref"]
                .as_str()
                .unwrap()
                .starts_with("ip~")
        );
        let identity = &json["stages"][1];
        assert_eq!(identity["stage"], "identity");
        assert_eq!(identity["authority"], "hangang");
        assert_eq!(identity["factors"][0], "password");
        if json["outcome"]["result"] == "allow" {
            assert_eq!(identity["verdict"], "authenticated");
            assert!(
                identity["subject_ref"]
                    .as_str()
                    .unwrap()
                    .starts_with("sub~")
            );
            assert_eq!(identity["subject_sealed"], true);
            assert_eq!(json["sampling"]["class"], "audit");
        } else {
            assert_eq!(json["outcome"]["result"], "challenge");
            assert_eq!(json["outcome"]["deciding_stage"], "identity");
            assert_eq!(identity["verdict"], "challenge");
            assert!(identity["subject_ref"].is_null());
        }
    }
    // The pseudonym is the keyed subject of the authenticated user.
    let allowed = events
        .iter()
        .find(|e| e.outcome.as_ref().unwrap().result == schema::v1::Result::Allow as i32)
        .unwrap();
    let json = schema::to_json(allowed);
    let epoch = keys.epoch_index(allowed.time_unix_ms);
    assert_eq!(
        json["stages"][1]["subject_ref"],
        keys.subject_ref(epoch, b"alice").unwrap()
    );
    policy.shutdown().await;
}

#[tokio::test]
async fn admin_observability_apis_report_disabled_when_off() {
    let reply =
        decision::broker::handle(None, "/v1/observability/decisions", Some("outcome=deny")).await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body["state"], "disabled");
    let reply = decision::broker::handle(None, "/v1/observability/requests/hg-1", None).await;
    assert_eq!(reply.body["state"], "disabled");
    let reply = decision::broker::handle(None, "/v1/observability/unknown", None).await;
    assert_eq!(reply.status, 404);
}
