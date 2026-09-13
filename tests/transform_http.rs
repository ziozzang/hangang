use arc_swap::ArcSwap;
use bytes::Bytes;
use hangang::{
    config::{Config, Snapshot},
    metrics::Metrics,
    policy::PolicyPool,
    proxy::{Proxy, response},
};
use http_body_util::{BodyExt, StreamBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinHandle};

struct Fixture {
    url: String,
    seen: Arc<Mutex<Vec<(hyper::HeaderMap, Bytes)>>>,
    tasks: Vec<JoinHandle<()>>,
    pool: Arc<PolicyPool>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn fixture(request_transform: Value, response_transform: Value, limit: usize) -> Fixture {
    fixture_with_policy(request_transform, response_transform, limit, None).await
}
async fn fixture_with_policy(
    request_transform: Value,
    response_transform: Value,
    limit: usize,
    lua: Option<&str>,
) -> Fixture {
    fixture_with_protocol(request_transform, response_transform, limit, lua, false).await
}
async fn fixture_with_protocol(
    request_transform: Value,
    response_transform: Value,
    limit: usize,
    lua: Option<&str>,
    h2: bool,
) -> Fixture {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let records = seen.clone();
    let upstream_task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let records = records.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let records = records.clone();
                    async move {
                        let path = request.uri().path().to_owned();
                        let (parts, body) = request.into_parts();
                        let body = match body.collect().await {
                            Ok(body) => body.to_bytes(),
                            Err(_) => {
                                return Ok::<_, Infallible>(response(400, "upstream body error"));
                            }
                        };
                        records.lock().unwrap().push((parts.headers, body.clone()));
                        let mut reply = match path.as_str() {
                            "/json" => response(200, r#"{"secret":"upstream","keep":"한강"}"#),
                            "/xml" => {
                                response(200, "<root><secret>x</secret><keep>yes</keep></root>")
                            }
                            "/204" => response(204, ""),
                            "/205" => response(205, ""),
                            "/304" => response(304, ""),
                            "/206" => response(206, "partial"),
                            "/slow" | "/bad-stream" | "/events" => {
                                let events: Vec<(u64, &'static [u8])> = match path.as_str() {
                                    "/slow" => vec![(200, b"late")],
                                    "/events" => vec![
                                        (0, b"data: {\"secret\":true,\"n\":1}\n\n"),
                                        (200, b"data: {\"secret\":false,\"n\":2}\n\n"),
                                    ],
                                    _ => vec![(0, b"{}\n"), (100, b"not-json\n")],
                                };
                                let stream = futures_util::stream::unfold(
                                    events.into_iter(),
                                    |mut events| async move {
                                        let (delay, data) = events.next()?;
                                        tokio::time::sleep(Duration::from_millis(delay)).await;
                                        Some((
                                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                                data,
                                            ))),
                                            events,
                                        ))
                                    },
                                );
                                Response::new(
                                    StreamBody::new(stream)
                                        .map_err(|never| match never {})
                                        .boxed_unsync(),
                                )
                            }
                            _ => Response::new(
                                http_body_util::Full::new(body)
                                    .map_err(|never| match never {})
                                    .boxed_unsync(),
                            ),
                        };
                        reply
                            .headers_mut()
                            .insert("etag", "\"old\"".parse().unwrap());
                        reply
                            .headers_mut()
                            .insert("digest", "stale".parse().unwrap());
                        reply
                            .headers_mut()
                            .append("set-cookie", "a=1".parse().unwrap());
                        reply
                            .headers_mut()
                            .append("set-cookie", "b=2".parse().unwrap());
                        if path == "/compressed" {
                            reply
                                .headers_mut()
                                .insert("content-encoding", "gzip".parse().unwrap());
                        }
                        if path == "/no-transform" {
                            reply
                                .headers_mut()
                                .insert("cache-control", "public, no-transform".parse().unwrap());
                        }
                        Ok::<_, Infallible>(reply)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    let cfg:Config=serde_json::from_value(json!({"http":[{"id":"transform","backends":[format!("http://{upstream}")],"request_transform":request_transform,"response_transform":response_transform,"lua":lua}]})).unwrap();
    cfg.validate().unwrap();
    let pool = Arc::new(PolicyPool::new(env!("CARGO_BIN_EXE_hangang").into(), 4));
    let proxy = Proxy::new(
        Arc::new(ArcSwap::from_pointee(Snapshot::new(cfg).unwrap())),
        pool.clone(),
        Arc::new(Metrics::default()),
    )
    .with_transform_limit(limit);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                break;
            };
            let proxy = proxy.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let proxy = proxy.clone();
                    async move { proxy.handle(request, peer).await }
                });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
                } else {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                }
            });
        }
    });
    Fixture {
        url: format!("http://{address}"),
        seen,
        tasks: vec![task, upstream_task],
        pool,
    }
}
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap()
}

#[tokio::test]
async fn native_request_response_json_headers_and_repeated_cookies() {
    let f=fixture(json!({"operations":[{"op":"json_set","pointer":"/source","value":"gateway"}],"set_headers":{"x-native":"request"},"remove_headers":["x-remove"]}),json!({"operations":[{"op":"json_remove","pointer":"/secret"}],"set_headers":{"x-native":"response"}}),1).await;
    let reply = client()
        .post(format!("{}/echo", f.url))
        .header("x-remove", "old")
        .header("digest", "stale")
        .body(r#"{"secret":true,"keep":42}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.headers()["x-native"], "response");
    assert!(!reply.headers().contains_key("etag"));
    assert!(!reply.headers().contains_key("digest"));
    assert_eq!(reply.headers().get_all("set-cookie").iter().count(), 2);
    assert_eq!(
        reply.json::<Value>().await.unwrap(),
        json!({"keep":42,"source":"gateway"})
    );
    {
        let seen = f.seen.lock().unwrap();
        assert_eq!(seen[0].0["x-native"], "request");
        assert!(!seen[0].0.contains_key("x-remove"));
        assert!(!seen[0].0.contains_key("digest"));
        assert_eq!(seen[0].0["accept-encoding"], "identity");
        assert_eq!(
            serde_json::from_slice::<Value>(&seen[0].1).unwrap(),
            json!({"secret":true,"keep":42,"source":"gateway"})
        );
    }
    f.pool.shutdown().await;
}

#[tokio::test]
async fn native_xml_both_directions_are_structural_and_escape_text() {
    let f = fixture(
        json!({"operations":[{"op":"xml_set_text","path":"/root/keep","value":"<new>&value"}]}),
        json!({"operations":[{"op":"xml_remove","path":"/root/secret"}]}),
        1,
    )
    .await;
    let reply = client()
        .post(format!("{}/echo", f.url))
        .body("<root><secret>private</secret><keep>old</keep></root>")
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    let body = reply.text().await.unwrap();
    assert!(!body.contains("secret"));
    assert!(body.contains("&lt;new&gt;&amp;value"));
    f.pool.shutdown().await;
}

#[tokio::test]
async fn encoded_range_conditional_upgrade_and_no_transform_are_explicit_failures() {
    let f = fixture(json!({}), json!({}), 2).await;
    let c = client();
    for (path, name, value, status) in [
        ("/echo", "content-encoding", "gzip", 415),
        ("/echo", "content-range", "bytes 0-3/10", 400),
        ("/echo", "range", "bytes=0-2", 416),
        ("/echo", "if-none-match", "old", 412),
        ("/echo", "upgrade", "websocket", 400),
        ("/echo", "cache-control", "no-transform", 400),
        ("/compressed", "x-test", "yes", 502),
        ("/no-transform", "x-test", "yes", 502),
        ("/206", "x-test", "yes", 502),
    ] {
        assert_eq!(
            c.post(format!("{}{path}", f.url))
                .header(name, value)
                .body("body")
                .send()
                .await
                .unwrap()
                .status(),
            status,
            "{path} {name}"
        );
    }
    f.pool.shutdown().await;
}

#[tokio::test]
async fn head_and_bodyless_statuses_skip_body_parsing() {
    let f = fixture(
        Value::Null,
        json!({"operations":[{"op":"json_remove","pointer":"/secret"}]}),
        1,
    )
    .await;
    let c = client();
    let reply = c.head(format!("{}/json", f.url)).send().await.unwrap();
    assert_eq!(reply.status(), 200);
    assert!(!reply.headers().contains_key("etag"));
    assert!(reply.bytes().await.unwrap().is_empty());
    let head = c
        .head(format!("{}/compressed", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(head.status(), 200);
    assert!(!head.headers().contains_key("content-encoding"));
    for code in [204, 205, 304] {
        let reply = c.get(format!("{}/{code}", f.url)).send().await.unwrap();
        assert_eq!(reply.status(), code);
        assert!(reply.bytes().await.unwrap().is_empty());
    }
    f.pool.shutdown().await;
}

#[tokio::test]
async fn body_limits_malformed_xml_and_timeouts_are_contained() {
    let f = fixture(
        json!({"max_buffer_bytes":4}),
        json!({"max_buffer_bytes":4,"timeout_ms":20}),
        1,
    )
    .await;
    let c = client();
    assert_eq!(
        c.post(format!("{}/echo", f.url))
            .body("12345")
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        c.get(format!("{}/json", f.url))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    assert_eq!(
        c.get(format!("{}/slow", f.url))
            .send()
            .await
            .unwrap()
            .status(),
        504
    );
    assert_eq!(
        c.post(format!("{}/echo", f.url))
            .body("ok")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap(),
        "ok"
    );
    f.pool.shutdown().await;
    let f = fixture(
        json!({"operations":[{"op":"xml_remove","path":"/root/secret"}]}),
        Value::Null,
        1,
    )
    .await;
    assert_eq!(c.post(format!("{}/echo",f.url)).body("<!DOCTYPE root [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><root>&secret;</root>").send().await.unwrap().status(),400);
    assert!(f.seen.lock().unwrap().is_empty());
    f.pool.shutdown().await;
}

#[tokio::test]
async fn sse_flushes_before_eof_and_admission_rejects_then_recovers() {
    let f = fixture(
        Value::Null,
        json!({"mode":"sse","operations":[{"op":"json_remove","pointer":"/secret"}]}),
        1,
    )
    .await;
    let c = client();
    let mut first = c.get(format!("{}/events", f.url)).send().await.unwrap();
    let chunk = tokio::time::timeout(Duration::from_millis(100), first.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(chunk, b"data: {\"n\":1}\n\n"[..]);
    let second = c.get(format!("{}/events", f.url)).send().await.unwrap();
    assert_eq!(second.status(), 503);
    assert_eq!(first.bytes().await.unwrap(), b"data: {\"n\":2}\n\n"[..]);
    let third = c.get(format!("{}/events", f.url)).send().await.unwrap();
    assert_eq!(third.status(), 200);
    drop(third);
    f.pool.shutdown().await;
}

#[tokio::test]
async fn malformed_later_stream_record_aborts_instead_of_silent_success() {
    let f = fixture(Value::Null, json!({"mode":"ndjson"}), 1).await;
    let mut reply = client()
        .get(format!("{}/bad-stream", f.url))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.chunk().await.unwrap().unwrap(), b"{}\n"[..]);
    assert!(reply.bytes().await.is_err());
    f.pool.shutdown().await;
}

#[tokio::test]
async fn lua_body_failure_does_not_crash_gateway_or_poison_next_request() {
    let script = "local v = hangang.json_decode(hangang.body()); if v.loop then while true do end end; v.secret = nil; v.phase = hangang.phase(); return hangang.json_encode(v)";
    let f = fixture(
        json!({"lua":script,"max_buffer_bytes":16384,"max_output_bytes":16384}),
        Value::Null,
        1,
    )
    .await;
    let c = client();
    assert_eq!(
        c.post(format!("{}/echo", f.url))
            .json(&json!({"loop":true}))
            .send()
            .await
            .unwrap()
            .status(),
        503
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    let reply = c
        .post(format!("{}/echo", f.url))
        .json(&json!({"secret":true,"keep":1}))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(
        reply.json::<Value>().await.unwrap(),
        json!({"keep":1,"phase":"request"})
    );
    f.pool.shutdown().await;
}

#[tokio::test]
async fn chunked_streaming_upload_transforms_records_before_backend_consumption() {
    let f = fixture(
        json!({"mode":"ndjson","operations":[{"op":"json_remove","pointer":"/secret"}]}),
        Value::Null,
        1,
    )
    .await;
    let parts = vec![
        b"{\"n\":1,\"sec".to_vec(),
        b"ret\":true}\r".to_vec(),
        b"\n{\"n\":2,\"secret\":false}\n".to_vec(),
    ];
    let stream = futures_util::stream::iter(parts.into_iter().map(Ok::<_, std::io::Error>));
    let reply = client()
        .post(format!("{}/echo", f.url))
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 200);
    assert_eq!(reply.text().await.unwrap(), "{\"n\":1}\n{\"n\":2}\n");
    f.pool.shutdown().await;
}

#[tokio::test]
async fn policy_mutations_cannot_bypass_transform_representation_checks() {
    for (header, value, status) in [
        ("content-range", "bytes 0-3/10", 400),
        ("range", "bytes=0-2", 416),
        ("if-none-match", "old", 412),
        ("cache-control", "no-transform", 400),
    ] {
        let lua = format!("hangang.set_header({header:?}, {value:?})");
        let f = fixture_with_policy(json!({}), json!({}), 1, Some(&lua)).await;
        let reply = client()
            .post(format!("{}/echo", f.url))
            .body("body")
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), status, "{header}");
        assert!(f.seen.lock().unwrap().is_empty());
        f.pool.shutdown().await;
    }
}

#[tokio::test]
async fn http2_transform_failure_resets_only_the_affected_stream() {
    let f = fixture_with_protocol(
        Value::Null,
        json!({"mode":"ndjson","operations":[{"op":"json_remove","pointer":"/secret"}]}),
        4,
        None,
        true,
    )
    .await;
    let c = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    // First record lacks /secret, so this stream must fail rather than bypass its transform.
    let bad = c.get(format!("{}/bad-stream", f.url)).send().await;
    if let Ok(reply) = bad {
        assert!(reply.bytes().await.is_err());
    }
    let good = c.get(format!("{}/json", f.url)).send().await.unwrap();
    assert_eq!(good.version(), reqwest::Version::HTTP_2);
    assert_eq!(good.json::<Value>().await.unwrap(), json!({"keep":"한강"}));
    f.pool.shutdown().await;
}

#[tokio::test]
async fn chunked_get_body_survives_a_streaming_request_transform() {
    // A transformed request body has no known length. The HTTP/1 client
    // encoder assumes a GET body without explicit framing is empty, so the
    // upstream used to receive a bodyless GET; the gateway now regenerates
    // chunked framing for every unknown-length body.
    let f = fixture(
        json!({"mode":"ndjson","operations":[{"op":"json_remove","pointer":"/secret"}]}),
        Value::Null,
        1,
    )
    .await;
    // Sent over a raw socket: an HTTP client library would itself drop an
    // unknown-length GET body before it ever reached the gateway.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let address = f.url.strip_prefix("http://").unwrap();
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream
        .write_all(
            b"GET /echo HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
              16\r\n{\"n\":1,\"secret\":true}\n\r\n\
              17\r\n{\"n\":2,\"secret\":false}\n\r\n\
              0\r\n\r\n",
        )
        .await
        .unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw);
    assert!(text.starts_with("HTTP/1.1 200"), "{text}");
    assert!(text.ends_with("{\"n\":1}\n{\"n\":2}\n"), "{text}");
    {
        let seen = f.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].1, "{\"n\":1}\n{\"n\":2}\n");
    }
    f.pool.shutdown().await;
}
