use hangang_decision_event::{self as schema, v1};
use hangang_decision_exporter::query::{self, Filters};
use hangang_decision_exporter::store::{Limits, PARTITION_MS, Store};
use hangang_decision_exporter::{Counters, accept_payload, now_ms};
use prost::Message;
use std::sync::atomic::Ordering;
use std::time::Duration;

struct Spec {
    time: u64,
    seed: u8,
    result: v1::Result,
    reason: &'static str,
    route: &'static str,
    subject: u8,
    kind: v1::Kind,
    ppm: u32,
    request: Option<&'static str>,
}

impl Default for Spec {
    fn default() -> Self {
        Self {
            time: now_ms() - 60_000,
            seed: 0,
            result: v1::Result::Deny,
            reason: "pumgye.class_denied",
            route: "app",
            subject: 1,
            kind: v1::Kind::Enforced,
            ppm: 1_000_000,
            request: None,
        }
    }
}

fn event(spec: Spec) -> (v1::DecisionEvent, Vec<u8>) {
    let mut random = [0u8; 10];
    random[0] = spec.seed;
    random[1] = spec.subject;
    let event = v1::DecisionEvent {
        schema: schema::SCHEMA.into(),
        event_id: schema::event_id(spec.time, random).to_vec(),
        kind: spec.kind as i32,
        request_id: spec.request.map(str::to_owned).unwrap_or_else(|| {
            format!(
                "hg-{:016x}",
                u64::from(spec.seed) << 8 | u64::from(spec.subject)
            )
        }),
        time_unix_ms: spec.time,
        emitter: Some(v1::Emitter {
            component: "hangang".into(),
            ..Default::default()
        }),
        route: Some(v1::Route {
            route_id: spec.route.into(),
            method: "GET".into(),
            service: "reports".into(),
            ..Default::default()
        }),
        outcome: Some(v1::Outcome {
            result: spec.result as i32,
            status: 403,
            deciding_stage: v1::Stage::Authorization as i32,
            reason: spec.reason.into(),
        }),
        stages: vec![v1::StageVerdict {
            stage: Some(v1::stage_verdict::Stage::Identity(v1::IdentityStage {
                subject_ref: schema::pseudonym("sub", &[spec.subject; 32]),
                principal: v1::PrincipalKind::Human as i32,
                ..Default::default()
            })),
        }],
        revisions: Some(v1::Revisions {
            hangang: Some(3),
            pumgye: Some(77),
            ..Default::default()
        }),
        sampling: Some(v1::Sampling {
            class: v1::SampleClass::Deny as i32,
            rate_ppm: spec.ppm,
        }),
        privacy: Some(v1::Privacy {
            profile: v1::PrivacyProfile::Strict as i32,
            key_epoch: "2026-10-16".into(),
        }),
        suppressed: None,
    };
    let bytes = event.encode_to_vec();
    (event, bytes)
}

fn store(dir: &tempfile::TempDir, limits: Limits) -> Store {
    Store::open(&dir.path().join("decisions.db"), limits).unwrap()
}

fn page(store: &Store, query: &str) -> serde_json::Value {
    let conn = Store::reader(store.path()).unwrap();
    let filters = Filters::parse(Some(query), now_ms()).unwrap();
    query::list(&conn, &filters).unwrap()
}

#[test]
fn duplicate_event_ids_are_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = store(&dir, Limits::default());
    let one = event(Spec::default());
    let outcome = store.insert(&[one.clone(), one.clone()]).unwrap();
    assert_eq!((outcome.inserted, outcome.duplicates), (1, 1));
    let outcome = store.insert(&[one]).unwrap();
    assert_eq!((outcome.inserted, outcome.duplicates), (0, 1));
}

#[test]
fn byte_cap_drops_whole_oldest_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let limits = Limits {
        max_bytes: 1024 * 1024,
        max_age: Duration::from_secs(30 * 86_400),
    };
    let mut store = store(&dir, limits.clone());
    let now = now_ms();
    // 24 hourly partitions of 200 events each: well above the 1 MiB cap.
    for hour in 0..24u64 {
        let time = now - (24 - hour) * PARTITION_MS;
        let batch: Vec<_> = (0..200u32)
            .map(|i| {
                event(Spec {
                    time: time + u64::from(i),
                    seed: hour as u8,
                    subject: (i % 250) as u8,
                    ..Default::default()
                })
            })
            .collect();
        store.insert(&batch).unwrap();
        store.enforce(now).unwrap();
        assert!(store.used_bytes().unwrap() <= limits.max_bytes);
    }
    let status = store.status().unwrap();
    let oldest = status["oldest_partition_start_ms"].as_u64().unwrap();
    assert!(oldest > (now - 24 * PARTITION_MS) / PARTITION_MS * PARTITION_MS);
    // The newest partition survives.
    assert_eq!(
        status["newest_partition_start_ms"].as_u64().unwrap(),
        (now - PARTITION_MS) / PARTITION_MS * PARTITION_MS
    );
    assert!(store.file_bytes().unwrap() <= limits.max_bytes);
}

#[test]
fn age_cap_drops_expired_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = store(
        &dir,
        Limits {
            max_bytes: 64 * 1024 * 1024,
            max_age: Duration::from_secs(7 * 86_400),
        },
    );
    let now = now_ms();
    store
        .insert(&[
            event(Spec {
                time: now - 8 * 86_400_000,
                seed: 1,
                ..Default::default()
            }),
            event(Spec {
                time: now - 3_600_000,
                seed: 2,
                ..Default::default()
            }),
        ])
        .unwrap();
    let enforced = store.enforce(now).unwrap();
    assert_eq!((enforced.partitions_dropped, enforced.rows_dropped), (1, 1));
    assert_eq!(store.status().unwrap()["rows"], 1);
}

#[test]
fn retention_limits_are_bounded() {
    assert!(
        Limits {
            max_bytes: 1 << 30,
            max_age: Duration::from_secs(91 * 86_400)
        }
        .validate()
        .is_err()
    );
    assert!(
        Limits {
            max_bytes: 1024,
            max_age: Duration::from_secs(86_400)
        }
        .validate()
        .is_err()
    );
}

#[test]
fn filters_combine_and_pagination_is_complete_and_stable() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = store(&dir, Limits::default());
    let now = now_ms();
    let mut batch = Vec::new();
    for i in 0..7u8 {
        batch.push(event(Spec {
            time: now - 600_000 + u64::from(i) * 1000,
            seed: i,
            subject: if i % 2 == 0 { 1 } else { 2 },
            ..Default::default()
        }));
    }
    batch.push(event(Spec {
        seed: 50,
        result: v1::Result::Allow,
        reason: "hangang.allowed",
        route: "other",
        ppm: 10_000,
        ..Default::default()
    }));
    batch.push(event(Spec {
        seed: 51,
        kind: v1::Kind::Simulation,
        ..Default::default()
    }));
    store.insert(&batch).unwrap();

    // Simulation events are excluded from traffic by default.
    assert_eq!(
        page(&store, "limit=200")["items"].as_array().unwrap().len(),
        8
    );
    assert_eq!(
        page(&store, "kind=simulation")["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    // Combined filters.
    let subject = schema::pseudonym("sub", &[1; 32]);
    let filtered = page(
        &store,
        &format!("outcome=deny&reason=pumgye.class_denied&route=app&subject_ref={subject}"),
    );
    assert_eq!(filtered["items"].as_array().unwrap().len(), 4);
    let allowed = page(&store, "outcome=allow");
    assert_eq!(allowed["items"][0]["estimate_weight"], 100.0);

    // Cursor pagination visits each row exactly once, newest first.
    let mut seen = Vec::new();
    let mut cursor = String::new();
    loop {
        let query = if cursor.is_empty() {
            "outcome=deny&limit=3".to_owned()
        } else {
            format!("outcome=deny&limit=3&cursor={cursor}")
        };
        let result = page(&store, &query);
        for item in result["items"].as_array().unwrap() {
            seen.push(item["event_id"].as_str().unwrap().to_owned());
        }
        match result["next_cursor"].as_str() {
            Some(next) => cursor = next.to_owned(),
            None => break,
        }
    }
    assert_eq!(seen.len(), 7);
    let mut sorted = seen.clone();
    sorted.sort();
    sorted.reverse();
    assert_eq!(seen, sorted);

    // Facets label sampled allows as estimates.
    let conn = Store::reader(store.path()).unwrap();
    let filters = Filters::parse(None, now).unwrap();
    let facets = query::facets(&conn, &filters).unwrap();
    let outcomes = facets["facets"]["outcome"].as_array().unwrap();
    let allow = outcomes.iter().find(|o| o["value"] == "allow").unwrap();
    assert_eq!(allow["events"], 1);
    assert_eq!(allow["estimated_requests"], 100);
    assert_eq!(allow["estimate"], true);
    let sampled = facets["facets"]["sampled"].as_array().unwrap();
    assert!(sampled.iter().any(|entry| entry["value"] == "deny"));
    let series = query::timeseries(&conn, &filters).unwrap();
    assert!(!series["points"].as_array().unwrap().is_empty());
}

#[test]
fn query_bounds_and_inputs_are_enforced() {
    let now = now_ms();
    for bad in [
        "limit=201",
        "limit=0",
        "from=0&to=4000000000",
        "outcome=permit",
        "reason=free%20text",
        "subject_ref=alice%40example.com",
        "ip_ref=203.0.113.7",
        "cursor=zz",
        "route=a%2Fb",
        "headers=1",
        "bucket=1",
    ] {
        assert!(Filters::parse(Some(bad), now).is_err(), "{bad}");
    }
    let many: String = (0..=query::MAX_REFS)
        .map(|_| format!("subject_ref={}&", schema::pseudonym("sub", &[1; 32])))
        .collect();
    assert!(Filters::parse(Some(&many), now).is_err());
    let window = Filters::parse(None, now).unwrap();
    assert_eq!(window.to_ms - window.from_ms, query::DEFAULT_WINDOW_MS);
}

#[test]
fn request_detail_returns_every_event_for_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = store(&dir, Limits::default());
    store
        .insert(&[
            event(Spec {
                seed: 1,
                request: Some("hg-00000000000000aa"),
                ..Default::default()
            }),
            event(Spec {
                seed: 2,
                request: Some("hg-00000000000000aa"),
                kind: v1::Kind::Simulation,
                ..Default::default()
            }),
            event(Spec {
                seed: 3,
                ..Default::default()
            }),
        ])
        .unwrap();
    let conn = Store::reader(store.path()).unwrap();
    let detail = query::request(&conn, "hg-00000000000000aa").unwrap();
    let events = detail["events"].as_array().unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[1]["kind"], "simulation");
    assert!(!query::valid_request_id("../etc"));
}

#[test]
fn ingest_validates_events_and_time() {
    let counters = Counters::default();
    let now = now_ms();
    let good = event(Spec::default()).1;
    let old = event(Spec {
        time: now - 30 * 86_400_000,
        ..Default::default()
    })
    .1;
    let mut bad = event(Spec::default()).0;
    bad.outcome.as_mut().unwrap().reason = "user alice@example.com".into();
    let frame = schema::encode_frame(&[good, old, bad.encode_to_vec(), vec![0xff; 8]]);
    let batch =
        accept_payload(&frame[4..], &counters, Duration::from_secs(7 * 86_400), now).unwrap();
    assert_eq!(batch.len(), 1);
    assert_eq!(counters.rejected_time.load(Ordering::Relaxed), 1);
    assert_eq!(counters.rejected_invalid.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn sockets_ingest_and_serve_queries_end_to_end() {
    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let config = hangang_decision_exporter::Config {
        ingest_socket: dir.path().join("ingest.sock"),
        query_socket: dir.path().join("query.sock"),
        store: dir.path().join("decisions.db"),
        limits: Limits::default(),
        max_connections: 2,
        socket_mode: 0o600,
    };
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(hangang_decision_exporter::run(config.clone(), async {
        let _ = stopped.await;
    }));
    for _ in 0..100 {
        if config.query_socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&config.ingest_socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let mut ingest = tokio::net::UnixStream::connect(&config.ingest_socket)
        .await
        .unwrap();
    let frame = schema::encode_frame(&[event(Spec {
        request: Some("hg-00000000000000bb"),
        ..Default::default()
    })
    .1]);
    ingest.write_all(&frame).await.unwrap();
    let mut found = serde_json::Value::Null;
    for _ in 0..100 {
        let stream = tokio::net::UnixStream::connect(&config.query_socket)
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                hyper::Request::get("/v1/requests/hg-00000000000000bb")
                    .header("host", "exporter")
                    .body(http_body_util::Empty::<bytes::Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        found = serde_json::from_slice(&body).unwrap();
        if !found["events"].as_array().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(found["events"][0]["request_id"], "hg-00000000000000bb");
    // An oversized frame header closes the connection without storing anything.
    ingest.write_all(&(u32::MAX).to_be_bytes()).await.unwrap();
    let _ = stop.send(());
    server.await.unwrap().unwrap();
}
