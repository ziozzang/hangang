use super::*;
use ring::rand::SystemRandom;
use std::sync::atomic::Ordering;

fn runtime(id: &str) -> Arc<crate::config::HttpRuntime> {
    let config: crate::config::Config = serde_json::from_value(serde_json::json!({
        "revision": 7,
        "http": [{
            "id": id,
            "hosts": ["app.example.test"],
            "path_prefix": "/api/",
            "backends": ["http://127.0.0.1:9"]
        }]
    }))
    .unwrap();
    crate::config::Snapshot::new(config).unwrap().http[0].clone()
}

struct Fixture {
    dir: tempfile::TempDir,
    emitter: Arc<Emitter>,
}

fn fixture(extra: serde_json::Value) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut config = serde_json::json!({
        "profile": "standard",
        "instance": "gw-a",
        "exporter_socket": dir.path().join("ingest.sock"),
        "query_socket": dir.path().join("query.sock"),
        "key_file": dir.path().join("keys.json"),
        "manage_keys": true,
        "key_rotation_hours": 1,
        "key_retention_hours": 2,
        "rings": {"shards": 1},
    });
    for (key, value) in extra.as_object().unwrap() {
        config[key] = value.clone();
    }
    let config: Config = serde_json::from_value(config).unwrap();
    let emitter = Emitter::new(config).unwrap().unwrap();
    drain::KeyKeeper::new().tick(&emitter, &SystemRandom::new(), true);
    Fixture { dir, emitter }
}

fn deny(emitter: &Emitter, route: &Arc<crate::config::HttpRuntime>, ip: &str, time: u64) {
    let mut capture = emitter.capture(&hyper::Method::GET, 7);
    capture.time_ms = time;
    capture.route(route);
    capture.client(ip.parse().unwrap());
    capture.refuse(Stage::Network, Reason::NetworkDenied);
    emitter.finish(capture, 403);
}

fn allow(emitter: &Emitter, route: &Arc<crate::config::HttpRuntime>) {
    let mut capture = emitter.capture(&hyper::Method::GET, 7);
    capture.route(route);
    capture.client("192.0.2.10".parse().unwrap());
    capture.identity(Identity {
        authority: IdentityAuthority::Hopae,
        verdict: IdentityVerdict::Authenticated,
        principal: Principal::Human,
        aal: Some(1),
        factor: FactorKind::Federated,
        subject: Some(Subject::new(b"u_alice")),
        latency_us: 10,
        transport: Transport::Hop1,
    });
    capture.forwarded();
    emitter.finish(capture, 200);
}

fn drain_all(emitter: &Emitter) -> Vec<Record> {
    let mut out = Vec::new();
    emitter.rings.pop_batch(usize::MAX, &mut out);
    out
}

fn context<'a>(
    emitter: &Emitter,
    keys: &'a keys::KeyRing,
    rng: &'a SystemRandom,
) -> drain::Context<'a> {
    drain::Context {
        keys,
        profile: emitter.profile(),
        instance: "gw-a",
        build: "0.3.11",
        rng,
    }
}

#[test]
fn off_is_the_default_and_builds_nothing() {
    let config: Config = serde_json::from_value(serde_json::json!({"profile": "off"})).unwrap();
    assert!(Emitter::new(config).unwrap().is_none());
    assert_eq!(Profile::default(), Profile::Off);
    for invalid in [
        serde_json::json!({"profile": "standard"}),
        serde_json::json!({"profile": "strict", "exporter_socket": "/x", "key_file": "/k", "key_rotation_hours": 0}),
        serde_json::json!({"profile": "strict", "exporter_socket": "/x", "key_file": "/k", "allow_sample_percent": 101.0}),
        serde_json::json!({"profile": "strict", "exporter_socket": "/x", "key_file": "/k", "key_retention_hours": 5000}),
        serde_json::json!({"profile": "strict", "exporter_socket": "/x", "key_file": "/k", "rings": {"deny_slots": 0}}),
        serde_json::json!({"profile": "strict", "exporter_socket": "/x", "key_file": "/k", "routes": {"a/b": {}}}),
    ] {
        let config: Config = serde_json::from_value(invalid.clone()).unwrap();
        assert!(config.validate().is_err(), "{invalid}");
    }
    assert!(serde_json::from_value::<Config>(serde_json::json!({"profile": "verbose"})).is_err());
    assert!(
        serde_json::from_value::<Config>(serde_json::json!({"profile": "off", "headers": true}))
            .is_err()
    );
}

#[test]
fn disabled_capture_is_inert() {
    let mut capture = Capture::disabled();
    capture.client("203.0.113.1".parse().unwrap());
    capture.route(&runtime("app"));
    capture.refuse(Stage::Network, Reason::NetworkDenied);
    capture.forwarded();
    assert!(!capture.active());
    assert!(capture.request_id().is_none());
    assert!(capture.clock().is_none());
    assert!(capture.route.is_none() && capture.refusal.is_none() && capture.client_ip.is_none());
}

#[test]
fn every_reason_code_is_registered_with_messages() {
    let mut reasons = vec![
        Reason::NetworkDenied,
        Reason::NetworkUnavailable,
        Reason::AuthenticationRequired,
        Reason::AuthenticationRedirect,
        Reason::AuthenticationDenied,
        Reason::AuthenticationUnavailable,
        Reason::NativeContextUnavailable,
        Reason::PumgyeMethodNotMapped,
        Reason::PumgyeIdentityMissing,
        Reason::Allowed,
        Reason::Redirected,
        Reason::IpBanned,
        Reason::UrlNotAllowlisted,
        Reason::RateLimited,
        Reason::RequestBlocked,
        Reason::ResourceNamespaceRefused,
        Reason::WorkloadDenied,
        Reason::JwtDenied,
        Reason::BasicDenied,
        Reason::ResourcePolicyDenied,
        Reason::ServiceScopeMismatch,
        Reason::NativePermissionDenied,
        Reason::NativeUnavailable,
        Reason::AuthorizationRetired,
        Reason::RouteAuthorizationUnavailable,
        Reason::UpstreamUnavailable,
        Reason::Refused,
        Reason::Error,
        Reason::Suppressed,
    ];
    use pumgye_core::Decision as D;
    for decision in [
        D::UnknownService,
        D::Guest,
        D::NetworkGuest,
        D::PermissionDenied,
        D::ClassDenied,
        D::AssuranceDenied,
        D::GuardDenied,
        D::GuardUnavailable,
    ] {
        reasons.push(Reason::Pumgye(Authorization::from_decision(decision)));
    }
    reasons.push(Reason::Pumgye(Authorization::from_resource(
        pumgye_core::ResourceDecision::UnknownResource,
    )));
    reasons.push(Reason::Pumgye(Authorization::from_resource(
        pumgye_core::ResourceDecision::UnknownAction,
    )));
    reasons.push(Reason::Pumgye(Authorization::Unavailable));
    for reason in reasons {
        assert!(
            schema::reasons::lookup(reason.code()).is_some(),
            "{} is not registered",
            reason.code()
        );
    }
}

#[test]
fn only_protected_or_refused_requests_are_candidates() {
    let f = fixture(serde_json::json!({}));
    let public = runtime("public");
    let mut capture = f.emitter.capture(&hyper::Method::GET, 7);
    capture.route(&public);
    capture.network(Network {
        verdict: NetworkVerdict::Allow,
        enforce: true,
        revision: Some(4),
        latency_us: 3,
        transport: Transport::Grpc,
    });
    capture.forwarded();
    f.emitter.finish(capture, 200);
    assert_eq!(f.emitter.counters.captured.load(Ordering::Relaxed), 0);
    assert!(f.emitter.rings.is_empty());
}

#[test]
fn deny_flood_is_bounded_by_the_bucket_and_summarized() {
    let f = fixture(
        serde_json::json!({"deny_bucket": {"burst": 5, "refill_per_second": 1.0, "window_seconds": 60}}),
    );
    let route = runtime("app");
    let t0 = now_ms();
    for i in 0..1000u64 {
        deny(&f.emitter, &route, &format!("198.51.100.{}", i % 200), t0);
    }
    let c = &f.emitter.counters;
    assert_eq!(c.kept_deny.load(Ordering::Relaxed), 5);
    assert_eq!(c.suppressed.load(Ordering::Relaxed), 995);
    // Another prefix has its own bucket.
    deny(&f.emitter, &route, "203.0.113.5", t0);
    assert_eq!(c.kept_deny.load(Ordering::Relaxed), 6);
    // After the window the sweep emits exactly one summary for the key.
    let mut summaries = Vec::new();
    f.emitter.buckets.sweep(t0 + 61_000, &mut summaries);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].count, 995);
    let summary = f.emitter.summary_record(summaries.remove(0));
    let keys = f.emitter.keys.load_full();
    let rng = SystemRandom::new();
    let bytes = drain::encode(&summary, &context(&f.emitter, &keys, &rng)).unwrap();
    let event = schema::decode(&bytes).unwrap();
    assert_eq!(event.suppressed.unwrap().count, 995);
    // Attributed to the underlying reason; the sampling class marks the summary.
    assert_eq!(
        event.outcome.as_ref().unwrap().reason,
        "sumunjang.network_denied"
    );
    assert_eq!(
        event.sampling.unwrap().class,
        v1::SampleClass::Suppressed as i32
    );
    let json = schema::to_json(&event);
    assert!(json["stages"][0]["client"]["ip_ref"].is_null());
    assert!(json["stages"][0]["client"]["prefix_ref"].is_string());
}

#[test]
fn allows_are_sampled_and_audit_routes_keep_everything() {
    let f = fixture(serde_json::json!({
        "rings": {"shards": 1, "allow_slots": 65536},
        "routes": {"admin": {"audit_all": true}, "quiet": {"allow_sample_percent": 0.0}}
    }));
    let normal = runtime("app");
    for _ in 0..20_000 {
        allow(&f.emitter, &normal);
    }
    let kept = f.emitter.counters.kept_allow.load(Ordering::Relaxed);
    assert!((120..=280).contains(&kept), "1% of 20000 kept {kept}");
    assert_eq!(
        kept + f.emitter.counters.sampled_out.load(Ordering::Relaxed),
        20_000
    );
    let records = drain_all(&f.emitter);
    assert!(
        records
            .iter()
            .all(|r| r.class == SampleClass::Allow && r.rate_ppm == 10_000)
    );

    let admin = runtime("admin");
    for _ in 0..100 {
        allow(&f.emitter, &admin);
    }
    let records = drain_all(&f.emitter);
    assert_eq!(records.len(), 100);
    assert!(
        records
            .iter()
            .all(|r| r.class == SampleClass::Audit && r.rate_ppm == 1_000_000)
    );

    let quiet = runtime("quiet");
    for _ in 0..100 {
        allow(&f.emitter, &quiet);
    }
    assert!(drain_all(&f.emitter).is_empty());
}

#[test]
fn full_rings_drop_and_count_and_allow_floods_cannot_evict_denies() {
    let f = fixture(serde_json::json!({
        "rings": {"shards": 1, "deny_slots": 4, "allow_slots": 4},
        "allow_sample_percent": 100.0,
        "deny_bucket": {"burst": 10000, "refill_per_second": 1.0, "window_seconds": 60}
    }));
    let route = runtime("app");
    for i in 0..10 {
        deny(&f.emitter, &route, &format!("10.0.{i}.1"), now_ms());
    }
    for _ in 0..50 {
        allow(&f.emitter, &route);
    }
    let c = &f.emitter.counters;
    assert_eq!(c.kept_deny.load(Ordering::Relaxed), 4);
    assert_eq!(c.dropped_ring_deny.load(Ordering::Relaxed), 6);
    assert_eq!(c.kept_allow.load(Ordering::Relaxed), 4);
    assert_eq!(c.dropped_ring_allow.load(Ordering::Relaxed), 46);
    let records = drain_all(&f.emitter);
    assert_eq!(
        records
            .iter()
            .filter(|r| r.class == SampleClass::Deny)
            .count(),
        4
    );
    // Denies drain first.
    assert!(records[..4].iter().all(|r| r.class == SampleClass::Deny));
    let mut metrics = String::new();
    f.emitter.render_metrics(&mut metrics);
    assert!(
        metrics.contains(
            "hangang_decision_events_dropped_total{class=\"deny\",reason=\"ring_full\"} 6"
        )
    );
    assert!(!metrics.contains("sub~") && !metrics.contains("ip~"));
}

#[test]
fn standard_events_are_pseudonymous_with_sealed_values_strict_has_none() {
    for profile in ["standard", "strict"] {
        let f = fixture(serde_json::json!({"profile": profile, "allow_sample_percent": 100.0}));
        let route = runtime("app");
        allow(&f.emitter, &route);
        let records = drain_all(&f.emitter);
        let keys = f.emitter.keys.load_full();
        let rng = SystemRandom::new();
        let bytes = drain::encode(&records[0], &context(&f.emitter, &keys, &rng)).unwrap();
        assert!(bytes.len() <= schema::MAX_EVENT_BYTES);
        let haystack = String::from_utf8_lossy(&bytes);
        assert!(!haystack.contains("u_alice") && !haystack.contains("192.0.2.10"));
        assert!(!bytes.windows(4).any(|w| w == [192, 0, 2, 10]));
        let event = schema::decode(&bytes).unwrap();
        let json = schema::to_json(&event);
        assert_eq!(json["route"]["path_template"], "/api/");
        assert_eq!(json["route"]["host"], "app.example.test");
        assert_eq!(json["revisions"]["hangang"], 7);
        assert_eq!(json["outcome"]["reason"], "hangang.allowed");
        assert_eq!(json["stages"][2]["action"], "forwarded");
        assert_eq!(json["stages"][2]["upstream_status_class"], 2);
        let epoch = keys.epoch_index(event.time_unix_ms);
        let identity = event
            .stages
            .iter()
            .find_map(|s| match &s.stage {
                Some(v1::stage_verdict::Stage::Identity(i)) => Some(i.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            identity.subject_ref,
            keys.subject_ref(epoch, b"u_alice").unwrap()
        );
        let id: [u8; 16] = event.event_id.as_slice().try_into().unwrap();
        if profile == "standard" {
            assert_eq!(
                keys.open(epoch, &id, b"sub", &identity.sealed_subject)
                    .unwrap(),
                b"u_alice"
            );
            assert_eq!(json["privacy"]["profile"], "standard");
        } else {
            assert!(identity.sealed_subject.is_empty());
            assert_eq!(json["privacy"]["profile"], "strict");
        }
        // Console projection never carries sealed values.
        assert!(!json.to_string().contains("sealed_subject"));
        drop(f.dir);
    }
}

#[tokio::test]
async fn missing_keys_and_a_down_exporter_drop_and_count_without_blocking() {
    let f = fixture(serde_json::json!({"allow_sample_percent": 100.0}));
    let route = runtime("app");
    for _ in 0..10 {
        allow(&f.emitter, &route);
    }
    // No exporter listening: the batch is dropped and counted, quickly.
    let keys = f.emitter.keys.load_full();
    let rng = SystemRandom::new();
    let started = Instant::now();
    let mut connection = drain::ConnectionState::new();
    drain::drain_once(
        &f.emitter,
        &context(&f.emitter, &keys, &rng),
        &mut connection,
    )
    .await;
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert_eq!(
        f.emitter.counters.dropped_exporter.load(Ordering::Relaxed),
        10
    );
    assert!(f.emitter.rings.is_empty());

    // Without an epoch key nothing can be pseudonymized: dropped, not leaked.
    allow(&f.emitter, &route);
    let empty = keys::KeyRing::empty(3600);
    drain::drain_once(
        &f.emitter,
        &context(&f.emitter, &empty, &rng),
        &mut connection,
    )
    .await;
    assert_eq!(f.emitter.counters.dropped_no_key.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn drain_delivers_valid_frames_to_the_exporter_socket() {
    use tokio::io::AsyncReadExt;
    let f = fixture(serde_json::json!({}));
    let listener = tokio::net::UnixListener::bind(f.dir.path().join("ingest.sock")).unwrap();
    let route = runtime("app");
    for i in 0..3 {
        deny(&f.emitter, &route, &format!("10.1.{i}.1"), now_ms());
    }
    let keys = f.emitter.keys.load_full();
    let rng = SystemRandom::new();
    let mut connection = drain::ConnectionState::new();
    let (accepted, ()) = tokio::join!(listener.accept(), async {
        drain::drain_once(
            &f.emitter,
            &context(&f.emitter, &keys, &rng),
            &mut connection,
        )
        .await;
    });
    let (mut stream, _) = accepted.unwrap();
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    let mut payload = vec![0u8; u32::from_be_bytes(header) as usize];
    stream.read_exact(&mut payload).await.unwrap();
    let events = schema::split_payload(&payload).unwrap();
    assert_eq!(events.len(), 3);
    for bytes in events {
        let event = schema::decode(bytes).unwrap();
        assert_eq!(event.outcome.unwrap().reason, "sumunjang.network_denied");
        assert!(event.request_id.starts_with("hg-"));
    }
    assert_eq!(f.emitter.counters.exported.load(Ordering::Relaxed), 3);
    assert!(f.emitter.exporter_connected.load(Ordering::Relaxed));
}

#[test]
fn broker_forward_lookup_uses_only_retained_epochs() {
    let rng = SystemRandom::new();
    let now = now_ms();
    let (ring, _) = keys::KeyRing::empty(3600)
        .maintain(now, 2 * 3_600_000, &rng)
        .unwrap()
        .unwrap();
    let epoch = ring.epoch_index(now);
    let query = broker::translate(
        Some(&format!(
            "subject=u_alice&ip=203.0.113.9&outcome=deny&from={}&to={now}",
            now - 3_600_000
        )),
        &ring,
        now,
    )
    .unwrap();
    assert!(!query.contains("u_alice") && !query.contains("203.0.113.9"));
    assert!(query.contains(&ring.subject_ref(epoch, b"u_alice").unwrap()));
    assert!(query.contains(&ring.ip_ref(epoch, "203.0.113.9".parse().unwrap()).unwrap()));
    assert!(query.contains("outcome=deny"));
    // After every epoch is destroyed, the lookup matches nothing.
    let empty = keys::KeyRing::empty(3600);
    let query = broker::translate(Some("subject=u_alice"), &empty, now).unwrap();
    assert!(query.contains("subject_ref=sub~0000000000000000"));
    assert!(broker::translate(Some("ip=not-an-ip"), &ring, now).is_err());
}

#[test]
fn outcomes_follow_registered_reason_classes() {
    let f = fixture(serde_json::json!({}));
    let route = runtime("app");
    for (reason, status, expected) in [
        (Reason::BasicDenied, 401, SampleClass::Challenge),
        (
            Reason::Pumgye(Authorization::ClassDenied),
            403,
            SampleClass::Deny,
        ),
        (
            Reason::Pumgye(Authorization::Unavailable),
            503,
            SampleClass::Unavailable,
        ),
        (Reason::UpstreamUnavailable, 502, SampleClass::Error),
    ] {
        let mut capture = f.emitter.capture(&hyper::Method::POST, 7);
        capture.route(&route);
        capture.client("192.0.2.77".parse().unwrap());
        capture.refuse(Stage::Authorization, reason);
        f.emitter.finish(capture, status);
        let records = drain_all(&f.emitter);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class, expected, "{reason:?}");
    }
}
