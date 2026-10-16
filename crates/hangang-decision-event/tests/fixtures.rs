//! D0 contract fixtures: one valid event modelled on ADR 0019 and adversarial
//! mutations that every receiver must reject or neutralize.

use hangang_decision_event::v1::{self, stage_verdict::Stage};
use hangang_decision_event::{self as schema, MAX_EVENT_BYTES};
use prost::Message;

fn reference(prefix: &str, seed: u8) -> String {
    schema::pseudonym(prefix, &[seed; 32])
}

fn valid() -> v1::DecisionEvent {
    let time = 1_760_605_964_512;
    v1::DecisionEvent {
        schema: schema::SCHEMA.into(),
        event_id: schema::event_id(time, [9; 10]).to_vec(),
        kind: v1::Kind::Enforced as i32,
        request_id: "hg-7f3a9c2e41d08b65".into(),
        time_unix_ms: time,
        emitter: Some(v1::Emitter {
            component: "hangang".into(),
            instance: "gw-a".into(),
            build: "0.3.12".into(),
        }),
        route: Some(v1::Route {
            listener: "https-443".into(),
            host: "app.example.test".into(),
            route_id: "app-api".into(),
            path_template: "/api/reports/{id}".into(),
            method: "GET".into(),
            service: "reports".into(),
            resource: "report".into(),
            action: "read".into(),
        }),
        outcome: Some(v1::Outcome {
            result: v1::Result::Deny as i32,
            status: 403,
            deciding_stage: v1::Stage::Authorization as i32,
            reason: "pumgye.class_denied".into(),
        }),
        stages: vec![
            v1::StageVerdict {
                stage: Some(Stage::Network(v1::NetworkStage {
                    verdict: v1::NetworkVerdict::Allow as i32,
                    mode: v1::GuardMode::Enforce as i32,
                    rules: vec!["asn-allow-corp".into()],
                    revision: Some(418),
                    latency_us: 41,
                    transport: v1::Transport::Hgd1 as i32,
                    ip_ref: reference("ip", 1),
                    prefix_ref: reference("pfx", 2),
                    asn: Some(64500),
                    country: "KR".into(),
                    sealed_ip: vec![0; 32],
                    ..Default::default()
                })),
            },
            v1::StageVerdict {
                stage: Some(Stage::Identity(v1::IdentityStage {
                    authority: v1::Authority::Hopae as i32,
                    verdict: v1::IdentityVerdict::Authenticated as i32,
                    subject_ref: reference("sub", 3),
                    principal: v1::PrincipalKind::Human as i32,
                    provider: "oidc-corp".into(),
                    aal: Some(1),
                    factors: vec![v1::Factor::Federated as i32],
                    session_ref: reference("ses", 4),
                    generation: Some(5521),
                    latency_us: 183,
                    transport: v1::Transport::Hop1 as i32,
                    sealed_subject: vec![0; 40],
                    ..Default::default()
                })),
            },
            v1::StageVerdict {
                stage: Some(Stage::Authorization(v1::AuthorizationStage {
                    decision: v1::AuthorizationDecision::ClassDenied as i32,
                    roles: vec!["analyst".into()],
                    information_class: "restricted".into(),
                    required_aal: Some(2),
                    revision: Some(77),
                    latency_us: 22,
                    transport: v1::Transport::Ppg1 as i32,
                    ..Default::default()
                })),
            },
            v1::StageVerdict {
                stage: Some(Stage::Enforcement(v1::EnforcementStage {
                    action: v1::EnforcementAction::Refused as i32,
                    fence: v1::Fence::Ok as i32,
                    revision: Some(268),
                    ..Default::default()
                })),
            },
        ],
        revisions: Some(v1::Revisions {
            hangang: Some(268),
            sumunjang: Some(418),
            hopae: Some(5521),
            pumgye: Some(77),
            catalog: Some(12),
        }),
        sampling: Some(v1::Sampling {
            class: v1::SampleClass::Deny as i32,
            rate_ppm: 1_000_000,
        }),
        privacy: Some(v1::Privacy {
            profile: v1::PrivacyProfile::Standard as i32,
            key_epoch: "2026-10-16".into(),
        }),
        suppressed: None,
    }
}

fn mutate(f: impl FnOnce(&mut v1::DecisionEvent)) -> Result<(), schema::Invalid> {
    let mut event = valid();
    f(&mut event);
    let bytes = event.encode_to_vec();
    schema::decode(&bytes).map(|_| ())
}

fn network(event: &mut v1::DecisionEvent) -> &mut v1::NetworkStage {
    match event.stages[0].stage.as_mut() {
        Some(Stage::Network(n)) => n,
        _ => unreachable!(),
    }
}

fn identity(event: &mut v1::DecisionEvent) -> &mut v1::IdentityStage {
    match event.stages[1].stage.as_mut() {
        Some(Stage::Identity(i)) => i,
        _ => unreachable!(),
    }
}

#[test]
fn reference_event_is_valid_and_bounded() {
    let bytes = valid().encode_to_vec();
    assert!(bytes.len() <= MAX_EVENT_BYTES, "{}", bytes.len());
    let decoded = schema::decode(&bytes).unwrap();
    let json = schema::to_json(&decoded);
    assert_eq!(json["outcome"]["reason"], "pumgye.class_denied");
    assert_eq!(json["outcome"]["result"], "deny");
    assert_eq!(json["outcome"]["deciding_stage"], "authorization");
    assert_eq!(json["stages"][2]["decision"], "ClassDenied");
    assert_eq!(json["revisions"]["pumgye"], 77);
    assert_eq!(json["time"], "2025-10-16T09:12:44.512Z");
    assert_eq!(json["stages"][0]["client"]["sealed"], true);
}

#[test]
fn oversize_lists_and_events_are_rejected() {
    assert!(mutate(|e| network(e).rules = (0..9).map(|i| format!("r{i}")).collect()).is_err());
    assert!(mutate(|e| identity(e).factors = vec![1; 7]).is_err());
    assert!(
        mutate(|e| {
            let stage = e.stages[0].clone();
            e.stages.push(stage);
        })
        .is_err()
    );
    assert!(mutate(|e| network(e).sealed_ip = vec![0; 200]).is_err());
    // A >2 KiB encoding is refused before protobuf decoding.
    let mut big = valid();
    big.route.as_mut().unwrap().path_template = format!("/{}", "a".repeat(250));
    big.stages.iter_mut().for_each(|s| {
        if let Some(Stage::Authorization(a)) = s.stage.as_mut() {
            a.roles = (0..8).map(|i| format!("{i}{}", "r".repeat(63))).collect();
        }
        if let Some(Stage::Network(n)) = s.stage.as_mut() {
            n.rules = (0..8).map(|i| format!("{i}{}", "n".repeat(63))).collect();
        }
        if let Some(Stage::Enforcement(n)) = s.stage.as_mut() {
            n.obligations = (0..8).map(|i| format!("{i}{}", "o".repeat(63))).collect();
        }
    });
    let bytes = big.encode_to_vec();
    assert!(bytes.len() > MAX_EVENT_BYTES);
    assert_eq!(
        schema::decode(&bytes).unwrap_err(),
        schema::Invalid("event exceeds 2 KiB")
    );
}

#[test]
fn unknown_enums_decode_as_unspecified_never_allow() {
    let mut event = valid();
    event.outcome.as_mut().unwrap().result = 99;
    event.kind = 77;
    if let Some(Stage::Authorization(a)) = event.stages[2].stage.as_mut() {
        a.decision = 1234;
    }
    let decoded = schema::decode(&event.encode_to_vec()).unwrap();
    let json = schema::to_json(&decoded);
    assert_eq!(json["outcome"]["result"], "unspecified");
    assert_eq!(json["kind"], "unspecified");
    assert_eq!(json["stages"][2]["decision"], "Unspecified");
}

#[test]
fn raw_addresses_email_paths_and_free_text_are_rejected() {
    // Raw IP where a pseudonym or identifier belongs.
    assert!(mutate(|e| network(e).ip_ref = "203.0.113.7".into()).is_err());
    assert!(mutate(|e| network(e).prefix_ref = "pfx~203.0.113.0/24".into()).is_err());
    assert!(mutate(|e| network(e).rules = vec!["198.51.100.1".into()]).is_err());
    assert!(mutate(|e| e.route.as_mut().unwrap().host = "203.0.113.7".into()).is_err());
    // E-mail addresses or display names in identity fields.
    assert!(mutate(|e| identity(e).subject_ref = "alice@example.com".into()).is_err());
    assert!(mutate(|e| identity(e).provider = "alice@example.com".into()).is_err());
    assert!(mutate(|e| identity(e).provider = "Alice Example".into()).is_err());
    // Raw paths with queries, encodings or parameters.
    assert!(mutate(|e| e.route.as_mut().unwrap().path_template = "/api?token=x".into()).is_err());
    assert!(mutate(|e| e.route.as_mut().unwrap().path_template = "/a%2Fb".into()).is_err());
    assert!(
        mutate(|e| e.route.as_mut().unwrap().path_template = "/a;jsessionid=1".into()).is_err()
    );
    // Unregistered namespaces and free-text reasons.
    assert!(mutate(|e| e.outcome.as_mut().unwrap().reason = "denied because".into()).is_err());
    assert!(mutate(|e| e.outcome.as_mut().unwrap().reason = "x.denied".into()).is_err());
    // Sealed values only under the standard profile.
    assert!(
        mutate(|e| e.privacy.as_mut().unwrap().profile = v1::PrivacyProfile::Strict as i32)
            .is_err()
    );
    // Stage order and duplication.
    assert!(mutate(|e| e.stages.swap(0, 1)).is_err());
    // Event ID must be bound to the event time.
    assert!(mutate(|e| e.event_id = schema::event_id(1, [0; 10]).to_vec()).is_err());
}

#[test]
fn sealed_values_never_leave_through_the_projection_or_export_copy() {
    let event = valid();
    let json = schema::to_json(&event).to_string();
    assert!(!json.contains("sealed_ip") && !json.contains("sealed_subject"));
    let exported = schema::without_sealed(event);
    for stage in &exported.stages {
        match &stage.stage {
            Some(Stage::Network(n)) => assert!(n.sealed_ip.is_empty()),
            Some(Stage::Identity(i)) => assert!(i.sealed_subject.is_empty()),
            _ => {}
        }
    }
}

#[test]
fn frames_round_trip_and_are_bounded() {
    let events: Vec<Vec<u8>> = (0..3).map(|_| valid().encode_to_vec()).collect();
    let frame = schema::encode_frame(&events);
    let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
    assert_eq!(len, frame.len() - 4);
    let split = schema::split_payload(&frame[4..]).unwrap();
    assert_eq!(split.len(), 3);
    assert!(split.iter().all(|e| schema::decode(e).is_ok()));
    // Truncated and oversized frames.
    assert!(schema::split_payload(&frame[4..frame.len() - 1]).is_err());
    let many: Vec<Vec<u8>> = (0..=schema::MAX_BATCH_EVENTS)
        .map(|_| vec![0u8; 1])
        .collect();
    let frame = schema::encode_frame(&many);
    assert!(schema::split_payload(&frame[4..]).is_err());
}

#[test]
fn every_registered_reason_has_both_messages() {
    for reason in schema::reasons::REGISTRY {
        assert_eq!(
            schema::reasons::message_key(reason.code),
            format!("decision.reason.{}", reason.code)
        );
    }
    assert_eq!(
        schema::reasons::message_key("pumgye.future_variant"),
        "decision.reason.unknown"
    );
}
