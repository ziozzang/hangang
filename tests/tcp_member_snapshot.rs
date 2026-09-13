use hangang::config::{Config, Snapshot};
use std::sync::Arc;

fn config() -> Config {
    serde_json::from_value(serde_json::json!({"tcp": [{
        "id": "stream", "listen": "127.0.0.1:19000", "backends": [
            {"id": "a", "address": "127.0.0.1:18001"},
            {"id": "b", "address": "127.0.0.1:18002"}
        ]
    }]}))
    .unwrap()
}

#[test]
fn logical_stream_activity_survives_endpoint_and_enablement_but_not_identity_gaps() {
    let initial = Snapshot::new(config()).unwrap();
    let a = initial.tcp_member_activity["stream"].node(0).unwrap();
    let lease = a.acquire().unwrap();
    let mut changed = initial.config.clone();
    changed.tcp[0].backends.reverse();
    if let hangang::pool_member::Backend::Member(member) = &mut changed.tcp[0].backends[1] {
        member.address = "127.0.0.1:18003".into();
        member.weight = 7;
    }
    changed.tcp[0].enabled = false;
    let next = Snapshot::replace(changed.clone(), &initial).unwrap();
    assert!(Arc::ptr_eq(
        &a,
        &next.tcp_member_activity["stream"].node(1).unwrap()
    ));
    assert_eq!(
        next.tcp_member_activity["stream"].node(1).unwrap().active(),
        1
    );
    assert_eq!(
        next.tcp_member_activity["stream"].node(0).unwrap().active(),
        0
    );

    // Preparing and dropping a candidate cannot mutate live activity.
    drop(next);
    assert_eq!(a.active(), 1);
    let mut invalid = changed.clone();
    invalid.tcp[0].backends.clear();
    assert!(Snapshot::replace(invalid, &initial).is_err());
    assert_eq!(a.active(), 1);

    let gap = Snapshot::replace(Config::default(), &initial).unwrap();
    let readded = Snapshot::replace(config(), &gap).unwrap();
    assert_eq!(
        readded.tcp_member_activity["stream"]
            .node(0)
            .unwrap()
            .active(),
        0
    );
    assert!(!Arc::ptr_eq(
        &a,
        &readded.tcp_member_activity["stream"].node(0).unwrap()
    ));

    let mut renamed = config();
    if let hangang::pool_member::Backend::Member(member) = &mut renamed.tcp[0].backends[0] {
        member.id = "renamed".into();
    }
    let renamed = Snapshot::replace(renamed, &initial).unwrap();
    assert_eq!(
        renamed.tcp_member_activity["stream"]
            .node(0)
            .unwrap()
            .active(),
        0
    );
    let mut legacy = config();
    legacy.tcp[0].backends = legacy.tcp[0]
        .backends
        .iter()
        .map(|b| b.address().to_owned().into())
        .collect();
    let legacy = Snapshot::replace(legacy, &initial).unwrap();
    assert!(legacy.tcp_member_activity["stream"].node(0).is_none());
    let named_again = Snapshot::replace(config(), &legacy).unwrap();
    assert_eq!(
        named_again.tcp_member_activity["stream"]
            .node(0)
            .unwrap()
            .active(),
        0
    );
    drop(lease);
    assert_eq!(a.active(), 0);
}

#[test]
fn health_generation_resets_without_erasing_logical_stream_activity() {
    let mut config = config();
    config.tcp[0].health = Some(hangang::tcp_health::TcpHealthPolicy {
        interval_ms: 1000,
        timeout_ms: 100,
        healthy_successes: 1,
        unhealthy_failures: 1,
        initial_state: hangang::balance::InitialHealthState::Checking,
    });
    let first = Snapshot::new(config).unwrap();
    let counter = first.tcp_member_activity["stream"].node(0).unwrap();
    let lease = counter.acquire().unwrap();
    first.tcp_health["stream"].record_success(0);
    assert!(
        first.tcp_health["stream"]
            .backend_state(0)
            .unwrap()
            .available
    );
    let mut config = first.config.clone();
    if let hangang::pool_member::Backend::Member(member) = &mut config.tcp[0].backends[0] {
        member.address = "127.0.0.1:18003".into();
    }
    let next = Snapshot::replace(config, &first).unwrap();
    assert!(
        !next.tcp_health["stream"]
            .backend_state(0)
            .unwrap()
            .available
    );
    assert!(
        next.tcp_health["stream"]
            .backend_state(0)
            .unwrap()
            .initial_check_pending
    );
    assert_eq!(
        next.tcp_member_activity["stream"].node(0).unwrap().active(),
        1
    );
    drop(lease);
    assert_eq!(
        next.tcp_member_activity["stream"].node(0).unwrap().active(),
        0
    );
}

#[test]
fn tcp_admission_generation_mapping_is_stricter_than_logical_stream_identity() {
    let first = Snapshot::new(config()).unwrap();
    let gate = first.tcp_member_admissions["stream"][0].clone();
    let lease = gate.lease().unwrap();
    let mut reordered = first.config.clone();
    reordered.tcp[0].backends.reverse();
    let reordered = Snapshot::replace(reordered, &first).unwrap();
    assert!(Arc::ptr_eq(
        &gate,
        &reordered.tcp_member_admissions["stream"][1]
    ));
    gate.retire();
    assert!(!reordered.tcp_member_admissions["stream"][1].is_open());
    assert_eq!(gate.active(), 1);
    let mut changed = reordered.config.clone();
    if let hangang::pool_member::Backend::Member(member) = &mut changed.tcp[0].backends[1] {
        member.address = "127.0.0.1:18003".into();
    }
    let changed = Snapshot::replace(changed, &reordered).unwrap();
    assert!(!Arc::ptr_eq(
        &gate,
        &changed.tcp_member_admissions["stream"][1]
    ));
    assert!(changed.tcp_member_admissions["stream"][1].is_open());
    assert_eq!(changed.tcp_member_admissions["stream"][1].active(), 0);
    assert!(!lease.is_open());
    assert_eq!(gate.active(), 1);
    drop(changed);
    assert_eq!(
        gate.active(),
        1,
        "candidate drop does not mutate old generation"
    );
    drop(lease);
    assert_eq!(gate.active(), 0);
}
