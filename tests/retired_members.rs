use hangang::config::{Config, Snapshot};
use std::{collections::HashSet, sync::Arc};

fn serving_config() -> Config {
    serde_json::from_value(serde_json::json!({
        "http": [{
            "id": "web", "backends": [
                {"id": "web-a", "address": "http://127.0.0.1:18001"}
            ]
        }],
        "tcp": [{
            "id": "stream", "listen": "127.0.0.1:19000", "backends": [
                {"id": "stream-a", "address": "127.0.0.1:18002"}
            ]
        }]
    }))
    .unwrap()
}

#[test]
fn published_removed_members_remain_observable_only_while_their_owners_live() {
    let old = Snapshot::new(serving_config()).unwrap();
    let http = old.http[0].balancer.clone();
    let http_lease = http.acquire(0).unwrap();
    let tcp = old.tcp_member_admissions["stream"][0].clone();
    let tcp_lease = tcp.lease().unwrap();
    let registry = old.retired_members.clone();

    let candidate = Snapshot::replace(Config::default(), &old).unwrap();
    assert!(Arc::ptr_eq(&registry, &candidate.retired_members));
    assert!(
        registry.snapshot().is_empty(),
        "preparation cannot record retirement"
    );
    assert!(http.available(0));
    assert!(tcp.is_open());
    candidate.activated();
    assert!(!http.available(0));
    assert!(!tcp.is_open());

    let observations = registry.snapshot();
    assert_eq!(
        observations.len(),
        2,
        "removed routes retain owned old members"
    );
    let routes: HashSet<_> = observations
        .iter()
        .map(|row| row.route_id.as_str())
        .collect();
    assert_eq!(routes, HashSet::from(["web", "stream"]));
    let members: HashSet<_> = observations
        .iter()
        .map(|row| row.member_id.as_str())
        .collect();
    assert_eq!(members, HashSet::from(["web-a", "stream-a"]));
    let ids: HashSet<_> = observations
        .iter()
        .map(|row| row.retirement_id.clone())
        .collect();
    assert_eq!(
        ids.len(),
        2,
        "each retired generation has a distinct identity"
    );
    assert!(observations.iter().all(|row| row.active_admissions == 1));
    assert_eq!(http.backend_state(0).unwrap().active_requests, Some(1));
    assert_eq!(tcp.active(), 1);

    // A fresh authority epoch must reset health/cache without erasing this
    // instance's still-owned retired streams.
    let fresh = Snapshot::replace_fresh(Config::default(), &candidate).unwrap();
    assert!(Arc::ptr_eq(&registry, &fresh.retired_members));
    fresh.activated();
    assert_eq!(fresh.retired_members.snapshot().len(), 2);

    drop(http_lease);
    drop(tcp_lease);
    assert!(
        registry.snapshot().is_empty(),
        "completed owners are pruned"
    );
    assert_eq!(http.backend_state(0).unwrap().active_requests, Some(0));
    assert_eq!(tcp.active(), 0);
}

#[test]
fn abandoned_candidates_release_reservations_without_closing_live_members() {
    let old = Snapshot::new(serving_config()).unwrap();
    let http = old.http[0].balancer.clone();
    let tcp = old.tcp_member_admissions["stream"][0].clone();
    let _http_lease = http.acquire(0).unwrap();
    let _tcp_lease = tcp.lease().unwrap();

    // Each candidate reserves two retirements. More than the documented
    // 4,096-entry bound would fail if dropped candidates leaked slots.
    for _ in 0..2_049 {
        let candidate = Snapshot::replace(Config::default(), &old).unwrap();
        assert!(candidate.retired_members.snapshot().is_empty());
        drop(candidate);
    }
    assert!(old.retired_members.snapshot().is_empty());
    assert!(http.available(0));
    assert!(tcp.is_open());

    let candidate = Snapshot::replace(Config::default(), &old).unwrap();
    candidate.activated();
    assert_eq!(old.retired_members.snapshot().len(), 2);
}

#[test]
fn compatible_unrelated_update_does_not_create_retirement_observations() {
    let old = Snapshot::new(serving_config()).unwrap();
    let http = old.http[0].balancer.clone();
    let tcp = old.tcp_member_admissions["stream"][0].clone();
    let _http_lease = http.acquire(0).unwrap();
    let _tcp_lease = tcp.lease().unwrap();
    let mut reordered = old.config.clone();
    reordered.http.push(
        serde_json::from_value(serde_json::json!({
            "id": "unrelated", "host": "unrelated.example.test",
            "backends": ["http://127.0.0.1:18003"]
        }))
        .unwrap(),
    );
    let candidate = Snapshot::replace(reordered, &old).unwrap();
    assert!(Arc::ptr_eq(&http, &candidate.http[0].balancer));
    assert!(Arc::ptr_eq(
        &tcp,
        &candidate.tcp_member_admissions["stream"][0]
    ));
    candidate.activated();
    assert!(old.retired_members.snapshot().is_empty());
    assert!(http.available(0));
    assert!(tcp.is_open());
}
