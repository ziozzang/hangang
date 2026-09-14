//! Release-only, single-process GeoIP lookup and policy-evaluation diagnostic.
//! This is not an HTTP throughput, latency SLO, or vendor comparison.

use std::{
    hint::black_box,
    net::IpAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hangang::{
    country_policy::{Policy, UnknownAction},
    geoip::Database,
};

const ITERATIONS: usize = 100_000;

fn fresh_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    let marker = b"build_epoch";
    let offset = bytes
        .windows(marker.len())
        .rposition(|part| part == marker)
        .expect("fixture has build epoch")
        + marker.len();
    assert_eq!(&bytes[offset..offset + 2], &[4, 2]);
    let now: u32 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    bytes[offset + 2..offset + 6].copy_from_slice(&now.to_be_bytes());
    bytes
}

#[test]
#[ignore = "run explicitly with cargo test --release --test geoip_performance -- --ignored --nocapture"]
fn geoip_lookup_and_country_policy_release_diagnostic() {
    assert!(
        !black_box(cfg!(debug_assertions)),
        "this diagnostic requires release mode"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("country.mmdb");
    let bytes = fresh_fixture();
    std::fs::write(&path, &bytes).unwrap();

    let load_started = Instant::now();
    let database =
        Database::load(&path, 32 * 1024 * 1024, Duration::from_secs(14 * 86_400)).unwrap();
    let load_elapsed = load_started.elapsed();
    assert_eq!(database.status().file_bytes, bytes.len() as u64);

    let policy = Policy {
        allow: vec!["GB".to_owned(), "KR".to_owned()],
        deny: vec!["US".to_owned()],
        on_unknown: UnknownAction::Deny,
        enforce: true,
    }
    .compile()
    .unwrap();

    println!(
        "geoip_release_diagnostic file_bytes={} load_elapsed_ms={:.3} iterations_per_case={ITERATIONS}",
        bytes.len(),
        load_elapsed.as_secs_f64() * 1_000.0,
    );
    for (label, text, expected_country, expected_allowed) in [
        ("ipv4_known", "81.2.69.160", Some("GB"), true),
        ("ipv6_known", "2001:220::1", Some("KR"), true),
        ("ipv4_mapped_ipv6", "::ffff:81.2.69.160", Some("GB"), true),
        ("private_unknown", "127.0.0.1", None, false),
    ] {
        let address: IpAddr = text.parse().unwrap();
        let first = database.lookup(address).unwrap();
        assert_eq!(first.as_ref().map(|code| code.as_str()), expected_country);
        assert_eq!(policy.evaluate(first), expected_allowed);

        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let country = black_box(&database).lookup(black_box(address)).unwrap();
            black_box(policy.evaluate(black_box(country)));
        }
        let elapsed = started.elapsed();
        println!(
            "geoip_release_diagnostic case={label} elapsed_ms={:.3} ns_per_iteration={:.1} iterations_per_second={:.0}",
            elapsed.as_secs_f64() * 1_000.0,
            elapsed.as_nanos() as f64 / ITERATIONS as f64,
            ITERATIONS as f64 / elapsed.as_secs_f64(),
        );
    }
}

/// Measures the owned lookup/counter/ring path under shared-state contention.
/// Deliberately excludes sockets, Lua IPC, upstream work and database reload.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "run explicitly in release mode; diagnostic, not an SLO gate"]
async fn geoip_observation_contention_release_diagnostic() {
    use hangang::{
        country_metrics::{Counters, Protocol},
        country_observation::{State, capture},
        geoip_runtime::{Slot, Source, watch},
        traffic::{TrafficHistory, TrafficInput},
    };
    use std::sync::{Arc, Barrier};
    use tokio_util::sync::CancellationToken;

    assert!(!black_box(cfg!(debug_assertions)), "requires release mode");
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("country.mmdb");
    std::fs::write(&file, fresh_fixture()).unwrap();
    let slot = Slot::new(Source {
        file,
        max_file_bytes: 32 * 1024 * 1024,
        max_age_days: 14,
        reload_interval_seconds: 3600,
    })
    .unwrap();
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(watch(slot.clone(), Arc::new(|_| true), cancel.clone()));
    tokio::time::timeout(Duration::from_secs(10), async {
        while !slot.status().ready {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    // Freeze loader activity for reproducible steady-state measurements.
    cancel.cancel();
    worker.await.unwrap();
    assert!(slot.status().ready);
    let addresses: [IpAddr; 4] = [
        "81.2.69.160",
        "2001:220::1",
        "::ffff:81.2.69.160",
        "127.0.0.1",
    ]
    .map(|text| text.parse().unwrap());
    for (index, address) in addresses.iter().enumerate() {
        let observed = capture(Some(&slot), *address);
        assert_eq!(
            observed.state,
            if index == 3 {
                State::Unknown
            } else {
                State::Known
            }
        );
    }
    const PER_WORKER: usize = 25_000;
    for workers in [1, 8] {
        for ring_enabled in [false, true] {
            for sample in 1..=3 {
                let counters = Arc::new(Counters::default());
                let history = Arc::new(TrafficHistory::default());
                let ready = Arc::new(Barrier::new(workers + 1));
                let start = Arc::new(Barrier::new(workers + 1));
                let mut threads = Vec::new();
                for _ in 0..workers {
                    let (slot, counters, history, ready, start) = (
                        slot.clone(),
                        counters.clone(),
                        history.clone(),
                        ready.clone(),
                        start.clone(),
                    );
                    threads.push(std::thread::spawn(move || {
                        ready.wait();
                        start.wait();
                        for index in 0..PER_WORKER {
                            let address = addresses[index % addresses.len()];
                            let observed = capture(Some(&slot), black_box(address));
                            counters.observe(Protocol::Http, black_box(&observed), None);
                            if ring_enabled {
                                history.record(TrafficInput {
                                    peer_ip: address,
                                    peer_port: 41000,
                                    client_ip: address,
                                    geoip: Some(&observed),
                                    method: "GET",
                                    path: "/diagnostic",
                                    route_id: Some("country"),
                                    status: 200,
                                    response_head_ms: 1,
                                    protocol: "h2",
                                    tls: false,
                                });
                            }
                            black_box(observed);
                        }
                    }));
                }
                ready.wait();
                // Start before releasing workers, so early work is not omitted.
                let started = Instant::now();
                start.wait();
                for thread in threads {
                    thread.join().unwrap();
                }
                let elapsed = started.elapsed();
                let total = workers * PER_WORKER;
                let metrics = counters.snapshot().http;
                assert_eq!(metrics.known, (total * 3 / 4) as u64);
                assert_eq!(metrics.unknown, (total / 4) as u64);
                assert_eq!(metrics.unavailable, 0);
                assert_eq!(
                    metrics.allowed + metrics.denied + metrics.admission_unavailable,
                    0
                );
                let batch = history.snapshot_since(None, 128);
                assert_eq!(batch.latest_id, if ring_enabled { total as u64 } else { 0 });
                assert!(batch.records.len() <= 128);
                println!(
                    "geoip_observation_diagnostic workers={workers} ring={ring_enabled} sample={sample} operations={total} elapsed_ms={:.3} ns_per_operation={:.1} operations_per_second={:.0}",
                    elapsed.as_secs_f64() * 1000.0,
                    elapsed.as_nanos() as f64 / total as f64,
                    total as f64 / elapsed.as_secs_f64(),
                );
            }
        }
    }
}
