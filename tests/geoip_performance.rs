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
        !cfg!(debug_assertions),
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
