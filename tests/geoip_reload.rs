//! Real-clock, real-file tests of the public GeoIP reload path.
use std::{sync::Arc, time::Duration};

use hangang::geoip_runtime::{Published, Slot, Source, watch};
use tokio_util::sync::CancellationToken;

fn fresh_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
    let marker = b"build_epoch";
    let offset = bytes
        .windows(marker.len())
        .rposition(|part| part == marker)
        .unwrap()
        + marker.len();
    // Synthetic fixture: extended uint64, four encoded bytes. Only the test
    // copy changes; preserve the checked-in upstream fixture and provenance.
    assert_eq!(&bytes[offset..offset + 2], &[4, 2]);
    let now: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap();
    bytes[offset + 2..offset + 6].copy_from_slice(&now.to_be_bytes());
    bytes
}

async fn wait_ready(slot: &Slot, ready: bool) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if slot.status().ready == ready {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reload reaches expected readiness");
}

#[tokio::test]
async fn public_watcher_recovers_after_atomic_invalid_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("country.mmdb");
    let bytes = fresh_fixture();
    std::fs::write(&path, &bytes).unwrap();
    let slot = Slot::new(Source {
        file: path.clone(),
        max_file_bytes: 32 * 1024 * 1024,
        max_age_days: 14,
        reload_interval_seconds: 1,
    })
    .unwrap();
    assert!(slot.load().is_none());
    let active = slot.clone();
    let published: Arc<Published> = Arc::new(move |candidate| Arc::ptr_eq(candidate, &active));
    let cancel = CancellationToken::new();
    let worker = tokio::spawn(watch(slot.clone(), published, cancel.clone()));
    wait_ready(&slot, true).await;
    let first = slot.load().unwrap();
    for (ip, country) in [
        ("81.2.69.160", "GB"),
        ("::ffff:81.2.69.160", "GB"),
        ("2001:220::1", "KR"),
    ] {
        assert_eq!(
            first.lookup(ip.parse().unwrap()).unwrap().unwrap().as_str(),
            country
        );
    }
    assert!(first.lookup("::1".parse().unwrap()).unwrap().is_none());
    let replacement = dir.path().join("replacement.mmdb");
    std::fs::write(&replacement, b"invalid database").unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    wait_ready(&slot, false).await;
    assert!(slot.load().is_none());
    assert_eq!(slot.status().error_code, Some("invalid_database"));
    std::fs::write(&replacement, &bytes).unwrap();
    std::fs::rename(&replacement, &path).unwrap();
    wait_ready(&slot, true).await;
    let recovered = slot.load().unwrap();
    assert!(!Arc::ptr_eq(&first, &recovered));
    assert_eq!(
        first.status().generation_sha256,
        recovered.status().generation_sha256
    );
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), worker)
        .await
        .unwrap()
        .unwrap();
}
