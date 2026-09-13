//! Live, fail-closed verification of configured inbound workload TLS material.
//!
//! A slot belongs to one published policy generation. The watcher never edits
//! a candidate snapshot: it only replaces the prepared material in a slot
//! which is still present in the active snapshot.

use std::{
    collections::HashSet,
    fs,
    os::unix::fs::MetadataExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use arc_swap::{ArcSwap, ArcSwapOption};
use tokio::time::{Instant, MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::{
    config::Snapshot,
    workload_tls::{Policy, Prepared},
};

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const FULL_VERIFY_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

impl Stamp {
    fn read(path: &Path) -> std::io::Result<Self> {
        // Follow an authorized symlink to its target (Kubernetes projected
        // secret volumes use them), then reject FIFOs/devices before opening.
        let meta = fs::metadata(path)?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mTLS material is not a regular file",
            ));
        }
        Ok(Self {
            dev: meta.dev(),
            ino: meta.ino(),
            len: meta.len(),
            mtime: meta.mtime(),
            mtime_ns: meta.mtime_nsec(),
            ctime: meta.ctime(),
            ctime_ns: meta.ctime_nsec(),
        })
    }
}

fn stamps(policy: &Policy) -> std::io::Result<Vec<Stamp>> {
    [
        Some(policy.cert_file.as_path()),
        Some(policy.key_file.as_path()),
        Some(policy.client_ca_file.as_path()),
        policy.client_crl_file.as_deref(),
    ]
    .into_iter()
    .flatten()
    .map(Stamp::read)
    .collect()
}

#[derive(Default)]
struct CheckState {
    stamps: Option<Vec<Stamp>>,
    verified_at: Option<Instant>,
}

pub struct Slot {
    policy: Policy,
    prepared: ArcSwapOption<Prepared>,
    http: bool,
    check: Mutex<CheckState>,
}

impl Slot {
    /// The prepared candidate proves publication can succeed, but cannot be
    /// admitted until the *active* policy is verified again by the watcher.
    pub fn new(policy: Policy, _prepared: Arc<Prepared>, http: bool) -> Self {
        Self {
            policy,
            prepared: ArcSwapOption::empty(),
            http,
            check: Mutex::new(CheckState::default()),
        }
    }

    pub fn load(&self) -> Option<Arc<Prepared>> {
        self.prepared.load_full()
    }

    fn present(active: &Arc<ArcSwap<Snapshot>>, slot: &Arc<Self>) -> bool {
        let snapshot = active.load();
        snapshot
            .tcp_inbound_tls
            .values()
            .any(|item| Arc::ptr_eq(item, slot))
            || snapshot
                .http_workload_tls
                .values()
                .any(|item| Arc::ptr_eq(item, slot))
    }

    async fn refresh(active: &Arc<ArcSwap<Snapshot>>, slot: &Arc<Self>) {
        let expected = slot.load();
        let policy = slot.policy.clone();
        let http = slot.http;
        let now = Instant::now();
        let (prior_stamps, prior_verified) = {
            let check = slot.check.lock().unwrap();
            (check.stamps.clone(), check.verified_at)
        };
        // All metadata and PEM operations run off the async executor. The
        // single watcher awaits each job before starting the next one.
        let checked = tokio::task::spawn_blocking(move || {
            let before = stamps(&policy)?;
            if prior_stamps.as_ref() == Some(&before)
                && prior_verified.is_some_and(|at| now.duration_since(at) < FULL_VERIFY_INTERVAL)
            {
                return Ok::<_, anyhow::Error>(None);
            }
            let mut prepared = Prepared::load(&policy)?;
            if http {
                Arc::make_mut(&mut prepared.server_config).alpn_protocols =
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            }
            let after = stamps(&policy)?;
            anyhow::ensure!(before == after, "mTLS material changed while loading");
            Ok(Some((prepared, after)))
        })
        .await;

        if !Self::present(active, slot) {
            return;
        }
        match checked {
            Ok(Ok(None)) => {}
            Ok(Ok(Some((prepared, stamps)))) => {
                let keep_old = expected
                    .as_ref()
                    .is_some_and(|old| old.fingerprint() == prepared.fingerprint());
                let next = if keep_old {
                    expected.clone()
                } else {
                    Some(Arc::new(prepared))
                };
                let prior = slot.prepared.compare_and_swap(&expected, next);
                if option_ptr_eq(&prior, &expected) {
                    let mut check = slot.check.lock().unwrap();
                    check.stamps = Some(stamps);
                    check.verified_at = Some(Instant::now());
                    if !keep_old {
                        tracing::info!(
                            kind = if http { "http" } else { "tcp" },
                            "mTLS material verified"
                        );
                    }
                }
            }
            _ => {
                let prior = slot.prepared.compare_and_swap(&expected, None);
                if option_ptr_eq(&prior, &expected) {
                    let mut check = slot.check.lock().unwrap();
                    check.stamps = None;
                    check.verified_at = None;
                    if expected.is_some() {
                        tracing::warn!(
                            kind = if http { "http" } else { "tcp" },
                            "mTLS material unavailable"
                        );
                    }
                }
            }
        }
    }
}

fn option_ptr_eq(a: &Option<Arc<Prepared>>, b: &Option<Arc<Prepared>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

pub async fn watch(active: Arc<ArcSwap<Snapshot>>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(POLL_INTERVAL);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased; _ = cancel.cancelled() => return, _ = tick.tick() => {} }
        let slots = {
            let snapshot = active.load();
            let mut seen = HashSet::new();
            snapshot
                .tcp_inbound_tls
                .values()
                .chain(snapshot.http_workload_tls.values())
                .filter(|slot| seen.insert(Arc::as_ptr(slot) as usize))
                .cloned()
                .collect::<Vec<_>>()
        };
        for slot in slots {
            if cancel.is_cancelled() {
                return;
            }
            if Slot::present(&active, &slot) {
                tokio::select! { biased; _ = cancel.cancelled() => return,
                _ = Slot::refresh(&active, &slot) => {} }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use serde_json::json;

    fn fixture() -> (tempfile::TempDir, Arc<ArcSwap<Snapshot>>, Arc<Slot>) {
        let dir = tempfile::tempdir().unwrap();
        let server =
            rcgen::generate_simple_self_signed(vec!["server.example.test".into()]).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap();
        let cert = dir.path().join("server.pem");
        let key = dir.path().join("server.key");
        let roots = dir.path().join("roots.pem");
        fs::write(&cert, server.cert.pem()).unwrap();
        fs::write(&key, server.signing_key.serialize_pem()).unwrap();
        fs::write(&roots, ca.pem()).unwrap();
        let config: Config = serde_json::from_value(json!({"tcp":[{
            "id":"mtls", "listen":"127.0.0.1:9443", "backends":["127.0.0.1:9"],
            "inbound_tls":{
                "cert_file":cert, "key_file":key, "client_ca_file":roots,
                "allowed_uri_sans":["spiffe://example.test/service"]
            }
        }]}))
        .unwrap();
        let snapshot = Snapshot::new(config).unwrap();
        let slot = snapshot.tcp_inbound_tls["mtls"].clone();
        (dir, Arc::new(ArcSwap::from_pointee(snapshot)), slot)
    }

    #[tokio::test]
    async fn malformed_disappearance_and_recovery_fail_closed() {
        let (_dir, active, slot) = fixture();
        assert!(
            slot.load().is_none(),
            "candidate material cannot open admission"
        );
        Slot::refresh(&active, &slot).await;
        let first = slot.load().unwrap();
        Slot::refresh(&active, &slot).await;
        assert!(Arc::ptr_eq(&first, &slot.load().unwrap()));

        let original = fs::read(&slot.policy.client_ca_file).unwrap();
        fs::write(&slot.policy.client_ca_file, b"invalid CA").unwrap();
        Slot::refresh(&active, &slot).await;
        assert!(slot.load().is_none());
        fs::remove_file(&slot.policy.client_ca_file).unwrap();
        Slot::refresh(&active, &slot).await;
        assert!(slot.load().is_none());
        fs::write(&slot.policy.client_ca_file, original).unwrap();
        Slot::refresh(&active, &slot).await;
        let recovered = slot.load().unwrap();
        assert!(
            !Arc::ptr_eq(&first, &recovered),
            "revoked generation must not resurrect"
        );
    }

    #[tokio::test]
    async fn unchanged_metadata_skips_content_read_and_old_slot_is_fenced() {
        let (_dir, active, slot) = fixture();
        Slot::refresh(&active, &slot).await;
        let first = slot.load().unwrap();
        // A verified metadata sample inside the five-second window avoids
        // reopening PEMs on every 500 ms poll. The full pass will detect a
        // same-metadata rewrite after that window.
        let original = fs::read(&slot.policy.client_ca_file).unwrap();
        fs::write(&slot.policy.client_ca_file, b"invalid CA").unwrap();
        let changed = stamps(&slot.policy).unwrap();
        {
            let mut check = slot.check.lock().unwrap();
            check.stamps = Some(changed);
            check.verified_at = Some(Instant::now());
        }
        Slot::refresh(&active, &slot).await;
        assert!(Arc::ptr_eq(&first, &slot.load().unwrap()));
        slot.check.lock().unwrap().verified_at = None;
        Slot::refresh(&active, &slot).await;
        assert!(slot.load().is_none());
        fs::write(&slot.policy.client_ca_file, original).unwrap();

        // A stale load finishing after publication must not mutate a slot
        // which is no longer in either active map.
        let disabled = {
            let mut config = active.load().config.clone();
            config.tcp[0].enabled = false;
            Snapshot::replace(config, &active.load_full()).unwrap()
        };
        active.store(Arc::new(disabled));
        Slot::refresh(&active, &slot).await;
        assert!(slot.load().is_none());
    }
}
