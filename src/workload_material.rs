//! Live, fail-closed verification of configured inbound workload TLS material.
//!
//! A slot belongs to one published policy generation. The watcher never edits
//! a candidate snapshot: it only replaces the prepared material in a slot
//! which is still present in the active snapshot.

use std::{
    collections::{HashMap, HashSet},
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

    #[cfg(test)]
    async fn refresh(active: &Arc<ArcSwap<Snapshot>>, slot: &Arc<Self>) {
        Self::refresh_many(active, std::slice::from_ref(slot)).await;
    }

    /// Verify one immutable policy and apply the result independently to all
    /// active slots that use it. Reusing a parsed generation is safe for new
    /// slots, while already-admitted old slots retain their exact Arc if the
    /// fingerprint is unchanged.
    async fn refresh_many(active: &Arc<ArcSwap<Snapshot>>, slots: &[Arc<Self>]) {
        let Some(first) = slots.first() else {
            return;
        };
        let policy = first.policy.clone();
        let http = first.http;
        let now = Instant::now();
        let prior = slots
            .iter()
            .map(|slot| {
                let check = slot.check.lock().unwrap();
                (slot.load(), check.stamps.clone(), check.verified_at)
            })
            .collect::<Vec<_>>();
        let freshness = prior
            .iter()
            .map(|(_, stamps, verified)| (stamps.clone(), *verified))
            .collect::<Vec<_>>();
        // All metadata and PEM operations run off the async executor. The
        // single watcher awaits each policy group before starting the next.
        let checked = tokio::task::spawn_blocking(move || {
            let before = stamps(&policy)?;
            if freshness.iter().all(|(stamps, verified)| {
                stamps.as_ref() == Some(&before)
                    && verified.is_some_and(|at| now.duration_since(at) < FULL_VERIFY_INTERVAL)
            }) {
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

        let verified = match checked {
            Ok(Ok(Some((prepared, stamps)))) => Some((Arc::new(prepared), stamps)),
            Ok(Ok(None)) => return,
            _ => None,
        };
        for (slot, (expected, _, _)) in slots.iter().zip(prior) {
            if !Self::present(active, slot) {
                continue;
            }
            match &verified {
                Some((prepared, stamps)) => {
                    let keep_old = expected
                        .as_ref()
                        .is_some_and(|old| old.fingerprint() == prepared.fingerprint());
                    let next = if keep_old {
                        expected.clone()
                    } else {
                        Some(prepared.clone())
                    };
                    let prior = slot.prepared.compare_and_swap(&expected, next);
                    if option_ptr_eq(&prior, &expected) {
                        let mut check = slot.check.lock().unwrap();
                        check.stamps = Some(stamps.clone());
                        check.verified_at = Some(Instant::now());
                        if !keep_old {
                            tracing::info!(
                                kind = if http { "http" } else { "tcp" },
                                "mTLS material verified"
                            );
                        }
                    }
                }
                None => {
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
        let mut groups: HashMap<(bool, Vec<u8>), Vec<Arc<Slot>>> = HashMap::new();
        for slot in slots {
            // Policy has already passed serialization during snapshot
            // preparation. On an impossible serialization failure, use the
            // ordinary fail-closed verification path with its active/CAS fence.
            let policy = match serde_json::to_vec(&slot.policy) {
                Ok(policy) => policy,
                Err(_) => {
                    tokio::select! { biased; _ = cancel.cancelled() => return,
                    _ = Slot::refresh_many(&active, std::slice::from_ref(&slot)) => {} }
                    continue;
                }
            };
            groups.entry((slot.http, policy)).or_default().push(slot);
        }
        for group in groups.values() {
            if cancel.is_cancelled() {
                return;
            }
            if group.iter().any(|slot| Slot::present(&active, slot)) {
                tokio::select! { biased; _ = cancel.cancelled() => return,
                _ = Slot::refresh_many(&active, group) => {} }
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
        Slot::refresh(&active, &slot).await;
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

    #[tokio::test]
    async fn prepared_candidate_cannot_open_after_material_is_revoked_before_publication() {
        let (_dir, active, old) = fixture();
        Slot::refresh(&active, &old).await;
        let mut config = active.load().config.clone();
        config.tcp[0]
            .inbound_tls
            .as_mut()
            .unwrap()
            .handshake_timeout_ms += 1;
        let candidate = Snapshot::replace(config, &active.load_full()).unwrap();
        let pending = candidate.tcp_inbound_tls["mtls"].clone();
        assert!(!Arc::ptr_eq(&old, &pending));
        assert!(pending.load().is_none());
        fs::write(&pending.policy.client_ca_file, b"invalid CA").unwrap();
        active.store(Arc::new(candidate));
        Slot::refresh(&active, &pending).await;
        assert!(pending.load().is_none());
    }

    #[tokio::test]
    async fn unchanged_snapshot_reuses_revoked_slot_and_recovery_gets_new_generation() {
        let (_dir, active, slot) = fixture();
        Slot::refresh(&active, &slot).await;
        let first = slot.load().unwrap();
        let original = fs::read(&slot.policy.client_ca_file).unwrap();
        fs::write(&slot.policy.client_ca_file, b"invalid CA").unwrap();
        Slot::refresh(&active, &slot).await;
        assert!(slot.load().is_none());
        let same = Snapshot::replace(active.load().config.clone(), &active.load_full()).unwrap();
        assert!(Arc::ptr_eq(&same.tcp_inbound_tls["mtls"], &slot));
        active.store(Arc::new(same));
        fs::write(&slot.policy.client_ca_file, original).unwrap();
        Slot::refresh(&active, &slot).await;
        let recovered = slot.load().unwrap();
        assert!(!Arc::ptr_eq(&first, &recovered));
    }

    #[tokio::test]
    async fn incremental_identical_policy_slots_share_one_parsed_generation() {
        let (_dir, active, original_slot) = fixture();
        let mut config = active.load().config.clone();
        let mut alias = config.tcp[0].clone();
        alias.id = "alias".into();
        alias.listen = "127.0.0.1:9444".parse().unwrap();
        config.tcp.push(alias);
        let next = Snapshot::replace(config, &active.load_full()).unwrap();
        let new_slot = next.tcp_inbound_tls["alias"].clone();
        assert!(!Arc::ptr_eq(&original_slot, &new_slot));
        assert!(original_slot.load().is_none() && new_slot.load().is_none());
        active.store(Arc::new(next));

        let slots = [original_slot.clone(), new_slot.clone()];
        let cancel = CancellationToken::new();
        let watcher = tokio::spawn(watch(active.clone(), cancel.clone()));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if original_slot.load().is_some() && new_slot.load().is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        cancel.cancel();
        watcher.await.unwrap();
        let first = original_slot.load().unwrap();
        assert!(Arc::ptr_eq(&first, &new_slot.load().unwrap()));
        let original = fs::read(&original_slot.policy.client_ca_file).unwrap();
        fs::write(&original_slot.policy.client_ca_file, b"invalid CA").unwrap();
        Slot::refresh_many(&active, &slots).await;
        assert!(original_slot.load().is_none() && new_slot.load().is_none());
        fs::write(&original_slot.policy.client_ca_file, original).unwrap();
        Slot::refresh_many(&active, &slots).await;
        let recovered = original_slot.load().unwrap();
        assert!(Arc::ptr_eq(&recovered, &new_slot.load().unwrap()));
        assert!(!Arc::ptr_eq(&first, &recovered));
    }

    #[tokio::test]
    async fn pending_alias_does_not_resurrect_an_existing_lease_generation() {
        let (_dir, active, original_slot) = fixture();
        Slot::refresh(&active, &original_slot).await;
        let existing = original_slot.load().unwrap();
        let mut config = active.load().config.clone();
        let mut alias = config.tcp[0].clone();
        alias.id = "alias".into();
        alias.listen = "127.0.0.1:9444".parse().unwrap();
        config.tcp.push(alias);
        let next = Snapshot::replace(config, &active.load_full()).unwrap();
        let pending = next.tcp_inbound_tls["alias"].clone();
        assert!(!Arc::ptr_eq(&original_slot, &pending));
        assert!(pending.load().is_none());
        active.store(Arc::new(next));

        Slot::refresh_many(&active, &[original_slot.clone(), pending.clone()]).await;
        assert!(Arc::ptr_eq(&existing, &original_slot.load().unwrap()));
        assert!(!Arc::ptr_eq(&existing, &pending.load().unwrap()));
    }
    #[tokio::test]
    async fn identical_new_tcp_policies_share_verification_without_coupling_disable() {
        let (_dir, source, _) = fixture();
        let mut config = source.load().config.clone();
        let mut alias = config.tcp[0].clone();
        alias.id = "alias".into();
        alias.listen = "127.0.0.1:9444".parse().unwrap();
        config.tcp.push(alias);
        let first = Snapshot::new(config).unwrap();
        assert!(Arc::ptr_eq(
            &first.tcp_inbound_tls["mtls"],
            &first.tcp_inbound_tls["alias"]
        ));
        let slot = first.tcp_inbound_tls["alias"].clone();
        let active = Arc::new(ArcSwap::from_pointee(first));
        Slot::refresh(&active, &slot).await;
        let generation = slot.load().unwrap();
        let mut disabled = active.load().config.clone();
        disabled.tcp[0].enabled = false;
        let next = Snapshot::replace(disabled, &active.load_full()).unwrap();
        assert!(!next.tcp_inbound_tls.contains_key("mtls"));
        assert!(Arc::ptr_eq(&slot, &next.tcp_inbound_tls["alias"]));
        active.store(Arc::new(next));
        Slot::refresh(&active, &slot).await;
        assert!(Arc::ptr_eq(&generation, &slot.load().unwrap()));
    }
}
