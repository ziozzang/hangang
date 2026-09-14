use hangang::{
    admin_users::{
        ConfigAcceptRequest, ConfigOperationState, ConfigReleaseState, ConfigStoreKind,
        MutationAuthority, Store,
    },
    config::Config,
    config_receipt_release::release,
    config_store::{
        CasResult, ConfigStore, SequencedCommitReceipt, SequencedOperationStamp,
        SequencedReceiptObservation, SqliteConfigStore, StoreError, StoreResult, Stored,
    },
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

fn private_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// Faults affect acknowledgement delivery, not SQL's durable implementation.
struct FaultStore {
    inner: SqliteConfigStore,
    fault: AtomicU8,
    releases: AtomicUsize,
}

#[async_trait::async_trait]
impl ConfigStore for FaultStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        self.inner.load_latest().await
    }
    async fn bootstrap(&self, initial: Config) -> StoreResult<Stored> {
        self.inner.bootstrap(initial).await
    }
    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        next: Config,
    ) -> StoreResult<CasResult> {
        self.inner.compare_and_swap(epoch, expected, next).await
    }
    fn supports_receipt_release_v2(&self) -> bool {
        true
    }
    async fn lookup_commit_receipt_v2(
        &self,
        authority: &str,
        sequence: u64,
    ) -> StoreResult<SequencedReceiptObservation> {
        self.inner
            .lookup_commit_receipt_v2(authority, sequence)
            .await
    }
    async fn lookup_receipt_release_v2(
        &self,
        id: &str,
    ) -> StoreResult<Option<SequencedCommitReceipt>> {
        if self.fault.load(Ordering::SeqCst) == 3 {
            return Err(StoreError::Indeterminate(anyhow::anyhow!(
                "injected lookup failure"
            )));
        }
        let evidence = self.inner.lookup_receipt_release_v2(id).await?;
        match self.fault.load(Ordering::SeqCst) {
            4 => Ok(evidence.map(|mut receipt| {
                receipt.stamp.candidate_sha256 = "f".repeat(64);
                receipt
            })),
            5 => Ok(None),
            _ => Ok(evidence),
        }
    }
    async fn release_commit_receipt_v2(
        &self,
        id: &str,
        receipt: &SequencedCommitReceipt,
    ) -> StoreResult<()> {
        self.releases.fetch_add(1, Ordering::SeqCst);
        let fault = self.fault.load(Ordering::SeqCst);
        if fault == 1 {
            return Err(StoreError::Indeterminate(anyhow::anyhow!("before commit")));
        }
        self.inner.release_commit_receipt_v2(id, receipt).await?;
        if fault == 2 {
            return Err(StoreError::Indeterminate(anyhow::anyhow!(
                "lost acknowledgement"
            )));
        }
        Ok(())
    }
    async fn publish_challenge(
        &self,
        token: &str,
        key: &str,
        ttl: std::time::Duration,
    ) -> StoreResult<()> {
        self.inner.publish_challenge(token, key, ttl).await
    }
    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        self.inner.lookup_challenge(token).await
    }
    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        self.inner.withdraw_challenge(token).await
    }
}

async fn fixture(
    dir: &std::path::Path,
    state: ConfigOperationState,
) -> (Store, FaultStore, String) {
    let users = Store::open(dir.join("accounts.db")).unwrap();
    let inner = SqliteConfigStore::open(dir.join("config.db").to_str().unwrap())
        .await
        .unwrap();
    let initial = inner.bootstrap(Config::default()).await.unwrap();
    let next = Config {
        revision: 1,
        ..Config::default()
    };
    let operation = users
        .accept_config(
            MutationAuthority::System,
            ConfigAcceptRequest {
                receipt_version: 2,
                store_kind: ConfigStoreKind::SharedStore,
                authority_epoch: Some(initial.epoch.clone()),
                expected_revision: 0,
                candidate_sha256: format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&next).unwrap())
                ),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        inner
            .compare_and_swap_operation_v2(
                &initial.epoch,
                0,
                next,
                SequencedOperationStamp {
                    authority_id: operation.authority_id,
                    acceptance_seq: operation.id as u64,
                    operation_id: operation.operation_id.clone(),
                    candidate_sha256: operation.candidate_sha256,
                }
            )
            .await
            .unwrap(),
        CasResult::Applied(_)
    ));
    if state != ConfigOperationState::Accepted {
        users
            .finish_config(&operation.operation_id, state)
            .await
            .unwrap();
    }
    (
        users,
        FaultStore {
            inner,
            fault: AtomicU8::new(0),
            releases: AtomicUsize::new(0),
        },
        operation.operation_id,
    )
}

#[tokio::test]
async fn lost_sql_ack_recovers_after_local_restart_without_repeating_release() {
    let dir = private_directory();
    let (users, store, id) = fixture(dir.path(), ConfigOperationState::CandidateActivated).await;
    store.fault.store(2, Ordering::SeqCst);
    assert!(
        release(&users, &store, MutationAuthority::System, &id)
            .await
            .is_err()
    );
    let pending = users.config_release(&id).await.unwrap().unwrap();
    assert_eq!(pending.state, ConfigReleaseState::Pending);
    assert_eq!(
        store
            .inner
            .lookup_receipt_pin_v2(
                &pending.receipt.stamp.authority_id,
                pending.receipt.stamp.acceptance_seq
            )
            .await
            .unwrap(),
        Some(false)
    );
    drop(users);
    let users = Store::open(dir.path().join("accounts.db")).unwrap();
    store.fault.store(0, Ordering::SeqCst);
    let ack = release(&users, &store, MutationAuthority::System, &id)
        .await
        .unwrap();
    assert_eq!(ack.release_id, pending.release_id);
    assert_eq!(ack.state, ConfigReleaseState::Acknowledged);
    assert_eq!(store.releases.load(Ordering::SeqCst), 1);
    release(&users, &store, MutationAuthority::System, &id)
        .await
        .unwrap();
    assert_eq!(store.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn failed_release_or_lookup_keeps_local_work_and_never_manufactures_ack() {
    for fault in [1, 3] {
        let dir = private_directory();
        let (users, store, id) =
            fixture(dir.path(), ConfigOperationState::CandidateActivated).await;
        store.fault.store(fault, Ordering::SeqCst);
        assert!(
            release(&users, &store, MutationAuthority::System, &id)
                .await
                .is_err()
        );
        let pending = users.config_release(&id).await.unwrap().unwrap();
        assert_eq!(pending.state, ConfigReleaseState::Pending);
        assert_eq!(
            store
                .inner
                .lookup_receipt_pin_v2(
                    &pending.receipt.stamp.authority_id,
                    pending.receipt.stamp.acceptance_seq
                )
                .await
                .unwrap(),
            Some(true)
        );
        assert_eq!(
            store.releases.load(Ordering::SeqCst),
            usize::from(fault == 1)
        );
        let page = users
            .config_operations(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert!(
            users
                .prune_config_operations(
                    MutationAuthority::System,
                    page.latest_id,
                    page.latest_id,
                    page.history_revision
                )
                .await
                .is_err()
        );
        assert!(users.config_operation(&id).await.unwrap().is_some());
        store.fault.store(0, Ordering::SeqCst);
        assert_eq!(
            release(&users, &store, MutationAuthority::System, &id)
                .await
                .unwrap()
                .state,
            ConfigReleaseState::Acknowledged
        );
    }
}

#[tokio::test]
async fn unresolved_and_conflicting_local_states_cannot_release_even_matching_sql_receipt() {
    for state in [
        ConfigOperationState::Accepted,
        ConfigOperationState::Indeterminate,
        ConfigOperationState::Conflict,
        ConfigOperationState::Failed,
    ] {
        let dir = private_directory();
        let (users, store, id) = fixture(dir.path(), state).await;
        assert!(
            release(&users, &store, MutationAuthority::System, &id)
                .await
                .is_err()
        );
        assert!(users.config_release(&id).await.unwrap().is_none());
        assert_eq!(store.releases.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn sql_release_survives_local_ack_failure_and_recovers_from_durable_evidence() {
    let dir = private_directory();
    let (users, store, id) = fixture(dir.path(), ConfigOperationState::CandidateActivated).await;
    let db = rusqlite::Connection::open(dir.path().join("accounts.db")).unwrap();
    db.execute_batch("CREATE TRIGGER inject_ack_failure BEFORE UPDATE ON admin_config_releases WHEN NEW.state='acknowledged' BEGIN SELECT RAISE(ABORT,'injected local ACK failure'); END;").unwrap();
    assert!(
        release(&users, &store, MutationAuthority::System, &id)
            .await
            .is_err()
    );
    let work = users.config_release(&id).await.unwrap().unwrap();
    assert_eq!(work.state, ConfigReleaseState::Pending);
    assert_eq!(
        store
            .inner
            .lookup_receipt_release_v2(&work.release_id)
            .await
            .unwrap(),
        Some(work.receipt.clone())
    );
    assert!(
        db.execute(
            "DELETE FROM admin_config_operations WHERE operation_id=?1",
            [&id]
        )
        .is_err()
    );
    db.execute_batch("DROP TRIGGER inject_ack_failure;")
        .unwrap();
    drop(users);
    let users = Store::open(dir.path().join("accounts.db")).unwrap();
    assert_eq!(
        release(&users, &store, MutationAuthority::System, &id)
            .await
            .unwrap()
            .state,
        ConfigReleaseState::Acknowledged
    );
    assert_eq!(store.releases.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn mismatched_or_missing_acknowledged_sql_evidence_never_releases_again() {
    let dir = private_directory();
    let (users, store, id) = fixture(dir.path(), ConfigOperationState::CandidateActivated).await;
    release(&users, &store, MutationAuthority::System, &id)
        .await
        .unwrap();
    for fault in [4, 5] {
        store.fault.store(fault, Ordering::SeqCst);
        assert!(
            release(&users, &store, MutationAuthority::System, &id)
                .await
                .is_err()
        );
        assert_eq!(store.releases.load(Ordering::SeqCst), 1);
    }
}

/// Owned SQLite control-plane diagnostic; not a data-plane throughput claim.
#[tokio::test]
#[ignore = "control-plane timing diagnostic; run explicitly in release mode"]
async fn receipt_release_control_plane_diagnostic() {
    for with_release in [false, true] {
        let dir = private_directory();
        let users = Store::open(dir.path().join("accounts.db")).unwrap();
        let store = SqliteConfigStore::open(dir.path().join("config.db").to_str().unwrap())
            .await
            .unwrap();
        let initial = store.bootstrap(Config::default()).await.unwrap();
        let start = std::time::Instant::now();
        for expected in 0..100 {
            let next = Config {
                revision: expected + 1,
                ..Config::default()
            };
            let operation = users
                .accept_config(
                    MutationAuthority::System,
                    ConfigAcceptRequest {
                        receipt_version: 2,
                        store_kind: ConfigStoreKind::SharedStore,
                        authority_epoch: Some(initial.epoch.clone()),
                        expected_revision: expected,
                        candidate_sha256: format!(
                            "{:x}",
                            Sha256::digest(serde_json::to_vec(&next).unwrap())
                        ),
                    },
                )
                .await
                .unwrap();
            assert!(matches!(
                store
                    .compare_and_swap_operation_v2(
                        &initial.epoch,
                        expected,
                        next,
                        SequencedOperationStamp {
                            authority_id: operation.authority_id,
                            acceptance_seq: operation.id as u64,
                            operation_id: operation.operation_id.clone(),
                            candidate_sha256: operation.candidate_sha256,
                        }
                    )
                    .await
                    .unwrap(),
                CasResult::Applied(_)
            ));
            users
                .finish_config(
                    &operation.operation_id,
                    ConfigOperationState::CandidateActivated,
                )
                .await
                .unwrap();
            if with_release {
                release(
                    &users,
                    &store,
                    MutationAuthority::System,
                    &operation.operation_id,
                )
                .await
                .unwrap();
            }
        }
        println!(
            "receipt_release_control_plane with_release={with_release} operations=100 elapsed_ms={:.3}",
            start.elapsed().as_secs_f64() * 1000.0
        );
        let page = users
            .config_operations(MutationAuthority::System, 0, 100)
            .await
            .unwrap();
        assert_eq!(page.records.len(), 100);
        assert!(page.records.iter().all(|op| op.release_state
            == if with_release {
                ConfigReleaseState::Acknowledged
            } else {
                ConfigReleaseState::Protected
            }));
    }
}

#[tokio::test]
#[ignore = "requires the owned disposable PostgreSQL fixture"]
async fn postgres_local_ack_failure_recovers_after_both_stores_reopen() -> anyhow::Result<()> {
    use hangang::config_store::PostgresConfigStore;
    anyhow::ensure!(
        std::env::var("HANGANG_TEST_POSTGRES_CONTAINER")?.starts_with("hangang-configstore-"),
        "owned PostgreSQL fixture required"
    );
    let url = std::env::var("HANGANG_TEST_POSTGRES_URL")?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let dir = private_directory();
    let users = Store::open(dir.path().join("accounts.db"))?;
    let initial = store.bootstrap(Config::default()).await?;
    assert_eq!(initial.config.revision, 0);
    let next = Config {
        revision: 1,
        ..Config::default()
    };
    let operation = users
        .accept_config(
            MutationAuthority::System,
            ConfigAcceptRequest {
                receipt_version: 2,
                store_kind: ConfigStoreKind::SharedStore,
                authority_epoch: Some(initial.epoch.clone()),
                expected_revision: 0,
                candidate_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(&next)?)),
            },
        )
        .await?;
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(
                &initial.epoch,
                0,
                next,
                SequencedOperationStamp {
                    authority_id: operation.authority_id.clone(),
                    acceptance_seq: operation.id as u64,
                    operation_id: operation.operation_id.clone(),
                    candidate_sha256: operation.candidate_sha256,
                }
            )
            .await?,
        CasResult::Applied(_)
    ));
    users
        .finish_config(
            &operation.operation_id,
            ConfigOperationState::CandidateActivated,
        )
        .await?;
    let db = rusqlite::Connection::open(dir.path().join("accounts.db"))?;
    db.execute_batch("CREATE TRIGGER inject_ack_failure BEFORE UPDATE ON admin_config_releases WHEN NEW.state='acknowledged' BEGIN SELECT RAISE(ABORT,'injected local ACK failure'); END;")?;
    assert!(
        release(
            &users,
            &store,
            MutationAuthority::System,
            &operation.operation_id
        )
        .await
        .is_err()
    );
    let pending = users
        .config_release(&operation.operation_id)
        .await?
        .unwrap();
    assert_eq!(pending.state, ConfigReleaseState::Pending);
    assert_eq!(
        store
            .lookup_receipt_pin_v2(&operation.authority_id, operation.id as u64)
            .await?,
        Some(false)
    );
    db.execute_batch("DROP TRIGGER inject_ack_failure;")?;
    drop(users);
    drop(store);
    let users = Store::open(dir.path().join("accounts.db"))?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let ack = release(
        &users,
        &store,
        MutationAuthority::System,
        &operation.operation_id,
    )
    .await?;
    assert_eq!(ack.state, ConfigReleaseState::Acknowledged);
    assert_eq!(ack.release_id, pending.release_id);
    let page = users
        .config_operations(MutationAuthority::System, 0, 100)
        .await?;
    assert_eq!(
        users
            .prune_config_operations(
                MutationAuthority::System,
                page.latest_id,
                page.latest_id,
                page.history_revision
            )
            .await?
            .pruned_records,
        1
    );
    assert_eq!(
        store.lookup_receipt_release_v2(&ack.release_id).await?,
        Some(ack.receipt)
    );
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 1);
    Ok(())
}
