use hangang::{
    certificates::CertificateFiles,
    config::{Config, HttpRoute},
    config_store::{
        CasResult, CommitReceipt, ConfigStore, EPOCH_LEN, FileConfigStore, OperationProof,
        OperationStamp, PostgresConfigStore, SequencedOperationStamp, SqliteConfigStore,
        StoreError, Stored, bootstrap_prepared, canonical_operation_id,
    },
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

fn operation_stamp(expected: u64, operation_id: &str, candidate: &Config) -> OperationStamp {
    use sha2::{Digest, Sha256};
    let mut committed = candidate.clone();
    committed.revision = expected + 1;
    OperationStamp {
        authority_id: "a".repeat(32),
        operation_id: operation_id.to_owned(),
        candidate_sha256: format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&committed).unwrap())
        ),
    }
}

fn sequenced_stamp(expected: u64, sequence: u64, candidate: &Config) -> SequencedOperationStamp {
    let authority_id = "a".repeat(32);
    let operation_id = canonical_operation_id(&authority_id, sequence).unwrap();
    let legacy = operation_stamp(expected, &operation_id, candidate);
    SequencedOperationStamp {
        authority_id,
        acceptance_seq: sequence,
        operation_id,
        candidate_sha256: legacy.candidate_sha256,
    }
}

fn config(revision: u64, id: &str) -> Config {
    Config {
        settings: Default::default(),
        cache_generation_floor: 0,
        certificates: vec![],
        cache: None,
        revision,
        http: vec![HttpRoute {
            access_mode: Default::default(),
            resource_policy: None,
            jwt_auth: None,
            workload_auth: None,
            enabled: true,
            upstream: Default::default(),
            priority: 0,
            host_regex: None,
            upstream_host: None,
            preserve_host: false,
            id: id.into(),
            host: None,
            hosts: Vec::new(),
            path_prefix: None,
            path_match: Default::default(),
            max_requests: None,
            upstream_timeout_ms: None,
            retries: 0,
            require_tls: false,
            https_redirect_code: None,
            cache: None,
            headers: BTreeMap::new(),
            json: BTreeMap::new(),
            backends: vec!["http://127.0.0.1:8080".into()],
            deny_cidrs: Vec::new(),
            lua: None,
            request_transform: None,
            response_transform: None,
            auth: None,
            basic_auth: None,
            balance: Default::default(),
            response_set_headers: std::collections::BTreeMap::new(),
            response_remove_headers: Vec::new(),
        }],
        tcp: Vec::new(),
        workload_http: Vec::new(),
    }
}

fn is_epoch(epoch: &str) -> bool {
    epoch.len() == EPOCH_LEN
        && epoch
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

const FOREIGN_EPOCH: &str = "ffffffffffffffffffffffffffffffff";

fn applied(result: CasResult) -> Stored {
    match result {
        CasResult::Applied(stored) => stored,
        CasResult::Conflict { current } => panic!("unexpected conflict at {current:?}"),
    }
}

fn conflict(result: CasResult) -> Stored {
    match result {
        CasResult::Conflict { current } => current,
        CasResult::Applied(stored) => panic!("unexpected apply of {stored:?}"),
    }
}

/// The CAS contract every backend must honour: idempotent re-application of
/// an identical write, conflicts for any other document at the same expected
/// revision, and conflicts that expose the real epoch to a foreign caller.
async fn assert_cas_contract(store: &dyn ConfigStore) {
    let bootstrapped = store.bootstrap(config(0, "initial")).await.unwrap();
    let epoch = bootstrapped.epoch.clone();
    assert!(is_epoch(&epoch), "{epoch:?}");
    assert_eq!(bootstrapped.config.revision, 0);

    let first = applied(
        store
            .compare_and_swap(&epoch, 0, config(77, "next"))
            .await
            .unwrap(),
    );
    assert_eq!(first.epoch, epoch);
    assert_eq!(first.config.revision, 1);
    assert_eq!(first.config.http[0].id, "next");

    // A lost acknowledgement: the same (epoch, expected, next) is applied
    // again without a second write.
    let again = applied(
        store
            .compare_and_swap(&epoch, 0, config(77, "next"))
            .await
            .unwrap(),
    );
    assert_eq!(again, first);
    assert_eq!(store.load_latest().await.unwrap().unwrap(), first);

    // A different document at the same expected revision is a real conflict.
    let current = conflict(
        store
            .compare_and_swap(&epoch, 0, config(77, "other"))
            .await
            .unwrap(),
    );
    assert_eq!(current, first);
    assert_eq!(store.load_latest().await.unwrap().unwrap(), first);

    // A stale expected revision conflicts even for the identical document.
    let current = conflict(
        store
            .compare_and_swap(&epoch, 5, config(77, "next"))
            .await
            .unwrap(),
    );
    assert_eq!(current.config.revision, 1);

    // A foreign epoch never writes; the conflict carries the real epoch.
    let current = conflict(
        store
            .compare_and_swap(FOREIGN_EPOCH, 1, config(0, "foreign"))
            .await
            .unwrap(),
    );
    assert_eq!(current.epoch, epoch);
    assert_eq!(current.config, first.config);
    assert_eq!(store.load_latest().await.unwrap().unwrap(), first);

    // A foreign epoch with the identical document is still not "our" write.
    let current = conflict(
        store
            .compare_and_swap(FOREIGN_EPOCH, 0, config(77, "next"))
            .await
            .unwrap(),
    );
    assert_eq!(current, first);
}

async fn assert_operation_cas_contract(store: &dyn ConfigStore) -> anyhow::Result<()> {
    assert!(store.supports_operation_cas());
    let initial = store.bootstrap(config(0, "initial")).await?;
    let epoch = initial.epoch;
    let candidate = config(0, "same-candidate");
    let first = operation_stamp(0, &"1".repeat(32), &candidate);
    let second = operation_stamp(0, &"2".repeat(32), &candidate);

    let mut bad_digest = first.clone();
    bad_digest.candidate_sha256 = "0".repeat(64);
    assert!(matches!(
        store
            .compare_and_swap_operation(&epoch, 0, candidate.clone(), bad_digest)
            .await,
        Err(StoreError::Invalid(_))
    ));
    let mut bad_id = first.clone();
    bad_id.operation_id = "synthetic-secret-id".into();
    let error = store
        .compare_and_swap_operation(&epoch, 0, candidate.clone(), bad_id)
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)));
    assert!(!error.to_string().contains("synthetic-secret-id"));
    assert_eq!(
        store.load_latest().await?,
        Some(Stored {
            epoch: epoch.clone(),
            config: config(0, "initial")
        })
    );
    assert_eq!(store.load_current_operation_proof().await?, None);

    let committed = applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate.clone(), first.clone())
            .await?,
    );
    assert_eq!(committed.config.revision, 1);
    assert_eq!(committed.http_id(), "same-candidate");
    let proof = OperationProof {
        epoch: epoch.clone(),
        revision: 1,
        stamp: first.clone(),
    };
    assert_eq!(
        store.load_current_operation_proof().await?,
        Some(proof.clone())
    );
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation(&epoch, 0, candidate.clone(), first.clone())
                .await?
        ),
        committed,
        "only the same operation ID may idempotently recover its own commit"
    );
    assert_eq!(
        conflict(
            store
                .compare_and_swap_operation(&epoch, 0, candidate.clone(), second)
                .await?
        ),
        committed,
        "a distinct operation with identical bytes did not commit"
    );
    assert_eq!(store.load_current_operation_proof().await?, Some(proof));

    let changed_candidate = config(0, "changed-candidate");
    let reused_id = operation_stamp(0, &first.operation_id, &changed_candidate);
    assert!(matches!(
        store
            .compare_and_swap_operation(&epoch, 0, changed_candidate, reused_id)
            .await,
        Err(StoreError::Invalid(_))
    ));
    let later_candidate = config(0, "later-candidate");
    let reused_id = operation_stamp(1, &first.operation_id, &later_candidate);
    assert!(matches!(
        store
            .compare_and_swap_operation(&epoch, 1, later_candidate, reused_id)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.load_latest().await?, Some(committed));

    // Legacy writers remain supported, but their revision is never attributed
    // to the previous operation after the durable document changes.
    applied(
        store
            .compare_and_swap(&epoch, 1, config(0, "legacy-next"))
            .await?,
    );
    assert_eq!(store.load_current_operation_proof().await?, None);
    Ok(())
}

async fn assert_commit_receipt_contract(store: &dyn ConfigStore) -> anyhow::Result<()> {
    assert!(store.supports_commit_receipts());
    let initial = store.bootstrap(config(0, "receipt-initial")).await?;
    let epoch = initial.epoch;
    let candidate_a = config(0, "receipt-A");
    let stamp_a = operation_stamp(0, &"1".repeat(32), &candidate_a);
    let absent = store
        .lookup_commit_receipt(&stamp_a.authority_id, &stamp_a.operation_id)
        .await?;
    assert_eq!(absent.receipt, None);
    assert_eq!(absent.stored_records, 0);
    assert_eq!(absent.capacity, 100_000);
    assert!(absent.writes_available);

    let committed_a = applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate_a.clone(), stamp_a.clone())
            .await?,
    );
    assert_eq!(committed_a.config.revision, 1);
    let receipt_a = CommitReceipt {
        epoch: epoch.clone(),
        revision: 1,
        stamp: stamp_a.clone(),
    };
    let observed = store
        .lookup_commit_receipt(&stamp_a.authority_id, &stamp_a.operation_id)
        .await?;
    assert_eq!(observed.receipt, Some(receipt_a.clone()));
    assert_eq!(observed.stored_records, 1);
    assert!(observed.writes_available);
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation(&epoch, 0, candidate_a.clone(), stamp_a.clone())
                .await?
        ),
        committed_a
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&stamp_a.authority_id, &stamp_a.operation_id)
            .await?
            .stored_records,
        1,
        "same-ID retry cannot append another receipt"
    );

    let candidate_b = config(0, "receipt-B");
    let stamp_b = operation_stamp(1, &"2".repeat(32), &candidate_b);
    let committed_b = applied(
        store
            .compare_and_swap_operation(&epoch, 1, candidate_b, stamp_b.clone())
            .await?,
    );
    assert_eq!(committed_b.config.revision, 2);
    assert_eq!(
        store
            .lookup_commit_receipt(&stamp_a.authority_id, &stamp_a.operation_id)
            .await?
            .receipt,
        Some(receipt_a)
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&stamp_b.authority_id, &stamp_b.operation_id)
            .await?
            .receipt,
        Some(CommitReceipt {
            epoch: epoch.clone(),
            revision: 2,
            stamp: stamp_b
        })
    );
    let replay = store
        .compare_and_swap_operation(&epoch, 0, candidate_a, stamp_a.clone())
        .await?;
    assert!(
        matches!(replay, CasResult::Conflict { current } if current == committed_b),
        "a retained historical receipt is not permission to activate stale A again"
    );

    // Existing system/old SQL writers can still advance the config, but they
    // cannot create a governed receipt or erase A and B's retained evidence.
    applied(
        store
            .compare_and_swap(&epoch, 2, config(0, "legacy-C"))
            .await?,
    );
    assert_eq!(store.load_current_operation_proof().await?, None);
    let observed = store
        .lookup_commit_receipt(&stamp_a.authority_id, &stamp_a.operation_id)
        .await?;
    assert_eq!(observed.stored_records, 2);
    assert_eq!(observed.receipt.unwrap().revision, 1);
    let absent = store
        .lookup_commit_receipt(&stamp_a.authority_id, &"f".repeat(32))
        .await?;
    assert_eq!(absent.receipt, None);
    assert_eq!(absent.stored_records, 2);

    for (authority, operation) in [
        ("not-hex", stamp_a.operation_id.as_str()),
        (stamp_a.authority_id.as_str(), "synthetic-secret-id"),
    ] {
        let error = store
            .lookup_commit_receipt(authority, operation)
            .await
            .unwrap_err();
        assert!(matches!(error, StoreError::Invalid(_)));
        assert!(!error.to_string().contains("synthetic-secret-id"));
    }
    Ok(())
}

async fn assert_challenge_contract(store: &dyn ConfigStore) {
    let ttl = Duration::from_secs(30);
    assert_eq!(store.lookup_challenge("absent").await.unwrap(), None);
    store
        .publish_challenge("tok-1_A", "tok-1_A.key-auth", ttl)
        .await
        .unwrap();
    assert_eq!(
        store.lookup_challenge("tok-1_A").await.unwrap().as_deref(),
        Some("tok-1_A.key-auth")
    );
    // Re-publishing replaces the key authorization.
    store
        .publish_challenge("tok-1_A", "replaced", ttl)
        .await
        .unwrap();
    assert_eq!(
        store.lookup_challenge("tok-1_A").await.unwrap().as_deref(),
        Some("replaced")
    );
    store.withdraw_challenge("tok-1_A").await.unwrap();
    assert_eq!(store.lookup_challenge("tok-1_A").await.unwrap(), None);
    // Withdrawing an absent token is not an error.
    store.withdraw_challenge("tok-1_A").await.unwrap();

    // Expiry: a one second ttl is gone after the rounding slack.
    store
        .publish_challenge("short", "gone-soon", Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(
        store.lookup_challenge("short").await.unwrap().as_deref(),
        Some("gone-soon")
    );
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    assert_eq!(store.lookup_challenge("short").await.unwrap(), None);

    // Limit violations are rejected without side effects.
    store
        .publish_challenge("kept", "still-here", ttl)
        .await
        .unwrap();
    for (token, key, ttl) in [
        ("", "k", ttl),
        ("bad token", "k", ttl),
        ("bad/token", "k", ttl),
        (&"a".repeat(129), "k", ttl),
        ("kept", "", ttl),
        ("kept", &"k".repeat(513), ttl),
        ("kept", "not\u{7f}printable", ttl),
        ("kept", "k", Duration::from_millis(500)),
        ("kept", "k", Duration::from_secs(3601)),
    ] {
        let error = store.publish_challenge(token, key, ttl).await.unwrap_err();
        assert!(
            matches!(error, StoreError::Invalid(_)),
            "{token:?}: {error}"
        );
    }
    assert!(matches!(
        store.lookup_challenge("bad token").await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.withdraw_challenge("").await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(
        store.lookup_challenge("kept").await.unwrap().as_deref(),
        Some("still-here"),
        "a rejected publish must not touch existing entries"
    );
    assert_eq!(store.lookup_challenge("bad").await.unwrap(), None);
    assert_eq!(
        store.lookup_challenge(&"a".repeat(128)).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn file_store_bootstrap_and_cas_are_backward_compatible() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = FileConfigStore::new(directory.path().join("state.json"));
    assert!(store.load_latest().await?.is_none());
    let bootstrapped = store.bootstrap(config(4, "initial")).await?;
    assert_eq!(bootstrapped.config.revision, 4);
    assert!(is_epoch(&bootstrapped.epoch));
    let epoch = bootstrapped.epoch.clone();
    assert_eq!(store.bootstrap(config(9, "ignored")).await?, bootstrapped);
    let current = conflict(
        store
            .compare_and_swap(&epoch, 3, config(0, "stale"))
            .await?,
    );
    assert_eq!(current.config.revision, 4);
    let applied = applied(
        store
            .compare_and_swap(&epoch, 4, config(99, "next"))
            .await?,
    );
    assert_eq!(applied.config.revision, 5);
    assert_eq!(applied.epoch, epoch);
    assert_eq!(store.load_latest().await?.unwrap(), applied);
    Ok(())
}

#[tokio::test]
async fn file_store_honours_the_cas_and_challenge_contracts() {
    let directory = tempfile::tempdir().unwrap();
    let store = FileConfigStore::new(directory.path().join("state.json"));
    assert_cas_contract(&store).await;
    assert_challenge_contract(&store).await;
}

#[tokio::test]
async fn file_store_explicitly_rejects_operation_cas() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = FileConfigStore::new(directory.path().join("state.json"));
    assert!(!store.supports_operation_cas());
    let initial = store.bootstrap(config(0, "initial")).await?;
    let candidate = config(0, "candidate");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    assert!(matches!(
        store
            .compare_and_swap_operation(&initial.epoch, 0, candidate, stamp)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert!(matches!(
        store.load_current_operation_proof().await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.load_latest().await?, Some(initial));
    assert!(!store.supports_commit_receipts());
    assert!(matches!(
        store
            .lookup_commit_receipt(&"a".repeat(32), &"1".repeat(32))
            .await,
        Err(StoreError::Invalid(_))
    ));
    Ok(())
}

/// A file written by `store::save` (as an operator or the admin API would)
/// has no epoch: the first reader assigns one, every reader afterwards sees
/// it, and a bootstrap after the document was deleted starts a new authority.
#[tokio::test]
async fn file_store_upgrades_a_legacy_document_once_and_rebootstrap_changes_the_epoch()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.json");
    hangang::store::save(path.clone(), config(3, "legacy")).await?;
    let left = FileConfigStore::new(&path);
    let right = FileConfigStore::new(&path);
    let (first, second) = tokio::join!(left.load_latest(), right.load_latest());
    let first = first?.unwrap();
    let second = second?.unwrap();
    assert!(is_epoch(&first.epoch));
    assert_eq!(first, second, "racing legacy readers converge on one epoch");
    assert_eq!(first.config.revision, 3);
    assert_eq!(left.load_latest().await?.unwrap().epoch, first.epoch);

    let stale = first.epoch.clone();
    std::fs::remove_file(&path)?;
    assert!(left.load_latest().await?.is_none());
    let fresh = left.bootstrap(config(0, "again")).await?;
    assert_ne!(fresh.epoch, stale, "a re-seeded store is a new authority");
    let current = conflict(left.compare_and_swap(&stale, 0, config(1, "old")).await?);
    assert_eq!(current.epoch, fresh.epoch);
    assert_eq!(right.load_latest().await?.unwrap(), fresh);
    Ok(())
}

#[tokio::test]
async fn sqlite_bootstrap_is_idempotent_and_cas_has_one_winner() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let left = Arc::new(SqliteConfigStore::open(&path).await?);
    let right = Arc::new(SqliteConfigStore::open(&path).await?);
    assert!(left.load_latest().await?.is_none());

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first = tokio::spawn({
        let store = left.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store.bootstrap(config(0, "first")).await
        }
    });
    let second = tokio::spawn({
        let store = right.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store.bootstrap(config(0, "second")).await
        }
    });
    let first = first.await??;
    let second = second.await??;
    assert_eq!(first, second);
    assert!(is_epoch(&first.epoch));
    let epoch = first.epoch.clone();

    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first = tokio::spawn({
        let store = left.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store
                .compare_and_swap(&epoch, 0, config(81, "identical"))
                .await
        }
    });
    let second = tokio::spawn({
        let store = right.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store
                .compare_and_swap(&epoch, 0, config(82, "identical"))
                .await
        }
    });
    // Both writers propose the same document: the CAS is idempotent, so both
    // are told it applied and the store holds exactly one write.
    let results = [first.await??, second.await??];
    assert!(
        results
            .iter()
            .all(|result| matches!(result, CasResult::Applied(_))),
        "{results:?}"
    );
    let current = left.load_latest().await?.unwrap();
    assert_eq!(current.epoch, epoch);
    assert_eq!(current.config.revision, 1);
    assert_eq!(current.http_id(), "identical");

    // Different documents at the same expected revision keep one winner.
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first = tokio::spawn({
        let store = left.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store.compare_and_swap(&epoch, 1, config(0, "left")).await
        }
    });
    let second = tokio::spawn({
        let store = right.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store.compare_and_swap(&epoch, 1, config(0, "right")).await
        }
    });
    let results = [first.await??, second.await??];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CasResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(
                result,
                CasResult::Conflict { current } if current.config.revision == 2 && current.epoch == epoch
            ))
            .count(),
        1
    );
    let current = left.load_latest().await?.unwrap();
    assert_eq!(current.config.revision, 2);
    assert!(["left", "right"].contains(&current.http_id()));
    Ok(())
}

trait HttpId {
    fn http_id(&self) -> &str;
}
impl HttpId for Stored {
    fn http_id(&self) -> &str {
        &self.config.http[0].id
    }
}

#[tokio::test]
async fn sqlite_store_honours_the_cas_and_challenge_contracts() {
    let directory = tempfile::tempdir().unwrap();
    let store = SqliteConfigStore::open(directory.path().join("state.db"))
        .await
        .unwrap();
    assert_cas_contract(&store).await;
    assert_challenge_contract(&store).await;
}

#[tokio::test]
async fn sqlite_operation_cas_proves_only_the_winning_operation_and_survives_reopen()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    assert_operation_cas_contract(&store).await?;

    let epoch = store.load_latest().await?.unwrap().epoch;
    let candidate = config(0, "reopened-proof");
    let stamp = operation_stamp(2, &"3".repeat(32), &candidate);
    applied(
        store
            .compare_and_swap_operation(&epoch, 2, candidate, stamp.clone())
            .await?,
    );
    drop(store);
    let reopened = SqliteConfigStore::open(path).await?;
    assert_eq!(
        reopened.load_current_operation_proof().await?,
        Some(OperationProof {
            epoch,
            revision: 3,
            stamp,
        })
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_commit_receipts_survive_later_writes_reopen_and_new_epoch() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    assert_commit_receipt_contract(&store).await?;
    let original = store.load_latest().await?.unwrap();
    let first = operation_stamp(0, &"1".repeat(32), &config(0, "receipt-A"));
    drop(store);

    let reopened = SqliteConfigStore::open(&path).await?;
    assert_eq!(
        reopened
            .lookup_commit_receipt(&first.authority_id, &first.operation_id)
            .await?
            .receipt,
        Some(CommitReceipt {
            epoch: original.epoch.clone(),
            revision: 1,
            stamp: first.clone()
        })
    );
    rusqlite::Connection::open(&path)?
        .execute("DELETE FROM hangang_config WHERE singleton=1", [])?;
    let fresh = reopened.bootstrap(config(0, "fresh-authority")).await?;
    assert_ne!(fresh.epoch, original.epoch);
    assert_eq!(reopened.load_current_operation_proof().await?, None);
    let observed = reopened
        .lookup_commit_receipt(&first.authority_id, &first.operation_id)
        .await?;
    assert_eq!(observed.receipt.unwrap().epoch, original.epoch);
    assert_eq!(observed.stored_records, 2);

    // Receipt IDs remain reserved across a new configuration epoch when the
    // same database is retained; a stale caller cannot repurpose one.
    let reused = config(0, "reused-id");
    let reused_stamp = operation_stamp(0, &first.operation_id, &reused);
    assert!(matches!(
        reopened
            .compare_and_swap_operation(&fresh.epoch, 0, reused, reused_stamp)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(reopened.load_latest().await?, Some(fresh));
    Ok(())
}

#[tokio::test]
async fn sqlite_receipt_insert_failure_rolls_back_configuration_and_stamp() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let initial = store.bootstrap(config(0, "initial")).await?;
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TRIGGER fail_receipt BEFORE INSERT ON hangang_commit_receipts
        BEGIN SELECT RAISE(ABORT, 'fixture receipt append failed'); END;",
    )?;
    let candidate = config(0, "candidate");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    assert!(
        store
            .compare_and_swap_operation(&initial.epoch, 0, candidate.clone(), stamp.clone())
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?, Some(initial.clone()));
    assert_eq!(store.load_current_operation_proof().await?, None);
    let observed = store
        .lookup_commit_receipt(&stamp.authority_id, &stamp.operation_id)
        .await?;
    assert_eq!(observed.receipt, None);
    assert_eq!(observed.stored_records, 0);
    connection.execute_batch("DROP TRIGGER fail_receipt")?;
    applied(
        store
            .compare_and_swap_operation(&initial.epoch, 0, candidate, stamp.clone())
            .await?,
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&stamp.authority_id, &stamp.operation_id)
            .await?
            .stored_records,
        1
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_receipt_capacity_blocks_config_write_without_losing_history() -> anyhow::Result<()>
{
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(config(0, "initial")).await?.epoch;
    let candidate_a = config(0, "A");
    let first = operation_stamp(0, &"1".repeat(32), &candidate_a);
    let committed = applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate_a, first.clone())
            .await?,
    );
    let connection = rusqlite::Connection::open(&path)?;
    // Synthetic metadata exercises the production 100,000-record gate.
    // Resetting it below is test-only: this phase has no production pruning
    // or full-capacity recovery protocol.
    connection.execute(
        "UPDATE hangang_commit_receipt_meta SET stored_records=100000 WHERE singleton=1",
        [],
    )?;
    let full = store
        .lookup_commit_receipt(&first.authority_id, &first.operation_id)
        .await?;
    assert_eq!(full.receipt.unwrap().revision, 1);
    assert_eq!(full.stored_records, 100_000);
    assert_eq!(full.capacity, 100_000);
    assert!(!full.writes_available);
    let candidate_b = config(0, "B");
    let second = operation_stamp(1, &"2".repeat(32), &candidate_b);
    assert!(
        store
            .compare_and_swap_operation(&epoch, 1, candidate_b.clone(), second.clone())
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?, Some(committed));
    assert_eq!(
        store
            .lookup_commit_receipt(&second.authority_id, &second.operation_id)
            .await?
            .receipt,
        None
    );
    connection.execute(
        "UPDATE hangang_commit_receipt_meta SET stored_records=1 WHERE singleton=1",
        [],
    )?;
    applied(
        store
            .compare_and_swap_operation(&epoch, 1, candidate_b, second.clone())
            .await?,
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&second.authority_id, &second.operation_id)
            .await?
            .stored_records,
        2
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_operation_proof_rejects_corrupt_identity_and_unproven_document()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(config(0, "initial")).await?.epoch;
    let candidate = config(0, "candidate");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate, stamp)
            .await?,
    );

    let connection = rusqlite::Connection::open(&path)?;
    let old_writer = connection.execute(
        "UPDATE hangang_config SET config_json=?1 WHERE singleton=1",
        [serde_json::to_string(&config(1, "different-document"))?],
    );
    assert!(
        old_writer.is_err(),
        "the old writer cannot change a stamped document without a new generation"
    );
    assert!(store.load_current_operation_proof().await?.is_some());
    // An owned corruption/restore fixture explicitly advances the new
    // generation. This is not evidence that an obsolete writer can do so.
    connection.execute(
        "UPDATE hangang_config SET config_json=?1,write_generation=write_generation+1 WHERE singleton=1",
        [serde_json::to_string(&config(1, "different-document"))?],
    )?;
    assert_eq!(
        store.load_current_operation_proof().await?,
        None,
        "the old stamp cannot prove a different document at the same revision"
    );
    let old_writer = connection.execute(
        "UPDATE hangang_config SET revision=2, config_json=?1 WHERE singleton=1",
        [serde_json::to_string(&config(2, "old-sql-writer"))?],
    );
    assert!(
        old_writer.is_err(),
        "the old writer cannot advance a stamped document without a new generation"
    );
    connection.execute(
        "UPDATE hangang_config SET revision=2, config_json=?1,write_generation=write_generation+1 WHERE singleton=1",
        [serde_json::to_string(&config(2, "owned-restore-injection"))?],
    )?;
    assert_eq!(
        store.load_current_operation_proof().await?,
        None,
        "a directly injected replacement that leaves the stamp cannot claim its new revision"
    );
    let retained = store
        .lookup_commit_receipt(&"a".repeat(32), &"1".repeat(32))
        .await?;
    assert_eq!(retained.receipt.unwrap().revision, 1);
    assert_eq!(retained.stored_records, 1);
    let fabricated = store
        .lookup_commit_receipt(&"a".repeat(32), &"2".repeat(32))
        .await?;
    assert_eq!(fabricated.receipt, None);
    assert_eq!(fabricated.stored_records, 1);

    connection.execute(
        "UPDATE hangang_config SET operation_id='synthetic-secret-id',write_generation=write_generation+1 WHERE singleton=1",
        [],
    )?;
    let error = store.load_current_operation_proof().await.unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)));
    assert!(!error.to_string().contains("synthetic-secret-id"));
    Ok(())
}

#[tokio::test]
async fn sqlite_reopen_installs_generation_guard_on_pre_v2_database() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(config(0, "initial")).await?.epoch;
    let candidate = config(0, "stamped");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate, stamp)
            .await?,
    );
    drop(store);

    // Simulate a database opened by the previous binary: only its original
    // NEW-only trigger is installed. The old generic writer could clear the
    // stamp without bumping write_generation; roll that probe back locally.
    let connection = rusqlite::Connection::open(&path)?;
    connection
        .execute_batch("DROP TRIGGER hangang_stamped_write_generation_v2; SAVEPOINT old_writer;")?;
    let old_clear = connection.execute(
        "UPDATE hangang_config SET revision=2,config_json=?1,operation_authority_id=NULL,operation_id=NULL,operation_revision=NULL,operation_sha256=NULL WHERE singleton=1",
        [serde_json::to_string(&config(2, "obsolete-writer"))?],
    );
    assert!(
        old_clear.is_ok(),
        "fixture must reproduce the pre-v2 trigger gap"
    );
    connection.execute_batch("ROLLBACK TO old_writer; RELEASE old_writer;")?;
    drop(connection);

    let reopened = SqliteConfigStore::open(&path).await?;
    let connection = rusqlite::Connection::open(&path)?;
    let old_clear = connection.execute(
        "UPDATE hangang_config SET revision=2,config_json=?1,operation_authority_id=NULL,operation_id=NULL,operation_revision=NULL,operation_sha256=NULL WHERE singleton=1",
        [serde_json::to_string(&config(2, "obsolete-writer"))?],
    );
    assert!(
        old_clear.is_err(),
        "reopen must add the stronger v2 generation guard"
    );
    assert_eq!(reopened.load_latest().await?.unwrap().config.revision, 1);
    Ok(())
}

#[tokio::test]
async fn sqlite_operation_cas_same_candidate_concurrent_ids_has_one_winner() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let left = Arc::new(SqliteConfigStore::open(&path).await?);
    let right = Arc::new(SqliteConfigStore::open(&path).await?);
    let epoch = left.bootstrap(config(0, "initial")).await?.epoch;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let run = |store: Arc<SqliteConfigStore>,
               barrier: Arc<tokio::sync::Barrier>,
               epoch: String,
               id: char| {
        tokio::spawn(async move {
            let candidate = config(0, "identical");
            let stamp = operation_stamp(0, &id.to_string().repeat(32), &candidate);
            barrier.wait().await;
            let result = store
                .compare_and_swap_operation(&epoch, 0, candidate, stamp.clone())
                .await;
            (stamp, result)
        })
    };
    let left_task = run(left.clone(), barrier.clone(), epoch.clone(), '1');
    let right_task = run(right.clone(), barrier, epoch.clone(), '2');
    let (stamp_a, result_a) = left_task.await?;
    let (stamp_b, result_b) = right_task.await?;
    let results = [(stamp_a, result_a?), (stamp_b, result_b?)];
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, CasResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|(_, result)| matches!(result, CasResult::Conflict { .. }))
            .count(),
        1
    );
    let winner = results
        .iter()
        .find(|(_, result)| matches!(result, CasResult::Applied(_)))
        .unwrap()
        .0
        .clone();
    assert_eq!(
        left.load_current_operation_proof().await?,
        Some(OperationProof {
            epoch,
            revision: 1,
            stamp: winner
        })
    );
    Ok(())
}

/// Control-plane diagnostic only: one process, sequential SQLite CAS, no
/// account acceptance, HTTP request, local activation or data-plane work.
#[tokio::test]
#[ignore = "run explicitly in release mode for an operation-CAS diagnostic"]
async fn sqlite_operation_cas_release_diagnostic() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = SqliteConfigStore::open(directory.path().join("state.db")).await?;
    let epoch = store.bootstrap(config(0, "diagnostic")).await?.epoch;
    let iterations = 100_u64;
    let start = std::time::Instant::now();
    for expected in 0..iterations {
        let candidate = config(0, "diagnostic");
        let stamp = operation_stamp(expected, &format!("{:032x}", expected + 1), &candidate);
        applied(
            store
                .compare_and_swap_operation(&epoch, expected, candidate, stamp)
                .await?,
        );
    }
    let elapsed = start.elapsed();
    println!(
        "SQLite operation CAS diagnostic: {iterations} sequential writes in {:.3}s ({:.1} writes/s); account acceptance, HTTP, activation and data plane excluded",
        elapsed.as_secs_f64(),
        iterations as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}

/// Deleting the document and bootstrapping again is a new authority: the
/// epoch differs and a CAS carrying the old epoch conflicts even though the
/// revision numbers overlap.
#[tokio::test]
async fn sqlite_rebootstrap_after_deletion_yields_a_new_epoch() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let old = store.bootstrap(config(0, "old")).await?;
    applied(
        store
            .compare_and_swap(&old.epoch, 0, config(0, "old-1"))
            .await?,
    );

    rusqlite::Connection::open(&path)?.execute("DELETE FROM hangang_config", [])?;
    assert!(store.load_latest().await?.is_none());
    let new = store.bootstrap(config(0, "new")).await?;
    assert_ne!(new.epoch, old.epoch);
    assert!(is_epoch(&new.epoch));

    // A stale instance with the old history at revision 1 tries to write
    // revision 2 of the new history.
    applied(
        store
            .compare_and_swap(&new.epoch, 0, config(0, "new-1"))
            .await?,
    );
    let current = conflict(
        store
            .compare_and_swap(&old.epoch, 1, config(0, "stale-2"))
            .await?,
    );
    assert_eq!(current.epoch, new.epoch);
    assert_eq!(current.http_id(), "new-1");
    Ok(())
}

/// Rows written before the epoch column existed are upgraded exactly once:
/// the column is added, two stores racing on one file agree on the epoch,
/// and later opens keep it.
#[tokio::test]
async fn sqlite_legacy_rows_are_upgraded_once_with_one_winner() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("legacy.db");
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE hangang_config (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                revision INTEGER NOT NULL CHECK (revision >= 0),
                config_json TEXT NOT NULL
            ) STRICT;",
        )?;
        connection.execute(
            "INSERT INTO hangang_config(singleton, revision, config_json) VALUES (1, 7, ?1)",
            [serde_json::to_string(&config(7, "legacy"))?],
        )?;
    }
    // Both opens race on `ALTER TABLE ... ADD COLUMN epoch`; both reads race
    // on the guarded epoch `UPDATE`.
    let (left, right) = tokio::join!(
        SqliteConfigStore::open(&path),
        SqliteConfigStore::open(&path)
    );
    let (left, right) = (left?, right?);
    let (first, second) = tokio::join!(left.load_latest(), right.load_latest());
    let first = first?.unwrap();
    let second = second?.unwrap();
    assert!(is_epoch(&first.epoch), "{first:?}");
    assert_eq!(
        first, second,
        "one upgrader wins, the other adopts its epoch"
    );
    assert_eq!(first.config.revision, 7);
    assert_eq!(first.http_id(), "legacy");

    let reopened = SqliteConfigStore::open(&path).await?;
    assert_eq!(reopened.load_latest().await?.unwrap(), first);
    let stored: String = rusqlite::Connection::open(&path)?.query_row(
        "SELECT epoch FROM hangang_config WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(stored, first.epoch);

    // The upgraded document is writable with its assigned epoch.
    let next = applied(
        reopened
            .compare_and_swap(&first.epoch, 7, config(0, "after"))
            .await?,
    );
    assert_eq!(next.config.revision, 8);
    assert_eq!(next.epoch, first.epoch);
    Ok(())
}

/// Corrupt content is `Invalid`; an unreachable file is `Unavailable`.
#[tokio::test]
async fn sqlite_errors_are_typed_by_cause() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.db");
    let store = SqliteConfigStore::open(&path).await?;
    let stored = store.bootstrap(config(0, "ok")).await?;

    rusqlite::Connection::open(&path)?.execute(
        "UPDATE hangang_config SET config_json = 'not json' WHERE singleton = 1",
        [],
    )?;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");
    assert!(!error.is_transport());
    assert!(error.to_string().starts_with("store content invalid: "));
    // A conflicting CAS has to read the document to report `current`.
    let error = store
        .compare_and_swap(&stored.epoch, 5, config(0, "x"))
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");

    rusqlite::Connection::open(&path)?.execute(
        "UPDATE hangang_config SET epoch = 'NOT-AN-EPOCH' WHERE singleton = 1",
        [],
    )?;
    rusqlite::Connection::open(&path)?.execute(
        "UPDATE hangang_config SET config_json = ?1 WHERE singleton = 1",
        [serde_json::to_string(&config(0, "ok"))?],
    )?;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");

    // The database file is replaced by a directory: the store cannot be
    // opened, which is a transport failure, not bad content.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
    std::fs::create_dir(&path)?;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    assert!(error.is_transport());
    assert!(error.to_string().starts_with("store unavailable: "));
    let error = store
        .compare_and_swap(&stored.epoch, 0, config(0, "x"))
        .await
        .unwrap_err();
    assert!(error.is_transport(), "{error}");
    let error = store.lookup_challenge("token").await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    Ok(())
}

#[tokio::test]
async fn sql_store_rejects_invalid_and_oversized_snapshots() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = SqliteConfigStore::open(directory.path().join("state.db")).await?;
    let mut invalid = config(0, "bad id");
    assert!(matches!(
        store.bootstrap(invalid.clone()).await,
        Err(StoreError::Invalid(_))
    ));
    invalid.http[0].id = "valid".into();
    let epoch = store.bootstrap(invalid).await?.epoch;

    let mut oversized = Config::default();
    for index in 0..1024 {
        let mut route = config(0, &format!("route-{index}")).http.remove(0);
        route.lua = Some("x".repeat(1100));
        oversized.http.push(route);
    }
    assert!(oversized.validate().is_ok());
    assert!(matches!(
        store.compare_and_swap(&epoch, 0, oversized).await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    Ok(())
}

/// Set HANGANG_TEST_POSTGRES_URL only to a disposable database owned by this
/// test run. The regular suite never discovers or contacts existing services.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_cas_when_disposable_fixture_is_explicitly_provided() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let store = Arc::new(PostgresConfigStore::connect_unencrypted(&url).await?);
    let peer = Arc::new(PostgresConfigStore::connect_unencrypted(&url).await?);
    let bootstrapped = store.bootstrap(config(0, "initial")).await?;
    assert_eq!(bootstrapped.config.revision, 0);
    assert!(is_epoch(&bootstrapped.epoch));
    let epoch = bootstrapped.epoch.clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let left = tokio::spawn({
        let store = store.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store.compare_and_swap(&epoch, 0, config(42, "left")).await
        }
    });
    let right = tokio::spawn({
        let store = peer.clone();
        let barrier = barrier.clone();
        let epoch = epoch.clone();
        async move {
            barrier.wait().await;
            store.compare_and_swap(&epoch, 0, config(99, "right")).await
        }
    });
    let results = [left.await??, right.await??];
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, CasResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(
                r,
                CasResult::Conflict { current } if current.config.revision == 1 && current.epoch == epoch
            ))
            .count(),
        1
    );
    let current = conflict(
        store
            .compare_and_swap(&epoch, 0, config(42, "stale"))
            .await?,
    );
    assert_eq!(current.config.revision, 1);

    // Idempotent re-application and epoch isolation on the real backend.
    let winner = store.load_latest().await?.unwrap();
    let again = applied(
        peer.compare_and_swap(&epoch, 0, config(0, winner.http_id()))
            .await?,
    );
    assert_eq!(again, winner);
    let current = conflict(
        peer.compare_and_swap(FOREIGN_EPOCH, 1, config(0, "foreign"))
            .await?,
    );
    assert_eq!(current, winner);
    assert_challenge_contract(&*peer).await;
    Ok(())
}

/// Run only through `tests/pg_fixture.py`; that fixture creates and removes
/// its own loopback PostgreSQL container and runs ignored tests serially.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_operation_cas_same_candidate_ids_prove_only_one_commit() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let left = Arc::new(PostgresConfigStore::connect_unencrypted(&url).await?);
    let right = Arc::new(PostgresConfigStore::connect_unencrypted(&url).await?);
    assert!(left.supports_operation_cas());
    let epoch = left.bootstrap(config(0, "initial")).await?.epoch;
    let candidate = config(0, "identical");
    let first = operation_stamp(0, &"1".repeat(32), &candidate);
    let second = operation_stamp(0, &"2".repeat(32), &candidate);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first_task = tokio::spawn({
        let store = left.clone();
        let epoch = epoch.clone();
        let candidate = candidate.clone();
        let stamp = first.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .compare_and_swap_operation(&epoch, 0, candidate, stamp)
                .await
        }
    });
    let second_task = tokio::spawn({
        let store = right.clone();
        let epoch = epoch.clone();
        let candidate = candidate.clone();
        let stamp = second.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .compare_and_swap_operation(&epoch, 0, candidate, stamp)
                .await
        }
    });
    let results = [first_task.await??, second_task.await??];
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CasResult::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, CasResult::Conflict { .. }))
            .count(),
        1
    );
    let winning_stamp = if matches!(results[0], CasResult::Applied(_)) {
        first.clone()
    } else {
        second.clone()
    };
    let losing_stamp = if winning_stamp == first {
        second
    } else {
        first
    };
    assert_eq!(
        left.load_current_operation_proof().await?,
        Some(OperationProof {
            epoch: epoch.clone(),
            revision: 1,
            stamp: winning_stamp.clone(),
        })
    );
    assert_eq!(
        applied(
            right
                .compare_and_swap_operation(&epoch, 0, candidate.clone(), winning_stamp)
                .await?
        )
        .config
        .revision,
        1
    );
    assert_eq!(
        conflict(
            right
                .compare_and_swap_operation(&epoch, 0, candidate, losing_stamp)
                .await?
        )
        .config
        .revision,
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_commit_receipts_survive_later_writer_and_rebootstrap() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute("DROP TABLE IF EXISTS hangang_config")
        .await?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    assert_commit_receipt_contract(&store).await?;
    let original = store.load_latest().await?.unwrap();
    let first = operation_stamp(0, &"1".repeat(32), &config(0, "receipt-A"));
    drop(store);

    let reopened = PostgresConfigStore::connect_unencrypted(&url).await?;
    assert_eq!(
        reopened
            .lookup_commit_receipt(&first.authority_id, &first.operation_id)
            .await?
            .receipt,
        Some(CommitReceipt {
            epoch: original.epoch.clone(),
            revision: 1,
            stamp: first.clone()
        })
    );
    client
        .execute("DELETE FROM hangang_config WHERE singleton=1", &[])
        .await?;
    let fresh = reopened.bootstrap(config(0, "fresh-authority")).await?;
    assert_ne!(fresh.epoch, original.epoch);
    let observed = reopened
        .lookup_commit_receipt(&first.authority_id, &first.operation_id)
        .await?;
    assert_eq!(observed.receipt.unwrap().epoch, original.epoch);
    assert_eq!(observed.stored_records, 2);
    let reused = config(0, "reused-id");
    let reused_stamp = operation_stamp(0, &first.operation_id, &reused);
    assert!(matches!(
        reopened
            .compare_and_swap_operation(&fresh.epoch, 0, reused, reused_stamp)
            .await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(reopened.load_latest().await?, Some(fresh));
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_receipt_insert_failure_rolls_back_configuration_and_stamp() -> anyhow::Result<()>
{
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let initial = store.bootstrap(config(0, "initial")).await?;
    client
        .batch_execute(
            "CREATE FUNCTION fail_receipt_fixture() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'fixture receipt append failed'; END $$;
        CREATE TRIGGER fail_receipt BEFORE INSERT ON hangang_commit_receipts
        FOR EACH ROW EXECUTE FUNCTION fail_receipt_fixture();",
        )
        .await?;
    let candidate = config(0, "candidate");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    assert!(
        store
            .compare_and_swap_operation(&initial.epoch, 0, candidate.clone(), stamp.clone())
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?, Some(initial.clone()));
    assert_eq!(store.load_current_operation_proof().await?, None);
    let observed = store
        .lookup_commit_receipt(&stamp.authority_id, &stamp.operation_id)
        .await?;
    assert_eq!(observed.receipt, None);
    assert_eq!(observed.stored_records, 0);
    client.batch_execute("DROP TRIGGER fail_receipt ON hangang_commit_receipts; DROP FUNCTION fail_receipt_fixture();").await?;
    applied(
        store
            .compare_and_swap_operation(&initial.epoch, 0, candidate, stamp.clone())
            .await?,
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&stamp.authority_id, &stamp.operation_id)
            .await?
            .stored_records,
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_receipt_capacity_blocks_config_write_without_losing_history() -> anyhow::Result<()>
{
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let epoch = store.bootstrap(config(0, "initial")).await?.epoch;
    let candidate_a = config(0, "A");
    let first = operation_stamp(0, &"1".repeat(32), &candidate_a);
    let committed = applied(
        store
            .compare_and_swap_operation(&epoch, 0, candidate_a, first.clone())
            .await?,
    );
    // Synthetic metadata only. Its reset below is not production retention.
    client
        .execute(
            "UPDATE hangang_commit_receipt_meta SET stored_records=100000 WHERE singleton=1",
            &[],
        )
        .await?;
    let full = store
        .lookup_commit_receipt(&first.authority_id, &first.operation_id)
        .await?;
    assert_eq!(full.receipt.unwrap().revision, 1);
    assert_eq!(full.stored_records, 100_000);
    assert_eq!(full.capacity, 100_000);
    assert!(!full.writes_available);
    let candidate_b = config(0, "B");
    let second = operation_stamp(1, &"2".repeat(32), &candidate_b);
    assert!(
        store
            .compare_and_swap_operation(&epoch, 1, candidate_b.clone(), second.clone())
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?, Some(committed));
    assert_eq!(
        store
            .lookup_commit_receipt(&second.authority_id, &second.operation_id)
            .await?
            .receipt,
        None
    );
    client
        .execute(
            "UPDATE hangang_commit_receipt_meta SET stored_records=1 WHERE singleton=1",
            &[],
        )
        .await?;
    applied(
        store
            .compare_and_swap_operation(&epoch, 1, candidate_b, second.clone())
            .await?,
    );
    assert_eq!(
        store
            .lookup_commit_receipt(&second.authority_id, &second.operation_id)
            .await?
            .stored_records,
        2
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_retained_receipt_survives_lost_ack_and_later_winner() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let epoch = direct.bootstrap(config(0, "initial")).await?.epoch;
    let candidate_a = config(0, "A");
    let stamp_a = operation_stamp(0, &"1".repeat(32), &candidate_a);
    let candidate_b = config(0, "B");
    let stamp_b = operation_stamp(1, &"2".repeat(32), &candidate_b);
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    // The receipt and configuration are one SQL statement. Drop that atomic
    // statement's answer, then hold A's recovery read until B wins revision 2.
    let mut proxy = losing_proxy(upstream, vec![RECEIPT_CAS_MARKER]).await?;
    proxy.hold(LOAD_MARKER);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    let pending_a = tokio::spawn({
        let epoch = epoch.clone();
        async move {
            writer
                .compare_and_swap_operation(&epoch, 0, candidate_a, stamp_a)
                .await
        }
    });
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(RECEIPT_CAS_MARKER));
    let observed_a = direct
        .lookup_commit_receipt(&"a".repeat(32), &"1".repeat(32))
        .await?;
    assert_eq!(
        observed_a.receipt.as_ref().map(|receipt| receipt.revision),
        Some(1)
    );
    proxy.gate.send_replace(true);
    assert_eq!(next_fault(&mut proxy.held).await?, Some(LOAD_MARKER));
    let committed_b = applied(
        direct
            .compare_and_swap_operation(&epoch, 1, candidate_b, stamp_b.clone())
            .await?,
    );
    proxy.release.send_replace(true);
    let error = join_fault(pending_a).await?.unwrap_err();
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert_eq!(direct.load_latest().await?, Some(committed_b));
    assert_eq!(
        direct.load_current_operation_proof().await?.unwrap().stamp,
        stamp_b
    );
    assert_eq!(
        direct
            .lookup_commit_receipt(&"a".repeat(32), &"1".repeat(32))
            .await?
            .receipt
            .unwrap()
            .revision,
        1
    );
    assert_eq!(
        direct
            .lookup_commit_receipt(&"a".repeat(32), &"2".repeat(32))
            .await?
            .stored_records,
        2
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_lost_ack_receipt_with_failed_current_read_stays_indeterminate()
-> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let epoch = direct.bootstrap(config(0, "initial")).await?.epoch;
    let candidate = config(0, "committed-but-unreadable");
    let stamp = operation_stamp(0, &"1".repeat(32), &candidate);
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    let mut proxy =
        losing_proxy(upstream, vec![RECEIPT_CAS_MARKER, LOAD_MARKER, LOAD_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let error = writer
        .compare_and_swap_operation(&epoch, 0, candidate, stamp.clone())
        .await
        .unwrap_err();
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(RECEIPT_CAS_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert_eq!(
        direct
            .lookup_commit_receipt(&stamp.authority_id, &stamp.operation_id)
            .await?
            .receipt
            .unwrap()
            .revision,
        1
    );
    assert_eq!(direct.load_latest().await?.unwrap().config.revision, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_v2_lost_ack_keeps_a_receipt_after_b_becomes_current() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    assert!(direct.supports_sequenced_operation_cas());
    let epoch = direct.bootstrap(config(0, "v2-initial")).await?.epoch;
    let candidate_a = config(0, "v2-A");
    let stamp_a = sequenced_stamp(0, 2, &candidate_a);
    let candidate_b = config(0, "v2-B");
    let stamp_b = sequenced_stamp(1, 3, &candidate_b);
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    let mut proxy = losing_proxy(upstream, vec![V2_CAS_MARKER]).await?;
    proxy.hold(LOAD_MARKER);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    let pending_a = tokio::spawn({
        let epoch = epoch.clone();
        let stamp_a = stamp_a.clone();
        async move {
            writer
                .compare_and_swap_operation_v2(&epoch, 0, candidate_a, stamp_a)
                .await
        }
    });
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(V2_CAS_MARKER));
    let observed_a = direct
        .lookup_commit_receipt_v2(&stamp_a.authority_id, 2)
        .await?;
    assert_eq!(
        observed_a.receipt.as_ref().map(|receipt| receipt.revision),
        Some(1)
    );
    assert_eq!(
        observed_a.high_water, 2,
        "the first V2 sequence need not be 1"
    );
    proxy.gate.send_replace(true);
    assert_eq!(next_fault(&mut proxy.held).await?, Some(LOAD_MARKER));
    let committed_b = applied(
        direct
            .compare_and_swap_operation_v2(&epoch, 1, candidate_b, stamp_b.clone())
            .await?,
    );
    proxy.release.send_replace(true);
    let error = join_fault(pending_a).await?.unwrap_err();
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert_eq!(direct.load_latest().await?, Some(committed_b));
    let old = direct
        .lookup_commit_receipt_v2(&stamp_a.authority_id, 2)
        .await?;
    let latest = direct
        .lookup_commit_receipt_v2(&stamp_b.authority_id, 3)
        .await?;
    assert_eq!(old.receipt.unwrap().stamp, stamp_a);
    assert_eq!(latest.receipt.unwrap().stamp, stamp_b);
    assert_eq!(old.high_water, 3);
    assert_eq!(latest.high_water, 3);
    assert_eq!(latest.stored_records, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_v2_lost_ack_with_failed_current_read_remains_indeterminate() -> anyhow::Result<()>
{
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let epoch = direct.bootstrap(config(0, "v2-initial")).await?.epoch;
    let candidate = config(0, "v2-committed-but-unreadable");
    let stamp = sequenced_stamp(0, 2, &candidate);
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    let mut proxy = losing_proxy(upstream, vec![V2_CAS_MARKER, LOAD_MARKER, LOAD_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let error = writer
        .compare_and_swap_operation_v2(&epoch, 0, candidate, stamp.clone())
        .await
        .unwrap_err();
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(V2_CAS_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    let observed = direct
        .lookup_commit_receipt_v2(&stamp.authority_id, 2)
        .await?;
    assert_eq!(observed.receipt.unwrap().stamp, stamp);
    assert_eq!(observed.high_water, 2);
    assert_eq!(direct.load_latest().await?.unwrap().config.revision, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_operation_cas_lost_ack_uses_exact_current_proof() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let initial = direct.bootstrap(config(0, "initial")).await?;
    let epoch = initial.epoch.clone();
    let candidate = config(0, "identical");
    let first = operation_stamp(0, &"1".repeat(32), &candidate);
    let second = operation_stamp(0, &"2".repeat(32), &candidate);
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;

    // The update commits but its answer is dropped. The same operation's
    // retry may use its exact durable stamp to prove the current commit.
    let mut proxy = losing_proxy(upstream, vec![RECEIPT_CAS_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let committed = applied(
        writer
            .compare_and_swap_operation(&epoch, 0, candidate.clone(), first.clone())
            .await?,
    );
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(RECEIPT_CAS_MARKER));
    assert_eq!(committed.config.revision, 1);
    assert_eq!(
        direct.load_current_operation_proof().await?,
        Some(OperationProof {
            epoch: epoch.clone(),
            revision: 1,
            stamp: first.clone(),
        })
    );
    drop(proxy);

    // A different ID proposing the same document has no ownership proof.
    // Its unanswered attempt remains uncertain; an answered retry conflicts.
    let mut proxy = losing_proxy(upstream, vec![RECEIPT_CAS_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let error = writer
        .compare_and_swap_operation(&epoch, 0, candidate.clone(), second.clone())
        .await
        .unwrap_err();
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(RECEIPT_CAS_MARKER));
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert_eq!(
        conflict(
            direct
                .compare_and_swap_operation(&epoch, 0, candidate, second)
                .await?
        ),
        committed
    );
    assert_eq!(
        direct.load_current_operation_proof().await?.unwrap().stamp,
        first
    );

    // A later operation commits without an acknowledgement. Before its
    // recovery read, an obsolete SQL writer tries to advance the document
    // while leaving the operation columns untouched. The generation trigger
    // rejects it. An owned restore fixture then explicitly advances the
    // generation; this does not model a compatible obsolete writer.
    drop(proxy);
    let candidate = config(0, "lost-before-old-writer");
    let third = operation_stamp(1, &"3".repeat(32), &candidate);
    let mut proxy = losing_proxy(upstream, vec![RECEIPT_CAS_MARKER]).await?;
    proxy.hold(LOAD_MARKER);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    let pending = tokio::spawn({
        let epoch = epoch.clone();
        async move {
            writer
                .compare_and_swap_operation(&epoch, 1, candidate, third)
                .await
        }
    });
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(RECEIPT_CAS_MARKER));
    assert_eq!(direct.load_latest().await?.unwrap().config.revision, 2);
    proxy.gate.send_replace(true);
    assert_eq!(next_fault(&mut proxy.held).await?, Some(LOAD_MARKER));
    let injected_document = config(3, "owned-restore-injection");
    let old_writer = client
        .execute(
            "UPDATE hangang_config SET revision=$1,config_json=$2 WHERE singleton=1 AND epoch=$3",
            &[&3_i64, &serde_json::to_string(&injected_document)?, &epoch],
        )
        .await;
    assert!(
        old_writer.is_err(),
        "obsolete stamped writer must be rejected"
    );
    let changed = client
        .execute(
            "UPDATE hangang_config SET revision=$1,config_json=$2,write_generation=write_generation+1 WHERE singleton=1 AND epoch=$3",
            &[&3_i64, &serde_json::to_string(&injected_document)?, &epoch],
        )
        .await?;
    assert_eq!(changed, 1);
    assert_eq!(direct.load_current_operation_proof().await?, None);
    proxy.release.send_replace(true);
    let error = join_fault(pending).await?.unwrap_err();
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert_eq!(
        direct.load_latest().await?.unwrap().config,
        injected_document
    );
    let retained = direct
        .lookup_commit_receipt(&"a".repeat(32), &"3".repeat(32))
        .await?;
    assert_eq!(retained.receipt.unwrap().revision, 2);
    assert_eq!(retained.stored_records, 2);
    assert_eq!(
        direct
            .lookup_commit_receipt(&"a".repeat(32), &"4".repeat(32))
            .await?
            .receipt,
        None
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_rejects_oversized_columns_before_returning_them() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute("DROP TABLE IF EXISTS hangang_config")
        .await?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let stored = store.bootstrap(config(0, "bounded")).await?;

    client
        .execute(
            "UPDATE hangang_config SET config_json = $1 WHERE singleton = 1",
            &[&"x".repeat(1024 * 1024 + 1)],
        )
        .await?;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");
    assert!(error.to_string().contains("exceeds 1 MiB"), "{error}");

    client
        .execute(
            "UPDATE hangang_config SET config_json = $1, epoch = $2 WHERE singleton = 1",
            &[
                &serde_json::to_string(&stored.config)?,
                &"a".repeat(EPOCH_LEN + 1),
            ],
        )
        .await?;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");
    assert!(error.to_string().contains("epoch exceeds"), "{error}");
    // Restore the owned shared fixture and prove that a repaired row can be
    // read again; later TLS tests intentionally read the current document.
    client
        .execute(
            "UPDATE hangang_config SET epoch = $1 WHERE singleton = 1",
            &[&stored.epoch],
        )
        .await?;
    assert_eq!(store.load_latest().await?, Some(stored));
    Ok(())
}

/// A legacy PostgreSQL table without the epoch column is upgraded in place;
/// two stores racing on it converge on one epoch.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_legacy_rows_are_upgraded_once_with_one_winner() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute(
            "DROP TABLE IF EXISTS hangang_config;
             CREATE TABLE hangang_config (
                singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
                revision BIGINT NOT NULL CHECK (revision >= 0),
                config_json TEXT NOT NULL
             )",
        )
        .await?;
    client
        .execute(
            "INSERT INTO hangang_config(singleton, revision, config_json) VALUES (1, 7, $1)",
            &[&serde_json::to_string(&config(7, "legacy"))?],
        )
        .await?;
    let left = PostgresConfigStore::connect_unencrypted(&url).await?;
    let right = PostgresConfigStore::connect_unencrypted(&url).await?;
    let (first, second) = tokio::join!(left.load_latest(), right.load_latest());
    let first = first?.unwrap();
    let second = second?.unwrap();
    assert!(is_epoch(&first.epoch));
    assert_eq!(first, second);
    assert_eq!(first.config.revision, 7);
    let next = applied(
        right
            .compare_and_swap(&first.epoch, 7, config(0, "after"))
            .await?,
    );
    assert_eq!(next.config.revision, 8);
    assert_eq!(left.load_latest().await?.unwrap(), next);
    Ok(())
}

/// A loopback TCP proxy in front of the fixture that loses acknowledgements
/// on purpose: for each marker in `schedule` (in order, one connection at a
/// time) it forwards the client's extended-query statement carrying that
/// marker, waits until the server has answered the execute round trip with
/// `ReadyForQuery` (the statement is committed), and then closes the client
/// connection instead of relaying the reply. Connections accepted after the
/// first loss wait for `gate` to open, so the test can interleave another
/// writer before the store's retry. `hold` names one statement whose
/// `Parse` is not forwarded until `release` opens (`held` reports when it is
/// waiting), so the test can change the durable state between two
/// statements of one connection.
struct LosingProxy {
    address: std::net::SocketAddr,
    lost: tokio::sync::mpsc::UnboundedReceiver<&'static str>,
    gate: tokio::sync::watch::Sender<bool>,
    hold: std::sync::Arc<std::sync::Mutex<Option<&'static str>>>,
    held: tokio::sync::mpsc::UnboundedReceiver<&'static str>,
    release: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl LosingProxy {
    /// Pause the next statement carrying `marker` before it reaches the
    /// server, until `release` opens.
    fn hold(&self, marker: &'static str) {
        *self.hold.lock().unwrap() = Some(marker);
    }
}

impl Drop for LosingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Split a byte stream into protocol messages: one type byte plus a
/// big-endian length that includes itself. The client's first message
/// (startup) has no type byte and is length-prefixed only.
fn take_frame(pending: &mut Vec<u8>, typed: bool) -> Option<Vec<u8>> {
    let (offset, header) = if typed { (1, 5) } else { (0, 4) };
    if pending.len() < header {
        return None;
    }
    let length = u32::from_be_bytes([
        pending[offset],
        pending[offset + 1],
        pending[offset + 2],
        pending[offset + 3],
    ]) as usize;
    (pending.len() >= offset + length).then(|| pending.drain(..offset + length).collect())
}

async fn losing_proxy(
    upstream: std::net::SocketAddr,
    schedule: Vec<&'static str>,
) -> anyhow::Result<LosingProxy> {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let (lost_tx, lost) = tokio::sync::mpsc::unbounded_channel();
    let (gate, gate_rx) = tokio::sync::watch::channel(false);
    let (held_tx, held) = tokio::sync::mpsc::unbounded_channel();
    let (release, release_rx) = tokio::sync::watch::channel(false);
    let hold: Arc<Mutex<Option<&'static str>>> = Arc::new(Mutex::new(None));
    let schedule = Arc::new(Mutex::new(std::collections::VecDeque::from(schedule)));
    let losses = Arc::new(AtomicUsize::new(0));
    let holds = hold.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            if losses.load(Ordering::SeqCst) > 0 {
                let mut gate = gate_rx.clone();
                if gate.wait_for(|open| *open).await.is_err() {
                    return;
                }
            }
            let Ok(server) = tokio::net::TcpStream::connect(upstream).await else {
                return;
            };
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            // Set by the client side when the scheduled marker's Parse was
            // forwarded: the marker and the 1-based index of the ReadyForQuery
            // that ends its execute round trip. Startup, every simple query
            // and every Sync are answered by exactly one ReadyForQuery, in
            // order, so the server side knows which reply to swallow even
            // when replies to earlier messages (a Close of a previous
            // statement) are still in flight.
            let armed: Arc<Mutex<Option<(&'static str, usize)>>> = Arc::new(Mutex::new(None));
            let schedule = schedule.clone();
            let losses = losses.clone();
            let lost_tx = lost_tx.clone();
            let hold = holds.clone();
            let held_tx = held_tx.clone();
            let release_rx = release_rx.clone();
            let mut client_to_server = tokio::spawn({
                let armed = armed.clone();
                async move {
                    let mut buffer = vec![0u8; 65_536];
                    let mut pending = Vec::new();
                    let mut startup_done = false;
                    let mut ready_expected = 0usize;
                    loop {
                        let Ok(count) = client_read.read(&mut buffer).await else {
                            return;
                        };
                        if count == 0 {
                            return;
                        }
                        pending.extend_from_slice(&buffer[..count]);
                        while let Some(frame) = take_frame(&mut pending, startup_done) {
                            if !startup_done {
                                ready_expected += 1;
                            } else {
                                match frame[0] {
                                    b'Q' | b'S' => ready_expected += 1,
                                    b'P' if armed.lock().unwrap().is_none() => {
                                        let mut schedule = schedule.lock().unwrap();
                                        if let Some(marker) = schedule.front().copied()
                                            && frame
                                                .windows(marker.len())
                                                .any(|window| window == marker.as_bytes())
                                        {
                                            schedule.pop_front();
                                            // This Parse batch ends with the
                                            // next Sync; the execute batch
                                            // with the one after.
                                            *armed.lock().unwrap() =
                                                Some((marker, ready_expected + 2));
                                        }
                                    }
                                    _ => {}
                                }
                                if frame[0] == b'P' {
                                    let holding = {
                                        let mut hold = hold.lock().unwrap();
                                        match *hold {
                                            Some(marker)
                                                if frame
                                                    .windows(marker.len())
                                                    .any(|window| window == marker.as_bytes()) =>
                                            {
                                                hold.take()
                                            }
                                            _ => None,
                                        }
                                    };
                                    if let Some(marker) = holding {
                                        let _ = held_tx.send(marker);
                                        let mut release = release_rx.clone();
                                        if release.wait_for(|open| *open).await.is_err() {
                                            return;
                                        }
                                    }
                                }
                            }
                            startup_done = true;
                            if server_write.write_all(&frame).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
            let mut server_to_client = tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_536];
                let mut pending = Vec::new();
                let mut replies = 0usize;
                loop {
                    let Ok(count) = server_read.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    pending.extend_from_slice(&buffer[..count]);
                    while let Some(frame) = take_frame(&mut pending, true) {
                        let ready = frame[0] == b'Z';
                        if let Some((marker, execute_sync)) = *armed.lock().unwrap()
                            && replies + 1 == execute_sync
                        {
                            // Inside the execute round trip: swallow it, and
                            // once the server reports ReadyForQuery the
                            // statement is committed and the client is cut
                            // off without an answer.
                            if ready {
                                losses.fetch_add(1, Ordering::SeqCst);
                                let _ = lost_tx.send(marker);
                                return;
                            }
                            continue;
                        }
                        if client_write.write_all(&frame).await.is_err() {
                            return;
                        }
                        if ready {
                            replies += 1;
                        }
                    }
                }
            });
            tokio::spawn(async move {
                tokio::select! {
                    _ = &mut client_to_server => {}
                    _ = &mut server_to_client => {}
                }
                // Dropping both halves closes the sockets.
                client_to_server.abort();
                server_to_client.abort();
            });
        }
    });
    Ok(LosingProxy {
        address,
        lost,
        gate,
        hold,
        held,
        release,
        task,
    })
}

/// Fixture-owned backup injection under the same epoch. The generation is
/// advanced explicitly; an obsolete SQL writer does not know how to do this.
async fn restore_same_epoch(url: &str, backup: &Stored) -> anyhow::Result<()> {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    let revision = i64::try_from(backup.config.revision)?;
    let restored = client
        .execute(
            "UPDATE hangang_config SET revision = $1, config_json = $2, write_generation=write_generation+1 WHERE singleton = 1 AND epoch = $3",
            &[
                &revision,
                &serde_json::to_string(&backup.config)?,
                &backup.epoch,
            ],
        )
        .await?;
    anyhow::ensure!(restored == 1, "restore changed {restored} rows");
    Ok(())
}

/// The fixture's TCP endpoint and a connection string for the same database
/// through `proxy`.
fn proxied_url(
    url: &str,
    proxy: std::net::SocketAddr,
) -> anyhow::Result<(std::net::SocketAddr, String)> {
    let config: tokio_postgres::Config = url.parse()?;
    let host = match config.get_hosts() {
        [tokio_postgres::config::Host::Tcp(host)] => host.clone(),
        other => anyhow::bail!("fixture URL must name one TCP host: {other:?}"),
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    let upstream = std::net::SocketAddr::new(host.parse()?, port);
    let user = config.get_user().unwrap_or("postgres");
    let password = std::str::from_utf8(config.get_password().unwrap_or_default())?;
    let dbname = config.get_dbname().unwrap_or("postgres");
    Ok((
        upstream,
        format!(
            "host={} port={} user={user} password={password} dbname={dbname}",
            proxy.ip(),
            proxy.port()
        ),
    ))
}

const CAS_MARKER: &str = "UPDATE hangang_config SET revision";
const RECEIPT_CAS_MARKER: &str = "INSERT INTO hangang_commit_receipts";
const V2_CAS_MARKER: &str = "SELECT hangang_cas_v2";
const LOAD_MARKER: &str = "SELECT revision,";
const BOOTSTRAP_MARKER: &str = "INSERT INTO hangang_config(singleton";

async fn next_fault(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<&'static str>,
) -> anyhow::Result<Option<&'static str>> {
    Ok(tokio::time::timeout(Duration::from_secs(10), receiver.recv()).await?)
}

async fn join_fault<T>(task: tokio::task::JoinHandle<T>) -> anyhow::Result<T> {
    Ok(tokio::time::timeout(Duration::from_secs(30), task).await??)
}

/// F6: a committed CAS whose acknowledgement is lost is recognised as our
/// own write when the store still holds it, and is `Indeterminate` (never a
/// conflict, never "nothing changed") when another writer moved on before
/// the retry, when the recovery read fails, or when a same-epoch backup
/// restore brought the expected revision back before the recovery read.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_lost_acknowledgement_is_never_a_false_conflict() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .batch_execute("DROP TABLE IF EXISTS hangang_config")
            .await?;
    }
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let epoch = direct.bootstrap(config(0, "initial")).await?.epoch;
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;

    // 1. Lost acknowledgement, no other writer: the retry finds our own
    //    document at expected + 1 and reports it applied.
    let mut proxy = losing_proxy(upstream, vec![CAS_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let result = writer
        .compare_and_swap(&epoch, 0, config(0, "lost-1"))
        .await;
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(CAS_MARKER));
    let stored = applied(result?);
    assert_eq!(stored.config.revision, 1);
    assert_eq!(stored.http_id(), "lost-1");
    assert_eq!(direct.load_latest().await?.unwrap(), stored);
    drop(proxy);

    // 2. Lost acknowledgement, then another writer commits before the retry:
    //    the durable state no longer proves anything about our write.
    let mut proxy = losing_proxy(upstream, vec![CAS_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    let racing = tokio::spawn({
        let writer = writer.clone();
        let epoch = epoch.clone();
        async move {
            writer
                .compare_and_swap(&epoch, 1, config(0, "lost-2"))
                .await
        }
    });
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(CAS_MARKER));
    // Our write is durable although we never heard back.
    let committed = direct.load_latest().await?.unwrap();
    assert_eq!(committed.config.revision, 2);
    assert_eq!(committed.http_id(), "lost-2");
    let other = applied(
        direct
            .compare_and_swap(&epoch, 2, config(0, "other"))
            .await?,
    );
    assert_eq!(other.config.revision, 3);
    proxy.gate.send_replace(true);
    let error = match join_fault(racing).await? {
        Ok(result) => panic!("a lost, overtaken write must not resolve: {result:?}"),
        Err(error) => error,
    };
    assert!(
        matches!(error, StoreError::Indeterminate(_)),
        "overtaken lost write: {error}"
    );
    assert_eq!(direct.load_latest().await?.unwrap(), other);
    drop(proxy);

    // 3. Lost acknowledgement and the recovery read fails on both attempts:
    //    the write is durable, so "unavailable, nothing changed" would lie.
    let mut proxy = losing_proxy(upstream, vec![CAS_MARKER, LOAD_MARKER, LOAD_MARKER]).await?;
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    proxy.gate.send_replace(true);
    let error = match writer
        .compare_and_swap(&epoch, 3, config(0, "lost-3"))
        .await
    {
        Ok(result) => {
            panic!("a lost write with a failed recovery read must not resolve: {result:?}")
        }
        Err(error) => error,
    };
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(CAS_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(LOAD_MARKER));
    assert!(
        matches!(error, StoreError::Indeterminate(_)),
        "lost write, unreadable store: {error}"
    );
    let durable = direct.load_latest().await?.unwrap();
    assert_eq!(durable.config.revision, 4);
    assert_eq!(durable.http_id(), "lost-3");
    drop(proxy);

    // 4. Lost acknowledgement, overtaken, and then a backup taken under the
    //    same epoch before our write is restored between the retry (which
    //    changed nothing) and the recovery read: the durable state is
    //    (epoch, expected) again although our write committed and was
    //    visible, so it does not prove that the write never landed.
    let backup = durable;
    let mut proxy = losing_proxy(upstream, vec![CAS_MARKER]).await?;
    proxy.hold(LOAD_MARKER);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let writer = PostgresConfigStore::connect_unencrypted(&through).await?;
    let racing = tokio::spawn({
        let writer = writer.clone();
        let epoch = epoch.clone();
        async move {
            writer
                .compare_and_swap(&epoch, 4, config(0, "lost-4"))
                .await
        }
    });
    assert_eq!(next_fault(&mut proxy.lost).await?, Some(CAS_MARKER));
    let committed = direct.load_latest().await?.unwrap();
    assert_eq!(committed.config.revision, 5);
    assert_eq!(committed.http_id(), "lost-4");
    let other = applied(
        direct
            .compare_and_swap(&epoch, 5, config(0, "other-2"))
            .await?,
    );
    assert_eq!(other.config.revision, 6);
    proxy.gate.send_replace(true);
    // The retry has been answered (it changed nothing: the row is at 6) and
    // the recovery read is waiting at the proxy.
    assert_eq!(next_fault(&mut proxy.held).await?, Some(LOAD_MARKER));
    assert_eq!(direct.load_latest().await?.unwrap(), other);
    restore_same_epoch(&url, &backup).await?;
    proxy.release.send_replace(true);
    let error = match join_fault(racing).await? {
        Ok(result) => {
            panic!("a lost write behind a same-epoch restore must not resolve: {result:?}")
        }
        Err(error) => error,
    };
    assert!(
        matches!(error, StoreError::Indeterminate(_)),
        "restored expected revision: {error}"
    );
    assert_eq!(direct.load_latest().await?.unwrap(), backup);
    Ok(())
}

/// A bootstrap whose INSERT was committed but never acknowledged may have
/// seeded the shared authority; when the read that follows fails too, the
/// outcome is `Indeterminate`, not "unavailable, nothing changed".
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_lost_bootstrap_acknowledgement_is_never_nothing_changed() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .batch_execute("DROP TABLE IF EXISTS hangang_config")
            .await?;
    }
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    let mut proxy =
        losing_proxy(upstream, vec![BOOTSTRAP_MARKER, LOAD_MARKER, LOAD_MARKER]).await?;
    proxy.gate.send_replace(true);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let seeder = PostgresConfigStore::connect_unencrypted(&through).await?;
    let outcome =
        tokio::time::timeout(Duration::from_secs(30), seeder.bootstrap(config(0, "seed"))).await?;
    let error = match outcome {
        Ok(stored) => panic!("a lost insert with a failed read must not resolve: {stored:?}"),
        Err(error) => error,
    };
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), proxy.lost.recv()).await?,
        Some(BOOTSTRAP_MARKER)
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), proxy.lost.recv()).await?,
        Some(LOAD_MARKER)
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), proxy.lost.recv()).await?,
        Some(LOAD_MARKER)
    );
    assert!(
        matches!(error, StoreError::Indeterminate(_)),
        "lost bootstrap insert, unreadable store: {error}"
    );
    assert!(
        error
            .to_string()
            .contains("bootstrap insert was not acknowledged"),
        "{error}"
    );
    // The seed is the shared authority now.
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let durable = direct.load_latest().await?.unwrap();
    assert_eq!(durable.config.revision, 0);
    assert_eq!(durable.http_id(), "seed");
    assert!(is_epoch(&durable.epoch));
    // Repeating the bootstrap is idempotent and returns the durable seed.
    assert_eq!(direct.bootstrap(config(0, "seed-again")).await?, durable);
    Ok(())
}

/// NEW26: a bootstrap whose INSERT was committed but never acknowledged, whose
/// retry changed nothing, and whose recovery read finds the store empty
/// because the row was wiped in between. The seed was the shared authority
/// and the empty read cannot say whether it ever was, so the outcome is
/// `Indeterminate`, not "invalid content, nothing changed".
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_lost_bootstrap_acknowledgement_behind_a_wipe_is_indeterminate()
-> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        client
            .batch_execute("DROP TABLE IF EXISTS hangang_config")
            .await?;
    }
    let (upstream, _) = proxied_url(&url, "127.0.0.1:1".parse()?)?;
    let mut proxy = losing_proxy(upstream, vec![BOOTSTRAP_MARKER]).await?;
    proxy.hold(LOAD_MARKER);
    proxy.gate.send_replace(true);
    let (_, through) = proxied_url(&url, proxy.address)?;
    let seeder = PostgresConfigStore::connect_unencrypted(&through).await?;
    let racing = tokio::spawn({
        let seeder = seeder.clone();
        async move { seeder.bootstrap(config(0, "seed")).await }
    });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), proxy.lost.recv()).await?,
        Some(BOOTSTRAP_MARKER)
    );
    // The retry has been answered (it changed nothing: the seed is there) and
    // the recovery read is waiting at the proxy.
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), proxy.held.recv()).await?,
        Some(LOAD_MARKER)
    );
    let direct = PostgresConfigStore::connect_unencrypted(&url).await?;
    let seeded = direct.load_latest().await?.unwrap();
    assert_eq!(seeded.config.revision, 0);
    assert_eq!(seeded.http_id(), "seed");
    assert!(is_epoch(&seeded.epoch));
    // The store is wiped while the read waits: the seed was the authority
    // until now, and the read that follows sees nothing.
    {
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
        tokio::spawn(connection);
        let wiped = client
            .execute("DELETE FROM hangang_config WHERE singleton = 1", &[])
            .await?;
        assert_eq!(wiped, 1);
    }
    proxy.release.send_replace(true);
    let outcome = tokio::time::timeout(Duration::from_secs(30), racing).await??;
    let error = match outcome {
        Ok(stored) => panic!("a lost insert behind a wipe must not resolve: {stored:?}"),
        Err(error) => error,
    };
    assert!(
        matches!(error, StoreError::Indeterminate(_)),
        "lost bootstrap insert, wiped store: {error}"
    );
    assert!(error.is_transport());
    assert!(
        error
            .to_string()
            .contains("bootstrap insert was not acknowledged"),
        "{error}"
    );
    // The wiped store is empty, and the next bootstrap is a new authority.
    assert_eq!(direct.load_latest().await?, None);
    let fresh = direct.bootstrap(config(0, "after-wipe")).await?;
    assert_eq!(fresh.config.revision, 0);
    assert_eq!(fresh.http_id(), "after-wipe");
    assert!(is_epoch(&fresh.epoch));
    assert_ne!(fresh.epoch, seeded.epoch);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_verified_tls_accepts_only_configured_trust() -> anyhow::Result<()> {
    let (Ok(url), Ok(ca)) = (
        std::env::var("HANGANG_TEST_POSTGRES_TLS_URL"),
        std::env::var("HANGANG_TEST_POSTGRES_CA"),
    ) else {
        return Ok(());
    };
    let trusted = hangang::tls::client_config(Some(std::path::Path::new(&ca)))?;
    let store = PostgresConfigStore::connect(&url, trusted).await?;
    store.bootstrap(config(0, "tls")).await?;

    let wrong_trust = hangang::tls::client_config(None)?;
    assert!(
        PostgresConfigStore::connect(&url, wrong_trust)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_reconnects_after_owned_fixture_restart() -> anyhow::Result<()> {
    let (Ok(url), Ok(container)) = (
        std::env::var("HANGANG_TEST_POSTGRES_URL"),
        std::env::var("HANGANG_TEST_POSTGRES_CONTAINER"),
    ) else {
        return Ok(());
    };
    assert!(container.starts_with("hangang-configstore-"));
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let before = store.bootstrap(config(0, "restart")).await?;

    let stopped = tokio::process::Command::new("docker")
        .args(["stop", &container])
        .status()
        .await?;
    assert!(stopped.success());
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    let error = store
        .compare_and_swap(&before.epoch, 0, config(0, "down"))
        .await
        .unwrap_err();
    assert!(error.is_transport(), "{error}");
    let started = tokio::process::Command::new("docker")
        .args(["start", &container])
        .status()
        .await?;
    assert!(started.success());

    let recovered = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            if let Ok(Some(stored)) = store.load_latest().await {
                break stored;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    })
    .await?;
    assert_eq!(recovered, before);
    Ok(())
}

#[tokio::test]
async fn plaintext_postgres_cannot_override_loopback_with_remote_hostaddr() {
    let result = hangang::config_store::PostgresConfigStore::connect_unencrypted(
        "host=localhost hostaddr=192.0.2.1 user=test",
    )
    .await;
    let error = match result {
        Ok(_) => panic!("remote plaintext address accepted"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("loopback host addresses"));
}

/// A seed whose runtime resources cannot be prepared must never be persisted
/// as the shared authority; a valid seed bootstraps normally, and a later
/// instance receives the committed snapshot prepared instead of its own seed.
#[tokio::test]
async fn bootstrap_prepares_the_seed_before_it_can_poison_the_store() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = SqliteConfigStore::open(directory.path().join("state.db")).await?;
    let mut unpreparable = config(0, "tls");
    unpreparable.certificates.push(CertificateFiles {
        id: "missing".into(),
        hosts: vec!["missing.example".into()],
        default: false,
        enabled: true,
        cert_file: "/nonexistent/hangang-cert.pem".into(),
        key_file: "/nonexistent/hangang-key.pem".into(),
        issuer_status_file: None,
    });
    assert!(unpreparable.validate().is_ok(), "metadata alone is valid");
    let error = match bootstrap_prepared(&store, unpreparable).await {
        Ok(_) => panic!("an unpreparable seed was accepted"),
        Err(error) => error,
    };
    assert!(matches!(error, StoreError::Invalid(_)), "{error}");
    assert!(format!("{error:#}").contains("seed"), "{error:#}");
    assert!(
        store.load_latest().await?.is_none(),
        "an unpreparable seed must not be persisted"
    );

    let prepared = bootstrap_prepared(&store, config(0, "first")).await?;
    assert_eq!(prepared.snapshot.config.http[0].id, "first");
    assert!(is_epoch(&prepared.epoch));
    let stored = store.load_latest().await?.unwrap();
    assert_eq!(stored.config, prepared.snapshot.config);
    assert_eq!(stored.epoch, prepared.epoch);

    let second = bootstrap_prepared(&store, config(0, "second")).await?;
    assert_eq!(
        second.snapshot.config.http[0].id, "first",
        "a losing instance prepares the committed snapshot"
    );
    assert_eq!(second.epoch, prepared.epoch);
    Ok(())
}
