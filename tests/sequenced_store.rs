use hangang::{
    config::Config,
    config_store::{
        CasResult, ConfigStore, MAX_ACCEPTANCE_SEQUENCE, OperationStamp, PostgresConfigStore,
        SequencedCommitReceipt, SequencedOperationStamp, SqliteConfigStore, StoreError,
        canonical_operation_id,
    },
};
use sha2::{Digest, Sha256};

const AUTHORITY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_AUTHORITY: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn document(revision: u64, dot_segments: bool) -> Config {
    let mut config = Config {
        revision,
        ..Config::default()
    };
    config.settings.allow_dot_segments = Some(dot_segments);
    config
}

fn stamp(
    authority: &str,
    sequence: u64,
    expected: u64,
    candidate: &Config,
) -> SequencedOperationStamp {
    let mut next = candidate.clone();
    next.revision = expected + 1;
    SequencedOperationStamp {
        authority_id: authority.into(),
        acceptance_seq: sequence,
        operation_id: canonical_operation_id(authority, sequence).unwrap(),
        candidate_sha256: format!("{:x}", Sha256::digest(serde_json::to_vec(&next).unwrap())),
    }
}

fn applied(result: CasResult) -> Config {
    match result {
        CasResult::Applied(stored) => stored.config,
        CasResult::Conflict { current } => panic!(
            "unexpected conflict at revision {}",
            current.config.revision
        ),
    }
}

async fn assert_sequenced_contract(store: &dyn ConfigStore) -> anyhow::Result<()> {
    assert!(store.supports_sequenced_operation_cas());
    let initial = store.bootstrap(document(0, false)).await?;
    let epoch = initial.epoch;
    let unknown = store.lookup_commit_receipt_v2(OTHER_AUTHORITY, 1).await?;
    assert_eq!(unknown.receipt, None);
    assert_eq!(unknown.high_water, 0);
    assert_eq!(unknown.stored_records, 0);
    assert_eq!(unknown.capacity, 100_000);
    assert!(unknown.writes_available);
    for (authority, sequence) in [
        (AUTHORITY, 0),
        (AUTHORITY, MAX_ACCEPTANCE_SEQUENCE + 1),
        ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1),
    ] {
        assert!(matches!(
            store.lookup_commit_receipt_v2(authority, sequence).await,
            Err(StoreError::Invalid(_))
        ));
    }
    let mut malformed = stamp(AUTHORITY, 1, 0, &document(0, true));
    malformed.operation_id = "f".repeat(32);
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), malformed)
            .await,
        Err(StoreError::Invalid(_)),
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);

    // A gap before first acceptance is legal. Committed sequence 2 fences a
    // later proposal with sequence 1 even when its config revision is current.
    let first_candidate = document(0, true);
    let second = stamp(AUTHORITY, 2, 0, &first_candidate);
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&epoch, 0, first_candidate.clone(), second.clone())
                .await?
        )
        .revision,
        1,
    );
    let retained = store.lookup_commit_receipt_v2(AUTHORITY, 2).await?;
    assert_eq!(retained.high_water, 2);
    assert_eq!(retained.stored_records, 1);
    assert_eq!(
        retained.receipt,
        Some(SequencedCommitReceipt {
            epoch: epoch.clone(),
            revision: 1,
            stamp: second.clone(),
        })
    );
    // The V2 operation_id has the same shape as a V1 ID. An older writer
    // presenting it as a V1 stamp must not convert a V2 commit into V1 Applied.
    let v1_collision = OperationStamp {
        authority_id: second.authority_id.clone(),
        operation_id: second.operation_id.clone(),
        candidate_sha256: second.candidate_sha256.clone(),
    };
    assert!(!matches!(
        store
            .compare_and_swap_operation(&epoch, 0, first_candidate.clone(), v1_collision)
            .await,
        Ok(CasResult::Applied(_)),
    ));
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&epoch, 0, first_candidate.clone(), second.clone())
                .await?
        )
        .revision,
        1,
    );
    let lower = stamp(AUTHORITY, 1, 1, &document(0, false));
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 1, document(0, false), lower)
            .await,
        Ok(CasResult::Conflict { .. }),
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 1);

    let third_candidate = document(0, false);
    let third = stamp(AUTHORITY, 3, 1, &third_candidate);
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&epoch, 1, third_candidate, third.clone())
                .await?
        )
        .revision,
        2,
    );
    let old_retry = store
        .compare_and_swap_operation_v2(&epoch, 0, first_candidate, second.clone())
        .await?;
    assert!(
        matches!(old_retry, CasResult::Conflict { .. }),
        "retained old receipt must not reactivate revision 1"
    );
    let old = store.lookup_commit_receipt_v2(AUTHORITY, 2).await?;
    assert_eq!(old.receipt.unwrap().stamp, second);
    assert_eq!(old.high_water, 3);
    assert_eq!(
        store
            .lookup_commit_receipt(AUTHORITY, &third.operation_id)
            .await?
            .receipt,
        None
    );

    // A legacy SQL writer clears the current stamp but not the V2 high-water
    // or previously committed historical receipts.
    assert_eq!(
        applied(store.compare_and_swap(&epoch, 2, document(0, true)).await?).revision,
        3
    );
    assert_eq!(store.load_current_operation_proof().await?, None);
    let after_legacy = store.lookup_commit_receipt_v2(AUTHORITY, 3).await?;
    assert_eq!(after_legacy.high_water, 3);
    assert_eq!(after_legacy.receipt.unwrap().stamp, third);
    assert_eq!(after_legacy.stored_records, 2);
    Ok(())
}

#[test]
fn canonical_sequences_and_stamp_validation_are_bounded() {
    let one = canonical_operation_id(AUTHORITY, 1).unwrap();
    let two = canonical_operation_id(AUTHORITY, 2).unwrap();
    assert_ne!(one, two);
    assert_eq!(one.len(), 32);
    assert_eq!(&one[..16], "0000000000000001");
    assert!(canonical_operation_id(AUTHORITY, MAX_ACCEPTANCE_SEQUENCE).is_ok());
    for (authority, sequence) in [
        (AUTHORITY, 0),
        (AUTHORITY, MAX_ACCEPTANCE_SEQUENCE + 1),
        ("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 1),
        ("short", 1),
    ] {
        assert!(matches!(
            canonical_operation_id(authority, sequence),
            Err(StoreError::Invalid(_))
        ));
    }
}

#[tokio::test]
async fn sqlite_sequenced_contract() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = SqliteConfigStore::open(directory.path().join("config.db")).await?;
    assert_sequenced_contract(&store).await
}

#[tokio::test]
async fn sqlite_release_is_atomic_exact_bounded_and_durable() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("release.db");
    let store = SqliteConfigStore::open(&path).await?;
    assert!(store.supports_receipt_release_v2());
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    let receipt = store
        .lookup_commit_receipt_v2(AUTHORITY, 2)
        .await?
        .receipt
        .unwrap();
    assert_eq!(store.lookup_receipt_pin_v2(AUTHORITY, 2).await?, Some(true));
    let release_id = "11111111111111111111111111111111";
    let mut wrong = receipt.clone();
    wrong.stamp.candidate_sha256 = "0".repeat(64);
    assert!(matches!(
        store.release_commit_receipt_v2(release_id, &wrong).await,
        Err(StoreError::Invalid(_))
    ));
    assert_eq!(store.lookup_receipt_release_v2(release_id).await?, None);
    assert_eq!(store.lookup_receipt_pin_v2(AUTHORITY, 2).await?, Some(true));
    store
        .release_commit_receipt_v2(release_id, &receipt)
        .await?;
    store
        .release_commit_receipt_v2(release_id, &receipt)
        .await?;
    assert_eq!(
        store.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(false)
    );
    assert_eq!(
        store.lookup_receipt_release_v2(release_id).await?,
        Some(receipt.clone())
    );
    assert!(matches!(
        store
            .release_commit_receipt_v2("22222222222222222222222222222222", &receipt)
            .await,
        Err(StoreError::Invalid(_))
    ));
    let reopened = SqliteConfigStore::open(&path).await?;
    assert_eq!(
        reopened.lookup_receipt_release_v2(release_id).await?,
        Some(receipt.clone())
    );
    assert_eq!(
        reopened.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(false)
    );

    let connection = rusqlite::Connection::open(&path)?;
    assert!(connection.execute(
        "UPDATE hangang_sequenced_receipts SET unresolved_pin=1 WHERE authority_id=?1 AND acceptance_seq=2",
        [AUTHORITY],
    ).is_err(), "released receipt cannot be re-pinned");
    connection.execute(
        "UPDATE hangang_receipt_release_meta SET stored_records=100000 WHERE singleton=1",
        [],
    )?;
    let operation = stamp(AUTHORITY, 3, 1, &document(0, false));
    applied(
        reopened
            .compare_and_swap_operation_v2(&epoch, 1, document(0, false), operation)
            .await?,
    );
    let next = reopened
        .lookup_commit_receipt_v2(AUTHORITY, 3)
        .await?
        .receipt
        .unwrap();
    assert!(matches!(
        reopened
            .release_commit_receipt_v2("33333333333333333333333333333333", &next)
            .await,
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(
        reopened.lookup_receipt_pin_v2(AUTHORITY, 3).await?,
        Some(true)
    );
    assert_eq!(
        reopened
            .lookup_receipt_release_v2("33333333333333333333333333333333")
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_versioned_schema_refuses_lost_release_ledger() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("lost-ledger.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    let receipt = store
        .lookup_commit_receipt_v2(AUTHORITY, 2)
        .await?
        .receipt
        .unwrap();
    store
        .release_commit_receipt_v2("11111111111111111111111111111111", &receipt)
        .await?;
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch("DROP TABLE hangang_receipt_releases")?;
    assert!(
        SqliteConfigStore::open(&path).await.is_err(),
        "version 2 must not rebuild lost evidence"
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_legacy_receipts_backfill_and_failed_migration_rolls_back() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("legacy-pins.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    drop(store);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER hangang_sequenced_pin_insert_guard;
         ALTER TABLE hangang_sequenced_receipts RENAME TO old_receipts;
         CREATE TABLE hangang_sequenced_receipts (
           authority_id TEXT NOT NULL, acceptance_seq INTEGER NOT NULL,
           operation_id TEXT NOT NULL, epoch TEXT NOT NULL, revision INTEGER NOT NULL,
           candidate_sha256 TEXT NOT NULL,
           PRIMARY KEY(authority_id,acceptance_seq),UNIQUE(authority_id,operation_id)
         ) STRICT;
         INSERT INTO hangang_sequenced_receipts SELECT authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256 FROM old_receipts;
         DROP TABLE old_receipts;
         UPDATE hangang_receipt_schema_meta SET version=1 WHERE singleton=1;
         CREATE TRIGGER reject_pin_migration BEFORE UPDATE ON hangang_receipt_schema_meta
           BEGIN SELECT RAISE(ABORT,'fixture migration failure'); END;",
    )?;
    assert!(SqliteConfigStore::open(&path).await.is_err());
    let pin_columns: i64 = connection.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('hangang_sequenced_receipts') WHERE name='unresolved_pin'",
        [], |row| row.get(0),
    )?;
    assert_eq!(
        pin_columns, 0,
        "failed migration must not leave a half-installed pin"
    );
    connection.execute_batch("DROP TRIGGER reject_pin_migration")?;
    let reopened = SqliteConfigStore::open(&path).await?;
    assert_eq!(
        reopened.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(true)
    );
    let next_id = canonical_operation_id(AUTHORITY, 3)?;
    connection.execute(
        "INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256)
         VALUES(?1,3,?2,?3,2,?4)",
        rusqlite::params![AUTHORITY, next_id, epoch, "f".repeat(64)],
    )?;
    assert_eq!(
        reopened.lookup_receipt_pin_v2(AUTHORITY, 3).await?,
        Some(true)
    );
    let rejected = connection.execute(
        "INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256,unresolved_pin)
         VALUES(?1,4,?2,?3,3,?4,0)",
        rusqlite::params![AUTHORITY, canonical_operation_id(AUTHORITY, 4)?, epoch, "f".repeat(64)],
    );
    assert!(
        rejected.is_err(),
        "explicit unpinned legacy INSERT must fail"
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_v2_insert_failure_rolls_back_document_receipt_and_fence() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let direct = rusqlite::Connection::open(&path)?;
    direct.execute_batch("CREATE TRIGGER fail_sequenced_receipt BEFORE INSERT ON hangang_sequenced_receipts BEGIN SELECT RAISE(ABORT,'owned fixture rejects receipt'); END")?;
    let candidate = document(0, true);
    let operation = stamp(AUTHORITY, 1, 0, &candidate);
    assert!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, candidate, operation)
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    let after = store.lookup_commit_receipt_v2(AUTHORITY, 1).await?;
    assert_eq!(after.receipt, None);
    assert_eq!(after.high_water, 0);
    assert_eq!(after.stored_records, 0);
    Ok(())
}

#[tokio::test]
async fn sqlite_v2_config_reseed_keeps_high_water_and_rejects_replay() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let old_epoch = store.bootstrap(document(0, false)).await?.epoch;
    let first = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&old_epoch, 0, document(0, true), first.clone())
            .await?,
    );
    let direct = rusqlite::Connection::open(&path)?;
    let old_writer_json = serde_json::to_string(&document(2, false))?;
    assert!(
        direct
            .execute(
                "UPDATE hangang_config SET revision=2,config_json=?1 WHERE singleton=1",
                [&old_writer_json]
            )
            .is_err()
    );
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 1);
    direct.execute("DELETE FROM hangang_config WHERE singleton=1", [])?;
    let new_epoch = store.bootstrap(document(0, false)).await?.epoch;
    assert_ne!(new_epoch, old_epoch);
    let retained = store.lookup_commit_receipt_v2(AUTHORITY, 2).await?;
    assert_eq!(retained.high_water, 2);
    assert_eq!(retained.receipt.unwrap().stamp, first);
    let replay = stamp(AUTHORITY, 1, 0, &document(0, true));
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&new_epoch, 0, document(0, true), replay)
            .await,
        Ok(CasResult::Conflict { .. }),
    ));
    let next = stamp(AUTHORITY, 3, 0, &document(0, true));
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&new_epoch, 0, document(0, true), next)
                .await?
        )
        .revision,
        1
    );
    assert_eq!(
        store
            .lookup_commit_receipt_v2(AUTHORITY, 3)
            .await?
            .high_water,
        3
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_v2_registry_capacity_rejects_new_authority_but_allows_known_one()
-> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let mut direct = rusqlite::Connection::open(&path)?;
    let transaction = direct.transaction()?;
    for id in 1..=4096_u64 {
        transaction.execute(
            "INSERT INTO hangang_sequenced_authorities(authority_id,high_water) VALUES(?1,1)",
            [format!("{id:032x}")],
        )?;
    }
    transaction.commit()?;
    let unknown = store.lookup_commit_receipt_v2(AUTHORITY, 1).await?;
    assert_eq!(unknown.high_water, 0);
    assert!(!unknown.writes_available);
    let rejected = stamp(AUTHORITY, 1, 0, &document(0, true));
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), rejected)
            .await,
        Err(StoreError::Unavailable(_)),
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    assert_eq!(
        store.lookup_commit_receipt_v2(AUTHORITY, 1).await?.receipt,
        None
    );
    let known = format!("{:032x}", 1);
    let accepted = stamp(&known, 2, 0, &document(0, true));
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&epoch, 0, document(0, true), accepted)
                .await?
        )
        .revision,
        1
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_v2_receipt_capacity_rolls_back_configuration() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let direct = rusqlite::Connection::open(&path)?;
    direct.execute(
        "UPDATE hangang_commit_receipt_meta SET stored_records=100000 WHERE singleton=1",
        [],
    )?;
    let before = store.lookup_commit_receipt_v2(AUTHORITY, 1).await?;
    assert_eq!(before.stored_records, 100_000);
    assert!(!before.writes_available);
    let candidate = document(0, true);
    let operation = stamp(AUTHORITY, 1, 0, &candidate);
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, candidate, operation)
            .await,
        Err(StoreError::Unavailable(_)),
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    assert_eq!(
        store.lookup_commit_receipt_v2(AUTHORITY, 1).await?.receipt,
        None
    );
    Ok(())
}

async fn postgres_fixture() -> anyhow::Result<Option<(PostgresConfigStore, tokio_postgres::Client)>>
{
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(None);
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config CASCADE; DROP TABLE IF EXISTS hangang_commit_receipts CASCADE; DROP TABLE IF EXISTS hangang_sequenced_receipts CASCADE; DROP TABLE IF EXISTS hangang_sequenced_authorities CASCADE; DROP TABLE IF EXISTS hangang_commit_receipt_meta CASCADE; DROP TABLE IF EXISTS hangang_receipt_schema_meta CASCADE; DROP TABLE IF EXISTS hangang_receipt_releases CASCADE; DROP TABLE IF EXISTS hangang_receipt_release_meta CASCADE").await?;
    Ok(Some((
        PostgresConfigStore::connect_unencrypted(&url).await?,
        client,
    )))
}

/// Run only through tests/pg_fixture.py with HANGANG_PG_TEST_TARGET=sequenced_store.
#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_sequenced_contract() -> anyhow::Result<()> {
    let Some((store, _client)) = postgres_fixture().await? else {
        return Ok(());
    };
    assert_sequenced_contract(&store).await
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_pin_guard_survives_legacy_cas_replacement_and_release_is_durable()
-> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    let receipt = store
        .lookup_commit_receipt_v2(AUTHORITY, 2)
        .await?
        .receipt
        .unwrap();
    assert_eq!(store.lookup_receipt_pin_v2(AUTHORITY, 2).await?, Some(true));
    let url = std::env::var("HANGANG_TEST_POSTGRES_URL")?;
    // Connecting an older-compatible initializer replaces hangang_cas_v2;
    // the independent receipt trigger must still protect INSERT.
    let reconnected = PostgresConfigStore::connect_unencrypted(&url).await?;
    let legacy_id = canonical_operation_id(AUTHORITY, 3)?;
    client.batch_execute(
        "CREATE OR REPLACE FUNCTION hangang_cas_v2(BIGINT,TEXT,TEXT,TEXT,TEXT,BIGINT,BIGINT,TEXT)
         RETURNS BOOLEAN LANGUAGE plpgsql AS $$ BEGIN
           INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256)
           VALUES($3,$6,$4,$8,$1,$5);
           RETURN TRUE;
         END $$;",
    ).await?;
    let inserted: bool = client
        .query_one(
            "SELECT hangang_cas_v2($1,$2,$3,$4,$5,$6,$7,$8)",
            &[
                &2_i64,
                &"old initializer",
                &AUTHORITY,
                &legacy_id,
                &"f".repeat(64),
                &3_i64,
                &1_i64,
                &epoch,
            ],
        )
        .await?
        .get(0);
    assert!(inserted);
    assert_eq!(
        reconnected.lookup_receipt_pin_v2(AUTHORITY, 3).await?,
        Some(true)
    );
    let bad = client.execute(
        "INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256,unresolved_pin) VALUES($1,4,$2,$3,3,$4,FALSE)",
        &[&AUTHORITY,&canonical_operation_id(AUTHORITY, 4)?,&epoch,&"f".repeat(64)],
    ).await;
    assert!(bad.is_err());
    let release_id = "11111111111111111111111111111111";
    client.batch_execute(
        "CREATE FUNCTION owned_skip_pin_update() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$;
         CREATE TRIGGER skip_pin_update BEFORE UPDATE ON hangang_sequenced_receipts
           FOR EACH ROW EXECUTE FUNCTION owned_skip_pin_update();",
    ).await?;
    assert!(
        reconnected
            .release_commit_receipt_v2(release_id, &receipt)
            .await
            .is_err()
    );
    assert_eq!(
        reconnected.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(true)
    );
    assert_eq!(
        reconnected.lookup_receipt_release_v2(release_id).await?,
        None
    );
    client
        .batch_execute("DROP TRIGGER skip_pin_update ON hangang_sequenced_receipts")
        .await?;
    reconnected
        .release_commit_receipt_v2(release_id, &receipt)
        .await?;
    reconnected
        .release_commit_receipt_v2(release_id, &receipt)
        .await?;
    assert_eq!(
        reconnected.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(false)
    );
    assert_eq!(
        reconnected.lookup_receipt_release_v2(release_id).await?,
        Some(receipt.clone())
    );
    assert!(
        reconnected
            .release_commit_receipt_v2("22222222222222222222222222222222", &receipt)
            .await
            .is_err()
    );
    let reopened = PostgresConfigStore::connect_unencrypted(&url).await?;
    assert_eq!(
        reopened.lookup_receipt_release_v2(release_id).await?,
        Some(receipt)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_pin_migration_failure_rolls_back_column_and_guard() -> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    client.batch_execute(
        "DROP TRIGGER hangang_sequenced_pin_insert_guard ON hangang_sequenced_receipts;
         DROP TRIGGER hangang_sequenced_pin_release_guard ON hangang_sequenced_receipts;
         ALTER TABLE hangang_sequenced_receipts DROP COLUMN unresolved_pin;
         UPDATE hangang_receipt_schema_meta SET version=1 WHERE singleton=1;
         CREATE FUNCTION owned_reject_pin_migration() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture abort'; END $$;
         CREATE TRIGGER reject_pin_version BEFORE UPDATE ON hangang_receipt_schema_meta FOR EACH ROW EXECUTE FUNCTION owned_reject_pin_migration();",
    ).await?;
    let url = std::env::var("HANGANG_TEST_POSTGRES_URL")?;
    assert!(
        PostgresConfigStore::connect_unencrypted(&url)
            .await
            .is_err()
    );
    let column: i64 = client.query_one(
        "SELECT count(*) FROM information_schema.columns WHERE table_name='hangang_sequenced_receipts' AND column_name='unresolved_pin'",
        &[],
    ).await?.get(0);
    assert_eq!(column, 0);
    client
        .batch_execute("DROP TRIGGER reject_pin_version ON hangang_receipt_schema_meta")
        .await?;
    let reopened = PostgresConfigStore::connect_unencrypted(&url).await?;
    assert_eq!(
        reopened.lookup_receipt_pin_v2(AUTHORITY, 2).await?,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_versioned_schema_refuses_lost_release_ledger() -> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    let operation = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), operation)
            .await?,
    );
    let receipt = store
        .lookup_commit_receipt_v2(AUTHORITY, 2)
        .await?
        .receipt
        .unwrap();
    store
        .release_commit_receipt_v2("11111111111111111111111111111111", &receipt)
        .await?;
    client
        .batch_execute("DROP TABLE hangang_receipt_releases CASCADE")
        .await?;
    let url = std::env::var("HANGANG_TEST_POSTGRES_URL")?;
    assert!(
        PostgresConfigStore::connect_unencrypted(&url)
            .await
            .is_err(),
        "version 2 must not recreate missing evidence"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_v2_insert_failure_rolls_back_document_receipt_and_fence() -> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    client.batch_execute("CREATE FUNCTION owned_reject_v2() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'owned fixture rejects receipt'; END $$; CREATE TRIGGER fail_sequenced_receipt BEFORE INSERT ON hangang_sequenced_receipts FOR EACH ROW EXECUTE FUNCTION owned_reject_v2()").await?;
    let candidate = document(0, true);
    let operation = stamp(AUTHORITY, 1, 0, &candidate);
    assert!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, candidate, operation)
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    let after = store.lookup_commit_receipt_v2(AUTHORITY, 1).await?;
    assert_eq!(after.receipt, None);
    assert_eq!(after.high_water, 0);
    assert_eq!(after.stored_records, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_v2_config_reseed_preserves_high_water() -> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let old_epoch = store.bootstrap(document(0, false)).await?.epoch;
    let first = stamp(AUTHORITY, 2, 0, &document(0, true));
    applied(
        store
            .compare_and_swap_operation_v2(&old_epoch, 0, document(0, true), first.clone())
            .await?,
    );
    let old_writer_json = serde_json::to_string(&document(2, false))?;
    assert!(
        client
            .execute(
                "UPDATE hangang_config SET revision=2,config_json=$1 WHERE singleton=1",
                &[&old_writer_json]
            )
            .await
            .is_err()
    );
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 1);
    client
        .execute("DELETE FROM hangang_config WHERE singleton=1", &[])
        .await?;
    let new_epoch = store.bootstrap(document(0, false)).await?.epoch;
    assert_ne!(new_epoch, old_epoch);
    let retained = store.lookup_commit_receipt_v2(AUTHORITY, 2).await?;
    assert_eq!(retained.high_water, 2);
    assert_eq!(retained.receipt.unwrap().stamp, first);
    let replay = stamp(AUTHORITY, 1, 0, &document(0, true));
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&new_epoch, 0, document(0, true), replay)
            .await,
        Ok(CasResult::Conflict { .. })
    ));
    let next = stamp(AUTHORITY, 3, 0, &document(0, true));
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&new_epoch, 0, document(0, true), next)
                .await?
        )
        .revision,
        1
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: HANGANG_PG_TEST_TARGET=sequenced_store python3 tests/pg_fixture.py"]
async fn postgres_v2_capacity_fences_new_authorities_and_receipts() -> anyhow::Result<()> {
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    client.execute("INSERT INTO hangang_sequenced_authorities(authority_id,high_water) SELECT lpad(to_hex(i),32,'0'),1 FROM generate_series(1,4096) AS i", &[]).await?;
    assert!(
        !store
            .lookup_commit_receipt_v2(AUTHORITY, 1)
            .await?
            .writes_available
    );
    let rejected = stamp(AUTHORITY, 1, 0, &document(0, true));
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, document(0, true), rejected)
            .await,
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    let known = format!("{:032x}", 1);
    let accepted = stamp(&known, 2, 0, &document(0, true));
    assert_eq!(
        applied(
            store
                .compare_and_swap_operation_v2(&epoch, 0, document(0, true), accepted)
                .await?
        )
        .revision,
        1
    );
    // Separate owned fixture reset: synthetic receipt-count saturation must
    // leave both document and new receipt untouched.
    let Some((store, client)) = postgres_fixture().await? else {
        return Ok(());
    };
    let epoch = store.bootstrap(document(0, false)).await?.epoch;
    client
        .execute(
            "UPDATE hangang_commit_receipt_meta SET stored_records=100000 WHERE singleton=1",
            &[],
        )
        .await?;
    assert!(
        !store
            .lookup_commit_receipt_v2(AUTHORITY, 1)
            .await?
            .writes_available
    );
    let candidate = document(0, true);
    let operation = stamp(AUTHORITY, 1, 0, &candidate);
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(&epoch, 0, candidate, operation)
            .await,
        Err(StoreError::Unavailable(_))
    ));
    assert_eq!(store.load_latest().await?.unwrap().config.revision, 0);
    assert_eq!(
        store.lookup_commit_receipt_v2(AUTHORITY, 1).await?.receipt,
        None
    );
    Ok(())
}
