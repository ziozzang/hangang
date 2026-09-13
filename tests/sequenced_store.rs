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
    client.batch_execute("DROP TABLE IF EXISTS hangang_config CASCADE; DROP TABLE IF EXISTS hangang_commit_receipts CASCADE; DROP TABLE IF EXISTS hangang_sequenced_receipts CASCADE; DROP TABLE IF EXISTS hangang_sequenced_authorities CASCADE; DROP TABLE IF EXISTS hangang_commit_receipt_meta CASCADE").await?;
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
