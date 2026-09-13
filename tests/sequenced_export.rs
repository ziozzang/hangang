use hangang::{
    config::{Config, Settings},
    config_store::{
        CasResult, ConfigStore, PostgresConfigStore, SequencedOperationStamp, SequencedReceiptPage,
        SequencedReceiptPageResult, SqliteConfigStore, StoreError, canonical_operation_id,
    },
};
use sha2::{Digest, Sha256};

fn candidate(marker: u64) -> Config {
    Config {
        settings: Settings {
            upstream_timeout_ms: Some(1_000 + marker),
            ..Settings::default()
        },
        ..Config::default()
    }
}

fn stamp(authority: &str, sequence: u64, expected: u64, next: &Config) -> SequencedOperationStamp {
    let mut committed = next.clone();
    committed.revision = expected + 1;
    SequencedOperationStamp {
        authority_id: authority.to_owned(),
        acceptance_seq: sequence,
        operation_id: canonical_operation_id(authority, sequence).unwrap(),
        candidate_sha256: format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&committed).unwrap())
        ),
    }
}

async fn commit(
    store: &dyn ConfigStore,
    epoch: &str,
    expected: u64,
    authority: &str,
    sequence: u64,
) -> anyhow::Result<SequencedOperationStamp> {
    let next = candidate(10 + sequence);
    let stamp = stamp(authority, sequence, expected, &next);
    assert!(matches!(
        store
            .compare_and_swap_operation_v2(epoch, expected, next, stamp.clone())
            .await?,
        CasResult::Applied(_)
    ));
    Ok(stamp)
}

fn page(result: SequencedReceiptPageResult) -> SequencedReceiptPage {
    match result {
        SequencedReceiptPageResult::Page(page) => page,
        SequencedReceiptPageResult::SnapshotChanged => {
            panic!("snapshot changed without an intentional retention or rollback")
        }
    }
}

fn sequences(page: &SequencedReceiptPage) -> Vec<u64> {
    page.receipts
        .iter()
        .map(|receipt| receipt.stamp.acceptance_seq)
        .collect()
}

#[tokio::test]
async fn sqlite_export_freezes_sparse_prefix_while_new_receipts_append() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let store = SqliteConfigStore::open(directory.path().join("config.db")).await?;
    let authority = "a".repeat(32);
    let epoch = store.bootstrap(Config::default()).await?.epoch;
    commit(&store, &epoch, 0, &authority, 2).await?;
    commit(&store, &epoch, 1, &authority, 4).await?;

    let first = page(
        store
            .list_commit_receipts_v2(&authority, 0, None, 1)
            .await?,
    );
    assert_eq!(sequences(&first), vec![2]);
    assert_eq!(first.snapshot.high_water, 4);
    assert_eq!(first.snapshot.retention_generation, 0);
    assert_eq!(first.next_after, 2);
    assert!(first.has_more);

    commit(&store, &epoch, 2, &authority, 7).await?;
    let second = page(
        store
            .list_commit_receipts_v2(&authority, first.next_after, Some(first.snapshot), 1)
            .await?,
    );
    assert_eq!(sequences(&second), vec![4]);
    assert!(!second.has_more);
    assert_eq!(
        second.snapshot, first.snapshot,
        "an append cannot alter the frozen prefix"
    );
    assert_eq!(second.next_after, 4);

    let fresh = page(
        store
            .list_commit_receipts_v2(&authority, 0, None, 100)
            .await?,
    );
    assert_eq!(sequences(&fresh), vec![2, 4, 7]);
    assert_eq!(fresh.snapshot.high_water, 7);
    assert!(!fresh.has_more);
    Ok(())
}

#[tokio::test]
async fn sqlite_export_is_authority_scoped_and_survives_config_rebootstrap() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let a = "a".repeat(32);
    let b = "b".repeat(32);
    let unknown = "c".repeat(32);
    let original = store.bootstrap(Config::default()).await?.epoch;
    commit(&store, &original, 0, &a, 5).await?;
    commit(&store, &original, 1, &b, 1).await?;
    let first = page(store.list_commit_receipts_v2(&a, 0, None, 100).await?);
    assert_eq!(sequences(&first), vec![5]);
    assert_eq!(first.snapshot.high_water, 5);
    let empty = page(
        store
            .list_commit_receipts_v2(&unknown, 0, None, 100)
            .await?,
    );
    assert!(empty.receipts.is_empty());
    assert_eq!(empty.snapshot.high_water, 0);
    assert!(!empty.has_more);
    assert_eq!(
        sequences(&page(
            store.list_commit_receipts_v2(&b, 0, None, 100).await?
        )),
        vec![1]
    );

    rusqlite::Connection::open(&path)?
        .execute("DELETE FROM hangang_config WHERE singleton=1", [])?;
    let new_epoch = store.bootstrap(Config::default()).await?.epoch;
    assert_ne!(new_epoch, original);
    let after = page(store.list_commit_receipts_v2(&a, 0, None, 100).await?);
    assert_eq!(after.snapshot, first.snapshot);
    assert_eq!(after.receipts, first.receipts);

    for (authority, after_seq, snapshot, limit) in [
        ("not-hex", 0, None, 100),
        (&a[..], 1, None, 100),
        (&a[..], 0, None, 0),
        (&a[..], 0, None, 101),
    ] {
        assert!(matches!(
            store
                .list_commit_receipts_v2(authority, after_seq, snapshot, limit)
                .await,
            Err(StoreError::Invalid(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn sqlite_export_detects_retention_and_high_water_fence_changes() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let authority = "a".repeat(32);
    let epoch = store.bootstrap(Config::default()).await?.epoch;
    commit(&store, &epoch, 0, &authority, 2).await?;
    commit(&store, &epoch, 1, &authority, 4).await?;
    let first = page(
        store
            .list_commit_receipts_v2(&authority, 0, None, 1)
            .await?,
    );
    let connection = rusqlite::Connection::open(&path)?;
    // Fixture-only future pruning simulation. A real retention workflow must
    // advance this durable generation in its own audited transaction.
    connection.execute("UPDATE hangang_sequenced_authorities SET retention_generation=retention_generation+1 WHERE authority_id=?1", [&authority])?;
    assert_eq!(
        store
            .list_commit_receipts_v2(&authority, first.next_after, Some(first.snapshot), 1)
            .await?,
        SequencedReceiptPageResult::SnapshotChanged
    );
    let newer = page(
        store
            .list_commit_receipts_v2(&authority, 0, None, 1)
            .await?,
    );
    assert_eq!(
        newer.snapshot.retention_generation,
        first.snapshot.retention_generation + 1
    );
    // A database restore/corruption that moves the high-water mark backwards
    // must not silently finish an export anchored to the older state.
    connection.execute(
        "UPDATE hangang_sequenced_authorities SET high_water=3 WHERE authority_id=?1",
        [&authority],
    )?;
    assert_eq!(
        store
            .list_commit_receipts_v2(&authority, newer.next_after, Some(newer.snapshot), 1)
            .await?,
        SequencedReceiptPageResult::SnapshotChanged
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable PostgreSQL fixture: python3 tests/pg_fixture.py"]
async fn postgres_export_freezes_sparse_prefix_and_rejects_retention_drift() -> anyhow::Result<()> {
    let Ok(url) = std::env::var("HANGANG_TEST_POSTGRES_URL") else {
        return Ok(());
    };
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.batch_execute("DROP TABLE IF EXISTS hangang_config; DROP TABLE IF EXISTS hangang_sequenced_receipts; DROP TABLE IF EXISTS hangang_sequenced_authorities; DROP TABLE IF EXISTS hangang_commit_receipts; DROP TABLE IF EXISTS hangang_commit_receipt_meta;").await?;
    let store = PostgresConfigStore::connect_unencrypted(&url).await?;
    let authority = "a".repeat(32);
    let epoch = store.bootstrap(Config::default()).await?.epoch;
    commit(&store, &epoch, 0, &authority, 2).await?;
    commit(&store, &epoch, 1, &authority, 4).await?;
    let first = page(
        store
            .list_commit_receipts_v2(&authority, 0, None, 1)
            .await?,
    );
    assert_eq!(sequences(&first), vec![2]);
    assert_eq!(first.snapshot.high_water, 4);
    commit(&store, &epoch, 2, &authority, 7).await?;
    let second = page(
        store
            .list_commit_receipts_v2(&authority, first.next_after, Some(first.snapshot), 1)
            .await?,
    );
    assert_eq!(sequences(&second), vec![4]);
    assert!(!second.has_more);

    client.execute("UPDATE hangang_sequenced_authorities SET retention_generation=retention_generation+1 WHERE authority_id=$1", &[&authority]).await?;
    assert_eq!(
        store
            .list_commit_receipts_v2(&authority, first.next_after, Some(first.snapshot), 1)
            .await?,
        SequencedReceiptPageResult::SnapshotChanged
    );
    Ok(())
}

#[tokio::test]
#[ignore = "release-only local SQLite export diagnostic; seeded receipts are synthetic"]
async fn sqlite_export_full_capacity_release_diagnostic() -> anyhow::Result<()> {
    const ROWS: u64 = 100_000;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("config.db");
    let store = SqliteConfigStore::open(&path).await?;
    let authority = "a".repeat(32);
    let mut connection = rusqlite::Connection::open(&path)?;
    let transaction =
        connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    transaction.execute(
        "INSERT INTO hangang_sequenced_authorities(authority_id,high_water,retention_generation) VALUES(?1,?2,0)",
        rusqlite::params![authority, ROWS],
    )?;
    {
        let mut insert = transaction.prepare(
            "INSERT INTO hangang_sequenced_receipts(authority_id,acceptance_seq,operation_id,epoch,revision,candidate_sha256) VALUES(?1,?2,?3,?4,?5,?6)",
        )?;
        let epoch = "c".repeat(32);
        let digest = "b".repeat(64);
        for sequence in 1..=ROWS {
            insert.execute(rusqlite::params![
                authority,
                sequence,
                canonical_operation_id(&authority, sequence)?,
                epoch,
                sequence,
                digest,
            ])?;
        }
    }
    transaction.execute(
        "UPDATE hangang_commit_receipt_meta SET stored_records=?1 WHERE singleton=1",
        [ROWS],
    )?;
    transaction.commit()?;
    drop(connection);

    // The clock starts after fixture seeding: this measures page reads and
    // JSON serialization only, not config acceptance, CAS, or HTTP delivery.
    let start = std::time::Instant::now();
    let mut cursor = 0;
    let mut snapshot = None;
    let mut received = 0usize;
    let mut json_bytes = 0usize;
    loop {
        let next = page(
            store
                .list_commit_receipts_v2(&authority, cursor, snapshot, 100)
                .await?,
        );
        assert_eq!(next.snapshot.high_water, ROWS);
        received += next.receipts.len();
        json_bytes += serde_json::to_vec(&next.receipts)?.len();
        cursor = next.next_after;
        snapshot = Some(next.snapshot);
        if !next.has_more {
            break;
        }
    }
    assert_eq!(received, ROWS as usize);
    assert_eq!(cursor, ROWS);
    let elapsed = start.elapsed();
    eprintln!(
        "SQLite V2 receipt export diagnostic: {received} synthetic receipts, {json_bytes} receipt-JSON bytes, 1000 pages in {:.3}s; seed, account authorization, HTTP and durable archive excluded",
        elapsed.as_secs_f64()
    );
    Ok(())
}
