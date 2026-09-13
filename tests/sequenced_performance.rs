//! Local control-plane write diagnostic. This is not HTTP, account acceptance,
//! activation, data-plane throughput, or a performance acceptance threshold.

use hangang::{
    config::Config,
    config_store::{
        CasResult, ConfigStore, OperationStamp, SequencedOperationStamp, SqliteConfigStore,
        canonical_operation_id,
    },
};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const ITERATIONS: u64 = 100;
const AUTHORITY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn candidate_identity(expected: u64) -> (String, String) {
    let committed = Config {
        revision: expected + 1,
        ..Default::default()
    };
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&committed).unwrap())
    );
    let id = canonical_operation_id(AUTHORITY, expected + 1).unwrap();
    (id, digest)
}

async fn run_series(store: &SqliteConfigStore, v2: bool) -> anyhow::Result<Duration> {
    let initial = store.bootstrap(Config::default()).await?;
    let start = Instant::now();
    for expected in 0..ITERATIONS {
        // Both series construct the exact same ID and candidate digest inside
        // the timed region. The only intended difference is the SQL CAS path.
        let (operation_id, candidate_sha256) = candidate_identity(expected);
        let result = if v2 {
            store
                .compare_and_swap_operation_v2(
                    &initial.epoch,
                    expected,
                    Config::default(),
                    SequencedOperationStamp {
                        authority_id: AUTHORITY.into(),
                        acceptance_seq: expected + 1,
                        operation_id,
                        candidate_sha256,
                    },
                )
                .await?
        } else {
            store
                .compare_and_swap_operation(
                    &initial.epoch,
                    expected,
                    Config::default(),
                    OperationStamp {
                        authority_id: AUTHORITY.into(),
                        operation_id,
                        candidate_sha256,
                    },
                )
                .await?
        };
        match result {
            CasResult::Applied(stored) => assert_eq!(stored.config.revision, expected + 1),
            CasResult::Conflict { current } => {
                panic!("unexpected revision conflict: {}", current.config.revision)
            }
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(
        store.load_latest().await?.unwrap().config.revision,
        ITERATIONS
    );
    if v2 {
        let observation = store
            .lookup_commit_receipt_v2(AUTHORITY, ITERATIONS)
            .await?;
        assert_eq!(observation.stored_records, ITERATIONS);
        assert_eq!(observation.high_water, ITERATIONS);
    } else {
        let last_id = canonical_operation_id(AUTHORITY, ITERATIONS)?;
        let observation = store.lookup_commit_receipt(AUTHORITY, &last_id).await?;
        assert_eq!(observation.stored_records, ITERATIONS);
    }
    Ok(elapsed)
}

#[tokio::test]
#[ignore = "release-only control-plane diagnostic"]
async fn sqlite_v1_vs_v2_sequential_operation_cas() -> anyhow::Result<()> {
    let directory = tempfile::tempdir()?;
    let v1 = SqliteConfigStore::open(directory.path().join("v1.db")).await?;
    let v2 = SqliteConfigStore::open(directory.path().join("v2.db")).await?;
    let v1_elapsed = run_series(&v1, false).await?;
    let v2_elapsed = run_series(&v2, true).await?;
    for (name, elapsed) in [("V1", v1_elapsed), ("V2", v2_elapsed)] {
        println!(
            "SQLite {name} operation CAS diagnostic: {ITERATIONS} sequential writes in {:.3}s ({:.1} writes/s); same binary, fresh owned DB, candidate digest and ID construction included; account acceptance, HTTP, activation and data plane excluded",
            elapsed.as_secs_f64(),
            ITERATIONS as f64 / elapsed.as_secs_f64(),
        );
    }
    Ok(())
}
