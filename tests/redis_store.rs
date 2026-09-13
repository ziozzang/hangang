use hangang::{
    config::{Config, HttpRoute},
    config_store::{CasResult, ConfigStore, EPOCH_LEN, StoreError, Stored},
    redis_store::RedisConfigStore,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
            enabled: true,
            upstream: Default::default(),
            priority: 0,
            host_regex: None,
            upstream_host: None,
            preserve_host: false,
            id: id.into(),
            max_requests: None,
            upstream_timeout_ms: None,
            retries: 0,
            require_tls: false,
            https_redirect_code: None,
            cache: None,
            host: None,
            hosts: Vec::new(),
            path_prefix: None,
            path_match: Default::default(),
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

fn redis_url() -> Option<String> {
    std::env::var("HANGANG_TEST_REDIS_URL").ok()
}

fn test_key(name: &str) -> String {
    format!("hangang-test-redis-{name}-{}", std::process::id())
}

async fn plaintext_store(url: &str, key: &str) -> anyhow::Result<RedisConfigStore> {
    RedisConfigStore::connect_unencrypted(url, key).await
}

async fn raw_set(url: &str, key: &str, value: impl redis::ToRedisArgs) -> anyhow::Result<()> {
    let client = redis::Client::open(url)?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .query_async::<()>(&mut connection)
        .await?;
    Ok(())
}

async fn raw_get(url: &str, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let client = redis::Client::open(url)?;
    let mut connection = client.get_multiplexed_async_connection().await?;
    Ok(redis::cmd("GET")
        .arg(key)
        .query_async::<Option<Vec<u8>>>(&mut connection)
        .await?)
}

#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_bootstrap_and_cas_have_one_atomic_winner() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let key = test_key("bootstrap-cas");
    let left = Arc::new(plaintext_store(&url, &key).await?);
    let right = Arc::new(plaintext_store(&url, &key).await?);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let first = tokio::spawn({
        let store = left.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store.bootstrap(config(0, "bootstrap-left")).await
        }
    });
    let second = tokio::spawn({
        let store = right.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store.bootstrap(config(0, "bootstrap-right")).await
        }
    });
    let first = first.await??;
    let second = second.await??;
    assert_eq!(first, second, "concurrent bootstrap must return the winner");
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
                .compare_and_swap(&epoch, 0, config(999, "cas-left"))
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
                .compare_and_swap(&epoch, 0, config(999, "cas-right"))
                .await
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
                CasResult::Conflict { current } if current.config.revision == 1 && current.epoch == epoch
            ))
            .count(),
        1
    );
    let winner = left.load_latest().await?.unwrap();
    assert_eq!(winner.config.revision, 1);

    // Idempotent re-application of the winning write, and epoch isolation.
    let again = applied(
        right
            .compare_and_swap(&epoch, 0, config(0, &winner.config.http[0].id))
            .await?,
    );
    assert_eq!(again, winner);
    let current = conflict(
        right
            .compare_and_swap(&epoch, 0, config(0, "other"))
            .await?,
    );
    assert_eq!(current, winner);
    let current = conflict(
        right
            .compare_and_swap(FOREIGN_EPOCH, 1, config(0, "foreign"))
            .await?,
    );
    assert_eq!(current, winner);
    assert_eq!(left.load_latest().await?.unwrap(), winner);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_revisions_keep_u64_precision_above_javascript_safe_range() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let key = test_key("u64");
    let store = plaintext_store(&url, &key).await?;
    let before_max = u64::MAX - 1;
    let epoch = store.bootstrap(config(before_max, "large")).await?.epoch;
    let applied = applied(
        store
            .compare_and_swap(&epoch, before_max, config(0, "max"))
            .await?,
    );
    assert_eq!(applied.config.revision, u64::MAX);
    assert_eq!(
        store.load_latest().await?.unwrap().config.revision,
        u64::MAX
    );
    let current = conflict(
        store
            .compare_and_swap(&epoch, before_max, config(0, "stale"))
            .await?,
    );
    assert_eq!(current.config.revision, u64::MAX);
    assert!(matches!(
        store
            .compare_and_swap(&epoch, u64::MAX, config(0, "over"))
            .await,
        Err(StoreError::Invalid(_))
    ));
    Ok(())
}

/// A v1 value written by an earlier release is rewritten to v2 with an epoch
/// by the first script that reads it; a second store sees the same epoch.
#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_legacy_values_are_upgraded_once_with_one_winner() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let key = test_key("legacy");
    let json = serde_json::to_string(&config(7, "legacy"))?;
    raw_set(&url, &key, format!("hangang-config-v1\n7\n{json}")).await?;
    let left = plaintext_store(&url, &key).await?;
    let right = plaintext_store(&url, &key).await?;
    let (first, second) = tokio::join!(left.load_latest(), right.load_latest());
    let first = first?.unwrap();
    let second = second?.unwrap();
    assert!(is_epoch(&first.epoch));
    assert_eq!(first, second);
    assert_eq!(first.config.revision, 7);
    let wire = raw_get(&url, &key).await?.unwrap();
    assert!(
        wire.starts_with(format!("hangang-config-v2\n{}\n7\n", first.epoch).as_bytes()),
        "{}",
        String::from_utf8_lossy(&wire)
    );
    let next = applied(
        right
            .compare_and_swap(&first.epoch, 7, config(0, "after"))
            .await?,
    );
    assert_eq!(next.config.revision, 8);
    assert_eq!(left.load_latest().await?.unwrap(), next);

    // Bootstrap and CAS upgrade a legacy value as well.
    let key = test_key("legacy-bootstrap");
    raw_set(&url, &key, format!("hangang-config-v1\n7\n{json}")).await?;
    let store = plaintext_store(&url, &key).await?;
    let bootstrapped = store.bootstrap(config(0, "ignored")).await?;
    assert!(is_epoch(&bootstrapped.epoch));
    assert_eq!(bootstrapped.config.revision, 7);
    let key = test_key("legacy-cas");
    raw_set(&url, &key, format!("hangang-config-v1\n7\n{json}")).await?;
    let store = plaintext_store(&url, &key).await?;
    let current = conflict(
        store
            .compare_and_swap(FOREIGN_EPOCH, 7, config(0, "foreign"))
            .await?,
    );
    assert!(is_epoch(&current.epoch));
    assert_eq!(current.config.revision, 7);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_challenges_are_shared_with_expiry_and_limits() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let key = test_key("challenges");
    let publisher = plaintext_store(&url, &key).await?;
    let responder = plaintext_store(&url, &key).await?;
    let ttl = Duration::from_secs(30);
    publisher
        .publish_challenge("tok-1_A", "tok-1_A.key", ttl)
        .await?;
    assert_eq!(
        responder.lookup_challenge("tok-1_A").await?.as_deref(),
        Some("tok-1_A.key")
    );
    assert_eq!(
        raw_get(&url, &format!("{key}:acme:tok-1_A"))
            .await?
            .as_deref(),
        Some(b"tok-1_A.key".as_slice())
    );
    responder.withdraw_challenge("tok-1_A").await?;
    assert_eq!(publisher.lookup_challenge("tok-1_A").await?, None);

    publisher
        .publish_challenge("short", "gone", Duration::from_secs(1))
        .await?;
    assert_eq!(
        responder.lookup_challenge("short").await?.as_deref(),
        Some("gone")
    );
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(responder.lookup_challenge("short").await?, None);

    for (token, value, ttl) in [
        ("bad token", "k", ttl),
        ("ok", "", ttl),
        ("ok", "k", Duration::ZERO),
        ("ok", "k", Duration::from_secs(3601)),
    ] {
        assert!(matches!(
            publisher.publish_challenge(token, value, ttl).await,
            Err(StoreError::Invalid(_))
        ));
    }
    assert_eq!(raw_get(&url, &format!("{key}:acme:ok")).await?, None);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_rejects_malformed_and_oversized_values_before_decode() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let key = test_key("bad-values");
    raw_set(&url, &key, b"hangang-config-v1\n01\n{}".as_slice()).await?;
    let store = plaintext_store(&url, &key).await?;
    let malformed = store.load_latest().await.unwrap_err();
    assert!(matches!(malformed, StoreError::Invalid(_)), "{malformed}");
    let malformed = malformed.to_string();
    assert!(malformed.contains("canonical") || malformed.contains("revision"));

    raw_set(&url, &key, vec![b'x'; 1_048_649]).await?;
    let oversized = store.load_latest().await.unwrap_err();
    assert!(matches!(oversized, StoreError::Invalid(_)), "{oversized}");
    assert!(
        oversized.to_string().contains("exceeds size limit"),
        "unexpected oversized-value error: {oversized}"
    );
    // A v1 value over the v1 limit is not upgraded either.
    let mut legacy = b"hangang-config-v1\n1\n".to_vec();
    legacy.resize(1_048_616, b'x');
    raw_set(&url, &key, legacy).await?;
    let oversized = store.load_latest().await.unwrap_err();
    assert!(oversized.to_string().contains("exceeds size limit"));
    assert!(
        raw_get(&url, &key)
            .await?
            .unwrap()
            .starts_with(b"hangang-config-v1\n")
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable fixture: python3 tests/redis_fixture.py"]
async fn redis_connection_manager_recovers_after_owned_fixture_restart() -> anyhow::Result<()> {
    let Some(url) = redis_url() else {
        return Ok(());
    };
    let Some(container) = std::env::var("HANGANG_TEST_REDIS_CONTAINER").ok() else {
        return Ok(());
    };
    assert!(container.starts_with("hangang-configstore-redis-"));
    let key = test_key("restart");
    let store = plaintext_store(&url, &key).await?;
    let before = store.bootstrap(config(0, "restart")).await?;

    let stopped = tokio::process::Command::new("docker")
        .args(["stop", &container])
        .status()
        .await?;
    assert!(stopped.success());
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    let started = tokio::process::Command::new("docker")
        .args(["start", &container])
        .status()
        .await?;
    assert!(started.success());

    let recovered = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(Some(current)) = store.load_latest().await {
                break current;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await?;
    assert_eq!(recovered, before);
    Ok(())
}

#[tokio::test]
#[ignore = "requires disposable TLS fixture: python3 tests/redis_fixture.py"]
async fn redis_tls_uses_custom_ca_and_rejects_wrong_ca() -> anyhow::Result<()> {
    let (Some(url), Ok(ca_path), Ok(wrong_ca_path)) = (
        std::env::var("HANGANG_TEST_REDIS_TLS_URL").ok(),
        std::env::var("HANGANG_TEST_REDIS_CA"),
        std::env::var("HANGANG_TEST_REDIS_WRONG_CA"),
    ) else {
        return Ok(());
    };
    let ca = std::fs::read(ca_path)?;
    let store = RedisConfigStore::connect_with_ca(&url, test_key("tls"), &ca).await?;
    assert_eq!(store.bootstrap(config(0, "tls")).await?.config.revision, 0);
    let wrong_ca = std::fs::read(wrong_ca_path)?;
    assert!(
        RedisConfigStore::connect_with_ca(&url, test_key("wrong-ca"), &wrong_ca)
            .await
            .is_err()
    );
    Ok(())
}

/// A minimal RESP listener: it acknowledges the client's connection setup
/// commands and drops the socket, without answering, as soon as a data
/// command arrives. That is exactly a lost acknowledgement.
async fn fake_redis() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                loop {
                    let mut chunk = [0u8; 4096];
                    let Ok(read) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    while let Some((command, consumed)) = parse_resp_array(&buffer) {
                        buffer.drain(..consumed);
                        let name = command.first().map(|name| name.to_ascii_uppercase());
                        match name.as_deref() {
                            Some(b"CLIENT") | Some(b"SELECT") | Some(b"AUTH") | Some(b"HELLO") => {
                                if stream.write_all(b"+OK\r\n").await.is_err() {
                                    return;
                                }
                            }
                            _ => return,
                        }
                    }
                }
            });
        }
    });
    (address, accept)
}

/// Parse one complete RESP array of bulk strings from the front of `input`.
fn parse_resp_array(input: &[u8]) -> Option<(Vec<Vec<u8>>, usize)> {
    fn line(input: &[u8], at: usize) -> Option<(&[u8], usize)> {
        let end = input[at..].windows(2).position(|pair| pair == b"\r\n")?;
        Some((&input[at..at + end], at + end + 2))
    }
    let (header, mut at) = line(input, 0)?;
    let count: usize = std::str::from_utf8(header.strip_prefix(b"*")?)
        .ok()?
        .parse()
        .ok()?;
    let mut arguments = Vec::with_capacity(count);
    for _ in 0..count {
        let (length, next) = line(input, at)?;
        let length: usize = std::str::from_utf8(length.strip_prefix(b"$")?)
            .ok()?
            .parse()
            .ok()?;
        if input.len() < next + length + 2 {
            return None;
        }
        arguments.push(input[next..next + length].to_vec());
        at = next + length + 2;
    }
    Some((arguments, at))
}

/// Transport failures are typed by access: a read whose connection dropped
/// is `Unavailable`, a CAS whose acknowledgement never arrived is
/// `Indeterminate`, and a refused connection is `Unavailable` again. No
/// fixture is needed: the listener is owned by this test.
#[tokio::test]
async fn redis_transport_failures_are_typed_by_access() -> anyhow::Result<()> {
    let (address, accept) = fake_redis().await;
    let url = format!("redis://{address}/");
    let store = RedisConfigStore::connect_unencrypted(&url, "hangang-test-fake").await?;

    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    assert!(error.is_transport());
    assert!(error.to_string().starts_with("store unavailable: "));

    let error = store
        .compare_and_swap(FOREIGN_EPOCH, 0, config(0, "lost"))
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");
    assert!(error.is_transport());
    assert!(
        error
            .to_string()
            .starts_with("store mutation indeterminate: ")
    );

    let error = store.lookup_challenge("token").await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    let error = store
        .publish_challenge("token", "key", Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(error, StoreError::Indeterminate(_)), "{error}");

    // The listener goes away: every access is refused and nothing changed.
    accept.abort();
    let _ = accept.await;
    let error = store.load_latest().await.unwrap_err();
    assert!(matches!(error, StoreError::Unavailable(_)), "{error}");
    assert!(
        RedisConfigStore::connect_unencrypted(&url, "hangang-test-fake")
            .await
            .is_err()
    );
    Ok(())
}
