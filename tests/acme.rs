use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use hangang::acme::{
    AcmeConfig, AcmeDirectory, AcmeFileConfig, ChallengeMode, EabConfig, HttpChallengeStore,
};
use hangang::config_store::{
    CasResult, ConfigStore, SqliteConfigStore, StoreError, StoreResult, Stored,
};
use http_body_util::BodyExt;
use hyper::{
    Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::SocketAddr,
    process::{Child, Command, Stdio},
    sync::OnceLock,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Mutex as TokioMutex, sync::watch, time::timeout};
use tokio_util::sync::CancellationToken;

// Pebble's validation endpoint is intentionally mapped to the standard
// HTTP-01 port. Serialize fixture tests so their host challenge listeners do
// not race for 5002 when Cargo runs async tests in parallel.
static PEBBLE_TEST_LOCK: OnceLock<TokioMutex<()>> = OnceLock::new();
async fn pebble_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
    PEBBLE_TEST_LOCK
        .get_or_init(|| TokioMutex::new(()))
        .lock()
        .await
}

/// Mirrors the opaque ConfigStore key used by HttpChallengeStore. The public
/// challenge token remains unchanged; only the backend namespace is hashed.
fn shared_challenge_key(host: &str, token: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"hangang-acme-http01-v2\0");
    digest.update(host.as_bytes());
    digest.update(b"\0");
    digest.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(digest.finalize())
}

#[tokio::test]
async fn http01_store_requires_exact_host_and_token() {
    let store = HttpChallengeStore::default();
    store
        .insert("Example.COM:80", "tok_123", "tok_123.account-thumb")
        .await
        .unwrap();

    let request = Request::builder()
        .method("GET")
        .uri("/.well-known/acme-challenge/tok_123")
        .header("host", "example.com")
        .body(())
        .unwrap();
    let response = store.response(&request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "tok_123.account-thumb"
    );

    let wrong_host = Request::builder()
        .method("GET")
        .uri("/.well-known/acme-challenge/tok_123")
        .header("host", "other.example.com")
        .body(())
        .unwrap();
    assert!(store.response(&wrong_host).await.is_none());
    let wrong_path = Request::builder()
        .method("GET")
        .uri("/.well-known/acme-challenge/tok_123/extra")
        .header("host", "example.com")
        .body(())
        .unwrap();
    assert!(store.response(&wrong_path).await.is_none());
}

fn challenge_request(host: &str, token: &str) -> Request<()> {
    Request::builder()
        .method("GET")
        .uri(format!("/.well-known/acme-challenge/{token}"))
        .header("host", host)
        .body(())
        .unwrap()
}

/// Two instances behind one load balancer share a SQLite store: a token
/// installed on A is answered by B for the same host only, disappears from B
/// when A removes it, and a store outage leaves A's local entries usable.
#[tokio::test]
async fn http01_challenges_are_shared_through_the_config_store() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fleet.db");
    let store: Arc<dyn ConfigStore> = Arc::new(SqliteConfigStore::open(&path).await.unwrap());
    let a = HttpChallengeStore::default().with_shared(store.clone());
    let b = HttpChallengeStore::default().with_shared(store.clone());
    assert!(a.has_shared() && b.has_shared());

    a.insert("Example.COM:80", "tok_fleet", "tok_fleet.account-thumb")
        .await
        .unwrap();
    assert_eq!(
        b.get("example.com", "tok_fleet").await.as_deref(),
        Some("tok_fleet.account-thumb"),
        "the CA's GET landing on another instance must be answered"
    );
    let response = b
        .response(&challenge_request("example.com", "tok_fleet"))
        .await
        .expect("listener path answers a shared token");
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "tok_fleet.account-thumb"
    );
    // The host check is kept across instances.
    assert!(b.get("other.example.com", "tok_fleet").await.is_none());
    assert!(
        b.response(&challenge_request("other.example.com", "tok_fleet"))
            .await
            .is_none()
    );
    assert!(b.get("example.com", "tok_unknown").await.is_none());
    // A record without a host was not written by an instance: never served.
    store
        .publish_challenge("tok_raw", "raw-key-authorization", Duration::from_secs(60))
        .await
        .unwrap();
    assert!(b.get("example.com", "tok_raw").await.is_none());
    assert!(b.get("raw-key-authorization", "tok_raw").await.is_none());

    a.remove("example.com", "tok_fleet").await.unwrap();
    assert!(
        b.get("example.com", "tok_fleet").await.is_none(),
        "withdrawal must reach the other instance"
    );
    assert!(a.get("example.com", "tok_fleet").await.is_none());

    // Store outage: the database file becomes a directory. Entries installed
    // while the store was healthy keep answering on their owner, remote
    // lookups miss, and a new token cannot be installed at all: the fleet
    // could not answer it, so the issuer must not mark it ready.
    a.insert("example.com", "tok_local", "tok_local.thumb")
        .await
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    for suffix in ["-wal", "-shm"] {
        let _ = std::fs::remove_file(temp.path().join(format!("fleet.db{suffix}")));
    }
    std::fs::create_dir(&path).unwrap();
    assert!(store.lookup_challenge("tok_local").await.is_err());
    assert_eq!(
        a.get("example.com", "tok_local").await.as_deref(),
        Some("tok_local.thumb")
    );
    assert!(b.get("example.com", "tok_local").await.is_none());
    let error = a
        .insert("example.com", "tok_outage", "tok_outage.thumb")
        .await
        .expect_err("an unacknowledged publication must fail the insert")
        .to_string();
    assert!(
        error.contains("not published to the shared store") && error.contains("example.com"),
        "{error}"
    );
    assert!(
        a.get("example.com", "tok_outage").await.is_none(),
        "a failed insert must not leave a local entry"
    );
    a.remove("example.com", "tok_local").await.unwrap();
    assert!(a.get("example.com", "tok_local").await.is_none());
}

/// The local challenge identity includes the authorization host. A CA that
/// reuses one token for two authorizations must not let one host overwrite or
/// withdraw the other in the shared backend.
/// RFC 8555 requires high-entropy tokens, so an honest public CA makes this
/// collision vanishingly unlikely; custom ACME directories still make the
/// state-key mismatch deterministic and worth keeping as a regression.
#[tokio::test]
async fn shared_http01_keeps_a_reused_token_isolated_between_hosts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fleet.db");
    let store: Arc<dyn ConfigStore> = Arc::new(SqliteConfigStore::open(&path).await.unwrap());
    let issuer = HttpChallengeStore::default().with_shared(store.clone());
    let follower = HttpChallengeStore::default().with_shared(store);

    issuer
        .insert("a.example.test", "tok_reused", "tok_reused.a-thumb")
        .await
        .unwrap();
    issuer
        .insert("b.example.test", "tok_reused", "tok_reused.b-thumb")
        .await
        .unwrap();

    assert_eq!(
        follower
            .get("a.example.test", "tok_reused")
            .await
            .as_deref(),
        Some("tok_reused.a-thumb"),
        "publishing the second host must not overwrite the first host's shared record"
    );
    assert_eq!(
        follower
            .get("b.example.test", "tok_reused")
            .await
            .as_deref(),
        Some("tok_reused.b-thumb")
    );

    issuer.remove("a.example.test", "tok_reused").await.unwrap();
    assert_eq!(
        follower
            .get("b.example.test", "tok_reused")
            .await
            .as_deref(),
        Some("tok_reused.b-thumb"),
        "withdrawing the first host must not delete the second host's shared record"
    );
    issuer.remove("b.example.test", "tok_reused").await.unwrap();
}

/// RFC 8555 sets a minimum entropy requirement but no 128-character ceiling
/// for HTTP-01 tokens. The public listener accepts up to 256 URL-safe bytes;
/// hashing the backend identity must let that same range work in shared mode.
#[tokio::test]
async fn shared_http01_round_trips_a_256_character_token() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("fleet.db");
    let store: Arc<dyn ConfigStore> = Arc::new(SqliteConfigStore::open(&path).await.unwrap());
    let issuer = HttpChallengeStore::default().with_shared(store.clone());
    let follower = HttpChallengeStore::default().with_shared(store);
    let token = "t".repeat(256);

    issuer
        .insert("example.test", &token, "long-token.account-thumb")
        .await
        .unwrap();
    assert_eq!(
        follower.get("example.test", &token).await.as_deref(),
        Some("long-token.account-thumb")
    );
    issuer.remove("example.test", &token).await.unwrap();
    assert!(follower.get("example.test", &token).await.is_none());
}

/// A store whose lookups never answer, whose withdrawals fail, and whose
/// publications fail while `fail_publish` is set.
struct HangingStore {
    lookups: AtomicUsize,
    publishes: AtomicUsize,
    fail_publish: AtomicBool,
}
#[async_trait]
impl ConfigStore for HangingStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn bootstrap(&self, _: hangang::config::Config) -> StoreResult<Stored> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: hangang::config::Config,
    ) -> StoreResult<CasResult> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn publish_challenge(&self, _: &str, _: &str, _: Duration) -> StoreResult<()> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        if self.fail_publish.load(Ordering::SeqCst) {
            Err(StoreError::Indeterminate(anyhow!("publish lost")))
        } else {
            Ok(())
        }
    }
    async fn lookup_challenge(&self, _: &str) -> StoreResult<Option<String>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }
    async fn withdraw_challenge(&self, _: &str) -> StoreResult<()> {
        Err(StoreError::Unavailable(anyhow!("withdraw failed")))
    }
}

/// In shared mode an insert is acknowledged by the store or fails after
/// three bounded attempts. The public listener must not hang on a slow
/// store: a lookup that never answers is cut off after 2 s and answered 404,
/// while tokens owned by this instance are still served without touching
/// the store.
#[tokio::test]
async fn shared_challenge_publication_is_acknowledged_and_lookups_are_bounded() {
    let hanging = Arc::new(HangingStore {
        lookups: AtomicUsize::new(0),
        publishes: AtomicUsize::new(0),
        fail_publish: AtomicBool::new(true),
    });
    let store = HttpChallengeStore::default().with_shared(hanging.clone());
    // A lost publication (indeterminate outcome) is retried, then fails the
    // insert: the token must not be marked ready when the fleet cannot
    // answer it. Nothing is left locally either.
    let started = std::time::Instant::now();
    let error = store
        .insert("example.com", "tok_lost", "tok_lost.thumb")
        .await
        .expect_err("unacknowledged publication must fail the insert")
        .to_string();
    assert!(
        error.contains("not published to the shared store")
            && error.contains("publish lost")
            && error.contains("after 3 attempts"),
        "{error}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "retries are bounded"
    );
    assert_eq!(hanging.publishes.load(Ordering::SeqCst), 3);
    // The failed token is gone locally; the miss costs one bounded lookup.
    let lookups_before = hanging.lookups.load(Ordering::SeqCst);
    assert!(
        timeout(
            Duration::from_secs(10),
            store.get("example.com", "tok_lost")
        )
        .await
        .unwrap()
        .is_none()
    );
    assert_eq!(hanging.lookups.load(Ordering::SeqCst), lookups_before + 1);
    // An acknowledged publication installs the token; a local hit never
    // touches the store.
    hanging.fail_publish.store(false, Ordering::SeqCst);
    store
        .insert("example.com", "tok_local", "tok_local.thumb")
        .await
        .unwrap();
    assert_eq!(hanging.publishes.load(Ordering::SeqCst), 4);
    let lookups_before = hanging.lookups.load(Ordering::SeqCst);
    assert_eq!(
        store.get("example.com", "tok_local").await.as_deref(),
        Some("tok_local.thumb")
    );
    assert_eq!(hanging.lookups.load(Ordering::SeqCst), lookups_before);

    let started = std::time::Instant::now();
    let response = timeout(
        Duration::from_secs(10),
        store.response(&challenge_request("example.com", "tok_elsewhere")),
    )
    .await
    .expect("lookup must be bounded");
    assert!(response.is_none(), "an unanswered lookup is a 404");
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(2) && elapsed < Duration::from_secs(5),
        "lookup bound was {elapsed:?}"
    );
    assert_eq!(hanging.lookups.load(Ordering::SeqCst), lookups_before + 1);
    // Removal succeeds locally even though the store withdrawal fails; the
    // following miss falls through to one more bounded lookup.
    store.remove("example.com", "tok_local").await.unwrap();
    assert!(store.get("example.com", "tok_local").await.is_none());
    assert_eq!(hanging.lookups.load(Ordering::SeqCst), lookups_before + 2);
    let lookups_before = hanging.lookups.load(Ordering::SeqCst);

    // The unauthenticated listener path cannot amplify into the store: with
    // eight lookups in flight, further unknown tokens are answered 404 at
    // once without another store round trip.
    let mut in_flight = Vec::new();
    for index in 0..8 {
        let store = store.clone();
        in_flight.push(tokio::spawn(async move {
            store
                .get("example.com", &format!("tok_flood_{index}"))
                .await
        }));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(hanging.lookups.load(Ordering::SeqCst), lookups_before + 8);
    let started = std::time::Instant::now();
    assert!(store.get("example.com", "tok_flood_extra").await.is_none());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "a saturated lookup budget must answer immediately"
    );
    assert_eq!(
        hanging.lookups.load(Ordering::SeqCst),
        lookups_before + 8,
        "no store round trip beyond the concurrency bound"
    );
    for task in in_flight {
        assert!(task.await.unwrap().is_none());
    }
}

/// Records published to the wrapped store are counted, so a test can tell a
/// refresh from the initial publication and see that refreshes stop.
struct CountingStore {
    inner: Arc<dyn ConfigStore>,
    publishes: AtomicUsize,
    withdrawals: AtomicUsize,
}
#[async_trait]
impl ConfigStore for CountingStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        self.inner.load_latest().await
    }
    async fn bootstrap(&self, config: hangang::config::Config) -> StoreResult<Stored> {
        self.inner.bootstrap(config).await
    }
    async fn compare_and_swap(
        &self,
        epoch: &str,
        expected: u64,
        next: hangang::config::Config,
    ) -> StoreResult<CasResult> {
        self.inner.compare_and_swap(epoch, expected, next).await
    }
    async fn publish_challenge(
        &self,
        token: &str,
        key_authorization: &str,
        ttl: Duration,
    ) -> StoreResult<()> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        self.inner
            .publish_challenge(token, key_authorization, ttl)
            .await
    }
    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        self.inner.lookup_challenge(token).await
    }
    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        self.withdrawals.fetch_add(1, Ordering::SeqCst);
        self.inner.withdraw_challenge(token).await
    }
}

/// An order can outlive the shared record's ttl (the CA may validate late in
/// a 24-hour `acme_timeout`), so the issuing instance refreshes the record
/// at half the ttl until it removes the token; removal stops the refresh.
#[tokio::test]
async fn shared_challenge_records_are_refreshed_until_removed() {
    let temp = tempfile::tempdir().unwrap();
    let sqlite: Arc<dyn ConfigStore> = Arc::new(
        SqliteConfigStore::open(temp.path().join("fleet.db"))
            .await
            .unwrap(),
    );
    let counting = Arc::new(CountingStore {
        inner: sqlite,
        publishes: AtomicUsize::new(0),
        withdrawals: AtomicUsize::new(0),
    });
    let store: Arc<dyn ConfigStore> = counting.clone();
    let a = HttpChallengeStore::default()
        .with_shared(store.clone())
        .with_shared_ttl(Duration::from_secs(2));
    let b = HttpChallengeStore::default().with_shared(store.clone());
    a.insert("example.com", "tok_slow", "tok_slow.thumb")
        .await
        .unwrap();
    assert_eq!(counting.publishes.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.get("example.com", "tok_slow").await.as_deref(),
        Some("tok_slow.thumb")
    );
    // Well past the initial 2 s ttl (the store rounds expiry up by a second).
    tokio::time::sleep(Duration::from_millis(4500)).await;
    assert_eq!(
        b.get("example.com", "tok_slow").await.as_deref(),
        Some("tok_slow.thumb"),
        "the record must be refreshed while the order is active"
    );
    let refreshed = counting.publishes.load(Ordering::SeqCst);
    assert!(
        refreshed >= 3,
        "expected refreshes at every half ttl, saw {refreshed}"
    );

    a.remove("example.com", "tok_slow").await.unwrap();
    assert_eq!(counting.withdrawals.load(Ordering::SeqCst), 1);
    assert!(b.get("example.com", "tok_slow").await.is_none());
    let after_removal = counting.publishes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(
        counting.publishes.load(Ordering::SeqCst),
        after_removal,
        "refresh must stop with the removal"
    );
    assert!(
        store
            .lookup_challenge(&shared_challenge_key("example.com", "tok_slow"))
            .await
            .unwrap()
            .is_none(),
        "a refresh must not resurrect a withdrawn record"
    );
}

/// An in-memory store that models a backend whose writes outlive the
/// caller's future (SQLite work runs on a blocking thread; a network store
/// may still apply a request whose response nobody awaits): every
/// publication and withdrawal runs as a detached task the caller merely
/// awaits. Operations on chosen records can be held at a gate — all of them
/// or only the next few — so a test can interleave an in-flight mutation
/// with a replacement or removal of the same token, and publications of
/// chosen records can be refused with a transport error once released.
struct GatedStore {
    me: Weak<Self>,
    records: Mutex<HashMap<String, String>>,
    /// Pattern (a suffix of the published record, or of the withdrawn
    /// token) -> gate holding its next operations until released.
    gates: Mutex<HashMap<String, Gate>>,
    /// Bumped by every release; held operations wait on it.
    released: watch::Sender<u64>,
    /// Records ending in one of these fail with a transport error.
    refused: Mutex<Vec<String>>,
    publishes: AtomicUsize,
    lookups: AtomicUsize,
    withdrawals: AtomicUsize,
}
struct Gate {
    /// Operations still to be held (`usize::MAX`: all of them).
    remaining: usize,
    open: bool,
}
impl GatedStore {
    fn new() -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            records: Mutex::default(),
            gates: Mutex::default(),
            released: watch::channel(0).0,
            refused: Mutex::default(),
            publishes: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
            withdrawals: AtomicUsize::new(0),
        })
    }
    /// Hold every operation matching `pattern` until `release`.
    fn hold(&self, pattern: &str) {
        self.hold_next(pattern, usize::MAX);
    }
    /// Hold only the next `count` operations matching `pattern`; later ones
    /// (a retry, for instance) go through at once.
    fn hold_next(&self, pattern: &str, count: usize) {
        self.gates.lock().unwrap().insert(
            pattern.to_owned(),
            Gate {
                remaining: count,
                open: false,
            },
        );
    }
    /// Let the operations held for `pattern` proceed and hold no new ones.
    fn release(&self, pattern: &str) {
        if let Some(gate) = self.gates.lock().unwrap().get_mut(pattern) {
            gate.remaining = 0;
            gate.open = true;
        }
        self.released.send_modify(|generation| *generation += 1);
    }
    /// Wait at the gate matching `subject`, if one still holds operations.
    async fn pass(&self, subject: &str) {
        let mut released = self.released.subscribe();
        let pattern = {
            let mut gates = self.gates.lock().unwrap();
            gates
                .iter_mut()
                .find(|(pattern, gate)| gate.remaining > 0 && subject.ends_with(pattern.as_str()))
                .map(|(pattern, gate)| {
                    gate.remaining -= 1;
                    pattern.clone()
                })
        };
        let Some(pattern) = pattern else {
            return;
        };
        while !self
            .gates
            .lock()
            .unwrap()
            .get(&pattern)
            .is_none_or(|gate| gate.open)
        {
            released.changed().await.expect("gate outlives the store");
        }
    }
    fn refuses(&self, record: &str) -> bool {
        self.refused
            .lock()
            .unwrap()
            .iter()
            .any(|suffix| record.ends_with(suffix.as_str()))
    }
    fn record(&self, token: &str) -> Option<String> {
        self.records.lock().unwrap().get(token).cloned()
    }
    /// Wait until `count` publications have been started (held ones count).
    async fn publications_started(&self, count: usize) {
        Self::started(&self.publishes, count, "publications").await;
    }
    /// Wait until `count` withdrawals have been started (held ones count).
    async fn withdrawals_started(&self, count: usize) {
        Self::started(&self.withdrawals, count, "withdrawals").await;
    }
    async fn started(counter: &AtomicUsize, count: usize, what: &str) {
        timeout(Duration::from_secs(10), async {
            while counter.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "expected {count} {what}, saw {}",
                counter.load(Ordering::SeqCst)
            )
        });
    }
}
#[async_trait]
impl ConfigStore for GatedStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn bootstrap(&self, _: hangang::config::Config) -> StoreResult<Stored> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: hangang::config::Config,
    ) -> StoreResult<CasResult> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn publish_challenge(&self, token: &str, record: &str, _: Duration) -> StoreResult<()> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        let me = self.me.upgrade().expect("store alive");
        let (token, record) = (token.to_owned(), record.to_owned());
        // Detached like a blocking-thread write: dropping the caller's
        // future does not stop it.
        tokio::spawn(async move {
            me.pass(&record).await;
            if me.refuses(&record) {
                return Err(StoreError::Unavailable(anyhow!("publish refused")));
            }
            me.records.lock().unwrap().insert(token, record);
            Ok(())
        })
        .await
        .expect("publication task")
    }
    async fn lookup_challenge(&self, token: &str) -> StoreResult<Option<String>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.record(token))
    }
    async fn withdraw_challenge(&self, token: &str) -> StoreResult<()> {
        self.withdrawals.fetch_add(1, Ordering::SeqCst);
        let me = self.me.upgrade().expect("store alive");
        let token = token.to_owned();
        tokio::spawn(async move {
            me.pass(&token).await;
            me.records.lock().unwrap().remove(&token);
            Ok(())
        })
        .await
        .expect("withdrawal task")
    }
}

/// Reinstalling a `(host, token)` replaces the entry and stops the previous
/// refresh. A refresh already in flight at that moment must neither
/// overwrite the replacement's record nor, on noticing its cancellation,
/// withdraw it: the replacement is published only after the refresh has
/// finished, and the cancelled keepalive leaves a key it no longer owns
/// alone. Afterwards only the replacement is refreshed.
#[tokio::test]
async fn replacing_a_token_during_a_blocked_refresh_keeps_the_replacement_published() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default()
        .with_shared(shared.clone())
        .with_shared_ttl(Duration::from_secs(2));
    let b = HttpChallengeStore::default().with_shared(shared);
    a.insert("example.com", "tok_replaced", "first.thumb")
        .await
        .unwrap();
    assert_eq!(gated.publishes.load(Ordering::SeqCst), 1);
    // Hold the first refresh (due after 1 s) at the gate; the replacement's
    // own publication is not held, so before the fix it landed at once and
    // was then overwritten and withdrawn by the cancelled keepalive.
    gated.hold(" first.thumb");
    gated.publications_started(2).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_replaced"))
            .as_deref(),
        Some("example.com first.thumb")
    );

    // Replace the token while that refresh is in flight.
    let replacement = tokio::spawn({
        let a = a.clone();
        async move {
            a.insert("example.com", "tok_replaced", "second.thumb")
                .await
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        a.get("example.com", "tok_replaced").await.as_deref(),
        Some("second.thumb"),
        "the replacement is installed locally at once"
    );
    let publishes_while_held = gated.publishes.load(Ordering::SeqCst);
    let replacement_returned_early = replacement.is_finished();

    gated.release(" first.thumb");
    timeout(Duration::from_secs(10), replacement)
        .await
        .expect("the replacement completes once the refresh has finished")
        .unwrap()
        .unwrap();
    // Give the cancelled keepalive time to act on its cancellation.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_replaced"))
            .as_deref(),
        Some("example.com second.thumb"),
        "the cancelled keepalive must not withdraw or overwrite the replacement's record"
    );
    assert_eq!(
        gated.withdrawals.load(Ordering::SeqCst),
        0,
        "nothing was removed, so nothing is withdrawn"
    );
    assert_eq!(
        publishes_while_held, 2,
        "the replacement is published only after the in-flight refresh"
    );
    assert!(
        !replacement_returned_early,
        "the replacement's insert waits for the in-flight refresh"
    );
    assert_eq!(
        b.get("example.com", "tok_replaced").await.as_deref(),
        Some("second.thumb"),
        "another instance answers the replacement"
    );

    // Only the replacement is refreshed from now on.
    let before = gated.publishes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        gated.publishes.load(Ordering::SeqCst) > before,
        "the replacement's keepalive refreshes the record"
    );
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_replaced"))
            .as_deref(),
        Some("example.com second.thumb"),
        "the replaced installation no longer refreshes its record"
    );

    a.remove("example.com", "tok_replaced").await.unwrap();
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_replaced"))
            .is_none()
    );
    assert!(gated.withdrawals.load(Ordering::SeqCst) >= 1);
    assert!(b.get("example.com", "tok_replaced").await.is_none());
}

/// An insert whose publication fails rolls back only its own installation:
/// when the key was reinstalled while the failing publication was in
/// flight, the newer local entry stays, and its own publication (queued
/// behind the failing one) lands.
#[tokio::test]
async fn failed_overlapping_insert_does_not_roll_back_the_newer_entry() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default().with_shared(shared);
    gated
        .refused
        .lock()
        .unwrap()
        .push(" first.thumb".to_owned());
    gated.hold(" first.thumb");
    let first = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_overlap", "first.thumb").await }
    });
    gated.publications_started(1).await;
    let second = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_overlap", "second.thumb").await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        a.get("example.com", "tok_overlap").await.as_deref(),
        Some("second.thumb")
    );
    assert!(!first.is_finished());

    gated.release(" first.thumb");
    let error = timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .expect_err("the refused publication fails its insert")
        .to_string();
    assert!(
        error.contains("not published to the shared store") && error.contains("publish refused"),
        "{error}"
    );
    timeout(Duration::from_secs(10), second)
        .await
        .unwrap()
        .unwrap()
        .expect("the replacement's publication is acknowledged");
    // The newer entry survived the rollback: it is served locally without
    // a store lookup, and its record is the one in the store.
    let lookups = gated.lookups.load(Ordering::SeqCst);
    assert_eq!(
        a.get("example.com", "tok_overlap").await.as_deref(),
        Some("second.thumb"),
        "the failed insert must not remove the newer installation"
    );
    assert_eq!(
        gated.lookups.load(Ordering::SeqCst),
        lookups,
        "the newer installation is still a local entry"
    );
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_overlap"))
            .as_deref(),
        Some("example.com second.thumb")
    );

    a.remove("example.com", "tok_overlap").await.unwrap();
    assert!(a.get("example.com", "tok_overlap").await.is_none());
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_overlap"))
            .is_none()
    );
}

/// A publication the store finishes only after the 5 s acknowledgement
/// timeout is not abandoned: it is awaited (up to the 30 s limit) while the
/// token's mutation lock is held, its late outcome counts, and a replacement
/// queued behind it publishes strictly after it. Before the fix the
/// timed-out attempt's future was dropped while its write kept running, a
/// retry was acknowledged, the replacement published, and the dropped
/// attempt then landed on top of the replacement's record.
#[tokio::test]
async fn a_late_publication_cannot_land_on_top_of_its_replacement() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default().with_shared(shared.clone());
    let b = HttpChallengeStore::default().with_shared(shared);
    // Only the first publication of the first record is held: a retry
    // would go through at once.
    gated.hold_next(" first.thumb", 1);
    let first = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_late", "first.thumb").await }
    });
    gated.publications_started(1).await;
    let replacement = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_late", "second.thumb").await }
    });
    // Past the acknowledgement timeout, well within the limit.
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert_eq!(
        a.get("example.com", "tok_late").await.as_deref(),
        Some("second.thumb"),
        "the replacement is installed locally at once"
    );
    let first_returned_early = first.is_finished();
    let replacement_returned_early = replacement.is_finished();
    let publishes_while_held = gated.publishes.load(Ordering::SeqCst);

    gated.release(" first.thumb");
    let first = timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap();
    let replacement = timeout(Duration::from_secs(10), replacement)
        .await
        .unwrap()
        .unwrap();
    // Give anything late time to land.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_late"))
            .as_deref(),
        Some("example.com second.thumb"),
        "the late publication must not overwrite the replacement's record"
    );
    replacement.expect("the replacement's publication is acknowledged");
    let error = first
        .expect_err("an installation replaced before its publication settled is not published")
        .to_string();
    assert!(error.contains("superseded"), "{error}");
    assert!(
        !first_returned_early,
        "the overdue publication is awaited, not given up on"
    );
    assert!(
        !replacement_returned_early,
        "the replacement publishes only after the overdue publication"
    );
    assert_eq!(
        publishes_while_held, 1,
        "no retry runs while the first attempt may still land"
    );
    assert_eq!(gated.publishes.load(Ordering::SeqCst), 2);
    assert_eq!(
        b.get("example.com", "tok_late").await.as_deref(),
        Some("second.thumb"),
        "another instance answers the replacement"
    );
    a.remove("example.com", "tok_late").await.unwrap();
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_late"))
            .is_none()
    );
}

/// A caller that is cancelled (its future dropped) while its publication is
/// still running must not release the key: the store's work continues and
/// keeps the key locked until it has finished, so a replacement publishes
/// strictly after it and the late write cannot land on top.
#[tokio::test]
async fn a_cancelled_caller_does_not_release_the_key_before_its_write_finishes() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default()
        .with_shared(shared.clone())
        .with_shared_mutation_bounds(Duration::from_secs(1), Duration::from_secs(3));
    let b = HttpChallengeStore::default().with_shared(shared);
    gated.hold_next(" first.thumb", 1);
    let first = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_cancel", "first.thumb").await }
    });
    gated.publications_started(1).await;
    // Drop the caller while its publication is held.
    first.abort();
    let _ = first.await;
    let replacement = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_cancel", "second.thumb").await }
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert!(
        !replacement.is_finished(),
        "the replacement must queue behind the cancelled caller's running write"
    );
    assert_eq!(gated.publishes.load(Ordering::SeqCst), 1);
    gated.release(" first.thumb");
    timeout(Duration::from_secs(10), replacement)
        .await
        .unwrap()
        .unwrap()
        .expect("the replacement publishes once the key is free");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_cancel"))
            .as_deref(),
        Some("example.com second.thumb"),
        "the cancelled caller's late write must not overwrite the replacement"
    );
    assert_eq!(
        b.get("example.com", "tok_cancel").await.as_deref(),
        Some("second.thumb")
    );
    a.remove("example.com", "tok_cancel").await.unwrap();
}

/// A withdrawal the store finishes late is awaited the same way, so a
/// reinstallation of the token queued behind the removal publishes strictly
/// after it. Before the fix the withdrawal was given up on after 5 s, the
/// removal returned, the reinstallation published, and the withdrawal then
/// deleted the new record.
#[tokio::test]
async fn a_late_withdrawal_cannot_delete_the_record_reinstalled_after_it() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default().with_shared(shared.clone());
    let b = HttpChallengeStore::default().with_shared(shared);
    a.insert("example.com", "tok_readded", "first.thumb")
        .await
        .unwrap();
    let shared_key = shared_challenge_key("example.com", "tok_readded");
    gated.hold_next(&shared_key, 1);
    let removal = tokio::spawn({
        let a = a.clone();
        async move { a.remove("example.com", "tok_readded").await }
    });
    gated.withdrawals_started(1).await;
    let reinstall = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_readded", "second.thumb").await }
    });
    tokio::time::sleep(Duration::from_secs(6)).await;
    let removal_returned_early = removal.is_finished();
    let reinstall_returned_early = reinstall.is_finished();

    gated.release(&shared_key);
    timeout(Duration::from_secs(10), removal)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(10), reinstall)
        .await
        .unwrap()
        .unwrap()
        .expect("the reinstallation's publication is acknowledged");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        gated.record(&shared_key).as_deref(),
        Some("example.com second.thumb"),
        "the late withdrawal must not delete the reinstalled record"
    );
    assert!(
        !removal_returned_early,
        "the removal waits for its overdue withdrawal"
    );
    assert!(
        !reinstall_returned_early,
        "the reinstallation publishes only after the withdrawal"
    );
    assert_eq!(gated.withdrawals.load(Ordering::SeqCst), 1);
    assert_eq!(
        b.get("example.com", "tok_readded").await.as_deref(),
        Some("second.thumb")
    );
    a.remove("example.com", "tok_readded").await.unwrap();
    assert!(gated.record(&shared_key).is_none());
}

/// A publication the store never answers is abandoned at the limit (30 s by
/// default; 3 s here, with a 1 s acknowledgement time): the insert fails
/// without a retry and leaves nothing installed, and the abandoned mutation
/// keeps the token's lock, so a later mutation of the token (here the
/// removal an issuer's cleanup makes) waits for it, bounded by the same
/// limit, instead of interleaving with it, and can withdraw the record once
/// the store has finally finished.
#[tokio::test]
async fn an_unanswered_publication_is_abandoned_at_the_limit_and_keeps_the_token_locked() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default()
        .with_shared(shared)
        .with_shared_mutation_bounds(Duration::from_secs(1), Duration::from_secs(3));
    gated.hold(" stuck.thumb");
    let started = tokio::time::Instant::now();
    let error = a
        .insert("example.com", "tok_stuck", "stuck.thumb")
        .await
        .expect_err("a publication the store never answers fails the insert")
        .to_string();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(4),
        "the insert gives up at the limit, took {elapsed:?}"
    );
    assert!(
        error.contains("not published to the shared store")
            && error.contains("still unacknowledged after 3s"),
        "{error}"
    );
    assert_eq!(
        gated.publishes.load(Ordering::SeqCst),
        1,
        "an attempt that may still land is not retried"
    );
    assert!(a.get("example.com", "tok_stuck").await.is_none());

    // The removal cannot take the token's lock while the abandoned
    // publication runs; it gives up at the limit without withdrawing.
    let started = tokio::time::Instant::now();
    a.remove("example.com", "tok_stuck").await.unwrap();
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(4),
        "the removal waits for the abandoned publication up to the limit, took {elapsed:?}"
    );
    assert_eq!(
        gated.withdrawals.load(Ordering::SeqCst),
        0,
        "no withdrawal may interleave with the abandoned publication"
    );

    // Once the store finishes the abandoned publication its record exists,
    // and the lock is free again: the next removal withdraws it at once.
    gated.release(" stuck.thumb");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_stuck"))
            .as_deref(),
        Some("example.com stuck.thumb")
    );
    let started = tokio::time::Instant::now();
    a.remove("example.com", "tok_stuck").await.unwrap();
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the lock was released when the abandoned publication completed"
    );
    assert_eq!(gated.withdrawals.load(Ordering::SeqCst), 1);
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_stuck"))
            .is_none()
    );
}

/// Two reinstallations of a token queued behind its in-flight refresh: the
/// first is replaced by the second before either publishes. It must not
/// report success, since nothing of it was ever published and the key is no
/// longer its (an issuer would otherwise tell the CA the challenge is
/// ready); only the last installation is published and refreshed.
#[tokio::test]
async fn a_reinstallation_superseded_before_it_published_reports_an_error() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default()
        .with_shared(shared)
        .with_shared_ttl(Duration::from_secs(2));
    a.insert("example.com", "tok_queue", "first.thumb")
        .await
        .unwrap();
    // The first refresh (due after 1 s) is held at the gate.
    gated.hold(" first.thumb");
    gated.publications_started(2).await;
    let second = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_queue", "second.thumb").await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        a.get("example.com", "tok_queue").await.as_deref(),
        Some("second.thumb")
    );
    let third = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_queue", "third.thumb").await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        a.get("example.com", "tok_queue").await.as_deref(),
        Some("third.thumb")
    );
    assert!(!second.is_finished() && !third.is_finished());
    assert_eq!(gated.publishes.load(Ordering::SeqCst), 2);

    gated.release(" first.thumb");
    let error = timeout(Duration::from_secs(10), second)
        .await
        .unwrap()
        .unwrap()
        .expect_err("a reinstallation replaced before it published must not report success")
        .to_string();
    assert!(error.contains("superseded"), "{error}");
    timeout(Duration::from_secs(10), third)
        .await
        .unwrap()
        .unwrap()
        .expect("the last installation is published");
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_queue"))
            .as_deref(),
        Some("example.com third.thumb")
    );
    assert_eq!(
        gated.publishes.load(Ordering::SeqCst),
        3,
        "the superseded installation never published"
    );
    assert_eq!(gated.withdrawals.load(Ordering::SeqCst), 0);
    // Only the last installation is refreshed from now on.
    let before = gated.publishes.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(gated.publishes.load(Ordering::SeqCst) > before);
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_queue"))
            .as_deref(),
        Some("example.com third.thumb")
    );
    a.remove("example.com", "tok_queue").await.unwrap();
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_queue"))
            .is_none()
    );
}

/// An installation replaced while its own publication is in flight was
/// published, but the replacement's record (queued behind it) is the one the
/// fleet will serve: the insert reports the installation as superseded
/// instead of succeeding, and rolls back nothing since the entry is the
/// replacement's now.
#[tokio::test]
async fn an_installation_replaced_during_its_publication_reports_an_error() {
    let gated = GatedStore::new();
    let shared: Arc<dyn ConfigStore> = gated.clone();
    let a = HttpChallengeStore::default().with_shared(shared);
    gated.hold_next(" first.thumb", 1);
    let first = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_swap", "first.thumb").await }
    });
    gated.publications_started(1).await;
    let second = tokio::spawn({
        let a = a.clone();
        async move { a.insert("example.com", "tok_swap", "second.thumb").await }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        a.get("example.com", "tok_swap").await.as_deref(),
        Some("second.thumb")
    );
    assert!(!first.is_finished());

    gated.release(" first.thumb");
    let error = timeout(Duration::from_secs(10), first)
        .await
        .unwrap()
        .unwrap()
        .expect_err("an installation replaced while being published must not report success")
        .to_string();
    assert!(error.contains("superseded"), "{error}");
    timeout(Duration::from_secs(10), second)
        .await
        .unwrap()
        .unwrap()
        .expect("the replacement's publication is acknowledged");
    let lookups = gated.lookups.load(Ordering::SeqCst);
    assert_eq!(
        a.get("example.com", "tok_swap").await.as_deref(),
        Some("second.thumb"),
        "the superseded insert must not remove the replacement"
    );
    assert_eq!(gated.lookups.load(Ordering::SeqCst), lookups);
    assert_eq!(
        gated
            .record(&shared_challenge_key("example.com", "tok_swap"))
            .as_deref(),
        Some("example.com second.thumb")
    );
    assert_eq!(gated.publishes.load(Ordering::SeqCst), 2);
    a.remove("example.com", "tok_swap").await.unwrap();
    assert!(
        gated
            .record(&shared_challenge_key("example.com", "tok_swap"))
            .is_none()
    );
}

/// The JSON payload carried by a JWS request body.
fn jws_payload(body: &[u8]) -> serde_json::Value {
    use base64::Engine as _;
    let envelope: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let payload = envelope
        .get("payload")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if payload.is_empty() {
        return serde_json::Value::Null;
    }
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// The public key of a CSR, in the shape rcgen needs to sign a certificate
/// for it (instant-acme's `finalize` always generates ECDSA P-256).
struct CsrPublicKey(Vec<u8>);
impl rcgen::PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

/// A minimal RFC 8555 CA on loopback TLS: one account, one HTTP-01 order
/// for `domain`. Its validation request "lands" on the challenge store it
/// was given (another instance of the fleet) and is only attempted once
/// `validate_after` has passed since the challenge was marked ready, which
/// models a CA that validates late in the order's lifetime.
struct MockCa {
    base: String,
    ca_path: std::path::PathBuf,
    domain: String,
    token: String,
    validator: Arc<HttpChallengeStore>,
    validation_destination: Mutex<Option<SocketAddr>>,
    validate_after: Duration,
    issuer_key_pem: String,
    set_ready: AtomicUsize,
    order_polls: AtomicUsize,
    validations: AtomicUsize,
    ready_at: Mutex<Option<std::time::Instant>>,
    validated: AtomicBool,
    certificate: Mutex<Option<String>>,
    nonce: AtomicUsize,
}
impl MockCa {
    async fn start(
        temp: &std::path::Path,
        domain: &str,
        validator: Arc<HttpChallengeStore>,
        validate_after: Duration,
    ) -> (Arc<Self>, CancellationToken) {
        let params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let ca_path = temp.join("mock-ca.pem");
        std::fs::write(&ca_path, cert.pem()).unwrap();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("https://{}", listener.local_addr().unwrap());
        let ca = Arc::new(Self {
            base,
            ca_path,
            domain: domain.to_owned(),
            token: "fleet-token-abc123".to_owned(),
            validator,
            validation_destination: Mutex::new(None),
            validate_after,
            issuer_key_pem: key.serialize_pem(),
            set_ready: AtomicUsize::new(0),
            order_polls: AtomicUsize::new(0),
            validations: AtomicUsize::new(0),
            ready_at: Mutex::new(None),
            validated: AtomicBool::new(false),
            certificate: Mutex::new(None),
            nonce: AtomicUsize::new(0),
        });
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let server = ca.clone();
        tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    result = listener.accept() => result,
                };
                let Ok((stream, _)) = accepted else { break };
                let acceptor = acceptor.clone();
                let server = server.clone();
                tokio::spawn(async move {
                    let Ok(stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let service = service_fn(move |request: Request<Incoming>| {
                        let server = server.clone();
                        async move { Ok::<_, std::convert::Infallible>(server.handle(request).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (ca, cancel)
    }
    fn directory(&self) -> String {
        format!("{}/directory", self.base)
    }
    fn order_json(&self) -> serde_json::Value {
        let mut order = serde_json::json!({
            "status": "pending",
            "expires": "2099-01-01T00:00:00Z",
            "identifiers": [{"type": "dns", "value": self.domain}],
            "authorizations": [format!("{}/authz/1", self.base)],
            "finalize": format!("{}/finalize/1", self.base),
        });
        if self.certificate.lock().unwrap().is_some() {
            order["status"] = "valid".into();
            order["certificate"] = format!("{}/cert/1", self.base).into();
        } else if self.validated.load(Ordering::SeqCst) {
            order["status"] = "ready".into();
        }
        order
    }
    /// The CA's validation: one GET for the token, sent to the instance the
    /// load balancer picked (`validator`), which must answer with the key
    /// authorization for this token.
    async fn validate(&self) {
        let destination = *self.validation_destination.lock().unwrap();
        let body = if let Some(destination) = destination {
            // Exercise the standalone issuer's actual bound HTTP-01 listener.
            let client = reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let Ok(response) = client
                .get(format!(
                    "http://{destination}/.well-known/acme-challenge/{}",
                    self.token
                ))
                .header(reqwest::header::HOST, &self.domain)
                .send()
                .await
            else {
                return;
            };
            if response.status() != reqwest::StatusCode::OK {
                return;
            }
            let Ok(body) = response.bytes().await else {
                return;
            };
            body
        } else {
            let Some(response) = self
                .validator
                .response(&challenge_request(&self.domain, &self.token))
                .await
            else {
                return;
            };
            if response.status() != 200 {
                return;
            }
            response.into_body().collect().await.unwrap().to_bytes()
        };
        if body.starts_with(format!("{}.", self.token).as_bytes()) {
            self.validations.fetch_add(1, Ordering::SeqCst);
            self.validated.store(true, Ordering::SeqCst);
        }
    }
    fn sign_csr(&self, csr_der: &[u8]) -> String {
        use x509_parser::prelude::FromDer as _;
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(csr_der)
                .expect("finalize carries a DER CSR");
        let public = CsrPublicKey(
            csr.certification_request_info
                .subject_pki
                .subject_public_key
                .data
                .to_vec(),
        );
        let issuer_key = rcgen::KeyPair::from_pem(&self.issuer_key_pem).unwrap();
        let issuer_params = rcgen::CertificateParams::new(vec!["127.0.0.1".to_owned()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&issuer_params, issuer_key);
        let leaf = rcgen::CertificateParams::new(vec![self.domain.clone()]).unwrap();
        leaf.signed_by(&public, &issuer).unwrap().pem()
    }
    async fn handle(&self, request: Request<Incoming>) -> Response<http_body_util::Full<Bytes>> {
        let (parts, request_body) = request.into_parts();
        let request_body = request_body.collect().await.unwrap().to_bytes();
        let path = parts.uri.path().to_owned();
        let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
        let mut response = Response::builder()
            .header("replay-nonce", format!("nonce-{nonce}"))
            .header("content-type", "application/json");
        let body: serde_json::Value = match path.as_str() {
            "/directory" => serde_json::json!({
                "newNonce": format!("{}/nonce", self.base),
                "newAccount": format!("{}/acct", self.base),
                "newOrder": format!("{}/order", self.base),
            }),
            "/nonce" => serde_json::Value::Null,
            "/acct" => {
                response = response
                    .status(StatusCode::CREATED)
                    .header("location", format!("{}/acct/1", self.base));
                serde_json::json!({"status": "valid"})
            }
            "/order" => {
                response = response
                    .status(StatusCode::CREATED)
                    .header("location", format!("{}/order/1", self.base));
                self.order_json()
            }
            "/authz/1" => serde_json::json!({
                "identifier": {"type": "dns", "value": self.domain},
                "status": "pending",
                "expires": "2099-01-01T00:00:00Z",
                "challenges": [{
                    "type": "http-01",
                    "url": format!("{}/chall/1", self.base),
                    "token": self.token,
                    "status": "pending",
                }],
            }),
            "/chall/1" => {
                self.set_ready.fetch_add(1, Ordering::SeqCst);
                self.ready_at
                    .lock()
                    .unwrap()
                    .get_or_insert_with(std::time::Instant::now);
                serde_json::json!({
                    "type": "http-01",
                    "url": format!("{}/chall/1", self.base),
                    "token": self.token,
                    "status": "processing",
                })
            }
            "/order/1" => {
                self.order_polls.fetch_add(1, Ordering::SeqCst);
                let ready_at = *self.ready_at.lock().unwrap();
                if let Some(ready_at) = ready_at
                    && !self.validated.load(Ordering::SeqCst)
                    && ready_at.elapsed() >= self.validate_after
                {
                    self.validate().await;
                    if !self.validated.load(Ordering::SeqCst) {
                        let mut order = self.order_json();
                        order["status"] = "invalid".into();
                        order["error"] = serde_json::json!({
                            "type": "urn:ietf:params:acme:error:unauthorized",
                            "detail": "validation landed on another instance and was not answered",
                        });
                        return response
                            .body(http_body_util::Full::new(Bytes::from(order.to_string())))
                            .unwrap();
                    }
                }
                let order = self.order_json();
                if order["status"] == "pending" {
                    response = response.header("retry-after", "1");
                }
                order
            }
            "/finalize/1" => {
                use base64::Engine as _;
                let payload = jws_payload(&request_body);
                let csr = payload
                    .get("csr")
                    .and_then(|value| value.as_str())
                    .unwrap_or("");
                let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(csr)
                    .expect("finalize CSR is base64url");
                let pem = self.sign_csr(&der);
                *self.certificate.lock().unwrap() = Some(pem);
                self.order_json()
            }
            "/cert/1" => {
                let pem = self.certificate.lock().unwrap().clone().unwrap_or_default();
                return response
                    .header("content-type", "application/pem-certificate-chain")
                    .body(http_body_util::Full::new(Bytes::from(pem)))
                    .unwrap();
            }
            _ => {
                return response
                    .status(StatusCode::NOT_FOUND)
                    .body(http_body_util::Full::new(Bytes::from(
                        r#"{"type":"urn:ietf:params:acme:error:malformed","detail":"unknown resource"}"#,
                    )))
                    .unwrap();
            }
        };
        let bytes = if body.is_null() {
            Bytes::new()
        } else {
            Bytes::from(body.to_string())
        };
        response.body(http_body_util::Full::new(bytes)).unwrap()
    }
}

/// A real standalone issuer process must serve the CA's GET over its bound
/// loopback listener, commit a readable pair, then avoid a second order after
/// restart. All ACME traffic and challenge validation stay on loopback.
#[tokio::test]
async fn standalone_http_issuer_issues_on_loopback_and_restarts_without_renewal() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let (ca, stop) = MockCa::start(
        temp.path(),
        "issuer.example.test",
        Arc::new(HttpChallengeStore::default()),
        Duration::ZERO,
    )
    .await;
    let address = {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        listener.local_addr()?
    };
    *ca.validation_destination.lock().unwrap() = Some(address);
    let account_dir = temp.path().join("accounts");
    let output = temp.path().join("output");
    std::fs::create_dir(&account_dir)?;
    std::fs::create_dir(&output)?;
    for directory in [&account_dir, &output] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let config_path = temp.path().join("issuer.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "directory": ca.directory(),
            "domains": ["issuer.example.test"],
            "challenge": "http-01",
            "account_path": account_dir.join("account.json"),
            "ca_path": ca.ca_path,
            "output_directory": output,
            "acme_timeout_secs": 25,
            "check_interval_secs": 3600
        }))?,
    )?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    let spawn = || -> Result<Child> {
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(temp.path().join("issuer-test.log"))?;
        Ok(Command::new(env!("CARGO_BIN_EXE_hangang-acme-issuer"))
            .args([
                "--config",
                config_path.to_str().unwrap(),
                "--http-listen",
                &address.to_string(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()?)
    };
    struct KillChild(Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let first = KillChild(spawn()?);
    timeout(Duration::from_secs(35), async {
        while !output.join("current/cert.pem").is_file() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    hangang::certificates::load(&[hangang::certificates::CertificateFiles {
        id: "issuer".into(),
        hosts: vec!["issuer.example.test".into()],
        default: false,
        enabled: true,
        cert_file: output.join("current/cert.pem"),
        key_file: output.join("current/key.pem"),
        issuer_status_file: None,
    }])?;
    assert_eq!(ca.validations.load(Ordering::SeqCst), 1);
    drop(first);
    let mut second = KillChild(spawn()?);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(second.0.try_wait()?.is_none(), "issuer exits on restart");
    assert_eq!(
        ca.set_ready.load(Ordering::SeqCst),
        1,
        "valid current pair triggered new ACME order"
    );
    drop(second);
    stop.cancel();
    Ok(())
}

/// Stopping during an outstanding authorization must close the public token
/// listener promptly, without waiting for the CA's delayed validation.
#[tokio::test]
async fn standalone_http_issuer_cancels_pending_order_and_closes_listener() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir()?;
    let (ca, stop) = MockCa::start(
        temp.path(),
        "cancel.example.test",
        Arc::new(HttpChallengeStore::default()),
        Duration::from_secs(120),
    )
    .await;
    let address = {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        listener.local_addr()?
    };
    let account_dir = temp.path().join("accounts");
    let output = temp.path().join("output");
    for directory in [&account_dir, &output] {
        std::fs::create_dir(directory)?;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let config_path = temp.path().join("issuer.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "directory": ca.directory(),
            "domains": ["cancel.example.test"],
            "challenge": "http-01",
            "account_path": account_dir.join("account.json"),
            "ca_path": ca.ca_path,
            "output_directory": output,
            "acme_timeout_secs": 30
        }))?,
    )?;
    std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))?;
    let log = std::fs::File::create(temp.path().join("issuer-test.log"))?;
    let child = Command::new(env!("CARGO_BIN_EXE_hangang-acme-issuer"))
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--http-listen",
            &address.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()?;
    struct KillChild(Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = KillChild(child);
    timeout(Duration::from_secs(10), async {
        while ca.set_ready.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    let url = format!("http://{address}/.well-known/acme-challenge/{}", ca.token);
    let client = reqwest::Client::builder().no_proxy().build()?;
    assert_eq!(
        client
            .get(&url)
            .header(reqwest::header::HOST, &ca.domain)
            .send()
            .await?
            .status(),
        reqwest::StatusCode::OK
    );
    // SAFETY: `child` is a live process we spawned and own in this fixture.
    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
    timeout(Duration::from_secs(8), async {
        while child.0.try_wait().unwrap().is_none() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    assert!(client.get(&url).send().await.is_err());
    assert!(!output.join("current").exists());
    stop.cancel();
    Ok(())
}

fn mock_ca_config(temp: &std::path::Path, ca: &MockCa) -> AcmeConfig {
    let mut config = AcmeConfig::new(vec![ca.domain.clone()], temp.join("account.json"));
    config.directory = AcmeDirectory::Custom(ca.directory());
    config.ca_path = Some(ca.ca_path.clone());
    config.challenge = ChallengeMode::Http01;
    config.renewal.acme_timeout = Duration::from_secs(30);
    config
}

/// A store whose publications fail and that counts them.
struct FailingPublishStore {
    publishes: AtomicUsize,
}
#[async_trait]
impl ConfigStore for FailingPublishStore {
    async fn load_latest(&self) -> StoreResult<Option<Stored>> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn bootstrap(&self, _: hangang::config::Config) -> StoreResult<Stored> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn compare_and_swap(
        &self,
        _: &str,
        _: u64,
        _: hangang::config::Config,
    ) -> StoreResult<CasResult> {
        Err(StoreError::Unavailable(anyhow!("unused")))
    }
    async fn publish_challenge(&self, _: &str, _: &str, _: Duration) -> StoreResult<()> {
        self.publishes.fetch_add(1, Ordering::SeqCst);
        Err(StoreError::Unavailable(anyhow!("store down")))
    }
    async fn lookup_challenge(&self, _: &str) -> StoreResult<Option<String>> {
        Ok(None)
    }
    async fn withdraw_challenge(&self, _: &str) -> StoreResult<()> {
        Ok(())
    }
}

/// Fleet issuance end to end: instance A places the order, the CA's
/// validation lands on instance B four seconds after A marked the challenge
/// ready, i.e. after the 2-second shared record would have expired, and the
/// order still completes because A keeps the record alive until it is
/// withdrawn together with the finished order.
#[tokio::test]
async fn shared_http01_order_validates_on_another_instance_past_the_record_ttl() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let store: Arc<dyn ConfigStore> =
        Arc::new(SqliteConfigStore::open(temp.path().join("fleet.db")).await?);
    let a = Arc::new(
        HttpChallengeStore::default()
            .with_shared(store.clone())
            .with_shared_ttl(Duration::from_secs(2)),
    );
    let b = Arc::new(HttpChallengeStore::default().with_shared(store.clone()));
    let (ca, stop) = MockCa::start(
        temp.path(),
        "fleet.example.test",
        b.clone(),
        Duration::from_secs(4),
    )
    .await;
    let engine =
        hangang::acme::AcmeEngine::new(mock_ca_config(temp.path(), &ca), a.clone(), None).await?;
    let issued = timeout(
        Duration::from_secs(40),
        engine.issue(&CancellationToken::new()),
    )
    .await??;
    assert_eq!(issued.domains, vec!["fleet.example.test".to_owned()]);
    assert_eq!(ca.set_ready.load(Ordering::SeqCst), 1);
    assert_eq!(
        ca.validations.load(Ordering::SeqCst),
        1,
        "the late validation on instance B must have been answered"
    );
    // The finished order withdrew the record and stopped refreshing it.
    assert!(a.get("fleet.example.test", &ca.token).await.is_none());
    assert!(b.get("fleet.example.test", &ca.token).await.is_none());
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        store.lookup_challenge(&ca.token).await?.is_none(),
        "no refresh may run after the order ended"
    );
    stop.cancel();
    Ok(())
}

/// When the fleet cannot be told about the token, the issuing instance must
/// not tell the CA the challenge is ready: validation could land on an
/// instance that answers 404. The authorization is aborted with a clear
/// error after bounded publication attempts, the CA never sees `set_ready`,
/// and no local entry is left behind.
#[tokio::test]
async fn shared_http01_publication_failure_aborts_before_set_ready() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let failing = Arc::new(FailingPublishStore {
        publishes: AtomicUsize::new(0),
    });
    let a = Arc::new(HttpChallengeStore::default().with_shared(failing.clone()));
    let (ca, stop) =
        MockCa::start(temp.path(), "fleet.example.test", a.clone(), Duration::ZERO).await;
    let engine =
        hangang::acme::AcmeEngine::new(mock_ca_config(temp.path(), &ca), a.clone(), None).await?;
    let started = std::time::Instant::now();
    let error = timeout(
        Duration::from_secs(40),
        engine.issue(&CancellationToken::new()),
    )
    .await?
    .expect_err("an unpublished token must fail the issuance");
    let message = format!("{error:#}");
    assert!(
        message.contains("not published to the shared store")
            && message.contains("after 3 attempts")
            && message.contains("store down"),
        "{message}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "retries are bounded"
    );
    assert_eq!(failing.publishes.load(Ordering::SeqCst), 3);
    assert_eq!(
        ca.set_ready.load(Ordering::SeqCst),
        0,
        "the CA must not be told the challenge is ready"
    );
    assert_eq!(ca.order_polls.load(Ordering::SeqCst), 0);
    assert!(
        a.get("fleet.example.test", &ca.token).await.is_none(),
        "a token the fleet cannot answer must not stay installed locally"
    );
    stop.cancel();
    Ok(())
}

#[test]
fn wildcard_requires_dns_and_directory_must_be_https() {
    let mut config = AcmeConfig::new(vec!["*.example.com".into()], "/tmp/hangang-acme-account");
    assert!(config.validate().is_ok());
    assert_eq!(config.challenge, ChallengeMode::Auto);
    config.challenge = ChallengeMode::Http01;
    assert!(config.validate().is_err());

    assert!(
        AcmeDirectory::Custom("http://ca.invalid/directory".into())
            .url()
            .is_err()
    );
    assert!(
        AcmeDirectory::LetsEncryptStaging
            .url()
            .unwrap()
            .starts_with("https://")
    );
}

#[test]
fn runtime_json_keeps_eab_secret_out_of_debug() {
    let config = AcmeFileConfig {
        directory: Some("zerossl-production".into()),
        contacts: Some(vec!["mailto:ops@example.com".into()]),
        domains: vec!["example.com".into()],
        challenge: Some("http-01".into()),
        account_path: "/tmp/account".into(),
        certificate_path: None,
        private_key_path: None,
        dns_propagation_timeout_secs: Some(30),
        dns_poll_interval_secs: Some(1),
        eab_kid: Some("kid".into()),
        eab_hmac_key_base64: Some("c2VjcmV0".into()),
        ca_path: None,
        renew_before_secs: None,
        check_interval_secs: None,
        retry_initial_secs: None,
        retry_max_secs: None,
        acme_timeout_secs: None,
    };
    let config = config.into_config().unwrap();
    let debug = format!(
        "{:?}",
        EabConfig {
            kid: "kid".into(),
            hmac_key_base64: "secret".into()
        }
    );
    assert!(debug.contains("[redacted]") && !debug.contains("secret"));
    assert_eq!(config.directory, AcmeDirectory::ZeroSslProduction);
    assert_eq!(config.dns_poll_interval, Duration::from_secs(1));
}

#[derive(Deserialize)]
struct FixtureInfo {
    skip: Option<String>,
    directory: Option<String>,
    ca_path: Option<String>,
    issuer_ca_path: Option<String>,
    management: Option<String>,
    eab_kid: Option<String>,
    eab_hmac_key_base64: Option<String>,
}
struct PebbleFixture(Child);
fn stop_fixture(child: &mut Child) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    #[cfg(not(unix))]
    let _ = child.kill();
    let _ = child.wait();
}
impl Drop for PebbleFixture {
    fn drop(&mut self) {
        // SIGKILL would skip the fixture's Docker cleanup finally block.
        stop_fixture(&mut self.0);
    }
}
fn pebble_fixture(hostnames: &[&str]) -> Option<(PebbleFixture, FixtureInfo)> {
    pebble_fixture_with_options(hostnames, false)
}
fn pebble_fixture_with_options(
    hostnames: &[&str],
    eab: bool,
) -> Option<(PebbleFixture, FixtureInfo)> {
    if std::env::var("HANGANG_PEBBLE_TEST").ok().as_deref() != Some("1") {
        return None;
    }
    let mut command = Command::new("python3");
    command.args(["tests/acme_fixture.py", "--start"]);
    if eab {
        command.arg("--eab");
    }
    for hostname in hostnames {
        command.args(["--hostname", hostname]);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line).ok()?;
    let info: FixtureInfo = serde_json::from_str(&line).ok()?;
    if info.skip.is_some() {
        eprintln!(
            "Pebble fixture skipped: {}",
            info.skip.as_deref().unwrap_or("unknown")
        );
        stop_fixture(&mut child);
        return None;
    }
    Some((PebbleFixture(child), info))
}

type CertificatePair = (Vec<u8>, Vec<u8>);
struct MemorySink(Arc<Mutex<Option<CertificatePair>>>);
#[async_trait]
impl hangang::acme::CertificateSink for MemorySink {
    async fn publish(&self, _domains: &[String], cert: &[u8], key: &[u8]) -> Result<()> {
        *self.0.lock().unwrap() = Some((cert.to_vec(), key.to_vec()));
        Ok(())
    }
}

#[derive(Clone)]
struct TestTxtResolver(Arc<Mutex<Vec<String>>>);
#[async_trait]
impl hangang::acme::TxtResolver for TestTxtResolver {
    async fn txt_values(&self, _name: &str) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[derive(Clone)]
struct WebhookState {
    management: String,
    values: Arc<Mutex<Vec<String>>>,
    fail_delete: Arc<AtomicBool>,
    deletes: Arc<AtomicUsize>,
}
async fn webhook_server(
    state: WebhookState,
) -> Result<(String, CancellationToken, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! { _ = task_cancel.cancelled() => break, result = listener.accept() => result };
            let Ok((stream, _)) = accepted else { break };
            let state = state.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let state = state.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let parsed: serde_json::Value =
                            serde_json::from_slice(&body.collect().await.unwrap().to_bytes())
                                .unwrap_or(serde_json::Value::Null);
                        let name = parsed
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        let value = parsed
                            .get("value")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_owned();
                        let action = parsed.get("action").and_then(|v| v.as_str()).unwrap_or("");
                        let (status, body) = if parts.method == "POST" && action == "present" {
                            let _ = reqwest::Client::new()
                                .post(format!("{}/set-txt", state.management))
                                .json(&serde_json::json!({"host": name, "value": value}))
                                .send()
                                .await;
                            state.values.lock().unwrap().push(value.clone());
                            (
                                StatusCode::OK,
                                serde_json::json!({"id":"pebble-owned-1","name":name,"value":value}),
                            )
                        } else if parts.method == "POST" && action == "delete" {
                            state.deletes.fetch_add(1, Ordering::SeqCst);
                            if state.fail_delete.load(Ordering::SeqCst) {
                                (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    serde_json::json!({"error":"injected cleanup failure"}),
                                )
                            } else {
                                let _ = reqwest::Client::new()
                                    .post(format!("{}/clear-txt", state.management))
                                    .json(&serde_json::json!({"host": name}))
                                    .send()
                                    .await;
                                state.values.lock().unwrap().retain(|entry| entry != &value);
                                (StatusCode::OK, serde_json::json!({"ok":true}))
                            }
                        } else {
                            (
                                StatusCode::BAD_REQUEST,
                                serde_json::json!({"error":"bad webhook request"}),
                            )
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder()
                                .status(status)
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(Bytes::from(body.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((endpoint, cancel, task))
}

async fn challenge_server(
    store: Arc<HttpChallengeStore>,
) -> Result<(CancellationToken, tokio::task::JoinHandle<()>)> {
    // Pebble reaches the host through the Docker bridge gateway.
    let listener = TcpListener::bind("0.0.0.0:5002").await?;
    let cancel = CancellationToken::new();
    let task_cancel = cancel.clone();
    let task = tokio::spawn(async move {
        loop {
            let accepted = tokio::select! { _ = task_cancel.cancelled() => break, result = listener.accept() => result };
            let Ok((stream, _)) = accepted else { break };
            let store = store.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let store = store.clone();
                    async move {
                        let response = store.response(&request).await.unwrap_or_else(|| {
                            Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(http_body_util::Full::new(Bytes::new()))
                                .unwrap()
                        });
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((cancel, task))
}

/// Real RFC 8555 JWS issuance against a test-owned Pebble CA. This is opt-in
/// because it needs locally preloaded Pebble images and Docker networking.
#[tokio::test]
async fn pebble_http01_issue_and_account_reuse() -> Result<()> {
    let _serial = pebble_test_lock().await;
    let Some((fixture, info)) = pebble_fixture(&["acme-http.example.test"]) else {
        return Ok(());
    };
    let Some(directory) = info.directory else {
        return Ok(());
    };
    let Some(ca_path) = info.ca_path else {
        return Ok(());
    };
    let store = HttpChallengeStore::shared();
    let (cancel_server, server) = match challenge_server(store.clone()).await {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    let directory_temp = tempfile::tempdir()?;
    let mut config = AcmeConfig::new(
        vec!["acme-http.example.test".into()],
        directory_temp.path().join("account.json"),
    );
    config.directory = AcmeDirectory::Custom(directory);
    config.ca_path = Some(ca_path.into());
    config.challenge = ChallengeMode::Http01;
    config.renewal.renew_before = Duration::from_secs(60);
    config.certificate_path = Some(directory_temp.path().join("cert.pem"));
    config.private_key_path = Some(directory_temp.path().join("key.pem"));
    let engine = hangang::acme::AcmeEngine::new(config.clone(), store, None).await?;
    let sink = MemorySink(Arc::new(Mutex::new(None)));
    let cancel = CancellationToken::new();
    let issued = timeout(
        Duration::from_secs(45),
        engine.issue_and_publish(&sink, &cancel),
    )
    .await??;
    assert!(
        issued
            .certificate_pem
            .windows(10)
            .any(|w| w == b"BEGIN CERT")
    );
    assert!(directory_temp.path().join("cert.pem").exists());
    assert!(
        !engine.needs_renewal().await?,
        "fresh Pebble certificate was considered due for renewal"
    );
    let _reused =
        hangang::acme::AcmeEngine::new(config, HttpChallengeStore::shared(), None).await?;
    cancel_server.cancel();
    let _ = timeout(Duration::from_secs(2), server).await;
    drop(fixture);
    Ok(())
}

/// Exercise RFC 8555 external account binding against Pebble's documented
/// test MAC key. A fresh account with the wrong key is rejected by the CA.
#[tokio::test]
async fn pebble_eab_accepts_known_key_and_rejects_wrong_key() -> Result<()> {
    let _serial = pebble_test_lock().await;
    let hosts = ["acme-eab.example.test"];
    let Some((fixture, info)) = pebble_fixture_with_options(&hosts, true) else {
        return Ok(());
    };
    let Some(directory) = info.directory else {
        return Ok(());
    };
    let Some(ca_path) = info.ca_path else {
        return Ok(());
    };
    let Some(kid) = info.eab_kid else {
        return Ok(());
    };
    let Some(hmac_key) = info.eab_hmac_key_base64 else {
        return Ok(());
    };
    let store = HttpChallengeStore::shared();
    let (cancel_server, server) = challenge_server(store.clone()).await?;
    let temp = tempfile::tempdir()?;
    let mut config = AcmeConfig::new(vec![hosts[0].into()], temp.path().join("eab-account.json"));
    config.directory = AcmeDirectory::Custom(directory.clone());
    config.ca_path = Some(ca_path.clone().into());
    config.challenge = ChallengeMode::Http01;
    config.eab = Some(EabConfig {
        kid,
        hmac_key_base64: hmac_key,
    });
    let engine = hangang::acme::AcmeEngine::new(config, store, None).await?;
    let issued = timeout(
        Duration::from_secs(45),
        engine.issue(&CancellationToken::new()),
    )
    .await??;
    assert!(
        issued
            .certificate_pem
            .windows(10)
            .any(|w| w == b"BEGIN CERT")
    );

    let mut wrong = AcmeConfig::new(
        vec![hosts[0].into()],
        temp.path().join("wrong-account.json"),
    );
    wrong.directory = AcmeDirectory::Custom(directory);
    wrong.ca_path = Some(ca_path.into());
    wrong.challenge = ChallengeMode::Http01;
    wrong.eab = Some(EabConfig {
        kid: "kid-1".into(),
        hmac_key_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
    });
    assert!(
        hangang::acme::AcmeEngine::new(wrong, HttpChallengeStore::shared(), None)
            .await
            .is_err()
    );
    cancel_server.cancel();
    let _ = timeout(Duration::from_secs(2), server).await;
    drop(fixture);
    Ok(())
}

/// Real wildcard DNS-01 flow through the typed webhook provider and Pebble's
/// test DNS server. The provider's injected cleanup failure is observable but
/// cannot change the already validated certificate publication.
#[tokio::test]
async fn pebble_wildcard_dns01_webhook_and_cleanup_failure() -> Result<()> {
    let _serial = pebble_test_lock().await;
    let Some((fixture, info)) = pebble_fixture(&["acme-wild.example.test"]) else {
        return Ok(());
    };
    let Some(directory) = info.directory else {
        return Ok(());
    };
    let Some(ca_path) = info.ca_path else {
        return Ok(());
    };
    let Some(management) = info.management else {
        return Ok(());
    };
    let values = Arc::new(Mutex::new(Vec::new()));
    let webhook_state = WebhookState {
        management,
        values: values.clone(),
        fail_delete: Arc::new(AtomicBool::new(true)),
        deletes: Arc::new(AtomicUsize::new(0)),
    };
    let (endpoint, webhook_cancel, webhook_task) = webhook_server(webhook_state.clone()).await?;
    let resolver = TestTxtResolver(values);
    let provider = hangang::acme::WebhookDnsProvider::with_resolver(
        endpoint,
        "test-webhook-secret",
        Arc::new(resolver),
    );
    let temp = tempfile::tempdir()?;
    let mut config = AcmeConfig::new(
        vec!["*.acme-wild.example.test".into()],
        temp.path().join("account.json"),
    );
    config.directory = AcmeDirectory::Custom(directory);
    config.ca_path = Some(ca_path.into());
    config.challenge = ChallengeMode::Dns01;
    config.certificate_path = Some(temp.path().join("cert.pem"));
    config.private_key_path = Some(temp.path().join("key.pem"));
    let engine = hangang::acme::AcmeEngine::new(
        config,
        HttpChallengeStore::shared(),
        Some(Arc::new(provider)),
    )
    .await?;
    let sink = MemorySink(Arc::new(Mutex::new(None)));
    let issued = timeout(
        Duration::from_secs(60),
        engine.issue_and_publish(&sink, &CancellationToken::new()),
    )
    .await??;
    assert!(
        issued
            .certificate_pem
            .windows(10)
            .any(|w| w == b"BEGIN CERT")
    );
    assert!(webhook_state.deletes.load(Ordering::SeqCst) >= 1);
    assert!(temp.path().join("cert.pem").exists());
    webhook_cancel.cancel();
    let _ = timeout(Duration::from_secs(2), webhook_task).await;
    drop(fixture);
    Ok(())
}

struct HangangProcess(std::process::Child);
impl Drop for HangangProcess {
    fn drop(&mut self) {
        #[cfg(unix)]
        let _ = Command::new("kill")
            .args(["-TERM", &self.0.id().to_string()])
            .status();
        #[cfg(not(unix))]
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_for_bundle(path: &std::path::Path) -> Result<Vec<u8>> {
    for _ in 0..120 {
        if let Ok(bytes) = tokio::fs::read(path).await {
            return Ok(bytes);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("Hangang ACME runtime did not publish a bundle")
}

/// End-to-end process test: the actual Hangang binary owns the HTTP-01
/// listener, publishes the Pebble certificate into its TLS SNI resolver, and
/// keeps serving the last certificate while its config becomes invalid.
/// Run explicitly with HANGANG_PEBBLE_TEST=1; it needs the local Pebble images.
#[tokio::test]
#[ignore = "opt-in process test: HANGANG_PEBBLE_TEST=1 cargo test --test acme gateway"]
async fn gateway_process_acme_issue_reload_and_restart() -> Result<()> {
    let _serial = pebble_test_lock().await;
    let Some((fixture, info)) = pebble_fixture(&["acme-gateway.example.test"]) else {
        return Ok(());
    };
    let Some(directory) = info.directory else {
        return Ok(());
    };
    let Some(ca_path) = info.ca_path else {
        return Ok(());
    };
    let Some(issuer_ca_path) = info.issuer_ca_path else {
        return Ok(());
    };
    let temp = tempfile::tempdir()?;
    let acme_path = temp.path().join("acme.json");
    let account_path = temp.path().join("account.json");
    let bundle = account_path.with_extension("tls.json");
    let app_config = temp.path().join("routes.json");
    std::fs::write(&app_config, r#"{"revision":0,"http":[],"tcp":[]}"#)?;
    let runtime = serde_json::json!({
        "directory": directory, "domains": ["acme-gateway.example.test"], "challenge": "http-01",
        "account_path": account_path, "ca_path": ca_path,
        "renew_before_secs": 31536000u64, "check_interval_secs": 1u64,
        "retry_initial_secs": 1u64, "retry_max_secs": 4u64, "acme_timeout_secs": 60u64
    });
    std::fs::write(&acme_path, serde_json::to_vec(&runtime)?)?;
    // Reserve ephemeral ports before starting Hangang.  Passing port 0 to the
    // binary would make the listener choose a port that this test cannot
    // discover for the TLS probe.
    let free = || -> std::net::SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        address
    };
    let public = free();
    let admin = free();
    let binary =
        std::env::var("HANGANG_BINARY").unwrap_or_else(|_| env!("CARGO_BIN_EXE_hangang").into());
    let log_path = temp.path().join("hangang.log");
    let log = std::fs::File::create(&log_path)?;
    let stdout = log.try_clone()?;
    let child = Command::new(binary)
        .args([
            "--supervised",
            "--config",
            app_config.to_str().unwrap(),
            "--acme-config",
            acme_path.to_str().unwrap(),
            "--acme-http-listen",
            "0.0.0.0:5002",
            "--listen",
            &public.to_string(),
            "--admin",
            &admin.to_string(),
            "--admin-token",
            "test-token-123456",
        ])
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log))
        .spawn()?;
    let mut process = HangangProcess(child);
    let first = match wait_for_bundle(&bundle).await {
        Ok(value) => value,
        Err(error) => {
            let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
            anyhow::bail!("{error}; Hangang log: {logs}")
        }
    };
    let _ = openssl_probe(&first, &issuer_ca_path, public.port()).await?;
    let account_before = tokio::fs::read(&account_path).await?;
    #[cfg(unix)]
    {
        // The supervisor keeps its PID and replaces the serving generation;
        // the inherited ACME listener and persisted account must survive.
        let status = Command::new("kill")
            .args(["-HUP", &process.0.id().to_string()])
            .status()?;
        anyhow::ensure!(status.success(), "could not request supervised restart");
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    anyhow::ensure!(
        process.0.try_wait()?.is_none(),
        "supervisor exited during SIGHUP restart"
    );
    assert_eq!(account_before, tokio::fs::read(&account_path).await?);
    let _ = openssl_probe(&first, &issuer_ca_path, public.port()).await?;
    let second = wait_for_bundle_changed(&bundle, &first).await?;
    assert_ne!(
        first, second,
        "renewal window did not trigger a second certificate"
    );
    std::fs::write(&acme_path, b"not-json")?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = openssl_probe(&second, &issuer_ca_path, public.port()).await?;
    drop(process);
    drop(fixture);
    Ok(())
}

async fn wait_for_bundle_changed(path: &std::path::Path, previous: &[u8]) -> Result<Vec<u8>> {
    for _ in 0..120 {
        if let Ok(bytes) = tokio::fs::read(path).await
            && bytes != previous
        {
            return Ok(bytes);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    anyhow::bail!("Hangang ACME runtime did not renew")
}

async fn openssl_probe(_bundle: &[u8], ca_path: &str, port: u16) -> Result<bool> {
    let result = tokio::process::Command::new("openssl")
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-servername",
            "acme-gateway.example.test",
            "-CAfile",
            ca_path,
            "-verify_return_error",
        ])
        .stdin(std::process::Stdio::null())
        .output()
        .await?;
    anyhow::ensure!(
        result.status.success(),
        "public TLS probe failed: {}\n{}",
        String::from_utf8_lossy(&result.stderr),
        String::from_utf8_lossy(&result.stdout)
    );
    Ok(true)
}
