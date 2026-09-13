//! One fail-closed, node-local GeoIP database slot and its bounded reload loop.
//!
//! A candidate slot starts empty. The caller starts `watch` only after the
//! snapshot containing that exact slot is active, and the publication closure
//! rechecks identity after file verification. No request performs file I/O.

use std::{
    path::{Component, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwapOption;
use serde::{Deserialize, Serialize};
use tokio::{sync::Semaphore, time::MissedTickBehavior};
use tokio_util::sync::CancellationToken;

use crate::geoip::{
    DEFAULT_MAX_AGE, DEFAULT_MAX_FILE_BYTES, Database, DatabaseStatus, GeoIpError, MAX_AGE,
    MAX_FILE_BYTES,
};

type Loader = dyn Fn(&Source, SystemTime) -> Result<Arc<Database>, GeoIpError> + Send + Sync;
type Clock = dyn Fn() -> SystemTime + Send + Sync;
type Freshness = dyn Fn(&Database, SystemTime) -> Result<(), GeoIpError> + Send + Sync;
pub type Published = dyn Fn(&Arc<Slot>) -> bool + Send + Sync;

fn max_file_default() -> u64 {
    DEFAULT_MAX_FILE_BYTES
}
fn max_age_default() -> u32 {
    (DEFAULT_MAX_AGE.as_secs() / 86_400) as u32
}
fn reload_default() -> u64 {
    30
}

/// Node-local file location and resource limits. Shared configuration means
/// each node must provision this path independently; the database bytes are
/// never moved through the shared configuration authority.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub file: PathBuf,
    #[serde(default = "max_file_default")]
    pub max_file_bytes: u64,
    #[serde(default = "max_age_default")]
    pub max_age_days: u32,
    #[serde(default = "reload_default")]
    pub reload_interval_seconds: u64,
}

impl Source {
    /// Structural validation only. All file I/O belongs to the loader.
    pub fn validate(&self) -> Result<(), GeoIpError> {
        if self.max_file_bytes == 0
            || self.max_file_bytes > MAX_FILE_BYTES
            || self.max_age_days == 0
            || u64::from(self.max_age_days) * 86_400 > MAX_AGE.as_secs()
            || !(1..=3_600).contains(&self.reload_interval_seconds)
        {
            return Err(GeoIpError::InvalidLimits);
        }
        if !self.file.is_absolute()
            || self.file.to_str().is_none()
            || self.file.as_os_str().as_encoded_bytes().contains(&0)
        {
            return Err(GeoIpError::InvalidPath);
        }
        let mut normalized = PathBuf::new();
        let mut normal_seen = false;
        for component in self.file.components() {
            match component {
                Component::RootDir => normalized.push(component),
                Component::Normal(_) => {
                    normalized.push(component);
                    normal_seen = true;
                }
                _ => return Err(GeoIpError::InvalidPath),
            }
        }
        if !normal_seen || normalized.as_os_str() != self.file.as_os_str() {
            return Err(GeoIpError::InvalidPath);
        }
        Ok(())
    }

    fn max_age(&self) -> Duration {
        Duration::from_secs(u64::from(self.max_age_days) * 86_400)
    }

    fn reload_interval(&self) -> Duration {
        Duration::from_secs(self.reload_interval_seconds)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotStatus {
    pub ready: bool,
    pub database: Option<DatabaseStatus>,
    pub error_code: Option<&'static str>,
    pub checked_at_unix_ms: Option<u64>,
}

#[derive(Default)]
struct Observation {
    error: Option<GeoIpError>,
    checked_at_unix_ms: Option<u64>,
}

pub struct Slot {
    source: Source,
    current: ArcSwapOption<Database>,
    observation: Mutex<Observation>,
    loader: Arc<Loader>,
    clock: Arc<Clock>,
    freshness: Arc<Freshness>,
    limiter: Arc<Semaphore>,
}

impl Slot {
    /// A new policy generation remains closed until a post-publication reload.
    pub fn new(source: Source) -> Result<Arc<Self>, GeoIpError> {
        Self::with_dependencies(
            source,
            Arc::new(|source, _| {
                Database::load(&source.file, source.max_file_bytes, source.max_age())
            }),
            Arc::new(SystemTime::now),
            Arc::new(|database, _| database.check_freshness()),
            blocking_limit(),
        )
    }

    fn with_dependencies(
        source: Source,
        loader: Arc<Loader>,
        clock: Arc<Clock>,
        freshness: Arc<Freshness>,
        limiter: Arc<Semaphore>,
    ) -> Result<Arc<Self>, GeoIpError> {
        source.validate()?;
        Ok(Arc::new(Self {
            source,
            current: ArcSwapOption::empty(),
            observation: Mutex::new(Observation::default()),
            loader,
            clock,
            freshness,
            limiter,
        }))
    }

    pub fn source(&self) -> &Source {
        &self.source
    }

    /// Returns no database after age expiry or clock reversal even between
    /// watcher ticks. The database independently checks freshness at lookup.
    pub fn load(&self) -> Option<Arc<Database>> {
        let database = self.current.load_full()?;
        (self.freshness)(&database, (self.clock)())
            .ok()
            .map(|()| database)
    }

    pub fn status(&self) -> SlotStatus {
        let loaded = self.current.load_full();
        let now = (self.clock)();
        let freshness = loaded
            .as_ref()
            .map(|database| (self.freshness)(database, now));
        let observation = self.observation.lock().unwrap();
        let ready = freshness.as_ref().is_some_and(Result::is_ok);
        SlotStatus {
            ready,
            database: loaded.map(|database| database.status().clone()),
            error_code: if ready {
                None
            } else {
                freshness
                    .and_then(Result::err)
                    .or(observation.error)
                    .map(GeoIpError::code)
            },
            checked_at_unix_ms: observation.checked_at_unix_ms,
        }
    }

    fn publish(&self, result: Result<Arc<Database>, GeoIpError>, now: SystemTime) {
        let checked_at_unix_ms = now
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| duration.as_millis().try_into().ok());
        match result {
            Ok(database) => {
                let existing = self.current.load_full();
                // Stable bytes preserve identity and any leases of the still
                // valid generation. Recovery after an invalidated slot always
                // publishes a fresh Arc, even when the restored bytes match.
                let keep_existing = existing.as_ref().is_some_and(|old| {
                    old.status().generation_sha256 == database.status().generation_sha256
                        && (self.freshness)(old, now).is_ok()
                });
                if !keep_existing {
                    self.current.store(Some(database));
                }
                let mut observation = self.observation.lock().unwrap();
                observation.error = None;
                observation.checked_at_unix_ms = checked_at_unix_ms;
            }
            Err(error) => {
                self.current.store(None);
                let mut observation = self.observation.lock().unwrap();
                observation.error = Some(error);
                observation.checked_at_unix_ms = checked_at_unix_ms;
            }
        }
    }

    /// One blocking load per process, including a cancelled watcher's worker.
    /// A busy loader skips this tick; an unready slot remains fail-closed.
    async fn refresh_once(
        self: &Arc<Self>,
        published: &Arc<Published>,
        cancel: &CancellationToken,
    ) {
        if cancel.is_cancelled() || !published(self) {
            return;
        }
        let Ok(permit) = self.limiter.clone().try_acquire_owned() else {
            return;
        };
        let source = self.source.clone();
        let loader = self.loader.clone();
        let now = (self.clock)();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            loader(&source, now)
        })
        .await
        .unwrap_or(Err(GeoIpError::Unavailable));
        // A cancellation drains the already-running blocking task but cannot
        // publish it; a retired candidate similarly cannot open admission.
        if cancel.is_cancelled() || !published(self) {
            return;
        }
        let result = result.and_then(|database| {
            (self.freshness)(&database, (self.clock)())?;
            Ok(database)
        });
        self.publish(result, (self.clock)());
    }
}

fn blocking_limit() -> Arc<Semaphore> {
    static LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();
    LIMIT.get_or_init(|| Arc::new(Semaphore::new(1))).clone()
}

/// The owner must cancel and join this single watcher before starting another
/// source. Cancellation waits for its sole in-flight blocking verification to
/// finish, preventing a detached verifier from publishing into a later epoch.
pub async fn watch(slot: Arc<Slot>, published: Arc<Published>, cancel: CancellationToken) {
    let mut tick = tokio::time::interval(slot.source.reload_interval());
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! { biased; _ = cancel.cancelled() => return, _ = tick.tick() => {} }
        if !published(&slot) {
            return;
        }
        slot.refresh_once(&published, &cancel).await;
        if cancel.is_cancelled() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    };

    const FAKE_DB: &[u8] = include_bytes!("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");

    fn source(path: PathBuf) -> Source {
        Source {
            file: path,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_age_days: 90,
            reload_interval_seconds: 1,
        }
    }

    fn fixture() -> (tempfile::TempDir, Source, Arc<AtomicU64>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("country.mmdb");
        fs::write(&path, FAKE_DB).unwrap();
        let reader = maxminddb::Reader::from_source(FAKE_DB.to_vec()).unwrap();
        let seconds = Arc::new(AtomicU64::new(reader.metadata().build_epoch + 60));
        (dir, source(path), seconds)
    }

    fn test_slot(source: Source, seconds: Arc<AtomicU64>) -> Arc<Slot> {
        let clock_seconds = seconds.clone();
        Slot::with_dependencies(
            source,
            Arc::new(|source, now| {
                Database::load_at(&source.file, source.max_file_bytes, source.max_age(), now)
            }),
            Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(clock_seconds.load(Ordering::SeqCst))
            }),
            Arc::new(|database, now| {
                let status = database.status();
                let seconds = now
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| GeoIpError::Clock)?
                    .as_secs();
                if seconds < status.build_epoch_unix_seconds {
                    Err(GeoIpError::FutureDatabase)
                } else if seconds > status.expires_at_unix_seconds {
                    Err(GeoIpError::StaleDatabase)
                } else {
                    Ok(())
                }
            }),
            Arc::new(Semaphore::new(1)),
        )
        .unwrap()
    }

    #[test]
    fn source_is_structural_and_bounded_without_file_io() {
        let (_dir, mut source, _) = fixture();
        assert!(source.validate().is_ok());
        source.file = PathBuf::from("relative.mmdb");
        assert_eq!(source.validate(), Err(GeoIpError::InvalidPath));
        source.file = PathBuf::from("/tmp/../country.mmdb");
        assert_eq!(source.validate(), Err(GeoIpError::InvalidPath));
        source.file = PathBuf::from("/tmp//country.mmdb");
        assert_eq!(source.validate(), Err(GeoIpError::InvalidPath));
        source.file = PathBuf::from("/tmp/country.mmdb");
        source.max_file_bytes = MAX_FILE_BYTES + 1;
        assert_eq!(source.validate(), Err(GeoIpError::InvalidLimits));
        source.max_file_bytes = MAX_FILE_BYTES;
        source.reload_interval_seconds = 0;
        assert_eq!(source.validate(), Err(GeoIpError::InvalidLimits));
    }

    #[tokio::test]
    async fn pending_invalid_recovery_and_stable_generation() {
        let (dir, source, seconds) = fixture();
        let slot = test_slot(source.clone(), seconds);
        let published: Arc<Published> = Arc::new(|_| true);
        let cancel = CancellationToken::new();
        assert!(slot.load().is_none());
        assert!(!slot.status().ready);
        slot.refresh_once(&published, &cancel).await;
        let first = slot.load().unwrap();
        assert!(slot.status().ready);
        slot.refresh_once(&published, &cancel).await;
        assert!(Arc::ptr_eq(&first, &slot.load().unwrap()));

        let replacement = dir.path().join("replacement.mmdb");
        fs::write(&replacement, b"invalid").unwrap();
        fs::rename(&replacement, &source.file).unwrap();
        slot.refresh_once(&published, &cancel).await;
        assert!(slot.load().is_none());
        assert_eq!(slot.status().error_code, Some("invalid_database"));

        fs::write(&replacement, FAKE_DB).unwrap();
        fs::rename(&replacement, &source.file).unwrap();
        slot.refresh_once(&published, &cancel).await;
        let recovered = slot.load().unwrap();
        assert!(!Arc::ptr_eq(&first, &recovered));
        assert_eq!(slot.status().error_code, None);
        assert_eq!(
            first.status().generation_sha256,
            recovered.status().generation_sha256
        );
    }

    #[tokio::test]
    async fn stale_clock_hides_loaded_generation_before_next_tick() {
        let (_dir, source, seconds) = fixture();
        let slot = test_slot(source, seconds.clone());
        let published: Arc<Published> = Arc::new(|_| true);
        slot.refresh_once(&published, &CancellationToken::new())
            .await;
        assert!(slot.load().is_some());
        let expiry = slot.status().database.unwrap().expires_at_unix_seconds;
        seconds.store(expiry + 1, Ordering::SeqCst);
        assert!(slot.load().is_none());
        assert!(!slot.status().ready);
        assert_eq!(slot.status().error_code, Some("stale_database"));
    }

    #[tokio::test]
    async fn unpublished_candidate_never_loads_or_publishes() {
        let (_dir, source, seconds) = fixture();
        let slot = test_slot(source, seconds);
        let published_flag = Arc::new(AtomicBool::new(false));
        let flag = published_flag.clone();
        let published: Arc<Published> = Arc::new(move |_| flag.load(Ordering::SeqCst));
        slot.refresh_once(&published, &CancellationToken::new())
            .await;
        assert!(slot.load().is_none());
        published_flag.store(true, Ordering::SeqCst);
        slot.refresh_once(&published, &CancellationToken::new())
            .await;
        assert!(slot.load().is_some());
    }

    #[tokio::test]
    async fn retired_candidate_and_cancellation_drain_without_publication() {
        let (_dir, source, seconds) = fixture();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let loader_entered = entered.clone();
        let loader_release = release.clone();
        let clock_seconds = seconds.clone();
        let slot = Slot::with_dependencies(
            source,
            Arc::new(move |source, now| {
                loader_entered.wait();
                loader_release.wait();
                Database::load_at(&source.file, source.max_file_bytes, source.max_age(), now)
            }),
            Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(clock_seconds.load(Ordering::SeqCst))
            }),
            Arc::new(|_, _| Ok(())),
            Arc::new(Semaphore::new(1)),
        )
        .unwrap();
        let published_flag = Arc::new(AtomicBool::new(true));
        let flag = published_flag.clone();
        let published: Arc<Published> = Arc::new(move |_| flag.load(Ordering::SeqCst));
        let cancel = CancellationToken::new();
        let task = tokio::spawn(watch(slot.clone(), published, cancel.clone()));
        tokio::task::spawn_blocking(move || entered.wait())
            .await
            .unwrap();
        published_flag.store(false, Ordering::SeqCst);
        cancel.cancel();
        assert!(!task.is_finished());
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert!(slot.load().is_none());
    }

    #[tokio::test]
    async fn processwide_loader_permit_skips_concurrent_refresh() {
        let (_dir, source, seconds) = fixture();
        let entered = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let calls = Arc::new(AtomicUsize::new(0));
        let loader_entered = entered.clone();
        let loader_release = release.clone();
        let loader_calls = calls.clone();
        let clock_seconds = seconds.clone();
        let limiter = Arc::new(Semaphore::new(1));
        let first = Slot::with_dependencies(
            source.clone(),
            Arc::new(move |source, now| {
                loader_calls.fetch_add(1, Ordering::SeqCst);
                loader_entered.wait();
                loader_release.wait();
                Database::load_at(&source.file, source.max_file_bytes, source.max_age(), now)
            }),
            Arc::new(move || {
                UNIX_EPOCH + Duration::from_secs(clock_seconds.load(Ordering::SeqCst))
            }),
            Arc::new(|_, _| Ok(())),
            limiter.clone(),
        )
        .unwrap();
        let second = Slot::with_dependencies(
            source,
            Arc::new(|source, now| {
                Database::load_at(&source.file, source.max_file_bytes, source.max_age(), now)
            }),
            Arc::new(move || UNIX_EPOCH + Duration::from_secs(seconds.load(Ordering::SeqCst))),
            Arc::new(|_, _| Ok(())),
            limiter,
        )
        .unwrap();
        let published: Arc<Published> = Arc::new(|_| true);
        let cancel = CancellationToken::new();
        let p = published.clone();
        let c = cancel.clone();
        let a = first.clone();
        let task = tokio::spawn(async move { a.refresh_once(&p, &c).await });
        tokio::task::spawn_blocking(move || entered.wait())
            .await
            .unwrap();
        second.refresh_once(&published, &cancel).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(second.load().is_none());
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        task.await.unwrap();
        second.refresh_once(&published, &cancel).await;
        assert!(second.load().is_some());
    }
}
