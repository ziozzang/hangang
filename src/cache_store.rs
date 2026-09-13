use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;

const MIB: usize = 1024 * 1024;
const MAX_OBJECT_BYTES: usize = 16 * MIB;
const MAX_ENTRIES: usize = 1_000_000;
const MIN_DISK_BYTES: u64 = 64 * 1024;
const SQLITE_PAGE_BYTES: u64 = 4096;
// Each rollback-journal page record is the original page plus its 4-byte page
// number and 4-byte checksum. Journal headers are sector-aligned; reserving at
// least 10% of the directory quota covers the header and alignment slack.
const SQLITE_JOURNAL_RECORD_OVERHEAD: u64 = 8;
const SQLITE_JOURNAL_MIN_HEADER_BYTES: u64 = SQLITE_PAGE_BYTES;
const MAX_DISK_BYTES: u64 = 2_147_483_647 * SQLITE_PAGE_BYTES;
// Smallest main-file page budget: the schema alone needs six root pages.
const MIN_DISK_PAGES: u64 = 7;
// Physical-capacity recovery: each round evicts at least this multiple of the
// object's logical size (the final round evicts everything) before retrying
// an insert that failed with SQLITE_FULL.
const FULL_RECOVERY_PRESSURE: [Option<u64>; 4] = [None, Some(2), Some(8), Some(u64::MAX)];
const CACHE_APPLICATION_ID: i64 = 0x4847_4348; // "HGCH"
const CACHE_USER_VERSION: i64 = 1;
const ENTRY_OVERHEAD: usize = 256;
/// Largest configuration generation. The generation shares the runtime fence
/// token with the local purge counter (see `crate::cache::CacheRuntime::epoch`),
/// so it is bounded to 32 bits.
pub const MAX_GENERATION: u64 = u32::MAX as u64;
/// Version of the key derivation in `crate::cache_policy::key`; part of the
/// disk policy fingerprint so rows keyed by an older derivation are discarded
/// on open instead of lingering unreachable until they expire.
const KEY_FORMAT: &[u8] = b"key-v2";

fn default_memory_bytes() -> usize {
    64 * MIB
}

fn default_memory_entries() -> usize {
    10_000
}

fn default_object_bytes() -> usize {
    MIB
}

fn default_max_fills() -> usize {
    32
}

fn default_fill_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Eviction {
    #[default]
    Lru,
    Fifo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryConfig {
    #[serde(default = "default_memory_bytes")]
    pub max_bytes: usize,
    #[serde(default = "default_memory_entries")]
    pub max_entries: usize,
    #[serde(default)]
    pub eviction: Eviction,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            max_bytes: default_memory_bytes(),
            max_entries: default_memory_entries(),
            eviction: Eviction::Lru,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskConfig {
    pub directory: PathBuf,
    /// Total physical disk budget for the cache directory. The main database
    /// file (`cache-v1.db`) is capped through SQLite's `max_page_count` at
    /// this budget minus rollback-journal headroom (see `disk_page_budget`),
    /// because the `-journal` sidecar temporarily holds the previous content
    /// of every page a transaction modifies and is not itself capped.
    pub max_bytes: u64,
    pub max_entries: usize,
    #[serde(default)]
    pub eviction: Eviction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    #[serde(
        default = "cache_enabled_default",
        skip_serializing_if = "cache_is_enabled"
    )]
    pub enabled: bool,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub disk: Option<DiskConfig>,
    #[serde(default = "default_object_bytes")]
    pub max_object_bytes: usize,
    #[serde(default = "default_max_fills")]
    pub max_fills: usize,
    #[serde(default = "default_fill_timeout_ms")]
    pub fill_timeout_ms: u64,
    /// Fleet-wide invalidation generation. It is part of the configuration
    /// document, so a change reaches every instance the way any configuration
    /// update does; every cache key is namespaced by it, and a runtime that
    /// observes a new value discards both storage tiers (see
    /// `crate::cache::CacheRuntime::adopt_generation`). Changing only this
    /// field keeps the existing runtime (`runtime_compatible`).
    #[serde(default)]
    pub generation: u64,
}

fn cache_enabled_default() -> bool {
    true
}
fn cache_is_enabled(value: &bool) -> bool {
    *value
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            memory: MemoryConfig::default(),
            disk: None,
            max_object_bytes: default_object_bytes(),
            max_fills: default_max_fills(),
            fill_timeout_ms: default_fill_timeout_ms(),
            generation: 0,
        }
    }
}

impl CacheConfig {
    /// Whether `other` can be served by a runtime built from `self`: every
    /// field equal except the invalidation `generation`, which the runtime
    /// adopts in place.
    pub fn runtime_compatible(&self, other: &CacheConfig) -> bool {
        let mut aligned = self.clone();
        aligned.generation = other.generation;
        aligned == *other
    }

    /// The same policy with the next invalidation generation (a fleet purge).
    /// Wraps within `MAX_GENERATION` so a purge is always a visible change.
    pub fn bumped(&self) -> Result<CacheConfig> {
        ensure!(
            self.generation < MAX_GENERATION,
            "cache generation exhausted; reset it in the configuration document"
        );
        Ok(CacheConfig {
            generation: self.generation + 1,
            ..self.clone()
        })
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=MAX_OBJECT_BYTES).contains(&self.max_object_bytes),
            "cache max_object_bytes must be 1..16777216"
        );
        ensure!(
            self.generation <= MAX_GENERATION,
            "cache generation must be 0..4294967295"
        );
        ensure!(
            (1..=1024).contains(&self.max_fills),
            "cache max_fills must be 1..1024"
        );
        ensure!(
            (1..=30_000).contains(&self.fill_timeout_ms),
            "cache fill_timeout_ms must be 1..30000"
        );
        ensure!(
            self.memory.max_bytes <= isize::MAX as usize,
            "memory cache capacity is too large"
        );
        ensure!(
            self.memory.max_entries <= MAX_ENTRIES,
            "memory cache max_entries must be <=1000000"
        );
        if self.memory.max_bytes > 0 {
            ensure!(
                self.memory.max_entries > 0,
                "enabled memory cache requires max_entries >0"
            );
        } else {
            ensure!(
                self.disk.is_some(),
                "cache must enable memory or disk storage"
            );
        }
        if let Some(disk) = &self.disk {
            ensure!(
                (MIN_DISK_BYTES..=MAX_DISK_BYTES).contains(&disk.max_bytes),
                "disk cache max_bytes must be 65536..8796093018112"
            );
            ensure!(
                (1..=MAX_ENTRIES).contains(&disk.max_entries),
                "disk cache max_entries must be 1..1000000"
            );
            validate_directory_path(&disk.directory)?;
            let pages = disk.max_bytes / SQLITE_PAGE_BYTES;
            ensure!(
                pages > 0 && pages <= i64::MAX as u64,
                "disk cache page limit is invalid"
            );
            let _ = disk
                .max_entries
                .checked_mul(std::mem::size_of::<usize>())
                .context("disk cache entry capacity overflow")?;
        }
        let _ = self
            .max_object_bytes
            .checked_add(ENTRY_OVERHEAD)
            .context("cache object capacity overflow")?;
        Ok(())
    }
}

fn validate_directory_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "disk cache directory must be absolute");
    ensure!(
        path != Path::new("/"),
        "disk cache directory must be dedicated"
    );
    ensure!(
        path.to_str().is_some(),
        "disk cache directory must be valid UTF-8"
    );
    ensure!(
        path.components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "disk cache directory must not contain '.' or '..'"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntry {
    pub body: Bytes,
    pub headers: Vec<(String, String)>,
    pub status: u16,
    pub stored_unix_ms: u64,
    pub ttl_ms: u64,
    pub initial_age_seconds: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CacheStats {
    pub memory_bytes: usize,
    pub memory_entries: usize,
    /// Size of the main database file.
    pub disk_bytes: u64,
    /// Size of the rollback-journal sidecar. Normally zero between
    /// transactions; non-zero after a crash until SQLite recovers it.
    pub disk_journal_bytes: u64,
    pub disk_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub errors: u64,
    /// Objects skipped because they cannot fit the physical disk budget even
    /// after eviction. Not an error: the response is still served.
    pub bypasses: u64,
}

pub struct CacheStore {
    config: CacheConfig,
    memory: Mutex<MemoryState>,
    disk: Option<Arc<DiskStore>>,
    counters: Arc<Counters>,
    /// Test-only gate run inside the blocking disk read, used to build
    /// deterministic interleavings between lookups and purge.
    #[cfg(test)]
    pub(crate) disk_read_hook: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

/// Main-file page budget after charging a worst-case rollback-journal record
/// for every main-file page and reserving 10% for journal headers/alignment.
/// The resulting main file is below half of the total directory quota.
pub fn disk_page_budget(disk: &DiskConfig, _max_object_bytes: usize) -> u64 {
    let header_headroom = (disk.max_bytes / 10).max(SQLITE_JOURNAL_MIN_HEADER_BYTES);
    let bytes_per_page = SQLITE_PAGE_BYTES
        .saturating_mul(2)
        .saturating_add(SQLITE_JOURNAL_RECORD_OVERHEAD);
    (disk.max_bytes.saturating_sub(header_headroom) / bytes_per_page).max(MIN_DISK_PAGES)
}

impl CacheStore {
    /// Creates an in-memory handle without touching the disk. Configuration is
    /// validated by `CacheConfig::validate` before installation and defensively
    /// revalidated by public operations.
    pub fn new(config: CacheConfig) -> Self {
        let counters = Arc::new(Counters::default());
        let disk = config.disk.as_ref().map(|disk| {
            Arc::new(DiskStore {
                config: disk.clone(),
                policy_id: policy_id(&config),
                generation: AtomicU64::new(config.generation),
                path: disk.directory.join("cache-v1.db"),
                max_pages: disk_page_budget(disk, config.max_object_bytes),
                unfittable: AtomicUsize::new(usize::MAX),
                state: Mutex::new(DiskState::default()),
                gate: Arc::new(Semaphore::new(1)),
                counters: counters.clone(),
            })
        });
        Self {
            config,
            memory: Mutex::new(MemoryState::default()),
            disk,
            counters,
            #[cfg(test)]
            disk_read_hook: Mutex::new(None),
        }
    }

    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    pub async fn get(&self, key: &str) -> Result<Option<CacheEntry>> {
        self.get_if(key, || true).await
    }

    /// Looks up `key`; a disk hit is promoted into memory only if `promote`
    /// still holds after the blocking read (callers use it to re-check the
    /// cache epoch so a purge that raced the read cannot be undone).
    pub async fn get_if(
        &self,
        key: &str,
        promote: impl Fn() -> bool + Send,
    ) -> Result<Option<CacheEntry>> {
        self.config.validate()?;
        if key.len() > self.config.max_object_bytes {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        let now = unix_time_ms();
        if self.config.memory.max_bytes > 0 {
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("memory cache lock poisoned"))?;
            match memory.get(key, now, self.config.memory.eviction) {
                MemoryLookup::Hit(entry) => {
                    self.counters.hits.fetch_add(1, Ordering::Relaxed);
                    return Ok(Some(entry));
                }
                MemoryLookup::Expired => {
                    self.counters.evictions.fetch_add(1, Ordering::Relaxed);
                }
                MemoryLookup::Miss => {}
            }
        }

        let Some(disk) = &self.disk else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let Ok(permit) = disk.gate.clone().try_acquire_owned() else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        let disk = disk.clone();
        let hash = key_hash(key);
        #[cfg(test)]
        let hook = self
            .disk_read_hook
            .lock()
            .ok()
            .and_then(|hook| hook.clone());
        let loaded = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            if let Some(hook) = hook {
                hook();
            }
            disk.get(&hash, now)
        })
        .await
        .context("disk cache task failed")?;
        let entry = match loaded {
            Ok(entry) => entry,
            Err(_) => {
                self.counters.errors.fetch_add(1, Ordering::Relaxed);
                None
            }
        };
        let Some(entry) = entry else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        };
        if !promote() {
            // The entry belongs to a generation that was purged while the read
            // was in flight: serve nothing rather than resurrect it.
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }
        if self.config.memory.max_bytes > 0 {
            let size = entry_size(key, &entry)?;
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("memory cache lock poisoned"))?;
            let evicted = memory.insert(key.to_owned(), entry.clone(), size, &self.config.memory);
            self.counters
                .evictions
                .fetch_add(evicted, Ordering::Relaxed);
        }
        self.counters.hits.fetch_add(1, Ordering::Relaxed);
        Ok(Some(entry))
    }

    pub async fn put(&self, key: String, entry: CacheEntry) -> Result<()> {
        self.config.validate()?;
        validate_entry(&entry)?;
        let size = entry_size(&key, &entry)?;
        if size > self.config.max_object_bytes || is_expired(&entry, unix_time_ms()) {
            return Ok(());
        }

        if self.config.memory.max_bytes > 0 {
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("memory cache lock poisoned"))?;
            let evicted = memory.insert(key.clone(), entry.clone(), size, &self.config.memory);
            self.counters
                .evictions
                .fetch_add(evicted, Ordering::Relaxed);
        }

        let Some(disk) = &self.disk else {
            return Ok(());
        };
        if size as u64 > disk.max_pages.saturating_mul(SQLITE_PAGE_BYTES) {
            self.counters.bypasses.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        let Ok(permit) = disk.gate.clone().try_acquire_owned() else {
            return Ok(());
        };
        let disk = disk.clone();
        let hash = key_hash(&key);
        let stored = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            disk.put(&hash, &entry, size)
        })
        .await
        .context("disk cache task failed")?;
        match stored {
            Ok(PutOutcome::Stored) => {}
            Ok(PutOutcome::Bypassed) => {
                self.counters.bypasses.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters.errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    pub async fn purge(&self) -> Result<()> {
        self.config.validate()?;
        {
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("memory cache lock poisoned"))?;
            memory.clear();
        }
        let Some(disk) = &self.disk else {
            return Ok(());
        };
        let permit = disk
            .gate
            .clone()
            .acquire_owned()
            .await
            .context("disk cache gate closed")?;
        let disk = disk.clone();
        let purged = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            disk.purge()
        })
        .await
        .context("disk cache task failed")?;
        if let Err(error) = purged {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        Ok(())
    }

    /// Discards both tiers for a new invalidation generation, synchronously.
    /// The caller has already fenced lookups and fills (keys now carry the new
    /// generation), so rows written under the previous one are unreachable;
    /// this reclaims them. Memory is cleared immediately. Disk rows are
    /// deleted when the database is already open; a store that has not opened
    /// yet reconciles the persisted generation on its first open instead, so
    /// the outcome is the same after a crash mid-adoption or a restart.
    pub fn adopt_generation(&self, generation: u64) -> Result<()> {
        self.config.validate()?;
        {
            let mut memory = self
                .memory
                .lock()
                .map_err(|_| anyhow::anyhow!("memory cache lock poisoned"))?;
            memory.clear();
        }
        let Some(disk) = &self.disk else {
            return Ok(());
        };
        disk.generation.store(generation, Ordering::Release);
        if let Err(error) = disk.purge_if_open() {
            self.counters.errors.fetch_add(1, Ordering::Relaxed);
            return Err(error);
        }
        Ok(())
    }

    pub async fn stats(&self) -> CacheStats {
        let (memory_bytes, memory_entries) = self
            .memory
            .lock()
            .map(|memory| (memory.bytes, memory.entries.len()))
            .unwrap_or_default();
        CacheStats {
            memory_bytes,
            memory_entries,
            disk_bytes: self.counters.disk_bytes.load(Ordering::Relaxed),
            disk_journal_bytes: self.counters.disk_journal_bytes.load(Ordering::Relaxed),
            disk_entries: self.counters.disk_entries.load(Ordering::Relaxed),
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            evictions: self.counters.evictions.load(Ordering::Relaxed),
            errors: self.counters.errors.load(Ordering::Relaxed),
            bypasses: self.counters.bypasses.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
struct Counters {
    disk_bytes: AtomicU64,
    disk_journal_bytes: AtomicU64,
    disk_entries: AtomicUsize,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    errors: AtomicU64,
    bypasses: AtomicU64,
}

#[derive(Default)]
struct MemoryState {
    entries: HashMap<String, MemoryItem>,
    order: BTreeSet<(u64, String)>,
    bytes: usize,
    sequence: u64,
}

struct MemoryItem {
    entry: CacheEntry,
    size: usize,
    inserted: u64,
    accessed: u64,
}

enum MemoryLookup {
    Hit(CacheEntry),
    Expired,
    Miss,
}

impl MemoryState {
    fn get(&mut self, key: &str, now: u64, eviction: Eviction) -> MemoryLookup {
        if self
            .entries
            .get(key)
            .is_some_and(|item| is_expired(&item.entry, now))
        {
            if let Some(item) = self.entries.remove(key) {
                self.bytes = self.bytes.saturating_sub(item.size);
                let sequence = match eviction {
                    Eviction::Lru => item.accessed,
                    Eviction::Fifo => item.inserted,
                };
                self.order.remove(&(sequence, key.to_owned()));
            }
            return MemoryLookup::Expired;
        }
        let Some(item) = self.entries.get_mut(key) else {
            return MemoryLookup::Miss;
        };
        if eviction == Eviction::Lru {
            self.order.remove(&(item.accessed, key.to_owned()));
            self.sequence = self.sequence.saturating_add(1);
            item.accessed = self.sequence;
            self.order.insert((item.accessed, key.to_owned()));
        }
        MemoryLookup::Hit(item.entry.clone())
    }

    fn insert(
        &mut self,
        key: String,
        entry: CacheEntry,
        size: usize,
        config: &MemoryConfig,
    ) -> u64 {
        if size > config.max_bytes || config.max_bytes == 0 || config.max_entries == 0 {
            return 0;
        }
        if let Some(previous) = self.entries.remove(&key) {
            self.bytes = self.bytes.saturating_sub(previous.size);
            let sequence = match config.eviction {
                Eviction::Lru => previous.accessed,
                Eviction::Fifo => previous.inserted,
            };
            self.order.remove(&(sequence, key.clone()));
        }
        self.sequence = self.sequence.saturating_add(1);
        self.bytes = self.bytes.saturating_add(size);
        self.order.insert((self.sequence, key.clone()));
        self.entries.insert(
            key,
            MemoryItem {
                entry,
                size,
                inserted: self.sequence,
                accessed: self.sequence,
            },
        );
        let mut evicted = 0;
        while self.bytes > config.max_bytes || self.entries.len() > config.max_entries {
            let Some((_, victim)) = self.order.pop_first() else {
                break;
            };
            if let Some(item) = self.entries.remove(&victim) {
                self.bytes = self.bytes.saturating_sub(item.size);
                evicted += 1;
            }
        }
        evicted
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.bytes = 0;
    }
}

struct DiskStore {
    config: DiskConfig,
    policy_id: String,
    /// Invalidation generation the rows must belong to. Persisted in
    /// `cache_meta` so an open after a crash or restart discards rows of any
    /// other generation.
    generation: AtomicU64,
    path: PathBuf,
    /// SQLite `max_page_count` for the main file (quota minus journal headroom).
    max_pages: u64,
    /// Smallest logical size observed to not fit an otherwise empty database;
    /// larger objects are bypassed without another eviction round.
    unfittable: AtomicUsize,
    state: Mutex<DiskState>,
    gate: Arc<Semaphore>,
    counters: Arc<Counters>,
}

pub(crate) enum PutOutcome {
    Stored,
    Bypassed,
}

struct InsertRow<'a> {
    hash: &'a [u8; 32],
    entry: &'a CacheEntry,
    headers: &'a [u8],
    size: usize,
    sequence: i64,
}

enum InsertFailure {
    /// SQLite reported SQLITE_FULL; `emptied` is true when no entries remained
    /// when the insert was attempted, i.e. the object cannot fit at all.
    Full {
        emptied: bool,
    },
    Other(anyhow::Error),
}

fn is_sqlite_full(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(failure, _)
            if failure.code == rusqlite::ErrorCode::DiskFull
    )
}

fn full_or_other(error: rusqlite::Error, emptied: bool) -> InsertFailure {
    if is_sqlite_full(&error) {
        InsertFailure::Full { emptied }
    } else {
        InsertFailure::Other(error.into())
    }
}

/// Lower bound on the pages a stored object occupies (overflow pages only, no
/// leaf or index share), used to skip eviction rounds for hopeless sizes.
fn estimated_pages(size: usize) -> u64 {
    (size as u64) / SQLITE_PAGE_BYTES.saturating_sub(4)
}

#[derive(Default)]
struct DiskState {
    connection: Option<Connection>,
    _lock_file: Option<File>,
    sequence: i64,
}

impl DiskStore {
    fn get(&self, hash: &[u8; 32], now: u64) -> Result<Option<CacheEntry>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("disk cache lock poisoned"))?;
        self.ensure_open(&mut state)?;
        let row = state
            .connection
            .as_mut()
            .expect("disk cache connection initialized")
            .query_row(
                "SELECT status, headers, body, stored_at_ms, ttl_ms, initial_age_seconds, expires_at_ms FROM entries WHERE key_hash=?1",
                params![hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .context("read disk cache entry")?;
        let Some((status, headers, body, stored_at, ttl, initial_age, expires_at)) = row else {
            return Ok(None);
        };
        if expires_at <= now_as_i64(now) {
            state
                .connection
                .as_mut()
                .expect("disk cache connection initialized")
                .execute(
                    "DELETE FROM entries WHERE key_hash=?1",
                    params![hash.as_slice()],
                )?;
            self.counters.evictions.fetch_add(1, Ordering::Relaxed);
            self.refresh_disk_stats(
                state
                    .connection
                    .as_ref()
                    .expect("disk cache connection initialized"),
            )?;
            return Ok(None);
        }
        if self.config.eviction == Eviction::Lru {
            state.sequence = state.sequence.saturating_add(1);
            let sequence = state.sequence;
            state
                .connection
                .as_mut()
                .expect("disk cache connection initialized")
                .execute(
                    "UPDATE entries SET access_sequence=?1 WHERE key_hash=?2",
                    params![sequence, hash.as_slice()],
                )?;
        }
        let entry = decode_disk_entry(status, headers, body, stored_at, ttl, initial_age)?;
        Ok(Some(entry))
    }

    fn put(&self, hash: &[u8; 32], entry: &CacheEntry, size: usize) -> Result<PutOutcome> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("disk cache lock poisoned"))?;
        self.ensure_open(&mut state)?;
        if size >= self.unfittable.load(Ordering::Relaxed)
            || estimated_pages(size) > self.max_pages.saturating_sub(1)
        {
            return Ok(PutOutcome::Bypassed);
        }
        let sequence = state.sequence.saturating_add(1);
        state.sequence = sequence;
        let connection = state
            .connection
            .as_mut()
            .expect("disk cache connection initialized");
        let headers = serde_json::to_vec(&entry.headers).context("encode cached headers")?;
        let row = InsertRow {
            hash,
            entry,
            headers: &headers,
            size,
            sequence,
        };
        // Logical limits are enforced on every round. When SQLite reports
        // SQLITE_FULL (the page cap was reached before the logical limits,
        // because structure and page allocation also consume space) the
        // transaction is rolled back and retried with additional eviction
        // pressure; the last round evicts everything. An object that does not
        // fit an emptied database is bypassed, and the failed size is
        // remembered so later objects of that size skip the rounds entirely.
        for pressure in FULL_RECOVERY_PRESSURE {
            match self.insert_round(connection, &row, pressure) {
                Ok(evicted) => {
                    self.counters
                        .evictions
                        .fetch_add(evicted, Ordering::Relaxed);
                    self.refresh_disk_stats(connection)?;
                    return Ok(PutOutcome::Stored);
                }
                Err(InsertFailure::Full { emptied: true }) => {
                    self.unfittable.fetch_min(size, Ordering::Relaxed);
                    self.refresh_disk_stats(connection)?;
                    return Ok(PutOutcome::Bypassed);
                }
                Err(InsertFailure::Full { emptied: false }) => continue,
                Err(InsertFailure::Other(error)) => return Err(error),
            }
        }
        bail!("disk cache remained physically full after eviction")
    }

    /// One transactional attempt: expire, evict for the logical limits, evict
    /// `pressure` times the object's size for physical recovery, then insert.
    /// Any SQLITE_FULL rolls the round back (drop of the transaction), so a
    /// failed attempt never loses entries.
    fn insert_round(
        &self,
        connection: &mut Connection,
        row: &InsertRow<'_>,
        pressure: Option<u64>,
    ) -> std::result::Result<u64, InsertFailure> {
        let size = row.size as i64;
        let transaction = connection
            .transaction()
            .map_err(|error| full_or_other(error, false))?;
        let expired = transaction
            .execute(
                "DELETE FROM entries WHERE expires_at_ms<=?1",
                params![now_as_i64(unix_time_ms())],
            )
            .map_err(|error| full_or_other(error, false))? as u64;
        transaction
            .execute(
                "DELETE FROM entries WHERE key_hash=?1",
                params![row.hash.as_slice()],
            )
            .map_err(|error| full_or_other(error, false))?;
        let (mut count, mut bytes): (i64, i64) = transaction
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(object_size),0) FROM entries",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|error| full_or_other(error, false))?;
        let mut evicted = expired;
        let mut freed: u64 = 0;
        let target = pressure.map(|multiple| (row.size as u64).saturating_mul(multiple));
        loop {
            let logical = count.saturating_add(1) > self.config.max_entries as i64
                || bytes.saturating_add(size) > self.config.max_bytes as i64;
            let physical = target.is_some_and(|target| freed < target);
            if !logical && !physical {
                break;
            }
            let victim = disk_victim_size(&transaction, self.config.eviction)
                .map_err(InsertFailure::Other)?;
            let Some(victim_size) = victim else {
                break;
            };
            delete_disk_victim(&transaction, self.config.eviction).map_err(|error| {
                match error.downcast::<rusqlite::Error>() {
                    Ok(error) => full_or_other(error, false),
                    Err(error) => InsertFailure::Other(error),
                }
            })?;
            count = count.saturating_sub(1);
            bytes = bytes.saturating_sub(victim_size);
            freed = freed.saturating_add(victim_size.max(0) as u64);
            evicted = evicted.saturating_add(1);
        }
        let emptied = count == 0;
        let expires = expires_at_ms(row.entry);
        transaction.execute(
            "INSERT INTO entries (key_hash,status,headers,body,stored_at_ms,ttl_ms,initial_age_seconds,expires_at_ms,object_size,insert_sequence,access_sequence) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)",
            params![
                row.hash.as_slice(),
                i64::from(row.entry.status),
                row.headers,
                row.entry.body.as_ref(),
                u64_as_i64(row.entry.stored_unix_ms),
                u64_as_i64(row.entry.ttl_ms),
                u64_as_i64(row.entry.initial_age_seconds),
                u64_as_i64(expires),
                size,
                row.sequence,
            ],
        ).map_err(|error| full_or_other(error, emptied))?;
        transaction
            .commit()
            .map_err(|error| full_or_other(error, emptied))?;
        Ok(evicted)
    }

    fn purge(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("disk cache lock poisoned"))?;
        self.ensure_open(&mut state)?;
        self.clear_rows(&mut state)
    }

    /// Like `purge`, but never opens a cold database: its rows are reconciled
    /// against the current generation when it opens.
    fn purge_if_open(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("disk cache lock poisoned"))?;
        if state.connection.is_none() {
            return Ok(());
        }
        self.clear_rows(&mut state)
    }

    /// Deletes every row and records the current generation in one
    /// transaction, so a crash leaves either the old rows with the old
    /// generation (discarded on the next open) or the empty, current state.
    fn clear_rows(&self, state: &mut DiskState) -> Result<()> {
        let generation = self.generation.load(Ordering::Acquire);
        let connection = state
            .connection
            .as_mut()
            .expect("disk cache connection initialized");
        let transaction = connection.transaction()?;
        transaction.execute("DELETE FROM entries", [])?;
        record_generation(&transaction, generation)?;
        transaction.commit()?;
        self.refresh_disk_stats(connection)?;
        Ok(())
    }

    fn ensure_open(&self, state: &mut DiskState) -> Result<()> {
        if state.connection.is_some() {
            return Ok(());
        }
        prepare_directory(&self.config.directory)?;
        let existed = self.path.exists();
        if existed {
            ensure!(
                !fs::symlink_metadata(&self.path)?.file_type().is_symlink(),
                "disk cache file must not be a symlink"
            );
        }
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&self.path)
            .context("open disk cache lock file")?;
        ensure!(
            lock_file.metadata()?.is_file(),
            "disk cache path is not a regular file"
        );
        let file_mode = lock_file.metadata()?.permissions().mode();
        if existed {
            ensure!(
                file_mode & 0o077 == 0 && file_mode & 0o600 == 0o600,
                "existing disk cache file permissions must be 0600"
            );
        } else {
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;
        }
        let lock_result =
            unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if lock_result != 0 {
            bail!("disk cache is already owned by another store");
        }
        let was_empty = lock_file.metadata()?.len() == 0;
        if !was_empty {
            let budget = self.max_pages.saturating_mul(SQLITE_PAGE_BYTES);
            ensure!(
                lock_file.metadata()?.len() <= budget,
                "existing disk cache database predates the journal-safe quota and is too large; remove cache-v1.db to rebuild it"
            );
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let mut connection =
            Connection::open_with_flags(&self.path, flags).context("open disk cache database")?;
        connection.busy_timeout(std::time::Duration::ZERO)?;
        if was_empty {
            connection.execute_batch(&format!(
                "PRAGMA page_size={SQLITE_PAGE_BYTES}; PRAGMA application_id={CACHE_APPLICATION_ID}; PRAGMA user_version={CACHE_USER_VERSION};"
            ))?;
        } else {
            let application_id: i64 =
                connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
            ensure!(
                application_id == CACHE_APPLICATION_ID,
                "refusing unrelated disk cache database"
            );
            let user_version: i64 =
                connection.query_row("PRAGMA user_version", [], |row| row.get(0))?;
            ensure!(
                user_version == CACHE_USER_VERSION,
                "unsupported disk cache schema version"
            );
        }
        connection.execute_batch(
            // A rollback journal (TRUNCATE) keeps the on-disk cache recoverable
            // if the process is killed mid-transaction (e.g. an OOM kill),
            // unlike MEMORY journaling which is documented to very likely
            // corrupt the file on such a crash. TRUNCATE avoids WAL's persistent
            // -wal/-shm sidecars, keeping the single-file layout the permission
            // checks enforce. synchronous=NORMAL is the crash-safe (not
            // power-loss-durable) setting appropriate for a rebuildable cache.
            "PRAGMA journal_mode=TRUNCATE;
             PRAGMA synchronous=NORMAL;
             PRAGMA foreign_keys=ON;
             CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS entries (
               key_hash BLOB PRIMARY KEY,
               status INTEGER NOT NULL,
               headers BLOB NOT NULL,
               body BLOB NOT NULL,
               stored_at_ms INTEGER NOT NULL,
               ttl_ms INTEGER NOT NULL,
               initial_age_seconds INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               object_size INTEGER NOT NULL,
               insert_sequence INTEGER NOT NULL,
               access_sequence INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS entries_expiry ON entries(expires_at_ms);
             CREATE INDEX IF NOT EXISTS entries_fifo ON entries(insert_sequence);
             CREATE INDEX IF NOT EXISTS entries_lru ON entries(access_sequence);",
        )?;
        let page_size: i64 = connection.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        ensure!(
            page_size == SQLITE_PAGE_BYTES as i64,
            "disk cache page size is not 4096 bytes"
        );
        let previous_policy: Option<String> = connection
            .query_row(
                "SELECT value FROM cache_meta WHERE key='policy_id'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if previous_policy
            .as_deref()
            .is_some_and(|value| value != self.policy_id)
        {
            connection.execute("DELETE FROM entries", [])?;
            connection.execute("DELETE FROM cache_meta", [])?;
            connection.execute_batch("VACUUM")?;
        }
        connection.execute(
            "INSERT INTO cache_meta(key,value) VALUES('policy_id',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![self.policy_id],
        )?;
        // Rows of another invalidation generation are unreachable (keys are
        // namespaced by it) and would otherwise hold quota until they expire:
        // a purge that did not complete before a crash, or a generation
        // adopted while this database was still cold.
        let generation = self.generation.load(Ordering::Acquire);
        let stored_generation: Option<String> = connection
            .query_row(
                "SELECT value FROM cache_meta WHERE key='generation'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if stored_generation.as_deref() != Some(generation.to_string().as_str()) {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM entries", [])?;
            record_generation(&transaction, generation)?;
            transaction.commit()?;
        }
        connection.execute(
            "DELETE FROM entries WHERE expires_at_ms<=?1",
            params![now_as_i64(unix_time_ms())],
        )?;
        let budget = self.max_pages.saturating_mul(SQLITE_PAGE_BYTES);
        ensure!(
            fs::metadata(&self.path)?.len() <= budget,
            "disk cache database cannot fit the configured physical quota"
        );
        let max_pages = self.max_pages;
        connection.execute_batch(&format!("PRAGMA max_page_count={max_pages};"))?;
        let enforced_pages: i64 =
            connection.query_row("PRAGMA max_page_count", [], |row| row.get(0))?;
        ensure!(
            enforced_pages as u64 <= max_pages,
            "SQLite refused the disk cache page quota"
        );
        state.sequence = connection.query_row(
            "SELECT COALESCE(MAX(MAX(insert_sequence,access_sequence)),0) FROM entries",
            [],
            |row| row.get(0),
        )?;
        self.refresh_disk_stats(&connection)?;
        state.connection = Some(connection);
        state._lock_file = Some(lock_file);
        Ok(())
    }

    fn refresh_disk_stats(&self, connection: &Connection) -> Result<()> {
        let entries: i64 =
            connection.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
        let bytes = fs::metadata(&self.path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let journal = fs::metadata(journal_path(&self.path))
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        self.counters
            .disk_entries
            .store(entries.max(0) as usize, Ordering::Relaxed);
        self.counters.disk_bytes.store(bytes, Ordering::Relaxed);
        self.counters
            .disk_journal_bytes
            .store(journal, Ordering::Relaxed);
        Ok(())
    }
}

fn record_generation(connection: &Connection, generation: u64) -> Result<()> {
    connection.execute(
        "INSERT INTO cache_meta(key,value) VALUES('generation',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![generation.to_string()],
    )?;
    Ok(())
}

/// SQLite's rollback-journal sidecar for the main database file.
fn journal_path(database: &Path) -> PathBuf {
    let mut name = database.as_os_str().to_owned();
    name.push("-journal");
    PathBuf::from(name)
}

fn prepare_directory(directory: &Path) -> Result<()> {
    validate_directory_path(directory)?;
    let existed = directory.exists();
    let mut current = PathBuf::new();
    for component in directory.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "disk cache directory path must not contain symlinks"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::create_dir_all(directory).context("create disk cache directory")?;
    ensure!(
        fs::metadata(directory)?.is_dir(),
        "disk cache path is not a directory"
    );
    if existed {
        let mode = fs::metadata(directory)?.permissions().mode();
        ensure!(
            mode & 0o077 == 0 && mode & 0o700 == 0o700,
            "existing disk cache directory permissions must be 0700"
        );
    } else {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn disk_victim_size(connection: &Connection, eviction: Eviction) -> Result<Option<i64>> {
    let order = match eviction {
        Eviction::Lru => "access_sequence",
        Eviction::Fifo => "insert_sequence",
    };
    connection
        .query_row(
            &format!("SELECT object_size FROM entries ORDER BY {order}, key_hash LIMIT 1"),
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
}

fn delete_disk_victim(connection: &Connection, eviction: Eviction) -> Result<()> {
    let order = match eviction {
        Eviction::Lru => "access_sequence",
        Eviction::Fifo => "insert_sequence",
    };
    connection.execute(
        &format!("DELETE FROM entries WHERE key_hash=(SELECT key_hash FROM entries ORDER BY {order}, key_hash LIMIT 1)"),
        [],
    )?;
    Ok(())
}

fn decode_disk_entry(
    status: i64,
    headers: Vec<u8>,
    body: Vec<u8>,
    stored_at: i64,
    ttl: i64,
    initial_age: i64,
) -> Result<CacheEntry> {
    ensure!((100..=599).contains(&status), "invalid cached HTTP status");
    ensure!(
        stored_at >= 0 && ttl >= 0 && initial_age >= 0,
        "invalid cached time value"
    );
    let headers = serde_json::from_slice(&headers).context("decode cached headers")?;
    let entry = CacheEntry {
        body: Bytes::from(body),
        headers,
        status: status as u16,
        stored_unix_ms: stored_at as u64,
        ttl_ms: ttl as u64,
        initial_age_seconds: initial_age as u64,
    };
    validate_entry(&entry)?;
    Ok(entry)
}

fn validate_entry(entry: &CacheEntry) -> Result<()> {
    ensure!(
        (100..=599).contains(&entry.status),
        "invalid cached HTTP status"
    );
    ensure!(entry.headers.len() <= 1024, "too many cached HTTP headers");
    ensure!(
        entry.stored_unix_ms <= i64::MAX as u64
            && entry.ttl_ms <= i64::MAX as u64
            && entry.initial_age_seconds <= i64::MAX as u64,
        "cached time value is too large"
    );
    for (name, value) in &entry.headers {
        ensure!(
            !name.is_empty()
                && name.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
                }),
            "invalid cached HTTP header name"
        );
        ensure!(
            value
                .bytes()
                .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f)),
            "invalid cached HTTP header value"
        );
    }
    Ok(())
}

fn entry_size(key: &str, entry: &CacheEntry) -> Result<usize> {
    let mut size = ENTRY_OVERHEAD
        .checked_add(key.len())
        .and_then(|size| size.checked_add(entry.body.len()))
        .context("cache entry size overflow")?;
    for (name, value) in &entry.headers {
        size = size
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .and_then(|size| size.checked_add(std::mem::size_of::<(String, String)>()))
            .context("cache entry size overflow")?;
    }
    Ok(size)
}

fn is_expired(entry: &CacheEntry, now: u64) -> bool {
    now >= expires_at_ms(entry)
}

fn expires_at_ms(entry: &CacheEntry) -> u64 {
    entry.stored_unix_ms.saturating_add(entry.ttl_ms)
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn now_as_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn u64_as_i64(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

fn key_hash(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

/// Fingerprint of the storage policy a database was written under. The
/// invalidation `generation` is deliberately not part of it: it is reconciled
/// separately on open (a generation change never needs a `VACUUM`).
fn policy_id(config: &CacheConfig) -> String {
    let mut hasher = Sha256::new();
    hasher.update(KEY_FORMAT);
    hasher.update([0]);
    hasher.update(config.memory.max_bytes.to_le_bytes());
    hasher.update(config.memory.max_entries.to_le_bytes());
    hasher.update([eviction_id(config.memory.eviction)]);
    hasher.update(config.max_object_bytes.to_le_bytes());
    hasher.update(config.max_fills.to_le_bytes());
    hasher.update(config.fill_timeout_ms.to_le_bytes());
    if let Some(disk) = &config.disk {
        hasher.update([1]);
        hasher.update(disk.directory.to_string_lossy().as_bytes());
        hasher.update([0]);
        hasher.update(disk.max_bytes.to_le_bytes());
        hasher.update(disk.max_entries.to_le_bytes());
        hasher.update([eviction_id(disk.eviction)]);
    } else {
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn eviction_id(eviction: Eviction) -> u8 {
    match eviction {
        Eviction::Lru => 0,
        Eviction::Fifo => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(body: &'static [u8]) -> CacheEntry {
        CacheEntry {
            body: Bytes::from_static(body),
            headers: vec![("content-type".into(), "text/plain".into())],
            status: 200,
            stored_unix_ms: unix_time_ms(),
            ttl_ms: 60_000,
            initial_age_seconds: 0,
        }
    }

    fn memory_config(eviction: Eviction, max_bytes: usize) -> CacheConfig {
        CacheConfig {
            memory: MemoryConfig {
                max_bytes,
                max_entries: 2,
                eviction,
            },
            ..CacheConfig::default()
        }
    }

    fn disk_config(directory: PathBuf, max_entries: usize) -> CacheConfig {
        CacheConfig {
            memory: MemoryConfig {
                max_bytes: 0,
                max_entries: 0,
                eviction: Eviction::Lru,
            },
            disk: Some(DiskConfig {
                directory,
                max_bytes: 256 * 1024,
                max_entries,
                eviction: Eviction::Lru,
            }),
            ..CacheConfig::default()
        }
    }

    #[test]
    fn serde_defaults_are_strict_and_validation_is_bounded() {
        let config: CacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config, CacheConfig::default());
        assert!(serde_json::from_str::<CacheConfig>(r#"{"unknown":true}"#).is_err());
        assert!(serde_json::from_str::<CacheConfig>(r#"{"memory":{"extra":1}}"#).is_err());

        let invalid = CacheConfig {
            max_object_bytes: 0,
            ..CacheConfig::default()
        };
        assert!(invalid.validate().is_err());
        let mut disabled = CacheConfig::default();
        disabled.memory.max_bytes = 0;
        assert!(disabled.validate().is_err());
        let relative = disk_config(PathBuf::from("relative"), 1);
        assert!(relative.validate().is_err());
    }

    #[tokio::test]
    async fn memory_lru_and_fifo_have_distinct_access_semantics() {
        for (policy, evicted) in [(Eviction::Lru, "b"), (Eviction::Fifo, "a")] {
            let sample = entry(b"value");
            let size = entry_size("a", &sample).unwrap();
            let store = CacheStore::new(memory_config(policy, size * 2));
            store.put("a".into(), sample.clone()).await.unwrap();
            store.put("b".into(), sample.clone()).await.unwrap();
            assert!(store.get("a").await.unwrap().is_some());
            store.put("c".into(), sample.clone()).await.unwrap();
            assert!(
                store.get(evicted).await.unwrap().is_none(),
                "policy={policy:?}"
            );
            assert!(store.get("c").await.unwrap().is_some());
            let stats = store.stats().await;
            assert_eq!(stats.memory_entries, 2);
            assert!(stats.evictions >= 1);
        }
    }

    #[tokio::test]
    async fn expiry_age_object_limit_and_purge_are_enforced() {
        let store = CacheStore::new(CacheConfig::default());
        let mut stale = entry(b"stale");
        stale.ttl_ms = 1_000;
        stale.stored_unix_ms = unix_time_ms().saturating_sub(1_001);
        store.put("stale".into(), stale).await.unwrap();
        assert!(store.get("stale").await.unwrap().is_none());

        let config = CacheConfig {
            max_object_bytes: 400,
            ..CacheConfig::default()
        };
        let store = CacheStore::new(config);
        store
            .put("large".into(), entry(&[b'x'; 256]))
            .await
            .unwrap();
        assert!(store.get("large").await.unwrap().is_none());
        store.put("small".into(), entry(b"x")).await.unwrap();
        assert!(store.get("small").await.unwrap().is_some());
        store.purge().await.unwrap();
        assert!(store.get("small").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disk_persists_for_the_same_policy_and_purges() {
        let directory = tempfile::tempdir().unwrap();
        let config = disk_config(directory.path().join("cache"), 8);
        config.validate().unwrap();
        {
            let store = CacheStore::new(config.clone());
            store.put("key".into(), entry(b"persistent")).await.unwrap();
            assert_eq!(
                store.get("key").await.unwrap().unwrap().body,
                b"persistent"[..]
            );
            let stats = store.stats().await;
            assert_eq!(stats.disk_entries, 1);
            assert!(stats.disk_bytes <= config.disk.as_ref().unwrap().max_bytes);
        }
        let store = CacheStore::new(config);
        assert_eq!(
            store.get("key").await.unwrap().unwrap().body,
            b"persistent"[..]
        );
        store.purge().await.unwrap();
        assert!(store.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn changed_disk_policy_starts_empty_and_entry_limit_evicts() {
        let directory = tempfile::tempdir().unwrap();
        let first = disk_config(directory.path().join("cache"), 2);
        {
            let store = CacheStore::new(first.clone());
            store.put("old".into(), entry(b"old")).await.unwrap();
        }
        let mut changed = first;
        changed.disk.as_mut().unwrap().eviction = Eviction::Fifo;
        let store = CacheStore::new(changed);
        assert!(store.get("old").await.unwrap().is_none());
        store.put("a".into(), entry(b"a")).await.unwrap();
        store.put("b".into(), entry(b"b")).await.unwrap();
        store.put("c".into(), entry(b"c")).await.unwrap();
        assert!(store.get("a").await.unwrap().is_none());
        assert!(store.get("c").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn unrelated_database_is_never_overwritten() {
        let directory = tempfile::tempdir().unwrap();
        let cache_directory = directory.path().join("cache");
        fs::create_dir(&cache_directory).unwrap();
        fs::set_permissions(&cache_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = cache_directory.join("cache-v1.db");
        fs::write(&path, b"unrelated-data").unwrap();
        let store = CacheStore::new(disk_config(cache_directory, 8));
        store.put("key".into(), entry(b"value")).await.unwrap();
        assert!(store.get("key").await.unwrap().is_none());
        assert_eq!(fs::read(path).unwrap(), b"unrelated-data");
        assert!(store.stats().await.errors >= 1);
    }

    #[tokio::test]
    async fn purge_waits_for_inflight_disk_work_and_removes_persistent_entries() {
        let directory = tempfile::tempdir().unwrap();
        let cache_directory = directory.path().join("cache");
        let store = Arc::new(CacheStore::new(disk_config(cache_directory.clone(), 8)));
        store.put("key".into(), entry(b"value")).await.unwrap();
        let disk = store.disk.as_ref().unwrap();
        let permit = disk.gate.clone().acquire_owned().await.unwrap();
        let task = {
            let store = store.clone();
            tokio::spawn(async move { store.purge().await })
        };
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        drop(permit);
        task.await.unwrap().unwrap();
        assert!(store.get("key").await.unwrap().is_none());
        drop(store);

        let reopened = CacheStore::new(disk_config(cache_directory, 8));
        assert!(reopened.get("key").await.unwrap().is_none());
    }

    fn sized_entry(len: usize) -> CacheEntry {
        CacheEntry {
            body: Bytes::from(vec![b'z'; len]),
            headers: vec![("content-type".into(), "text/plain".into())],
            status: 200,
            stored_unix_ms: unix_time_ms(),
            ttl_ms: 60_000,
            initial_age_seconds: 0,
        }
    }

    fn physical_config(directory: PathBuf, max_bytes: u64, max_object_bytes: usize) -> CacheConfig {
        CacheConfig {
            memory: MemoryConfig {
                max_bytes: 0,
                max_entries: 0,
                eviction: Eviction::Lru,
            },
            disk: Some(DiskConfig {
                directory,
                max_bytes,
                max_entries: 1000,
                eviction: Eviction::Fifo,
            }),
            max_object_bytes,
            ..CacheConfig::default()
        }
    }

    #[test]
    fn journal_headroom_is_reserved_inside_the_disk_quota() {
        let disk = DiskConfig {
            directory: PathBuf::from("/cache"),
            max_bytes: 1024 * 1024,
            max_entries: 8,
            eviction: Eviction::Lru,
        };
        // Charge both the main page and a complete rollback-journal record for
        // every page, plus fixed/alignment headroom. This assertion failed with
        // the former main-only 90% page budget.
        let pages = disk_page_budget(&disk, 4096);
        let header_headroom = (disk.max_bytes / 10).max(SQLITE_JOURNAL_MIN_HEADER_BYTES);
        let journal_bytes = pages * (SQLITE_PAGE_BYTES + SQLITE_JOURNAL_RECORD_OVERHEAD);
        assert!(pages * SQLITE_PAGE_BYTES + journal_bytes + header_headroom <= disk.max_bytes);
        assert!(pages * SQLITE_PAGE_BYTES < disk.max_bytes / 2);
        // Object size does not alter the proof: a transaction that modifies
        // every page is the larger journal case.
        assert_eq!(pages, disk_page_budget(&disk, 16 * MIB));
        // The smallest supported quota still has one page beyond the six-page
        // schema while satisfying the same physical bound.
        let tiny = DiskConfig {
            max_bytes: MIN_DISK_BYTES,
            ..disk
        };
        assert_eq!(disk_page_budget(&tiny, 16 * MIB), MIN_DISK_PAGES);
        let tiny_headroom = (tiny.max_bytes / 10).max(SQLITE_JOURNAL_MIN_HEADER_BYTES);
        assert!(
            MIN_DISK_PAGES * (2 * SQLITE_PAGE_BYTES + SQLITE_JOURNAL_RECORD_OVERHEAD)
                + tiny_headroom
                <= tiny.max_bytes
        );
    }

    #[tokio::test]
    async fn physical_page_exhaustion_evicts_and_retries_instead_of_failing() {
        // The logical byte limit admits many objects of 12,000 bytes, but the
        // journal-safe main-file page budget physically holds only a few. Inserts past that point
        // hit SQLITE_FULL and must recover by evicting, not fail forever.
        let directory = tempfile::tempdir().unwrap();
        let config = physical_config(directory.path().join("cache"), 256 * 1024, 16 * 1024);
        config.validate().unwrap();
        let store = CacheStore::new(config.clone());
        for index in 0..40 {
            store
                .put(format!("key-{index}"), sized_entry(12_000))
                .await
                .unwrap();
        }
        let stats = store.stats().await;
        assert_eq!(stats.errors, 0, "{stats:?}");
        assert_eq!(stats.bypasses, 0, "{stats:?}");
        assert!(stats.evictions > 0, "{stats:?}");
        assert!(
            stats.disk_entries < 40 && stats.disk_entries > 1,
            "{stats:?}"
        );
        let budget = disk_page_budget(config.disk.as_ref().unwrap(), config.max_object_bytes)
            * SQLITE_PAGE_BYTES;
        assert!(stats.disk_bytes <= budget, "{stats:?}");
        assert!(
            stats.disk_bytes + stats.disk_journal_bytes <= config.disk.as_ref().unwrap().max_bytes,
            "{stats:?}"
        );
        assert!(store.get("key-39").await.unwrap().is_some());
        assert!(store.get("key-0").await.unwrap().is_none());
        // The store keeps working at the physical boundary.
        store
            .put("after".into(), sized_entry(12_000))
            .await
            .unwrap();
        assert!(store.get("after").await.unwrap().is_some());
        assert_eq!(store.stats().await.errors, 0);
    }

    #[tokio::test]
    async fn oversized_legacy_database_is_rejected_before_destructive_migration() {
        let directory = tempfile::tempdir().unwrap();
        let config = physical_config(directory.path().join("cache"), MIB as u64, 16 * 1024);
        let store = CacheStore::new(config.clone());
        store.put("small".into(), entry(b"x")).await.unwrap();
        drop(store);

        // Simulate the previous release's roughly 90%-of-quota main-file cap
        // while preserving this exact policy fingerprint.
        let path = config.disk.as_ref().unwrap().directory.join("cache-v1.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("PRAGMA max_page_count=230;")
            .unwrap();
        connection
            .execute(
                "INSERT INTO entries(key_hash,status,headers,body,stored_at_ms,ttl_ms,initial_age_seconds,expires_at_ms,object_size,insert_sequence,access_sequence)
                 VALUES(zeroblob(32),200,'[]',zeroblob(?1),0,1,0,9223372036854775807,?1,2,2)",
                params![700_000_i64],
            )
            .unwrap();
        drop(connection);

        let before = fs::metadata(&path).unwrap().len();
        let safe_main_budget =
            disk_page_budget(config.disk.as_ref().unwrap(), config.max_object_bytes)
                * SQLITE_PAGE_BYTES;
        assert!(before > safe_main_budget);
        assert!(before <= config.disk.as_ref().unwrap().max_bytes);

        let reopened = CacheStore::new(config);
        assert!(reopened.get("small").await.unwrap().is_none());
        assert_eq!(reopened.stats().await.errors, 1);
        assert_eq!(fs::metadata(&path).unwrap().len(), before);
        let connection = Connection::open(path).unwrap();
        let rows: i64 = connection
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 2, "rejection must preserve the rebuildable old file");
    }

    #[tokio::test]
    async fn objects_that_cannot_fit_the_physical_quota_are_bypassed_not_errors() {
        // 64 KiB quota with a 32 KiB object cap leaves the minimum 7-page main
        // file: six schema pages plus one page of data.
        let directory = tempfile::tempdir().unwrap();
        let config = physical_config(directory.path().join("cache"), MIN_DISK_BYTES, 32 * 1024);
        config.validate().unwrap();
        let store = CacheStore::new(config);
        store.put("small".into(), entry(b"x")).await.unwrap();
        assert!(store.get("small").await.unwrap().is_some());
        // Needs three overflow pages: passes the cheap estimate, exhausts the
        // pages even after evicting everything, and is bypassed. The failed
        // round is rolled back, so the small entry survives.
        store.put("big".into(), sized_entry(13_000)).await.unwrap();
        let stats = store.stats().await;
        assert_eq!(stats.errors, 0, "{stats:?}");
        assert_eq!(stats.bypasses, 1, "{stats:?}");
        assert!(store.get("big").await.unwrap().is_none());
        assert!(store.get("small").await.unwrap().is_some());
        // A repeat of the same size short-circuits via the learned threshold,
        // and an obviously oversized object is bypassed by the estimate.
        store
            .put("big-again".into(), sized_entry(13_000))
            .await
            .unwrap();
        store.put("huge".into(), sized_entry(31_000)).await.unwrap();
        let stats = store.stats().await;
        assert_eq!(stats.errors, 0, "{stats:?}");
        assert_eq!(stats.bypasses, 3, "{stats:?}");
        assert!(store.get("small").await.unwrap().is_some());
    }

    #[test]
    fn generation_is_optional_bounded_and_excluded_from_runtime_compatibility() {
        let config: CacheConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(config.generation, 0);
        let parsed: CacheConfig = serde_json::from_str(r#"{"generation":7}"#).unwrap();
        assert_eq!(parsed.generation, 7);
        assert!(parsed.validate().is_ok());
        assert!(config.runtime_compatible(&parsed));
        assert!(parsed.runtime_compatible(&config));
        let mut other_policy = parsed.clone();
        other_policy.max_fills += 1;
        assert!(!parsed.runtime_compatible(&other_policy));
        assert_eq!(config.bumped().unwrap().generation, 1);
        assert_eq!(config.bumped().unwrap().bumped().unwrap().generation, 2);
        assert!(config.bumped().unwrap() != config);
        assert!(config.runtime_compatible(&config.bumped().unwrap()));
        let last = CacheConfig {
            generation: MAX_GENERATION,
            ..CacheConfig::default()
        };
        assert!(last.validate().is_ok());
        assert!(
            last.bumped().is_err(),
            "exhaustion is an error, never a wrap that reopens an old namespace"
        );
        let too_large = CacheConfig {
            generation: MAX_GENERATION + 1,
            ..CacheConfig::default()
        };
        assert!(too_large.validate().is_err());
        assert!(serde_json::from_str::<CacheConfig>(r#"{"generation":-1}"#).is_err());
    }

    #[tokio::test]
    async fn rows_of_another_generation_are_discarded_on_open() {
        // A crash between the token switch and the disk delete, or a
        // generation adopted while the database was still cold, leaves rows
        // of an older generation behind. They are unreachable through the
        // namespaced keys and must not hold quota until they expire.
        let directory = tempfile::tempdir().unwrap();
        let first = disk_config(directory.path().join("cache"), 8);
        {
            let store = CacheStore::new(first.clone());
            store.put("key".into(), entry(b"old")).await.unwrap();
            assert_eq!(store.stats().await.disk_entries, 1);
        }
        let second = CacheConfig {
            generation: 1,
            ..first.clone()
        };
        {
            let store = CacheStore::new(second.clone());
            assert!(store.get("key").await.unwrap().is_none());
            assert_eq!(store.stats().await.disk_entries, 0);
            store.put("key".into(), entry(b"new")).await.unwrap();
        }
        // The same generation survives a restart (a local purge does not
        // change it), so persistence is kept.
        {
            let store = CacheStore::new(second);
            assert_eq!(store.get("key").await.unwrap().unwrap().body, b"new"[..]);
            assert_eq!(store.stats().await.errors, 0);
        }
        // Rolling the configuration back to an older generation also starts
        // empty: the rows on disk belong to a namespace nothing can address.
        let store = CacheStore::new(first);
        assert!(store.get("key").await.unwrap().is_none());
        assert_eq!(store.stats().await.disk_entries, 0);
    }

    #[tokio::test]
    async fn adopting_a_generation_clears_open_tiers_and_persists_it() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = disk_config(directory.path().join("cache"), 8);
        config.memory = MemoryConfig::default();
        config.validate().unwrap();
        let store = CacheStore::new(config.clone());
        store.put("key".into(), entry(b"value")).await.unwrap();
        let stats = store.stats().await;
        assert_eq!((stats.memory_entries, stats.disk_entries), (1, 1));
        store.adopt_generation(3).unwrap();
        let stats = store.stats().await;
        assert_eq!((stats.memory_entries, stats.disk_entries), (0, 0));
        assert_eq!(stats.errors, 0);
        assert!(store.get("key").await.unwrap().is_none());
        store.put("key".into(), entry(b"third")).await.unwrap();
        drop(store);
        // The adopted generation was recorded, so a restart under the same
        // configuration keeps the rows written after adoption ...
        let reopened = CacheStore::new(CacheConfig {
            generation: 3,
            ..config.clone()
        });
        assert_eq!(
            reopened.get("key").await.unwrap().unwrap().body,
            b"third"[..]
        );
        drop(reopened);
        // ... while the configuration the store was built with does not.
        let stale = CacheStore::new(config);
        assert!(stale.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn adopting_a_generation_on_a_cold_disk_store_defers_to_open() {
        let directory = tempfile::tempdir().unwrap();
        let config = disk_config(directory.path().join("cache"), 8);
        {
            let store = CacheStore::new(config.clone());
            store.put("key".into(), entry(b"old")).await.unwrap();
        }
        let store = CacheStore::new(config);
        // Adoption before the first disk access must not open the database
        // (nothing to reclaim yet) and must still win on open.
        store.adopt_generation(5).unwrap();
        assert!(
            store
                .disk
                .as_ref()
                .unwrap()
                .state
                .lock()
                .unwrap()
                .connection
                .is_none()
        );
        assert!(store.get("key").await.unwrap().is_none());
        assert_eq!(store.stats().await.disk_entries, 0);
        assert_eq!(store.stats().await.errors, 0);
    }

    #[tokio::test]
    async fn second_owner_of_a_disk_directory_degrades_until_the_first_releases() {
        // Snapshot replacement with changed cache settings builds a new store
        // while in-flight requests may still hold the previous one, which owns
        // the database lock. The newcomer must fail open (memory only, error
        // counted) and take over once the previous owner is dropped.
        let directory = tempfile::tempdir().unwrap();
        let config = disk_config(directory.path().join("cache"), 8);
        let first = CacheStore::new(config.clone());
        first.put("key".into(), entry(b"first")).await.unwrap();
        let second = CacheStore::new(config);
        second.put("key".into(), entry(b"second")).await.unwrap();
        assert!(second.get("key").await.unwrap().is_none());
        let contended = second.stats().await.errors;
        assert!(
            contended >= 1,
            "the second owner must not open the database"
        );
        assert_eq!(first.get("key").await.unwrap().unwrap().body, b"first"[..]);
        drop(first);
        second.put("key".into(), entry(b"second")).await.unwrap();
        assert_eq!(
            second.get("key").await.unwrap().unwrap().body,
            b"second"[..]
        );
        assert_eq!(second.stats().await.errors, contended);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlinked_directory_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;
        let outer = tempfile::tempdir().unwrap();
        let target = tempfile::tempdir().unwrap();
        let link = outer.path().join("linked");
        symlink(target.path(), &link).unwrap();
        let store = CacheStore::new(disk_config(link, 8));
        store.put("key".into(), entry(b"value")).await.unwrap();
        assert!(!target.path().join("cache-v1.db").exists());
        assert!(store.stats().await.errors >= 1);
    }
}
