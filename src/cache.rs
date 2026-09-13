//! Bounded fill coalescing and demand-driven cache capture around the HTTP path.
use crate::{
    cache_store::{CacheConfig, CacheEntry, CacheStore, MAX_GENERATION},
    proxy::{Body, BodyError},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Response,
    body::{Body as _, Frame, SizeHint},
    header::{HeaderName, HeaderValue},
};
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Layout of the fence token returned by `CacheRuntime::epoch`: the
/// configuration generation in the high 32 bits and the local purge counter
/// in the low 32 bits. `cache_policy::key` namespaces keys by the generation
/// only, so entries survive a restart while a fleet-wide invalidation still
/// changes every key.
const LOCAL_EPOCH_BITS: u32 = 32;
const LOCAL_EPOCH_MASK: u64 = (1 << LOCAL_EPOCH_BITS) - 1;

/// The configuration generation carried by a fence token (see `CacheRuntime::epoch`).
pub const fn generation_of(epoch: u64) -> u64 {
    epoch >> LOCAL_EPOCH_BITS
}

const fn local_of(epoch: u64) -> u64 {
    epoch & LOCAL_EPOCH_MASK
}

const fn pack(generation: u64, local: u64) -> u64 {
    (generation << LOCAL_EPOCH_BITS) | (local & LOCAL_EPOCH_MASK)
}

pub struct CacheRuntime {
    /// Policy the runtime was built with. Its `generation` is the value at
    /// construction; the live value is `generation()`.
    pub config: CacheConfig,
    pub store: Arc<CacheStore>,
    /// Fence token, see `epoch()`.
    epoch: AtomicU64,
    fills: Arc<Semaphore>,
    fill_ids: AtomicU64,
    filling: Mutex<HashMap<String, FillRegistration>>,
    // Lookups (including disk-to-memory promotion) and publications hold the
    // read side; purge holds the write side across both storage tiers so a
    // read that started before the purge cannot repopulate memory afterwards.
    publication: Arc<tokio::sync::RwLock<()>>,
    maintenance: Arc<Semaphore>,
}
struct FillRegistration {
    id: u64,
    done: watch::Sender<bool>,
}
impl CacheRuntime {
    pub fn new(config: CacheConfig) -> Arc<Self> {
        Arc::new(Self {
            store: Arc::new(CacheStore::new(config.clone())),
            fills: Arc::new(Semaphore::new(config.max_fills)),
            epoch: AtomicU64::new(pack(config.generation.min(MAX_GENERATION), 0)),
            config,
            fill_ids: AtomicU64::new(0),
            filling: Mutex::new(HashMap::new()),
            publication: Arc::new(tokio::sync::RwLock::new(())),
            maintenance: Arc::new(Semaphore::new(1)),
        })
    }
    /// Fence token a request captures once and passes to both
    /// `cache_policy::key` and `lookup`. It changes on every local purge and
    /// on every adopted configuration generation, so a lookup or fill that
    /// started under an earlier token bypasses or skips publication. Keys
    /// derive their namespace from the generation half only (`generation_of`).
    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }
    /// The invalidation generation currently in effect.
    pub fn generation(&self) -> u64 {
        generation_of(self.epoch())
    }
    /// Takes a configuration generation into effect on an existing runtime.
    /// Any value other than the current one is adopted (a document that
    /// lowers or resets the generation still invalidates, so a later bump can
    /// never be skipped); the current value is a no-op. Returns whether the
    /// generation changed.
    ///
    /// The token is switched first, which fences every in-flight lookup and
    /// fill exactly like `purge` does, and moves new keys into the new
    /// namespace; both tiers are then reclaimed synchronously (a disk error
    /// only costs quota, never correctness, and is counted in the store's
    /// error statistic). This is safe to call from synchronous snapshot
    /// construction.
    pub fn adopt_generation(&self, generation: u64) -> bool {
        // Monotonic: a document that carries a lower generation (a rollback
        // of the whole document) must not reopen an older namespace, or a
        // fill started before the bump could publish pre-purge data behind a
        // fence that reads as current again.
        let generation = generation.min(MAX_GENERATION);
        let changed = self
            .epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                (generation_of(epoch) < generation).then_some(pack(generation, local_of(epoch)))
            })
            .is_ok();
        if changed {
            let _ = self.store.adopt_generation(generation);
        }
        changed
    }
    pub fn active_fills(&self) -> usize {
        self.filling.lock().expect("cache fill lock").len()
    }
    /// Reads the store under the publication read lock. Purge takes the write
    /// lock before bumping the epoch and clearing either tier, so the epoch
    /// check, the disk read and the memory promotion form one critical section
    /// with respect to purge. `None` means the epoch is stale or the store
    /// failed, i.e. the caller must bypass.
    async fn guarded_get(&self, key: &str, epoch: u64) -> Option<Option<CacheEntry>> {
        let _publication = self.publication.read().await;
        if epoch != self.epoch() {
            return None;
        }
        self.store.get_if(key, || epoch == self.epoch()).await.ok()
    }
    pub async fn lookup(self: &Arc<Self>, key: String, epoch: u64) -> Lookup {
        match self.guarded_get(&key, epoch).await {
            Some(Some(entry)) => return Lookup::Hit(entry),
            None => return Lookup::Bypass,
            Some(None) => {}
        }
        let wait = {
            let mut filling = self.filling.lock().expect("cache fill lock");
            if let Some(registration) = filling.get(&key) {
                Some(registration.done.subscribe())
            } else {
                let Ok(permit) = self.fills.clone().try_acquire_owned() else {
                    return Lookup::Bypass;
                };
                let (done, _) = watch::channel(false);
                let id = self.fill_ids.fetch_add(1, Ordering::Relaxed);
                filling.insert(key.clone(), FillRegistration { id, done });
                return Lookup::Fill(Fill {
                    cache: self.clone(),
                    key,
                    id,
                    epoch,
                    _permit: Some(permit),
                });
            }
        };
        if let Some(mut receiver) = wait {
            let _ = tokio::time::timeout(Duration::from_millis(250), receiver.changed()).await;
            if let Some(Some(entry)) = self.guarded_get(&key, epoch).await {
                return Lookup::Hit(entry);
            }
        }
        Lookup::Bypass
    }
    pub async fn purge(self: &Arc<Self>) -> anyhow::Result<()> {
        let permit = self
            .maintenance
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("cache maintenance is busy"))?;
        let cache = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _publication = cache.publication.clone().write_owned().await;
            // Advance the local half only; the generation is configuration.
            let _ = cache
                .epoch
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |epoch| {
                    Some(pack(generation_of(epoch), local_of(epoch).wrapping_add(1)))
                });
            cache.store.purge().await
        })
        .await?
    }
}
pub enum Lookup {
    Hit(CacheEntry),
    Fill(Fill),
    Bypass,
}
pub struct Fill {
    cache: Arc<CacheRuntime>,
    key: String,
    // Identifies this registration in `filling` so a fill that was abandoned
    // at its deadline can never deregister a newer fill for the same key.
    id: u64,
    epoch: u64,
    // For a streaming capture the permit is moved into a detached deadline guard
    // (see FillPermitGuard) so it is released at fill_timeout even when the
    // client stops reading and never polls the capture body. For non-streaming
    // paths the Fill drops the permit directly.
    _permit: Option<OwnedSemaphorePermit>,
}

// Enforces the fill deadline independently of whether the capture body is
// being polled: at the deadline it discards the captured bytes, deregisters
// the fill (which also wakes coalesced followers) and only then releases the
// admission permit. Dropping the guard (on normal completion or when the
// response body is dropped) releases the permit promptly instead.
struct FillPermitGuard {
    _cancel: tokio::sync::oneshot::Sender<()>,
}

impl FillPermitGuard {
    fn spawn(
        permit: OwnedSemaphorePermit,
        timeout: Duration,
        state: Arc<Mutex<CaptureState>>,
    ) -> Self {
        let (cancel, cancelled) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(timeout) => {
                    // Abandon before releasing capacity so the freed permit can
                    // never be observed while stale capture state still exists.
                    CaptureState::abandon(&state);
                }
                _ = cancelled => {}
            }
            drop(permit);
        });
        Self { _cancel: cancel }
    }
}
impl Drop for Fill {
    fn drop(&mut self) {
        let mut filling = self.cache.filling.lock().expect("cache fill lock");
        if filling
            .get(&self.key)
            .is_some_and(|registration| registration.id == self.id)
            && let Some(registration) = filling.remove(&self.key)
        {
            let _ = registration.done.send(true);
        }
    }
}
impl Fill {
    fn publish(self, entry: CacheEntry) {
        tokio::spawn(async move {
            let _publication = self.cache.publication.clone().read_owned().await;
            if self.epoch == self.cache.epoch() {
                let _ = self.cache.store.put(self.key.clone(), entry).await;
            }
            // Dropping the guard notifies followers only after publication finishes.
        });
    }
}

pub fn cached_response(entry: CacheEntry) -> Option<Response<Body>> {
    let age = entry
        .initial_age_seconds
        .saturating_add(now_ms().checked_sub(entry.stored_unix_ms)? / 1000);
    let mut response = Response::builder()
        .status(entry.status)
        .body(
            Full::new(entry.body)
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .ok()?;
    for (name, value) in entry.headers {
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "content-length" | "transfer-encoding" | "connection" | "trailer"
        ) {
            continue;
        }
        response.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).ok()?,
            HeaderValue::from_str(&value).ok()?,
        );
    }
    response
        .headers_mut()
        .insert("age", HeaderValue::from_str(&age.to_string()).ok()?);
    Some(response)
}

pub fn capture(
    response: Response<Body>,
    fill: Fill,
    ttl_ms: u64,
    initial_age_seconds: u64,
    stored_unix_ms: u64,
) -> Response<Body> {
    match prepare_capture(response, fill, ttl_ms, initial_age_seconds, stored_unix_ms) {
        Ok((parts, capture)) => Response::from_parts(parts, capture.boxed_unsync()),
        Err(passthrough) => *passthrough,
    }
}

/// Builds the streaming capture, or returns the response untouched when it is
/// not capturable (or was published directly because the body was empty).
fn prepare_capture(
    response: Response<Body>,
    fill: Fill,
    ttl_ms: u64,
    initial_age_seconds: u64,
    stored_unix_ms: u64,
) -> Result<(hyper::http::response::Parts, Capture), Box<Response<Body>>> {
    let (parts, body) = response.into_parts();
    let headers: Option<Vec<(String, String)>> = parts
        .headers
        .iter()
        .map(|(name, value)| Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned())))
        .collect();
    let Some(headers) = headers else {
        return Err(Box::new(Response::from_parts(parts, body)));
    };
    // Reserve metadata as well as body bytes, matching the storage weight contract.
    let overhead = headers
        .iter()
        .map(|(k, v)| k.len() + v.len() + std::mem::size_of::<(String, String)>())
        .sum::<usize>()
        .saturating_add(fill.key.len())
        .saturating_add(256);
    let Some(limit) = fill.cache.config.max_object_bytes.checked_sub(overhead) else {
        return Err(Box::new(Response::from_parts(parts, body)));
    };
    if body.size_hint().lower() > limit as u64 {
        return Err(Box::new(Response::from_parts(parts, body)));
    }
    let entry = CacheEntry {
        status: parts.status.as_u16(),
        headers,
        body: Bytes::new(),
        stored_unix_ms,
        ttl_ms,
        initial_age_seconds,
    };
    if body.is_end_stream() {
        fill.publish(entry);
        return Err(Box::new(Response::from_parts(parts, body)));
    }
    let timeout = Duration::from_millis(fill.cache.config.fill_timeout_ms);
    // Move the permit into a deadline guard so a client that stops reading (and
    // therefore never polls this body) cannot pin a fill slot, the capture
    // buffer or the per-key registration for longer than fill_timeout.
    let mut fill = fill;
    let permit = fill._permit.take();
    let state = Arc::new(Mutex::new(CaptureState {
        fill: Some(fill),
        entry: Some(entry),
        buffer: Vec::new(),
    }));
    let permit_guard = permit.map(|permit| FillPermitGuard::spawn(permit, timeout, state.clone()));
    Ok((
        parts,
        Capture {
            body,
            state,
            capturing: true,
            limit,
            ended: false,
            permit_guard,
        },
    ))
}
// Shared between the capture body and its deadline guard so the deadline can
// discard everything atomically even when the body is never polled again.
struct CaptureState {
    fill: Option<Fill>,
    entry: Option<CacheEntry>,
    buffer: Vec<u8>,
}
impl CaptureState {
    fn lock(state: &Mutex<CaptureState>) -> std::sync::MutexGuard<'_, CaptureState> {
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn abandon(state: &Mutex<CaptureState>) {
        let taken = {
            let mut state = Self::lock(state);
            (
                state.fill.take(),
                state.entry.take(),
                std::mem::take(&mut state.buffer),
            )
        };
        // Dropping the Fill outside the lock deregisters the key and wakes followers.
        drop(taken);
    }
}
struct Capture {
    body: Body,
    state: Arc<Mutex<CaptureState>>,
    // Local fast path: once the capture is known to be finished or abandoned
    // the shared state is never touched again.
    capturing: bool,
    limit: usize,
    ended: bool,
    permit_guard: Option<FillPermitGuard>,
}
impl Capture {
    fn finish(&mut self) {
        self.ended = true;
        if !self.capturing {
            return;
        }
        self.capturing = false;
        // Release the fill permit promptly on completion rather than waiting for
        // the guard's deadline.
        self.permit_guard = None;
        let taken = {
            let mut state = CaptureState::lock(&self.state);
            (
                state.fill.take(),
                state.entry.take(),
                std::mem::take(&mut state.buffer),
            )
        };
        if let (Some(fill), Some(mut entry), buffer) = taken {
            entry.body = Bytes::from(buffer);
            fill.publish(entry);
        }
    }
    fn abandon(&mut self) {
        if !self.capturing {
            return;
        }
        self.capturing = false;
        self.permit_guard = None;
        CaptureState::abandon(&self.state);
    }
    fn push(&mut self, data: &[u8]) {
        if !self.capturing {
            return;
        }
        let mut state = CaptureState::lock(&self.state);
        if state.fill.is_none() {
            // The deadline guard abandoned this capture while it was not polled.
            drop(state);
            self.abandon();
        } else if data.len() > self.limit.saturating_sub(state.buffer.len()) {
            drop(state);
            self.abandon();
        } else {
            state.buffer.extend_from_slice(data);
        }
    }
}
impl hyper::body::Body for Capture {
    type Data = Bytes;
    type Error = BodyError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        if self.ended {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if self.capturing {
                    if let Some(data) = frame.data_ref() {
                        self.push(data);
                    } else {
                        self.abandon();
                    }
                }
                if self.body.is_end_stream() {
                    self.finish();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.abandon();
                self.ended = true;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(None)
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.ended
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache_store::{DiskConfig, Eviction};
    fn entry() -> CacheEntry {
        CacheEntry {
            status: 200,
            headers: vec![],
            body: Bytes::from_static(b"ok"),
            stored_unix_ms: now_ms(),
            ttl_ms: 60000,
            initial_age_seconds: 0,
        }
    }
    #[tokio::test]
    async fn purge_prevents_inflight_fill_repopulation() {
        let cache = CacheRuntime::new(CacheConfig::default());
        let Lookup::Fill(fill) = cache.lookup("old".into(), 0).await else {
            panic!("fill")
        };
        cache.purge().await.unwrap();
        fill.publish(entry());
        for _ in 0..100 {
            if cache.active_fills() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(cache.store.get("old").await.unwrap().is_none());
        assert!(matches!(
            cache.lookup("old".into(), 0).await,
            Lookup::Bypass
        ));
    }
    #[tokio::test]
    async fn exhausted_fill_budget_and_cancel_release_capacity() {
        let cache = CacheRuntime::new(CacheConfig {
            max_fills: 1,
            ..Default::default()
        });
        let Lookup::Fill(fill) = cache.lookup("a".into(), 0).await else {
            panic!("fill")
        };
        assert!(matches!(cache.lookup("b".into(), 0).await, Lookup::Bypass));
        drop(fill);
        assert!(matches!(cache.lookup("b".into(), 0).await, Lookup::Fill(_)));
    }
    #[tokio::test]
    async fn unpolled_capture_releases_the_fill_permit_after_timeout() {
        // Regression for M-6: a client that stops reading never polls the
        // capture body, so the fill-timeout check in poll_frame cannot run. A
        // detached guard must still release the fill permit at the deadline so
        // other routes' fills are not starved.
        let cache = CacheRuntime::new(CacheConfig {
            max_fills: 1,
            fill_timeout_ms: 20,
            ..Default::default()
        });
        let Lookup::Fill(fill) = cache.lookup("a".into(), 0).await else {
            panic!("fill")
        };
        // The only permit is held, so another key bypasses for now.
        assert!(matches!(cache.lookup("b".into(), 0).await, Lookup::Bypass));
        // Wrap a body that never yields, and deliberately never poll it.
        let source = http_body_util::StreamBody::new(futures_util::stream::pending::<
            Result<Frame<Bytes>, BodyError>,
        >())
        .boxed_unsync();
        let _response = capture(Response::new(source), fill, 60000, 0, now_ms());
        // After the deadline the guard releases the permit even though the
        // capture body (still held in _response) is never polled, so another
        // key can acquire a fill again.
        let mut released = false;
        for _ in 0..200 {
            if let Lookup::Fill(_) = cache.lookup("b".into(), 0).await {
                released = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            released,
            "the fill permit must be released at the deadline even if the body is never polled"
        );
        // The stalled capture is still alive; its permit is what was freed.
        drop(_response);
    }

    fn channel_body() -> (
        tokio::sync::mpsc::UnboundedSender<Result<Frame<Bytes>, BodyError>>,
        Body,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let stream = futures_util::stream::unfold(receiver, |mut receiver| async move {
            receiver.recv().await.map(|frame| (frame, receiver))
        });
        (
            sender,
            http_body_util::StreamBody::new(stream).boxed_unsync(),
        )
    }

    #[tokio::test]
    async fn deadline_discards_unpolled_partial_capture_and_frees_the_key() {
        // A stalled HTTP/2 stream can stop polling the capture body after some
        // bytes were captured. The deadline must then discard the buffer,
        // deregister the key and release the permit even though the body is
        // never polled again, and a later poll must not publish stale bytes
        // or disturb a replacement fill for the same key.
        let cache = CacheRuntime::new(CacheConfig {
            max_fills: 1,
            fill_timeout_ms: 20,
            ..Default::default()
        });
        let Lookup::Fill(fill) = cache.lookup("a".into(), 0).await else {
            panic!("fill")
        };
        let (frames, source) = channel_body();
        let Ok((_parts, mut capture)) =
            prepare_capture(Response::new(source), fill, 60000, 0, now_ms())
        else {
            panic!("streaming body is captured")
        };
        let state = capture.state.clone();
        frames
            .send(Ok(Frame::data(Bytes::from_static(b"partial"))))
            .unwrap();
        let first = std::future::poll_fn(|cx| Pin::new(&mut capture).poll_frame(cx)).await;
        assert!(matches!(first, Some(Ok(_))));
        assert_eq!(CaptureState::lock(&state).buffer, b"partial");
        assert_eq!(cache.active_fills(), 1);
        // Nobody polls the body again; the deadline guard must clean up alone.
        let mut abandoned = false;
        for _ in 0..200 {
            if CaptureState::lock(&state).fill.is_none() {
                abandoned = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(abandoned, "deadline must abandon the unpolled capture");
        {
            let state = CaptureState::lock(&state);
            assert!(state.buffer.is_empty(), "captured bytes must be discarded");
            assert!(state.entry.is_none());
        }
        assert_eq!(cache.active_fills(), 0, "stale fill entry must be removed");
        // The permit is free and the key is fillable again.
        let Lookup::Fill(replacement) = cache.lookup("a".into(), 0).await else {
            panic!("key must be fillable again after the deadline")
        };
        assert_eq!(cache.active_fills(), 1);
        // The stalled body completes later: bytes are forwarded but never
        // published, and the replacement registration survives.
        frames
            .send(Ok(Frame::data(Bytes::from_static(b"-late"))))
            .unwrap();
        drop(frames);
        let forwarded = capture.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, "-late");
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        assert!(cache.store.get("a").await.unwrap().is_none());
        assert_eq!(cache.active_fills(), 1);
        drop(replacement);
        assert_eq!(cache.active_fills(), 0);
    }

    #[tokio::test]
    async fn stale_fill_handle_cannot_deregister_a_newer_fill() {
        let cache = CacheRuntime::new(CacheConfig::default());
        let Lookup::Fill(current) = cache.lookup("k".into(), 0).await else {
            panic!("fill")
        };
        let mut follower = cache
            .filling
            .lock()
            .unwrap()
            .get("k")
            .unwrap()
            .done
            .subscribe();
        // A handle whose registration was already replaced must be inert.
        let stale = Fill {
            cache: cache.clone(),
            key: "k".into(),
            id: current.id.wrapping_add(1),
            epoch: 0,
            _permit: None,
        };
        drop(stale);
        assert_eq!(cache.active_fills(), 1);
        assert!(!follower.has_changed().unwrap());
        drop(current);
        assert_eq!(cache.active_fills(), 0);
        // The real registration's drop wakes followers (value sent, then the
        // sender is dropped; either outcome resolves `changed`).
        assert!(
            tokio::time::timeout(Duration::from_millis(50), follower.changed())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn purge_waits_for_inflight_disk_lookup_and_never_repopulates_memory() {
        // Interleaving: a memory miss starts reading an existing disk entry,
        // purge runs, then the read finishes. Its promotion must not resurrect
        // the purged entry in memory.
        let directory = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            disk: Some(DiskConfig {
                directory: directory.path().join("cache"),
                max_bytes: 1024 * 1024,
                max_entries: 8,
                eviction: Eviction::Lru,
            }),
            ..CacheConfig::default()
        };
        config.validate().unwrap();
        // Seed the disk tier from a separate store so the runtime starts with
        // a cold memory tier and a warm disk tier.
        {
            let seed = CacheStore::new(config.clone());
            seed.put("key".into(), entry()).await.unwrap();
        }
        let cache = CacheRuntime::new(config);
        let (release, gate) = std::sync::mpsc::channel::<()>();
        let gate = std::sync::Mutex::new(gate);
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed = started.clone();
        *cache.store.disk_read_hook.lock().unwrap() = Some(Arc::new(move || {
            observed.store(true, Ordering::SeqCst);
            let _ = gate.lock().unwrap().recv();
        }));
        let lookup = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.lookup("key".into(), 0).await })
        };
        while !started.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        let purge = {
            let cache = cache.clone();
            tokio::spawn(async move { cache.purge().await })
        };
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(
            !purge.is_finished(),
            "purge must wait for the in-flight read"
        );
        release.send(()).unwrap();
        assert!(matches!(lookup.await.unwrap(), Lookup::Hit(_)));
        purge.await.unwrap().unwrap();
        *cache.store.disk_read_hook.lock().unwrap() = None;
        let stats = cache.store.stats().await;
        assert_eq!(
            stats.memory_entries, 0,
            "a purged disk entry must not be promoted back into memory"
        );
        assert!(cache.store.get("key").await.unwrap().is_none());
        assert!(matches!(
            cache.lookup("key".into(), cache.epoch()).await,
            Lookup::Fill(_)
        ));
    }

    #[tokio::test]
    async fn adopted_generation_fences_inflight_work_and_survives_local_purge() {
        let cache = CacheRuntime::new(CacheConfig::default());
        assert_eq!((cache.generation(), cache.epoch()), (0, 0));
        let before = cache.epoch();
        let Lookup::Fill(fill) = cache.lookup("k".into(), before).await else {
            panic!("fill")
        };
        cache.store.put("other".into(), entry()).await.unwrap();
        assert!(cache.adopt_generation(1));
        assert_eq!(cache.generation(), 1);
        assert_eq!(generation_of(cache.epoch()), 1);
        assert_eq!(local_of(cache.epoch()), 0, "adoption keeps the local half");
        assert_eq!(
            cache.store.stats().await.memory_entries,
            0,
            "adoption discards the memory tier"
        );
        // Work that started under the previous token is inert.
        fill.publish(entry());
        for _ in 0..100 {
            if cache.active_fills() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(cache.store.get("k").await.unwrap().is_none());
        assert!(matches!(
            cache.lookup("k".into(), before).await,
            Lookup::Bypass
        ));
        let current = cache.epoch();
        assert!(matches!(
            cache.lookup("k".into(), current).await,
            Lookup::Fill(_)
        ));
        // Re-adopting the current value is a no-op, and adoption is monotonic:
        // a lower value (a document rollback) never reopens an older namespace
        // behind which a pre-purge fill could publish; the authority preserves
        // the generation through rollbacks so a later bump is never skipped.
        assert!(!cache.adopt_generation(1));
        assert_eq!(cache.epoch(), current);
        assert!(!cache.adopt_generation(0));
        assert_eq!(cache.generation(), 1);
        assert!(cache.adopt_generation(2));
        // A local purge advances only the local half.
        cache.purge().await.unwrap();
        assert_eq!(cache.generation(), 2);
        assert_eq!(local_of(cache.epoch()), 1);
        assert_ne!(cache.epoch(), current);
    }

    #[test]
    fn fence_token_packs_generation_and_local_counter_without_carry() {
        assert_eq!(generation_of(pack(5, 9)), 5);
        assert_eq!(local_of(pack(5, 9)), 9);
        assert_eq!(pack(MAX_GENERATION, u32::MAX as u64), u64::MAX);
        // The local counter wraps inside its own bits.
        assert_eq!(
            pack(3, local_of(pack(3, u32::MAX as u64)).wrapping_add(1)),
            pack(3, 0)
        );
        let cache = CacheRuntime::new(CacheConfig {
            generation: 4,
            ..CacheConfig::default()
        });
        assert_eq!(cache.generation(), 4);
        assert_eq!(cache.epoch(), pack(4, 0));
        // Values beyond the bound cannot come from validated configuration;
        // they are clamped rather than allowed to spill into the local half.
        assert!(cache.adopt_generation(u64::MAX));
        assert_eq!(cache.epoch(), pack(MAX_GENERATION, 0));
    }

    #[tokio::test]
    async fn adopting_a_generation_reclaims_disk_rows_of_the_previous_one() {
        let directory = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            disk: Some(DiskConfig {
                directory: directory.path().join("cache"),
                max_bytes: 1024 * 1024,
                max_entries: 8,
                eviction: Eviction::Lru,
            }),
            ..CacheConfig::default()
        };
        config.validate().unwrap();
        let cache = CacheRuntime::new(config);
        cache.store.put("key".into(), entry()).await.unwrap();
        let stats = cache.store.stats().await;
        assert_eq!((stats.memory_entries, stats.disk_entries), (1, 1));
        assert!(cache.adopt_generation(1));
        let stats = cache.store.stats().await;
        assert_eq!((stats.memory_entries, stats.disk_entries), (0, 0));
        assert_eq!(stats.errors, 0);
        assert!(cache.store.get("key").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn capture_timeout_forwards_complete_body_without_storing() {
        let cache = CacheRuntime::new(CacheConfig {
            fill_timeout_ms: 1,
            ..Default::default()
        });
        let Lookup::Fill(fill) = cache.lookup("a".into(), 0).await else {
            panic!("fill")
        };
        let source = Full::new(Bytes::from_static(b"hello"))
            .map_err(|n| match n {})
            .boxed_unsync();
        let response = capture(Response::new(source), fill, 60000, 0, now_ms());
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "hello"
        );
        assert_eq!(cache.active_fills(), 0);
        assert!(cache.store.get("a").await.unwrap().is_none());
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    #[tokio::test]
    async fn trailers_and_errors_never_publish_partial_entries() {
        for fail in [false, true] {
            let cache = CacheRuntime::new(CacheConfig::default());
            let Lookup::Fill(fill) = cache.lookup("stream".into(), 0).await else {
                panic!("fill")
            };
            let mut trailers = hyper::HeaderMap::new();
            trailers.insert("x-checksum", HeaderValue::from_static("yes"));
            let last = if fail {
                Err::<Frame<Bytes>, BodyError>(BodyError::from_error(std::io::Error::other(
                    "truncated",
                )))
            } else {
                Ok(Frame::trailers(trailers))
            };
            let frames = vec![Ok(Frame::data(Bytes::from_static(b"part"))), last];
            let source =
                http_body_util::StreamBody::new(futures_util::stream::iter(frames)).boxed_unsync();
            let result = capture(Response::new(source), fill, 60000, 0, now_ms())
                .into_body()
                .collect()
                .await;
            if fail {
                assert!(result.is_err());
            } else {
                assert_eq!(result.unwrap().trailers().unwrap()["x-checksum"], "yes");
            }
            assert_eq!(cache.active_fills(), 0);
            assert!(cache.store.get("stream").await.unwrap().is_none());
        }
    }
}
