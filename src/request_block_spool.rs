//! Anonymous, quota-owned multipart staging and demand-driven replay.
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    future::Future,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileExt, MetadataExt},
        },
    },
    path::{Component, Path},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
fn total_timeout() -> u64 {
    3600000
}
fn idle_timeout() -> u64 {
    60000
}
fn field_limit() -> usize {
    65536
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub directory: String,
    pub max_body_bytes: u64,
    #[serde(default = "total_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "idle_timeout")]
    pub idle_timeout_ms: u64,
    #[serde(default = "field_limit")]
    pub max_field_bytes: usize,
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            cfg!(target_os = "linux"),
            "multipart disk inspection is supported only on Linux"
        );
        ensure!(
            self.directory.len() <= 2048
                && Path::new(&self.directory).is_absolute()
                && !self.directory.split('/').any(|s| matches!(s, "." | "..")),
            "multipart spool directory must be bounded absolute path without traversal"
        );
        ensure!(
            (1..=64 * 1024 * 1024 * 1024).contains(&self.max_body_bytes),
            "multipart spool body limit must be1..64GiB"
        );
        ensure!(
            (1..=7200000).contains(&self.timeout_ms)
                && (1..=120000).contains(&self.idle_timeout_ms)
                && (1..=65536).contains(&self.max_field_bytes),
            "invalid multipart spool limits"
        );
        Ok(())
    }
}
#[derive(Debug)]
pub(crate) struct Directory(File);
impl Directory {
    pub(crate) fn open(path: &str) -> Result<Arc<Self>> {
        let mut directory = File::open("/")?;
        for component in Path::new(path).components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    let name = std::ffi::CString::new(name.as_bytes())?;
                    // Each lookup is relative to the pinned parent and refuses symlinks.
                    let fd = unsafe {
                        libc::openat(
                            directory.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    ensure!(fd >= 0, "multipart spool directory cannot be opened safely");
                    directory = unsafe { File::from_raw_fd(fd) };
                }
                _ => anyhow::bail!("invalid multipart spool directory"),
            }
        }
        let metadata = directory.metadata()?;
        ensure!(
            metadata.is_dir()
                && metadata.mode() & 0o777 == 0o700
                && metadata.uid() == unsafe { libc::geteuid() },
            "multipart spool directory must be owned private0700"
        );
        Ok(Arc::new(Self(directory)))
    }
    #[cfg(not(target_os = "linux"))]
    fn anonymous(&self) -> Result<File, u16> {
        // Never fall back to a named temporary file on another platform.
        Err(503)
    }
    #[cfg(target_os = "linux")]
    fn anonymous(&self) -> Result<File, u16> {
        let directory = self.0.metadata().map_err(|_| 503u16)?;
        if directory.mode() & 0o777 != 0o700 || directory.uid() != unsafe { libc::geteuid() } {
            return Err(503);
        }
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err(503);
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| 503u16)?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err(503);
        }
        Ok(file)
    }
}
#[derive(Debug)]
pub(crate) struct Pool {
    slots: Arc<tokio::sync::Semaphore>,
    used: AtomicU64,
    quota: u64,
}
impl Pool {
    pub(crate) fn new() -> Self {
        Self::with_limits(2, 128 * 1024 * 1024 * 1024)
    }
    fn with_limits(slots: usize, quota: u64) -> Self {
        Self {
            slots: Arc::new(tokio::sync::Semaphore::new(slots)),
            used: AtomicU64::new(0),
            quota,
        }
    }
    fn reserve(&self, amount: u64) -> Result<(), u16> {
        let mut current = self.used.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(amount)
                .filter(|n| *n <= self.quota)
                .ok_or(503u16)?;
            match self.used.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }
}
struct Lease {
    file: Option<File>,
    pool: Arc<Pool>,
    charged: AtomicU64,
    _slot: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for Lease {
    fn drop(&mut self) {
        drop(self.file.take());
        self.pool
            .used
            .fetch_sub(self.charged.load(Ordering::Acquire), Ordering::AcqRel);
    }
}
impl Lease {
    fn grow(&self, size: u64) -> Result<(), u16> {
        let previous = self.charged.load(Ordering::Acquire);
        if size > previous {
            self.pool.reserve(size - previous)?;
            self.charged.store(size, Ordering::Release);
        }
        Ok(())
    }
}
struct OwnedChunk {
    bytes: Vec<u8>,
    _lease: Arc<Lease>,
}
impl AsRef<[u8]> for OwnedChunk {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone)]
pub(crate) struct Staged {
    lease: Arc<Lease>,
    pub size: u64,
}
impl Staged {
    pub(crate) fn body(&self) -> crate::proxy::Body {
        Replay {
            staged: self.clone(),
            offset: 0,
            task: None,
        }
        .boxed_unsync()
    }
}
#[derive(Clone)]
pub(crate) struct WeakStaged {
    lease: std::sync::Weak<Lease>,
    size: u64,
}
impl WeakStaged {
    pub(crate) fn upgrade(&self) -> Option<Staged> {
        self.lease.upgrade().map(|lease| Staged {
            lease,
            size: self.size,
        })
    }
}
impl Staged {
    pub(crate) fn downgrade(&self) -> WeakStaged {
        WeakStaged {
            lease: Arc::downgrade(&self.lease),
            size: self.size,
        }
    }
}
struct Replay {
    staged: Staged,
    offset: u64,
    task: Option<tokio::task::JoinHandle<Result<Bytes, u16>>>,
}
impl Body for Replay {
    type Data = Bytes;
    type Error = crate::proxy::BodyError;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if self.offset >= self.staged.size {
            return Poll::Ready(None);
        }
        if self.task.is_none() {
            let lease = self.staged.lease.clone();
            let offset = self.offset;
            let size = (self.staged.size - offset).min(65536) as usize;
            self.task = Some(tokio::task::spawn_blocking(move || {
                let mut bytes = vec![0; size];
                lease
                    .file
                    .as_ref()
                    .expect("owned spool file")
                    .read_exact_at(&mut bytes, offset)
                    .map_err(|_| 503u16)?;
                Ok(Bytes::from_owner(OwnedChunk {
                    bytes,
                    _lease: lease,
                }))
            }));
        }
        let result = match Pin::new(self.task.as_mut().unwrap()).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => result,
        };
        self.task = None;
        match result {
            Ok(Ok(bytes)) => {
                self.offset += bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            _ => {
                self.offset = self.staged.size;
                Poll::Ready(Some(Err(crate::proxy::BodyError::from_error(
                    std::io::Error::other("spooled request read failed"),
                ))))
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.offset >= self.staged.size
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.staged.size - self.offset)
    }
}
pub(crate) async fn collect(
    mut body: crate::proxy::Body,
    boundary: &str,
    config: &Config,
    directory: Arc<Directory>,
    pool: Arc<Pool>,
    declared: Option<u64>,
) -> Result<(Staged, Vec<crate::request_block_multipart::Field>), u16> {
    let slot = pool.slots.clone().try_acquire_owned().map_err(|_| 503u16)?;
    if declared.is_some_and(|size| size > config.max_body_bytes) {
        return Err(413);
    }
    // The blocking creator owns the slot and quota even if its caller is canceled.
    let deadline = Instant::now() + Duration::from_millis(config.timeout_ms);
    let create = tokio::task::spawn_blocking(move || {
        let mut lease = Lease {
            file: None,
            pool,
            charged: AtomicU64::new(0),
            _slot: slot,
        };
        if let Some(size) = declared {
            lease.grow(size)?;
        }
        lease.file = Some(directory.anonymous()?);
        Ok::<_, u16>(Arc::new(lease))
    });
    let lease = tokio::time::timeout(
        Duration::from_millis(config.timeout_ms.min(config.idle_timeout_ms)),
        create,
    )
    .await
    .map_err(|_| 408u16)?
    .map_err(|_| 503u16)??;
    let mut parser = crate::request_block_multipart::Parser::new(boundary, config.max_field_bytes)?;
    let mut size = 0u64;
    let mut frames = 0usize;
    let mut idle_deadline = Instant::now() + Duration::from_millis(config.idle_timeout_ms);
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(408u16)?;
        let idle_remaining = idle_deadline
            .checked_duration_since(Instant::now())
            .ok_or(408u16)?;
        let frame = tokio::time::timeout(remaining.min(idle_remaining), body.frame())
            .await
            .map_err(|_| 408u16)?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|_| 400u16)?;
        frames += 1;
        if frames.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
        if let Ok(data) = frame.into_data() {
            if data.is_empty() {
                continue;
            }
            idle_deadline = Instant::now() + Duration::from_millis(config.idle_timeout_ms);
            let next = size
                .checked_add(data.len() as u64)
                .filter(|n| *n <= config.max_body_bytes)
                .ok_or(413u16)?;
            lease.grow(next)?;
            parser.feed(&data)?;
            let writer = lease.clone();
            let offset = size;
            let write = tokio::task::spawn_blocking(move || {
                writer
                    .file
                    .as_ref()
                    .expect("owned spool file")
                    .write_all_at(&data, offset)
                    .map_err(|_| 503u16)
            });
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(408u16)?;
            let idle_remaining = idle_deadline
                .checked_duration_since(Instant::now())
                .ok_or(408u16)?;
            tokio::time::timeout(remaining.min(idle_remaining), write)
                .await
                .map_err(|_| 408u16)?
                .map_err(|_| 503u16)??;
            size = next;
        }
    }
    if declared.is_some_and(|declared| declared != size) {
        return Err(400);
    }
    let fields = parser.finish()?;
    if Instant::now() >= deadline {
        return Err(408);
    }
    Ok((Staged { lease, size }, fields))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    fn setup() -> (tempfile::TempDir, Arc<Directory>, Config) {
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().to_str().unwrap().to_owned();
        let config = Config {
            directory: path.clone(),
            max_body_bytes: 32 * 1024 * 1024,
            timeout_ms: 2000,
            idle_timeout_ms: 30,
            max_field_bytes: 65536,
        };
        (dir, Directory::open(&path).unwrap(), config)
    }
    fn body(bytes: Bytes) -> crate::proxy::Body {
        http_body_util::Full::new(bytes)
            .map_err(|e| match e {})
            .boxed_unsync()
    }
    fn message() -> Bytes {
        Bytes::from_static(b"--owned\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"sample.bin\"\r\n\r\nbinary-file\r\n--owned\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nread\r\n--owned--\r\n")
    }
    #[tokio::test]
    async fn anonymous_replay_retains_quota_until_network_references_drop() {
        let (dir, directory, config) = setup();
        let pool = Arc::new(Pool::with_limits(2, 1048576));
        let expected = message();
        let (staged, fields) = collect(
            body(expected.clone()),
            "owned",
            &config,
            directory,
            pool.clone(),
            Some(expected.len() as u64),
        )
        .await
        .unwrap();
        assert_eq!(fields.last().unwrap().value, "read");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "anonymous spool left pathname"
        );
        assert_eq!(pool.used.load(Ordering::Acquire), expected.len() as u64);
        let replay = staged.body();
        drop(staged);
        let bytes = replay.collect().await.unwrap().to_bytes();
        assert_eq!(bytes, expected);
        assert_eq!(pool.slots.available_permits(), 1);
        assert_eq!(pool.used.load(Ordering::Acquire), expected.len() as u64);
        drop(bytes);
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.available_permits(), 2);
    }
    #[tokio::test]
    async fn idle_failure_and_quota_exhaustion_release_every_resource() {
        let (dir, directory, config) = setup();
        let pool = Arc::new(Pool::with_limits(2, 10));
        let message = message();
        assert_eq!(
            collect(
                body(message.clone()),
                "owned",
                &config,
                directory.clone(),
                pool.clone(),
                Some(message.len() as u64)
            )
            .await
            .err()
            .unwrap(),
            503
        );
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.available_permits(), 2);
        let pool = Arc::new(Pool::with_limits(2, 1048576));
        let slow = http_body_util::StreamBody::new(futures_util::stream::once(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok::<_, crate::proxy::BodyError>(Frame::data(Bytes::from_static(b"late")))
        }))
        .boxed_unsync();
        assert_eq!(
            collect(slow, "owned", &config, directory, pool.clone(), None)
                .await
                .err()
                .unwrap(),
            408
        );
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.available_permits(), 2);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[tokio::test]
    async fn cancellation_releases_staging_and_owned_blocking_tasks_keep_budget() {
        let (dir, directory, config) = setup();
        let pool = Arc::new(Pool::with_limits(1, 1048576));
        let slow = http_body_util::StreamBody::new(futures_util::stream::pending::<
            Result<Frame<Bytes>, crate::proxy::BodyError>,
        >())
        .boxed_unsync();
        let shared = pool.clone();
        let task = tokio::spawn(async move {
            collect(slow, "owned", &config, directory, shared, Some(100)).await
        });
        for _ in 0..100 {
            if pool.used.load(Ordering::Acquire) == 100 {
                break;
            }
            tokio::task::yield_now().await;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(pool.slots.available_permits(), 0);
        task.abort();
        let _ = task.await;
        for _ in 0..100 {
            if pool.slots.available_permits() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.available_permits(), 1);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        let file = Directory::open(dir.path().to_str().unwrap())
            .unwrap()
            .anonymous()
            .unwrap();
        let slot = pool.slots.clone().try_acquire_owned().unwrap();
        let lease = Arc::new(Lease {
            file: Some(file),
            pool: pool.clone(),
            charged: AtomicU64::new(0),
            _slot: slot,
        });
        lease.grow(100).unwrap();
        let worker_lease = lease.clone();
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _owner = worker_lease;
            let _ = start_tx.send(());
            done_rx.recv().unwrap();
        });
        start_rx.await.unwrap();
        drop(worker);
        drop(lease);
        assert_eq!(pool.used.load(Ordering::Acquire), 100);
        assert_eq!(pool.slots.available_permits(), 0);
        done_tx.send(()).unwrap();
        for _ in 0..100 {
            if pool.used.load(Ordering::Acquire) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
        assert_eq!(pool.slots.available_permits(), 1);
    }
    #[test]
    fn directory_handles_reject_symlinks_and_foreign_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let (dir, directory, _) = setup();
        let link = dir.path().join("link");
        symlink(dir.path(), &link).unwrap();
        assert!(Directory::open(link.to_str().unwrap()).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Directory::open(dir.path().to_str().unwrap()).is_err());
        assert_eq!(
            directory.anonymous().unwrap_err(),
            503,
            "pinned directory must revalidate permissions before file creation"
        );
    }
    #[tokio::test]
    async fn empty_frames_do_not_extend_upload_progress_deadline() {
        let (_dir, directory, config) = setup();
        let pool = Arc::new(Pool::with_limits(2, 1048576));
        let stream = futures_util::stream::unfold(0, |count| async move {
            if count >= 50 {
                None
            } else {
                tokio::time::sleep(Duration::from_millis(2)).await;
                Some((
                    Ok::<_, crate::proxy::BodyError>(Frame::data(Bytes::new())),
                    count + 1,
                ))
            }
        });
        let body = http_body_util::StreamBody::new(stream).boxed_unsync();
        assert_eq!(
            collect(body, "owned", &config, directory, pool.clone(), None)
                .await
                .err()
                .unwrap(),
            408
        );
        assert_eq!(pool.slots.available_permits(), 2);
        assert_eq!(pool.used.load(Ordering::Acquire), 0);
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_platform_tests {
    #[test]
    fn multipart_spool_configuration_fails_closed_without_linux_anonymous_files() {
        let config = super::Config {
            directory: "/tmp/private-spool".into(),
            max_body_bytes: 1048576,
            timeout_ms: 2000,
            idle_timeout_ms: 1000,
            max_field_bytes: 4096,
        };
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("only on Linux")
        );
    }
}
