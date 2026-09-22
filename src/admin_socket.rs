//! Private Unix-domain listener with exclusive ownership and safe stale
//! socket recovery after an unclean process exit.
use crate::{admin::Admin, metrics::Metrics};
use anyhow::{Context, Result, ensure};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::{
    os::unix::{
        ffi::OsStrExt,
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{net::UnixListener, sync::Semaphore, task::JoinSet};
use tokio_util::sync::CancellationToken;

struct OwnedPath {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for OwnedPath {
    fn drop(&mut self) {
        let Ok(metadata) = std::fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
            && let Err(error) = std::fs::remove_file(&self.path)
        {
            tracing::warn!(%error, "could not remove owned admin socket");
        }
    }
}

pub struct BoundAdminSocket {
    listener: UnixListener,
    _owned: OwnedPath,
    _lock: std::fs::File,
}

impl BoundAdminSocket {
    pub fn bind(path: &Path) -> Result<Self> {
        let bytes = path.as_os_str().as_bytes();
        #[cfg(target_os = "macos")]
        let max_path_bytes = 103;
        #[cfg(not(target_os = "macos"))]
        let max_path_bytes = 107;
        ensure!(
            path.is_absolute() && !bytes.contains(&0) && bytes.len() <= max_path_bytes,
            "admin socket path must be absolute and fit the Unix socket path limit"
        );
        let parent = path.parent().context("admin socket path needs a parent")?;
        let metadata = std::fs::symlink_metadata(parent).context("inspect admin socket parent")?;
        ensure!(
            metadata.file_type().is_dir()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0,
            "admin socket parent must be a private directory owned by this process"
        );
        let lock = lock_path(path)?;
        recover_stale_socket(path)?;
        let listener = UnixListener::bind(path).context("bind private Unix socket")?;
        let metadata =
            std::fs::symlink_metadata(path).context("inspect newly bound admin socket")?;
        ensure!(
            metadata.file_type().is_socket(),
            "admin socket bind did not create a socket"
        );
        let bound = Self {
            listener,
            _owned: OwnedPath {
                path: path.to_owned(),
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            _lock: lock,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .context("make admin socket private")?;
        Ok(bound)
    }

    pub async fn accept(
        &self,
    ) -> std::io::Result<(tokio::net::UnixStream, tokio::net::unix::SocketAddr)> {
        self.listener.accept().await
    }
}

fn lock_path(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path
        .file_name()
        .context("Unix socket path needs a filename")?
        .to_os_string();
    name.push(".lock");
    let lock_path = path.with_file_name(name);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(lock_path)
        .context("open Unix socket ownership lock")?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "Unix socket ownership lock must be a private process-owned regular file"
    );
    file.try_lock()
        .context("another process owns this Unix socket path")?;
    Ok(file)
}

fn recover_stale_socket(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect existing Unix socket path"),
    };
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == unsafe { libc::geteuid() },
        "existing Unix socket path is not a process-owned socket"
    );
    // A blocking connect can hang when a live listener's accept backlog is
    // full. Only ECONNREFUSED proves that this owned pathname is stale.
    match probe_socket_nonblocking(path) {
        Ok(_) => anyhow::bail!("Unix socket is already accepting connections"),
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error).context("probe existing Unix socket"),
    }
    let current = std::fs::symlink_metadata(path).context("reinspect stale Unix socket")?;
    ensure!(
        current.file_type().is_socket()
            && current.dev() == metadata.dev()
            && current.ino() == metadata.ino(),
        "Unix socket path changed during stale recovery"
    );
    std::fs::remove_file(path).context("remove stale owned Unix socket")?;
    Ok(())
}

fn probe_socket_nonblocking(path: &Path) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let bytes = path.as_os_str().as_bytes();
    #[cfg(target_os = "linux")]
    let socket_type = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let socket_type = libc::SOCK_STREAM;
    let raw = unsafe { libc::socket(libc::AF_UNIX, socket_type, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Darwin does not implement Linux's atomic SOCK_NONBLOCK/SOCK_CLOEXEC
    // socket flags. Set the equivalent flags immediately after creation.
    #[cfg(not(target_os = "linux"))]
    {
        let status = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if status < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, status | libc::O_NONBLOCK) } < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let descriptor = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if descriptor < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, descriptor | libc::FD_CLOEXEC) }
                < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    #[cfg(target_os = "linux")]
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    #[cfg(target_os = "macos")]
    let length: libc::socklen_t = (std::mem::offset_of!(libc::sockaddr_un, sun_path)
        + bytes.len()
        + 1)
    .try_into()
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "socket path too long"))?;
    #[cfg(target_os = "macos")]
    {
        address.sun_len = length.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "socket path too long")
        })?;
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    let length = (std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1) as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            fd.as_raw_fd(),
            (&raw const address).cast::<libc::sockaddr>(),
            length,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub async fn serve(
    bound: BoundAdminSocket,
    admin: Arc<Admin>,
    cancel: CancellationToken,
    metrics: Arc<Metrics>,
    grace: Duration,
    header_bytes: usize,
) {
    let permits = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(result) = tasks.join_next(), if !tasks.is_empty() => {
                if let Err(error) = result { tracing::warn!(%error, "admin socket connection task failed"); }
            },
            accepted = bound.accept() => {
                let (stream, _) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(%error, "admin socket accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                let admin = admin.clone();
                let cancel = cancel.clone();
                let lease = Arc::new(crate::metrics::ConnectionLease::new(permit, metrics.clone()));
                tasks.spawn(async move {
                    let held_lease = lease.clone();
                    let (io, idle_watch) = crate::idle::IdleIo::new(stream, Duration::from_secs(10));
                    let service = service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
                        request.extensions_mut().insert(lease.clone());
                        request.extensions_mut().insert(crate::tls::TransportInfo { tls: false, local_port: 0 });
                        let admin = admin.clone();
                        async move { admin.handle(request).await }
                    });
                    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                    builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10)).max_buf_size(header_bytes);
                    builder.http2().timer(TokioTimer::new()).max_concurrent_streams(64).max_header_list_size(header_bytes as u32).keep_alive_interval(Some(Duration::from_secs(30))).keep_alive_timeout(Duration::from_secs(10));
                    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
                    tokio::pin!(connection);
                    tokio::select! {
                        _ = &mut connection => {},
                        _ = idle_watch.expired() => {},
                        _ = cancel.cancelled() => { connection.as_mut().graceful_shutdown(); let _ = connection.await; }
                    }
                    drop(held_lease);
                });
            }
        }
    }
    if tokio::time::timeout(grace, async { while tasks.join_next().await.is_some() {} })
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    drop(bound);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn private_socket_refuses_existing_path_and_removes_only_its_own_inode() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("admin.sock");
        let bound = BoundAdminSocket::bind(&path).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(BoundAdminSocket::bind(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(bound);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_file(&path).unwrap();
        let bound = BoundAdminSocket::bind(&path).unwrap();
        drop(bound);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn stale_private_socket_recovers_but_live_listener_is_preserved() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("admin.sock");
        let live = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // A crash may occur between bind and the mode-0600 chmod. The
        // enclosing directory is already private, so recovery remains safe.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(BoundAdminSocket::bind(&path).is_err());
        assert!(path.exists());
        drop(live);
        let recovered = BoundAdminSocket::bind(&path).unwrap();
        drop(recovered);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn parent_and_path_must_be_private_absolute_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("admin.sock");
        assert!(BoundAdminSocket::bind(Path::new("relative.sock")).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(BoundAdminSocket::bind(&path).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(BoundAdminSocket::bind(&directory.path().join("a".repeat(200))).is_err());
    }

    #[test]
    fn ownership_lock_refuses_a_fifo_without_waiting_for_a_writer() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = directory.path().join("admin.sock");
        let lock = directory.path().join("admin.sock.lock");
        let path = std::ffi::CString::new(lock.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(BoundAdminSocket::bind(&socket).is_err());
        assert!(!socket.exists());
    }
}
