//! One local, revisioned Docker daemon connection. This is instance state,
//! not a fleet-wide configuration value: file references resolve on this host.
use crate::docker::DockerResolver;
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::{Mutex, Semaphore};

const MAX_STATE: usize = 4096;
const MAX_PEM: usize = 65536;
const MAX_WORK: usize = 8;

#[derive(Debug)]
pub struct Busy;

impl std::fmt::Display for Busy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Docker connection work capacity exhausted")
    }
}
impl std::error::Error for Busy {}

#[derive(Debug)]
pub struct Frozen;
impl std::fmt::Display for Frozen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Docker connection writes are frozen for handoff")
    }
}
impl std::error::Error for Frozen {}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "transport", rename_all = "lowercase", deny_unknown_fields)]
pub enum ConnectionConfig {
    Unix {
        socket_path: PathBuf,
    },
    Https {
        url: String,
        ca_file: PathBuf,
        client_cert_file: PathBuf,
        client_key_file: PathBuf,
    },
    Disabled,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    revision: u64,
    config: Option<ConnectionConfig>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionView {
    pub revision: u64,
    pub source: &'static str,
    pub enabled: bool,
    pub config: ConnectionConfig,
}

struct State {
    revision: u64,
    override_config: Option<ConnectionConfig>,
}

pub struct DockerConnections {
    writer_lock: Arc<std::fs::File>,
    path: PathBuf,
    cli_socket: Option<PathBuf>,
    state: Arc<Mutex<State>>,
    current: Arc<ArcSwap<Current>>,
    work: Arc<Semaphore>,
    frozen: Arc<AtomicBool>,
}

struct Current {
    generation: u64,
    resolver: Option<Arc<DockerResolver>>,
}

impl DockerConnections {
    pub fn open(path: PathBuf, cli_socket: Option<PathBuf>) -> Result<Self> {
        Self::open_with_lock(path, cli_socket, None)
    }

    pub fn open_with_lock(
        path: PathBuf,
        cli_socket: Option<PathBuf>,
        inherited_lock: Option<std::fs::File>,
    ) -> Result<Self> {
        Self::open_with_capacity(path, cli_socket, MAX_WORK, inherited_lock)
    }

    pub fn lock_file(&self) -> &std::fs::File {
        &self.writer_lock
    }

    pub async fn freeze(&self) {
        self.frozen.store(true, Ordering::Release);
        drop(self.state.lock().await);
    }

    pub fn resume(&self) {
        self.frozen.store(false, Ordering::Release);
    }

    fn open_with_capacity(
        path: PathBuf,
        cli_socket: Option<PathBuf>,
        capacity: usize,
        inherited_lock: Option<std::fs::File>,
    ) -> Result<Self> {
        let writer_lock = writer_lock(&path, inherited_lock)?;
        let stored = match load_state(&path) {
            Ok(stored) => stored,
            Err(error) => {
                tracing::warn!(%error, "Docker connection state unavailable at startup");
                // An unreadable override may have explicitly disabled the
                // CLI fallback. Keep Docker off until an administrator
                // repairs the sidecar with a new revisioned PUT.
                Some(Stored {
                    revision: 0,
                    config: Some(ConnectionConfig::Disabled),
                })
            }
        };
        let effective = stored
            .as_ref()
            .and_then(|s| s.config.clone())
            .or_else(|| {
                cli_socket
                    .clone()
                    .map(|socket_path| ConnectionConfig::Unix { socket_path })
            })
            .unwrap_or(ConnectionConfig::Disabled);
        let resolver = match build(&effective) {
            Ok(resolver) => resolver,
            Err(error) => {
                // A missing/expired local credential must not take the
                // unrelated HTTP/TCP listeners down. Docker references fail
                // closed until an administrator replaces the connection.
                tracing::warn!(%error, "Docker connection unavailable at startup");
                None
            }
        };
        Ok(Self {
            writer_lock: Arc::new(writer_lock),
            path,
            cli_socket,
            state: Arc::new(Mutex::new(State {
                revision: stored.as_ref().map_or(0, |s| s.revision),
                override_config: stored.and_then(|s| s.config),
            })),
            current: Arc::new(ArcSwap::from_pointee(Current {
                generation: 0,
                resolver,
            })),
            work: Arc::new(Semaphore::new(capacity)),
            frozen: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn resolver(&self) -> Option<Arc<DockerResolver>> {
        self.current.load().resolver.clone()
    }

    pub fn generation(&self) -> u64 {
        self.current.load().generation
    }

    pub fn generation_resolver(&self) -> (u64, Option<Arc<DockerResolver>>) {
        let current = self.current.load();
        (current.generation, current.resolver.clone())
    }

    pub async fn view(&self) -> ConnectionView {
        let state = self.state.lock().await;
        view_from_state(&state, &self.cli_socket)
    }

    pub async fn test_candidate(&self, config: ConnectionConfig) -> Result<()> {
        let permit = self.work.clone().try_acquire_owned().map_err(|_| Busy)?;
        tokio::spawn(async move {
            let _permit = permit;
            let resolver = tokio::task::spawn_blocking(move || build(&config))
                .await??
                .context("Docker connection is disabled")?;
            resolver.ping().await
        })
        .await?
    }

    /// Compare-and-swap. Persistence completes before the resolver is
    /// published, and discovery's next refresh observes the new generation.
    pub async fn put(
        &self,
        expected: u64,
        config: ConnectionConfig,
    ) -> Result<Option<ConnectionView>> {
        let permit = self.work.clone().try_acquire_owned().map_err(|_| Busy)?;
        let writer_lock = self.writer_lock.clone();
        let state = self.state.clone();
        let frozen = self.frozen.clone();
        let current = self.current.clone();
        let cli_socket = self.cli_socket.clone();
        let path = self.path.clone();
        let changed = tokio::spawn(async move {
            let _permit = permit;
            let _writer_lock = writer_lock;
            let resolver = tokio::task::spawn_blocking({
                let config = config.clone();
                move || build(&config)
            })
            .await??;
            let mut state = state.lock().await;
            if frozen.load(Ordering::Acquire) {
                return Err(Frozen.into());
            }
            if state.revision != expected {
                return Ok::<_, anyhow::Error>(None);
            }
            let revision = next_revision(state.revision)?;
            let generation = current
                .load()
                .generation
                .checked_add(1)
                .context("Docker connection generation exhausted")?;
            let stored = Stored {
                revision,
                config: Some(config.clone()),
            };
            let commit_lock = _writer_lock.clone();
            tokio::task::spawn_blocking(move || {
                // A blocking write can outlive async task cancellation during
                // runtime shutdown. Keep ownership until disk work finishes.
                let _commit_lock = commit_lock;
                save_state(&path, &stored)
            })
            .await??;
            state.revision = revision;
            state.override_config = Some(config);
            current.store(Arc::new(Current {
                generation,
                resolver,
            }));
            Ok(Some(view_from_state(&state, &cli_socket)))
        })
        .await??;
        Ok(changed)
    }

    /// Remove the managed override; the initial CLI socket becomes effective.
    pub async fn delete(&self, expected: u64) -> Result<Option<ConnectionView>> {
        let permit = self.work.clone().try_acquire_owned().map_err(|_| Busy)?;
        let writer_lock = self.writer_lock.clone();
        let fallback = self
            .cli_socket
            .clone()
            .map(|socket_path| ConnectionConfig::Unix { socket_path })
            .unwrap_or(ConnectionConfig::Disabled);
        let state = self.state.clone();
        let frozen = self.frozen.clone();
        let current = self.current.clone();
        let cli_socket = self.cli_socket.clone();
        let path = self.path.clone();
        let changed = tokio::spawn(async move {
            let _permit = permit;
            let _writer_lock = writer_lock;
            let resolver = tokio::task::spawn_blocking(move || build(&fallback)).await??;
            let mut state = state.lock().await;
            if frozen.load(Ordering::Acquire) {
                return Err(Frozen.into());
            }
            if state.revision != expected {
                return Ok::<_, anyhow::Error>(None);
            }
            let revision = next_revision(state.revision)?;
            let generation = current
                .load()
                .generation
                .checked_add(1)
                .context("Docker connection generation exhausted")?;
            let commit_lock = _writer_lock.clone();
            tokio::task::spawn_blocking(move || {
                let _commit_lock = commit_lock;
                save_state(
                    &path,
                    &Stored {
                        revision,
                        config: None,
                    },
                )
            })
            .await??;
            state.revision = revision;
            state.override_config = None;
            current.store(Arc::new(Current {
                generation,
                resolver,
            }));
            Ok(Some(view_from_state(&state, &cli_socket)))
        })
        .await??;
        Ok(changed)
    }
}

fn writer_lock(path: &Path, inherited: Option<std::fs::File>) -> Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let file_name = path
        .file_name()
        .context("Docker connection state needs a filename")?;
    let mut lock_name = file_name.to_os_string();
    lock_name.push(".lock");
    let lock_path = path.with_file_name(lock_name);
    let was_inherited = inherited.is_some();
    let file = if let Some(inherited) = inherited {
        let at_path =
            std::fs::symlink_metadata(&lock_path).context("inspect inherited Docker lock path")?;
        let meta = inherited
            .metadata()
            .context("inspect inherited Docker lock")?;
        ensure!(
            at_path.file_type().is_file()
                && at_path.dev() == meta.dev()
                && at_path.ino() == meta.ino(),
            "inherited Docker lock does not match this state path"
        );
        inherited
    } else {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lock_path)
            .context("open Docker connection writer lock")?
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "Docker connection writer lock must be a private regular file"
    );
    if !was_inherited {
        file.try_lock().context("another process owns this Docker connection state; use --docker-connection-state for instance-local state")?;
    }
    Ok(file)
}

fn view_from_state(state: &State, cli_socket: &Option<PathBuf>) -> ConnectionView {
    let (source, config) = if let Some(config) = &state.override_config {
        (
            if matches!(config, ConnectionConfig::Disabled) {
                "disabled"
            } else {
                "managed"
            },
            config.clone(),
        )
    } else if let Some(socket_path) = cli_socket {
        (
            "cli",
            ConnectionConfig::Unix {
                socket_path: socket_path.clone(),
            },
        )
    } else {
        ("disabled", ConnectionConfig::Disabled)
    };
    ConnectionView {
        revision: state.revision,
        source,
        enabled: !matches!(config, ConnectionConfig::Disabled),
        config,
    }
}

fn next_revision(current: u64) -> Result<u64> {
    let next = current
        .checked_add(1)
        .context("Docker connection revision exhausted")?;
    ensure!(
        next <= 9_007_199_254_740_991,
        "Docker connection revision exceeds JSON safe integer range"
    );
    Ok(next)
}

fn build(config: &ConnectionConfig) -> Result<Option<Arc<DockerResolver>>> {
    Ok(match config {
        ConnectionConfig::Disabled => None,
        ConnectionConfig::Unix { socket_path } => {
            ensure!(
                socket_path.is_absolute() && socket_path.as_os_str().len() <= 1024,
                "Docker socket path must be absolute and bounded"
            );
            Some(Arc::new(DockerResolver::new(socket_path.clone())))
        }
        ConnectionConfig::Https {
            url,
            ca_file,
            client_cert_file,
            client_key_file,
        } => {
            ensure!(url.len() <= 512, "Docker HTTPS origin is too long");
            let ca = read_pem(ca_file, false)?;
            let cert = read_pem(client_cert_file, false)?;
            let key = read_pem(client_key_file, true)?;
            let mut identity = cert;
            identity.push(b'\n');
            identity.extend_from_slice(&key);
            Some(Arc::new(DockerResolver::https(url, &ca, &identity)?))
        }
    })
}

fn read_pem(path: &Path, private: bool) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    ensure!(
        path.is_absolute() && path.as_os_str().len() <= 1024,
        "Docker certificate path must be absolute and bounded"
    );
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("open Docker certificate file")?;
    let metadata = file.metadata().context("inspect Docker certificate file")?;
    ensure!(
        metadata.is_file(),
        "Docker certificate path must be a regular file"
    );
    if private {
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.permissions().mode() & 0o077 == 0,
            "Docker client key must be private and process-owned"
        );
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_PEM + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_PEM,
        "Docker certificate file is too large"
    );
    Ok(bytes)
}

fn load_state(path: &Path) -> Result<Option<Stored>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open Docker connection state"),
    };
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "Docker connection state must be a private regular file"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take((MAX_STATE + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_STATE,
        "Docker connection state is too large"
    );
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse Docker connection state")?,
    ))
}

fn save_state(path: &Path, stored: &Stored) -> Result<()> {
    let bytes = serde_json::to_vec(stored)?;
    ensure!(
        bytes.len() <= MAX_STATE,
        "Docker connection state is too large"
    );
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .context("create Docker connection temporary file")?;
    tmp.write_all(&bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path)
        .context("persist Docker connection state")?;
    if let Err(error) = std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
        tracing::warn!(%error, "Docker connection state renamed but directory sync failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use hyper::{Request, Response, server::conn::http1 as server_http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn disable_swap_and_restart_keep_revision_and_cli_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-connection.json");
        let cli = dir.path().join("cli.sock");
        let managed = dir.path().join("managed.sock");
        let connections = DockerConnections::open(path.clone(), Some(cli.clone())).unwrap();
        assert_eq!(connections.view().await.source, "cli");
        assert!(connections.resolver().is_some());
        let first = connections
            .put(
                0,
                ConnectionConfig::Unix {
                    socket_path: managed.clone(),
                },
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(first.revision, 1);
        assert_eq!(first.source, "managed");
        assert!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap()
                .is_none()
        );
        let disabled = connections
            .put(1, ConnectionConfig::Disabled)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(disabled.revision, 2);
        assert!(!disabled.enabled);
        assert!(connections.resolver().is_none());
        drop(connections);
        let restarted = DockerConnections::open(path.clone(), Some(cli.clone())).unwrap();
        assert_eq!(restarted.view().await.revision, 2);
        assert!(restarted.resolver().is_none());
        let fallback = restarted.delete(2).await.unwrap().unwrap();
        assert_eq!(fallback.source, "cli");
        assert_eq!(fallback.revision, 3);
        drop(restarted);
        let restarted = DockerConnections::open(path, Some(cli)).unwrap();
        assert_eq!(restarted.view().await.revision, 3);
        assert_eq!(restarted.view().await.source, "cli");
        assert!(restarted.resolver().is_some());
    }

    #[tokio::test]
    async fn failed_validation_does_not_publish_or_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-connection.json");
        let connections = DockerConnections::open(path.clone(), None).unwrap();
        let invalid = ConnectionConfig::Unix {
            socket_path: PathBuf::from("relative.sock"),
        };
        assert!(connections.put(0, invalid).await.is_err());
        assert_eq!(connections.view().await.revision, 0);
        assert!(!path.exists());
        let invalid = ConnectionConfig::Https {
            url: "http://127.0.0.1:2375".into(),
            ca_file: path.clone(),
            client_cert_file: path.clone(),
            client_key_file: path.clone(),
        };
        assert!(connections.test_candidate(invalid).await.is_err());
    }

    #[test]
    fn a_second_instance_cannot_write_the_same_sidecar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection.json");
        let first = DockerConnections::open(path.clone(), None).unwrap();
        assert!(DockerConnections::open(path.clone(), None).is_err());
        drop(first);
        assert!(DockerConnections::open(path, None).is_ok());
    }

    #[test]
    fn inherited_lock_keeps_hot_restart_writer_exclusive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection.json");
        let old = DockerConnections::open(path.clone(), None).unwrap();
        let inherited = old.lock_file().try_clone().unwrap();
        let new = DockerConnections::open_with_lock(path.clone(), None, Some(inherited)).unwrap();
        drop(old);
        assert!(DockerConnections::open(path.clone(), None).is_err());
        drop(new);
        assert!(DockerConnections::open(path, None).is_ok());
    }

    #[tokio::test]
    async fn frozen_generation_rejects_mutations_and_resume_restores_writes() {
        let dir = tempfile::tempdir().unwrap();
        let connections =
            DockerConnections::open(dir.path().join("connection.json"), None).unwrap();
        connections.freeze().await;
        assert!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap_err()
                .is::<Frozen>()
        );
        assert!(connections.delete(0).await.unwrap_err().is::<Frozen>());
        assert_eq!(connections.view().await.revision, 0);
        connections.resume();
        assert_eq!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[tokio::test]
    async fn canceled_owner_does_not_release_writer_lock_before_detached_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection.json");
        let connections = Arc::new(DockerConnections::open(path.clone(), None).unwrap());
        let state = connections.state.clone();
        let guard = state.lock().await;
        let outer = {
            let connections = connections.clone();
            tokio::spawn(async move { connections.put(0, ConnectionConfig::Disabled).await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while connections.work.available_permits() != MAX_WORK - 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        outer.abort();
        let _ = outer.await;
        drop(connections);
        assert!(
            DockerConnections::open(path.clone(), None).is_err(),
            "detached write lost its exclusive writer lock"
        );
        drop(guard);
        let reopened = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Ok(reopened) = DockerConnections::open(path.clone(), None) {
                    break reopened;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(reopened.view().await.revision, 1);
    }

    #[tokio::test]
    async fn corrupt_local_state_disables_docker_without_blocking_startup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("connection.json");
        std::fs::write(&path, b"not-json").unwrap();
        let connections =
            DockerConnections::open(path.clone(), Some(dir.path().join("cli.sock"))).unwrap();
        assert!(!connections.view().await.enabled);
        assert!(connections.resolver().is_none());
        assert_eq!(std::fs::read(&path).unwrap(), b"not-json");
        assert_eq!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
        drop(connections);
        assert_eq!(
            DockerConnections::open(path, None)
                .unwrap()
                .view()
                .await
                .revision,
            1
        );
    }

    #[tokio::test]
    async fn candidate_test_only_pings_and_never_publishes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("docker-connection.json");
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
                assert_eq!(request.uri().path(), "/_ping");
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"OK"))))
            });
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let connections = DockerConnections::open(path.clone(), None).unwrap();
        connections
            .test_candidate(ConnectionConfig::Unix {
                socket_path: socket.clone(),
            })
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(connections.view().await.revision, 0);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn work_admission_is_bounded_and_releases_after_canceled_request() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                assert_eq!(request.uri().path(), "/_ping");
                async move {
                    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"OK"))))
                }
            });
            let _ = accepted_tx.send(());
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let connections = Arc::new(
            DockerConnections::open_with_capacity(
                dir.path().join("connection.json"),
                None,
                1,
                None,
            )
            .unwrap(),
        );
        let testing = {
            let connections = connections.clone();
            tokio::spawn(async move {
                connections
                    .test_candidate(ConnectionConfig::Unix {
                        socket_path: socket,
                    })
                    .await
            })
        };
        accepted_rx.await.unwrap();
        testing.abort();
        assert!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap_err()
                .is::<Busy>()
        );
        server.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while connections.work.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            connections
                .put(0, ConnectionConfig::Disabled)
                .await
                .unwrap()
                .unwrap()
                .revision,
            1
        );
    }

    #[tokio::test]
    async fn unix_resolver_reaches_only_inspect_path() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(|request: Request<hyper::body::Incoming>| async move {
                assert_eq!(request.uri().path(), "/containers/api/json");
                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(br#"{"State":{"Running":true},"NetworkSettings":{"Networks":{"edge":{"IPAddress":"172.20.0.7","GlobalIPv6Address":""}}}}"#))))
            });
            server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await
                .unwrap();
        });
        let resolver = DockerResolver::new(socket);
        assert_eq!(
            resolver
                .resolve("api", "edge", 80)
                .await
                .unwrap()
                .tcp_backend,
            "172.20.0.7:80"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn https_connection_verifies_server_and_requires_client_certificate() {
        use rustls::{
            RootCertStore,
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
        };
        use tokio::net::TcpListener;
        let server_cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let client_cert = rcgen::generate_simple_self_signed(vec!["client".into()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(client_cert.cert.der().clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                    server_cert.signing_key.serialize_der(),
                )),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..4 {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    if let Ok(stream) = acceptor.accept(stream).await {
                        let service = service_fn(
                            |request: Request<hyper::body::Incoming>| async move {
                                let body = if request.uri().path() == "/_ping" {
                                    Bytes::from_static(b"OK")
                                } else {
                                    assert_eq!(request.uri().path(), "/containers/api/json");
                                    Bytes::from_static(br#"{"State":{"Running":true},"NetworkSettings":{"Networks":{"edge":{"IPAddress":"172.20.0.7","GlobalIPv6Address":""}}}}"#)
                                };
                                Ok::<_, Infallible>(Response::new(Full::new(body)))
                            },
                        );
                        let _ = server_http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    }
                });
            }
        });
        let ca = server_cert.cert.pem();
        let identity = format!(
            "{}\n{}",
            client_cert.cert.pem(),
            client_cert.signing_key.serialize_pem()
        );
        let url = format!("https://localhost:{}", address.port());
        let resolver = DockerResolver::https(&url, ca.as_bytes(), identity.as_bytes()).unwrap();
        resolver.ping().await.unwrap();
        assert_eq!(
            resolver
                .resolve("api", "edge", 8080)
                .await
                .unwrap()
                .tcp_backend,
            "172.20.0.7:8080"
        );
        let directory = tempfile::tempdir().unwrap();
        let ca_path = directory.path().join("ca.pem");
        let cert_path = directory.path().join("client.crt");
        let key_path = directory.path().join("client.key");
        std::fs::write(&ca_path, ca.as_bytes()).unwrap();
        std::fs::write(&cert_path, client_cert.cert.pem()).unwrap();
        std::fs::write(&key_path, client_cert.signing_key.serialize_pem()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let config = ConnectionConfig::Https {
            url: url.clone(),
            ca_file: ca_path,
            client_cert_file: cert_path,
            client_key_file: key_path.clone(),
        };
        let connections =
            DockerConnections::open(directory.path().join("connection.json"), None).unwrap();
        connections.test_candidate(config.clone()).await.unwrap();
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(build(&config).is_err());
        let wrong = rcgen::generate_simple_self_signed(vec!["other".into()]).unwrap();
        let resolver =
            DockerResolver::https(&url, wrong.cert.pem().as_bytes(), identity.as_bytes()).unwrap();
        assert!(resolver.ping().await.is_err());
        server.await.unwrap();
    }
}
