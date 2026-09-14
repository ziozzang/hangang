//! Local observer identity and dedicated, revocable peer credential.
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tokio_util::sync::CancellationToken;

const CONFIG_MAX: usize = 16 * 1024;
const TOKEN_MAX: usize = 257;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    node_id: String,
    token_file: PathBuf,
}

struct Credential {
    token: Vec<u8>,
}
struct State {
    generation: u64,
    credential: Option<Credential>,
    exhausted: bool,
}

pub struct Runtime {
    config_path: PathBuf,
    node_id: String,
    forbidden_digest: Option<[u8; 32]>,
    state: ArcSwap<State>,
    watching: AtomicBool,
}

#[derive(Clone, Serialize)]
pub struct Status {
    pub configured: bool,
    pub available: bool,
    pub node_id: Option<String>,
    pub generation: String,
}

#[derive(Clone, Serialize)]
pub struct Identity {
    pub node_id: String,
    pub generation: String,
}

fn secure_read(path: &Path, cap: usize) -> Result<Vec<u8>> {
    ensure!(path.is_absolute(), "observer file path must be absolute");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("observer file unavailable")?;
    let meta = file
        .metadata()
        .context("observer file metadata unavailable")?;
    ensure!(
        meta.is_file() && meta.len() <= cap as u64,
        "observer file type or size invalid"
    );
    ensure!(
        meta.permissions().mode() & 0o077 == 0,
        "observer file permissions invalid"
    );
    let uid = unsafe { libc::geteuid() };
    ensure!(
        meta.uid() == uid || meta.uid() == 0,
        "observer file owner invalid"
    );
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    (&file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .context("observer file read failed")?;
    ensure!(bytes.len() <= cap, "observer file too large");
    let after = file
        .metadata()
        .context("observer file metadata unavailable")?;
    ensure!(
        after.is_file()
            && after.len() == bytes.len() as u64
            && meta.len() == after.len()
            && meta.uid() == after.uid()
            && meta.mode() == after.mode()
            && meta.mtime() == after.mtime()
            && meta.mtime_nsec() == after.mtime_nsec()
            && meta.ctime() == after.ctime()
            && meta.ctime_nsec() == after.ctime_nsec(),
        "observer file changed during read"
    );
    Ok(bytes)
}

fn load(path: &Path) -> Result<(String, Vec<u8>)> {
    let raw = secure_read(path, CONFIG_MAX)?;
    let config: FileConfig =
        serde_json::from_slice(&raw).map_err(|_| anyhow::anyhow!("invalid observer config"))?;
    ensure!(
        (1..=64).contains(&config.node_id.len())
            && config
                .node_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid observer node id"
    );
    let mut token = secure_read(&config.token_file, TOKEN_MAX)?;
    if token.last() == Some(&b'\n') {
        token.pop();
    }
    ensure!(
        (32..=256).contains(&token.len())
            && token
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(c)),
        "invalid observer token"
    );
    Ok((config.node_id, token))
}

impl Runtime {
    pub async fn open(path: PathBuf, forbidden_admin_token: Option<&str>) -> Result<Arc<Self>> {
        let copy = path.clone();
        let (node_id, token) = tokio::task::spawn_blocking(move || load(&copy)).await??;
        let forbidden_digest =
            forbidden_admin_token.map(|value| Sha256::digest(value.as_bytes()).into());
        ensure!(
            !Self::forbidden(&token, &forbidden_digest),
            "observer token must differ from admin token"
        );
        Ok(Arc::new(Self {
            config_path: path,
            node_id,
            forbidden_digest,
            state: ArcSwap::from_pointee(State {
                generation: 1,
                credential: Some(Credential { token }),
                exhausted: false,
            }),
            watching: AtomicBool::new(false),
        }))
    }

    fn forbidden(token: &[u8], digest: &Option<[u8; 32]>) -> bool {
        digest
            .as_ref()
            .is_some_and(|value| bool::from(Sha256::digest(token).as_slice().ct_eq(value)))
    }

    pub fn status(&self) -> Status {
        let state = self.state.load();
        Status {
            configured: true,
            available: state.credential.is_some(),
            node_id: Some(self.node_id.clone()),
            generation: state.generation.to_string(),
        }
    }

    pub fn authenticate(&self, token: &str) -> Option<Identity> {
        let state = self.state.load();
        let expected = &state.credential.as_ref()?.token;
        if expected.len() != token.len() || !bool::from(expected.ct_eq(token.as_bytes())) {
            return None;
        }
        Some(Identity {
            node_id: self.node_id.clone(),
            generation: state.generation.to_string(),
        })
    }

    async fn refresh(&self) {
        let path = self.config_path.clone();
        let loaded = tokio::task::spawn_blocking(move || load(&path))
            .await
            .ok()
            .and_then(Result::ok);
        let next = loaded.and_then(|(id, token)| {
            (id == self.node_id && !Self::forbidden(&token, &self.forbidden_digest))
                .then_some(token)
        });
        let old = self.state.load();
        if old.exhausted {
            return;
        }
        let same = match (&old.credential, &next) {
            (Some(a), Some(b)) => a.token == *b,
            (None, None) => true,
            _ => false,
        };
        if !same {
            let exhausted = old.generation == u64::MAX;
            self.state.store(Arc::new(State {
                generation: old.generation.saturating_add(1),
                credential: (!exhausted)
                    .then_some(next)
                    .flatten()
                    .map(|token| Credential { token }),
                exhausted,
            }));
        }
    }

    pub async fn watch(self: Arc<Self>, cancel: CancellationToken) {
        if self.watching.swap(true, Ordering::AcqRel) {
            return;
        }
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! { _ = cancel.cancelled() => break, _ = ticker.tick() => self.refresh().await }
        }
        self.watching.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("observer.json");
        let token = dir.path().join("observer.token");
        fs::write(&token, b"abcdefghijklmnopqrstuvwxyz012345\n").unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(
            &config,
            serde_json::json!({"node_id":"edge.a", "token_file":token}).to_string(),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        (dir, config, token)
    }

    #[tokio::test]
    async fn rotation_and_invalid_reload_withdraw_without_secret_serialization() {
        let (_dir, config, token) = fixture();
        let runtime = Runtime::open(config.clone(), Some("admin-secret"))
            .await
            .unwrap();
        assert_eq!(runtime.status().generation, "1");
        runtime.refresh().await;
        assert_eq!(runtime.status().generation, "1");
        assert!(
            runtime
                .authenticate("abcdefghijklmnopqrstuvwxyz012345")
                .is_some()
        );
        let serialized = serde_json::to_string(&runtime.status()).unwrap();
        assert!(!serialized.contains("abcdefghijklmnopqrstuvwxyz012345"));
        fs::write(&token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n").unwrap();
        runtime.refresh().await;
        assert_eq!(runtime.status().generation, "2");
        assert!(
            runtime
                .authenticate("abcdefghijklmnopqrstuvwxyz012345")
                .is_none()
        );
        assert!(
            runtime
                .authenticate("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
                .is_some()
        );
        fs::write(
            &config,
            serde_json::json!({"node_id":"edge.b", "token_file":token}).to_string(),
        )
        .unwrap();
        runtime.refresh().await;
        assert!(!runtime.status().available);
        assert_eq!(runtime.status().node_id.as_deref(), Some("edge.a"));
        fs::write(
            &config,
            serde_json::json!({"node_id":"edge.a", "token_file":token}).to_string(),
        )
        .unwrap();
        runtime.refresh().await;
        assert!(runtime.status().available);
        assert_eq!(runtime.status().generation, "4");
        fs::write(&token, b"invalid").unwrap();
        runtime.refresh().await;
        assert!(!runtime.status().available);
        fs::write(&token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n").unwrap();
        runtime.refresh().await;
        assert_eq!(runtime.status().generation, "6");
        assert!(runtime.status().available);
    }

    #[tokio::test]
    async fn rejects_admin_token_and_revokes_on_reload_collision() {
        let (_dir, config, token) = fixture();
        assert!(
            Runtime::open(config.clone(), Some("abcdefghijklmnopqrstuvwxyz012345"))
                .await
                .is_err()
        );
        let runtime = Runtime::open(config, Some("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"))
            .await
            .unwrap();
        fs::write(token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345").unwrap();
        runtime.refresh().await;
        assert!(!runtime.status().available);
    }

    #[tokio::test]
    async fn bounds_permissions_and_fifo_fail_without_blocking() {
        let (dir, config, token) = fixture();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(Runtime::open(config.clone(), None).await.is_err());
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&token, vec![b'a'; 258]).unwrap();
        assert!(Runtime::open(config.clone(), None).await.is_err());
        fs::remove_file(&token).unwrap();
        let fifo = std::ffi::CString::new(token.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(Runtime::open(config.clone(), None).await.is_err());
        fs::remove_file(&token).unwrap();
        let target = dir.path().join("target.token");
        fs::write(&target, vec![b'a'; 256]).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&target, &token).unwrap();
        assert!(Runtime::open(config, None).await.is_ok());
    }

    #[tokio::test]
    async fn exhausted_generation_withdraws_permanently() {
        let (_dir, config, token) = fixture();
        let runtime = Runtime::open(config, None).await.unwrap();
        runtime.state.store(Arc::new(State {
            generation: u64::MAX,
            credential: Some(Credential {
                token: b"abcdefghijklmnopqrstuvwxyz012345".to_vec(),
            }),
            exhausted: false,
        }));
        fs::write(token, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ012345").unwrap();
        runtime.refresh().await;
        assert!(!runtime.status().available);
        assert_eq!(runtime.status().generation, u64::MAX.to_string());
        runtime.refresh().await;
        assert!(!runtime.status().available);
    }
}
