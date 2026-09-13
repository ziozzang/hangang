//! Durable whole-document snapshots. Single writer process per state file.
use crate::config::Config;
use anyhow::{Context, Result};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Upper bound for a configuration document in every representation: the
/// on-disk file, the shared-store row, and the API request body. `save`
/// enforces it on the exact bytes it writes so a document that `load` would
/// refuse can never be persisted.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

pub fn load(path: &Path) -> Result<Config> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A FIFO (or a symlink to one) at the configuration path must not
        // block the opener while the configuration writer lock is held.
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).context("open configuration")?;
    anyhow::ensure!(
        file.metadata().context("inspect configuration")?.is_file(),
        "configuration path is not a regular file"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_CONFIG_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read configuration")?;
    anyhow::ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "configuration exceeds 1 MiB"
    );
    let config: Config = serde_json::from_slice(&bytes).context("parse configuration")?;
    config.validate()?;
    Ok(config)
}
pub async fn save(path: PathBuf, config: Config) -> Result<()> {
    tokio::task::spawn_blocking(move || save_sync(&path, &config)).await?
}
/// Serialize exactly as the file will be written. Pretty printing can expand a
/// compact document that passed the API body limit well beyond `load`'s bound.
fn encode_file(config: &Config) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(config)?;
    bytes.push(b'\n');
    anyhow::ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "configuration exceeds 1 MiB when persisted"
    );
    Ok(bytes)
}
fn save_sync(path: &Path, config: &Config) -> Result<()> {
    let bytes = encode_file(config)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp =
        tempfile::NamedTempFile::new_in(parent).context("create snapshot temporary file")?;
    tmp.write_all(&bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).context("persist snapshot")?;
    // The rename is the commit point. A directory sync error cannot be rolled
    // back honestly, so report reduced durability in logs and keep activation.
    if let Err(error) = std::fs::File::open(parent).and_then(|d| d.sync_all()) {
        tracing::warn!(%error,"snapshot renamed but directory sync failed");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn round_trip_and_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let c = Config {
            certificates: vec![],
            revision: 7,
            ..Default::default()
        };
        save(path.clone(), c).await.unwrap();
        assert_eq!(load(&path).unwrap().revision, 7);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                0
            );
        }
    }
    #[tokio::test]
    async fn failed_write_preserves_previous() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        save(path.clone(), Config::default()).await.unwrap();
        assert!(
            save(dir.path().join("absent/state.json"), Config::default())
                .await
                .is_err()
        );
        assert_eq!(load(&path).unwrap().revision, 0);
    }

    /// A compact document under the API limit whose pretty form exceeds the
    /// read limit must be rejected before the rename, leaving the file intact.
    #[tokio::test]
    async fn save_rejects_documents_that_only_the_pretty_form_makes_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        save(path.clone(), Config::default()).await.unwrap();
        let before = std::fs::read(&path).unwrap();

        let mut oversized: Config = serde_json::from_value(serde_json::json!({
            "http":[{"id":"wide","backends":["http://127.0.0.1:9"],
                     "json":{"/values": vec![0_u8; 200_000]}}]
        }))
        .unwrap();
        oversized.revision = 1;
        assert!(oversized.validate().is_ok());
        assert!(serde_json::to_vec(&oversized).unwrap().len() < MAX_CONFIG_BYTES);
        assert!(serde_json::to_vec_pretty(&oversized).unwrap().len() > MAX_CONFIG_BYTES);

        let error = save(path.clone(), oversized).await.unwrap_err();
        assert!(error.to_string().contains("1 MiB"), "{error:#}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(load(&path).unwrap().revision, 0);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no temporary file is left behind"
        );
    }

    /// A FIFO at the configuration path (directly or through a symlink) must
    /// fail promptly instead of blocking the opener until a writer appears.
    #[cfg(unix)]
    #[test]
    fn load_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("state.json");
        let c_path = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path and mode are passed.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();

        for path in [fifo, link] {
            let (sender, receiver) = std::sync::mpsc::channel();
            let started = std::time::Instant::now();
            std::thread::spawn(move || {
                let _ = sender.send(load(&path).map(|_| ()));
            });
            let result = receiver
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("load must not block on a FIFO");
            let error = result.unwrap_err();
            assert!(
                error.to_string().contains("not a regular file"),
                "{error:#}"
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
        }
    }
}
