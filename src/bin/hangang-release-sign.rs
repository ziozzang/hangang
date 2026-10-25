use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hangang::update::{MAX_MANIFEST_BYTES, sign_release_manifest, signing_key_from_base64};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

fn main() -> Result<()> {
    if hangang::cli_about::print_if_requested("hangang-release-sign") {
        return Ok(());
    }
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let first = arguments
        .next()
        .context("usage: hangang-release-sign <payload.json> <base64-seed-file> <envelope.json> | --public-key <base64-seed-file>")?;
    if first == "--public-key" {
        let key_path = arguments
            .next()
            .map(PathBuf::from)
            .context("usage: hangang-release-sign --public-key <base64-seed-file>")?;
        ensure!(arguments.next().is_none(), "too many arguments");
        let encoded_key = String::from_utf8(read_file(&key_path, 1024, true)?)?;
        let signing_key = signing_key_from_base64(&encoded_key)?;
        println!(
            "{}",
            STANDARD.encode(signing_key.verifying_key().to_bytes())
        );
        return Ok(());
    }
    let payload_path = PathBuf::from(first);
    let key_path = arguments
        .next()
        .map(PathBuf::from)
        .context("usage: hangang-release-sign <payload.json> <base64-seed-file> <envelope.json>")?;
    let output_path = arguments
        .next()
        .map(PathBuf::from)
        .context("usage: hangang-release-sign <payload.json> <base64-seed-file> <envelope.json>")?;
    ensure!(arguments.next().is_none(), "too many arguments");

    let payload = read_file(&payload_path, MAX_MANIFEST_BYTES as usize, false)
        .context("read release manifest payload")?;
    let encoded_key = String::from_utf8(read_file(&key_path, 1024, true)?)?;
    let signing_key = signing_key_from_base64(&encoded_key)?;
    let envelope = sign_release_manifest(&payload, &signing_key)?;

    let output_parent = output_path.parent().unwrap_or_else(|| Path::new("."));
    ensure!(output_parent.is_dir(), "output parent is not a directory");
    let mut temporary = tempfile::Builder::new()
        .prefix(".hangang-signed-manifest-")
        .tempfile_in(output_parent)
        .context("create signed manifest output")?;
    temporary
        .as_file_mut()
        .write_all(&envelope)
        .context("write signed release manifest")?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("fsync signed release manifest")?;
    temporary
        .persist(&output_path)
        .map_err(|error| error.error)
        .context("publish signed release manifest")?;
    sync_directory(output_parent).context("fsync signed manifest directory")?;
    println!("wrote {}", output_path.display());
    Ok(())
}

fn read_file(path: &Path, limit: usize, secret: bool) -> Result<Vec<u8>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
        if secret {
            flags |= libc::O_NOFOLLOW;
        }
        options.custom_flags(flags);
    }
    #[cfg(not(unix))]
    if secret {
        ensure!(
            fs::symlink_metadata(path)?.file_type().is_file(),
            "release signing key must be a regular file"
        );
    }
    let file = options.open(path).context("open release input")?;
    let metadata = file.metadata().context("inspect release input")?;
    ensure!(
        metadata.is_file() && metadata.len() <= limit as u64,
        "release input must be a bounded regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if secret {
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "release signing key must not be accessible by group or other users"
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "release input exceeds size limit");
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_input_rejects_oversize_before_loading() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("payload.json");
        fs::File::create(&path)
            .unwrap()
            .set_len(MAX_MANIFEST_BYTES + 1)
            .unwrap();
        assert!(read_file(&path, MAX_MANIFEST_BYTES as usize, false).is_err());
        assert!(read_file(directory.path(), 1024, false).is_err());
        fs::write(&path, b"{}").unwrap();
        assert_eq!(
            read_file(&path, MAX_MANIFEST_BYTES as usize, false).unwrap(),
            b"{}"
        );
    }
    #[cfg(unix)]
    #[test]
    fn signing_key_refuses_symlink_and_public_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        fs::write(&path, b"not-a-secret-test-input").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_file(&link, 1024, true).is_err());
        assert!(read_file(&path, 1024, true).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&path, 1024, true).is_err());
    }
}
