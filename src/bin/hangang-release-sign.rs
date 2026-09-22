use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hangang::update::{MAX_MANIFEST_BYTES, sign_release_manifest, signing_key_from_base64};
use std::{
    fs,
    io::Write,
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
        validate_secret_file(&key_path)?;
        let encoded_key = fs::read_to_string(&key_path).context("read release signing key")?;
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

    let payload = fs::read(&payload_path).context("read release manifest payload")?;
    ensure!(
        payload.len() <= MAX_MANIFEST_BYTES as usize,
        "release payload exceeds 64 KiB"
    );
    validate_secret_file(&key_path)?;
    let encoded_key = fs::read_to_string(&key_path).context("read release signing key")?;
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

fn validate_secret_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).context("inspect release signing key")?;
    ensure!(
        metadata.file_type().is_file(),
        "release signing key must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "release signing key must not be accessible by group or other users"
        );
    }
    ensure!(
        metadata.len() <= 1024,
        "release signing key file is unexpectedly large"
    );
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
