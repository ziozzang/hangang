//! Signed release verification, staging, and atomic on-disk activation.
//!
//! This module deliberately does not restart the process. A supervisor or the
//! server's future readiness handoff owns process replacement and connection
//! draining after a candidate has been staged and activated.

use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use reqwest::{Client, Url, redirect};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;

pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
pub const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

/// A valid signed manifest describes the version that is already running.
/// Periodic checkers can downcast `anyhow::Error` to this type and report a
/// healthy no-op separately from rejected or failed updates.
#[derive(Debug)]
pub struct UpToDate {
    version: Version,
}

impl UpToDate {
    pub fn version(&self) -> &Version {
        &self.version
    }
}

impl std::fmt::Display for UpToDate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "release {} is already running", self.version)
    }
}

impl std::error::Error for UpToDate {}

#[derive(Clone)]
pub struct TrustKey(VerifyingKey);

impl TrustKey {
    /// Parse an operator-provided base64 Ed25519 public key (exactly 32 bytes).
    pub fn from_base64(encoded: &str) -> Result<Self> {
        let decoded = STANDARD
            .decode(encoded.trim())
            .context("update trust key is not valid base64")?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| anyhow::anyhow!("update trust key must decode to exactly 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&bytes).context("invalid Ed25519 update trust key")?;
        ensure!(
            !key.is_weak(),
            "weak Ed25519 update trust key is not allowed"
        );
        Ok(Self(key))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub version: Version,
    pub target: String,
    pub artifact_url: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedEnvelope {
    payload: String,
    signature: String,
}

/// Sign the exact JSON bytes supplied by a release process and wrap them in an
/// envelope. Verification never reserializes the payload before checking it.
pub fn sign_release_manifest(payload_json: &[u8], signing_key: &SigningKey) -> Result<Vec<u8>> {
    ensure!(
        payload_json.len() <= MAX_MANIFEST_BYTES as usize,
        "release payload exceeds 64 KiB"
    );
    let manifest: ReleaseManifest =
        serde_json::from_slice(payload_json).context("invalid release manifest payload")?;
    validate_manifest_fields(&manifest)?;
    let signature = signing_key.sign(payload_json);
    let envelope = SignedEnvelope {
        payload: STANDARD.encode(payload_json),
        signature: STANDARD.encode(signature.to_bytes()),
    };
    let encoded = serde_json::to_vec(&envelope).context("serialize signed release manifest")?;
    ensure!(
        encoded.len() <= MAX_MANIFEST_BYTES as usize,
        "signed release manifest exceeds 64 KiB"
    );
    Ok(encoded)
}

/// Parse a base64 Ed25519 signing seed for the offline release helper. The
/// secret is never accepted by the network updater or stored in its state.
pub fn signing_key_from_base64(encoded: &str) -> Result<SigningKey> {
    let decoded = STANDARD
        .decode(encoded.trim())
        .context("release signing key is not valid base64")?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("release signing key must decode to exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub struct UpdateManager {
    trust_key: TrustKey,
    current_version: Version,
    target: String,
    client: Client,
    allow_loopback_http: bool,
}

impl UpdateManager {
    /// Construct a production updater. Both manifest and artifact requests are
    /// restricted to HTTPS, and redirects cannot change origin.
    pub fn new(
        trust_key: TrustKey,
        current_version: Version,
        target: impl Into<String>,
    ) -> Result<Self> {
        Self::new_with_ca(trust_key, current_version, target, None)
    }

    /// Construct a production updater with an optional additional HTTPS root
    /// certificate, for a private release origin selected by the operator.
    pub fn new_with_ca(
        trust_key: TrustKey,
        current_version: Version,
        target: impl Into<String>,
        additional_root: Option<reqwest::Certificate>,
    ) -> Result<Self> {
        Self::build(
            trust_key,
            current_version,
            target.into(),
            false,
            additional_root,
            false,
        )
    }

    /// Construct an updater that additionally permits IP-literal loopback HTTP.
    /// This exists for hermetic test fixtures and must not be used for releases.
    #[doc(hidden)]
    pub fn loopback_http_for_tests(
        trust_key: TrustKey,
        current_version: Version,
        target: impl Into<String>,
    ) -> Result<Self> {
        Self::build(trust_key, current_version, target.into(), true, None, false)
    }

    /// GitHub release assets may redirect only to GitHub's release CDN.
    pub fn new_github(
        trust_key: TrustKey,
        current_version: Version,
        target: impl Into<String>,
    ) -> Result<Self> {
        Self::build(trust_key, current_version, target.into(), false, None, true)
    }

    pub async fn stage_github(&self, destination_dir: &Path) -> Result<StagedUpdate> {
        let release =
            crate::github_release::fetch(&self.client, crate::github_release::API_URL).await?;
        let version = release.version()?;
        if version == self.current_version {
            return Err(UpToDate { version }.into());
        }
        ensure!(
            version > self.current_version,
            "GitHub release is older than the running version"
        );
        let selection = release.select(&self.target)?;
        self.stage_selected(&selection.manifest_url, destination_dir, Some(&selection))
            .await
    }

    fn build(
        trust_key: TrustKey,
        current_version: Version,
        target: String,
        allow_loopback_http: bool,
        additional_root: Option<reqwest::Certificate>,
        github_assets: bool,
    ) -> Result<Self> {
        ensure!(!target.trim().is_empty(), "update target cannot be empty");
        let mut client = update_client_builder(allow_loopback_http, github_assets);
        if let Some(root) = additional_root {
            client = client.add_root_certificate(root);
        }
        let client = client.build().context("build update HTTPS client")?;
        Ok(Self {
            trust_key,
            current_version,
            target,
            client,
            allow_loopback_http,
        })
    }

    /// Fetch and verify a signed manifest and artifact, leaving an executable
    /// candidate in `destination_dir`. Failures and cancellation remove the
    /// partial temporary file.
    pub async fn stage(&self, manifest_url: &str, destination_dir: &Path) -> Result<StagedUpdate> {
        self.stage_selected(manifest_url, destination_dir, None)
            .await
    }

    async fn stage_selected(
        &self,
        manifest_url: &str,
        destination_dir: &Path,
        expected: Option<&crate::github_release::Selection>,
    ) -> Result<StagedUpdate> {
        let manifest_url = parse_transport_url(manifest_url, self.allow_loopback_http)
            .context("invalid update manifest URL")?;
        ensure!(
            destination_dir.is_dir(),
            "update destination is not a directory"
        );

        let response = self
            .client
            .get(manifest_url)
            .send()
            .await
            .context("fetch signed update manifest")?
            .error_for_status()
            .context("update manifest server returned an error")?;
        let envelope_bytes = read_response_limited(response, MAX_MANIFEST_BYTES, "64 KiB").await?;
        let manifest = self.verify_envelope(&envelope_bytes)?;
        if let Some(expected) = expected {
            ensure!(
                manifest.version == expected.version,
                "signed manifest version differs from GitHub release tag"
            );
            ensure!(
                manifest.artifact_url == expected.artifact_url,
                "signed artifact URL differs from selected GitHub asset"
            );
            ensure!(
                manifest.size == expected.artifact_size,
                "signed artifact size differs from GitHub asset size"
            );
        }
        let artifact_url = parse_transport_url(&manifest.artifact_url, self.allow_loopback_http)
            .context("invalid signed artifact URL")?;

        let response = self
            .client
            .get(artifact_url)
            .send()
            .await
            .context("fetch signed update artifact")?
            .error_for_status()
            .context("update artifact server returned an error")?;
        if let Some(length) = response.content_length() {
            ensure!(
                length == manifest.size,
                "artifact length does not match signed size"
            );
        }

        let temporary = tempfile::Builder::new()
            .prefix(".hangang-update-")
            .tempfile_in(destination_dir)
            .context("create staged update file")?;
        set_executable(temporary.as_file())?;
        let async_file = temporary
            .reopen()
            .context("open staged update file for download")?;
        let mut async_file = tokio::fs::File::from_std(async_file);
        let mut response = response;
        let mut digest = Sha256::new();
        let mut received = 0_u64;
        while let Some(chunk) = response.chunk().await.context("read update artifact")? {
            received = received
                .checked_add(chunk.len() as u64)
                .context("artifact length overflow")?;
            ensure!(received <= MAX_ARTIFACT_BYTES, "artifact exceeds 128 MiB");
            ensure!(received <= manifest.size, "artifact exceeds signed size");
            digest.update(&chunk);
            async_file
                .write_all(&chunk)
                .await
                .context("write staged update")?;
        }
        ensure!(
            received == manifest.size,
            "artifact length does not match signed size"
        );
        let actual_digest = format!("{:x}", digest.finalize());
        ensure!(
            actual_digest == manifest.sha256,
            "artifact SHA-256 digest mismatch"
        );
        async_file.flush().await.context("flush staged update")?;
        async_file.sync_all().await.context("fsync staged update")?;
        drop(async_file);

        // `keep` transfers cleanup ownership to StagedUpdate. Before this point,
        // NamedTempFile removes a partial file if the future is cancelled.
        let (_, path) = temporary.keep().context("retain staged update")?;
        let staged = StagedUpdate {
            path: Some(path),
            version: manifest.version,
            target: manifest.target,
            sha256: manifest.sha256,
            size: manifest.size,
        };
        sync_directory(destination_dir).context("fsync update staging directory")?;
        Ok(staged)
    }

    fn verify_envelope(&self, encoded: &[u8]) -> Result<ReleaseManifest> {
        ensure!(
            encoded.len() <= MAX_MANIFEST_BYTES as usize,
            "signed release manifest exceeds 64 KiB"
        );
        let envelope: SignedEnvelope =
            serde_json::from_slice(encoded).context("invalid signed release manifest envelope")?;
        let payload = STANDARD
            .decode(&envelope.payload)
            .context("manifest payload is not valid base64")?;
        let signature_bytes = STANDARD
            .decode(&envelope.signature)
            .context("manifest signature is not valid base64")?;
        let signature = Signature::from_slice(&signature_bytes)
            .context("manifest signature must be exactly 64 bytes")?;
        self.trust_key
            .0
            .verify_strict(&payload, &signature)
            .context("update manifest signature verification failed")?;
        let manifest: ReleaseManifest =
            serde_json::from_slice(&payload).context("invalid signed release manifest payload")?;
        validate_manifest_fields(&manifest)?;
        ensure!(
            manifest.target == self.target,
            "signed release target does not match this binary"
        );
        if manifest.version == self.current_version {
            return Err(UpToDate {
                version: manifest.version,
            }
            .into());
        }
        ensure!(
            manifest.version > self.current_version,
            "signed release version is a downgrade"
        );
        Ok(manifest)
    }

    /// Atomically replace a fake or installed binary with a staged candidate.
    /// The prior file is retained as a hard-linked rollback path.
    pub fn activate(mut staged: StagedUpdate, install_path: &Path) -> Result<ActivatedUpdate> {
        #[cfg(not(unix))]
        bail!("atomic update activation is currently supported only on Unix");

        let staged_path = staged
            .path
            .as_ref()
            .context("staged update was already consumed")?;
        let install_parent = install_path
            .parent()
            .context("install path has no parent")?;
        ensure!(install_parent.is_dir(), "install parent is not a directory");
        let staged_parent = staged_path.parent().context("staged path has no parent")?;
        ensure!(
            fs::canonicalize(staged_parent)? == fs::canonicalize(install_parent)?,
            "staged update and install path must be in the same directory"
        );
        ensure_regular_file(staged_path, "staged update")?;
        ensure_regular_file(install_path, "installed binary")?;
        verify_file(staged_path, staged.size, &staged.sha256)
            .context("staged update changed before activation")?;

        let placeholder = tempfile::Builder::new()
            .prefix(".hangang-rollback-")
            .tempfile_in(install_parent)
            .context("reserve rollback path")?;
        let rollback_path = placeholder.path().to_owned();
        placeholder.close().context("prepare rollback path")?;
        fs::hard_link(install_path, &rollback_path).context("retain rollback binary")?;
        let mut rollback_guard = RollbackGuard::new(rollback_path.clone());
        sync_directory(install_parent).context("fsync retained rollback")?;

        fs::rename(staged_path, install_path).context("atomically activate staged update")?;
        staged.path = None;
        if let Err(error) = sync_directory(install_parent) {
            match fs::rename(&rollback_path, install_path) {
                Ok(()) => {
                    let _ = sync_directory(install_parent);
                    bail!("fsync activated update directory: {error}; restored rollback");
                }
                Err(rollback_error) => {
                    // Keep the rollback path for an operator or caller to recover.
                    rollback_guard.commit();
                    bail!(
                        "fsync activated update directory: {error}; automatic rollback failed: {rollback_error}; rollback retained at {}",
                        rollback_path.display()
                    );
                }
            }
        }
        rollback_guard.commit();
        Ok(ActivatedUpdate {
            install_path: install_path.to_owned(),
            rollback_path,
            version: staged.version.clone(),
            target: staged.target.clone(),
        })
    }

    /// Atomically restore the retained binary. The activated candidate is
    /// replaced and the rollback link is consumed.
    pub fn rollback(activated: ActivatedUpdate) -> Result<()> {
        ensure_regular_file(&activated.install_path, "activated binary")?;
        ensure_regular_file(&activated.rollback_path, "rollback binary")?;
        fs::rename(&activated.rollback_path, &activated.install_path)
            .context("atomically restore rollback binary")?;
        let parent = activated
            .install_path
            .parent()
            .context("install path has no parent")?;
        sync_directory(parent).context("fsync rollback directory")
    }
}

#[derive(Debug)]
pub struct StagedUpdate {
    path: Option<PathBuf>,
    version: Version,
    target: String,
    sha256: String,
    size: u64,
}

impl StagedUpdate {
    pub fn path(&self) -> &Path {
        self.path.as_deref().expect("staged update path is present")
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn target(&self) -> &str {
        &self.target
    }
}

impl Drop for StagedUpdate {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Debug)]
pub struct ActivatedUpdate {
    install_path: PathBuf,
    rollback_path: PathBuf,
    version: Version,
    target: String,
}

impl ActivatedUpdate {
    pub fn install_path(&self) -> &Path {
        &self.install_path
    }

    pub fn rollback_path(&self) -> &Path {
        &self.rollback_path
    }

    pub fn version(&self) -> &Version {
        &self.version
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    /// Delete a rollback only when the caller has independently established
    /// that the newly started process is healthy.
    pub fn discard_rollback(self) -> Result<()> {
        fs::remove_file(&self.rollback_path).context("remove retained rollback binary")?;
        if let Some(parent) = self.rollback_path.parent() {
            sync_directory(parent).context("fsync rollback removal")?;
        }
        Ok(())
    }
}

struct RollbackGuard {
    path: PathBuf,
    committed: bool,
}

impl RollbackGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for RollbackGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub(crate) async fn read_response_limited(
    mut response: reqwest::Response,
    maximum: u64,
    display_limit: &str,
) -> Result<Vec<u8>> {
    if let Some(length) = response.content_length() {
        ensure!(length <= maximum, "response exceeds {display_limit}");
    }
    let mut received = 0_u64;
    let mut bytes = Vec::with_capacity(response.content_length().unwrap_or(0) as usize);
    while let Some(chunk) = response.chunk().await.context("read update response")? {
        received = received
            .checked_add(chunk.len() as u64)
            .context("update response length overflow")?;
        ensure!(received <= maximum, "response exceeds {display_limit}");
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_manifest_fields(manifest: &ReleaseManifest) -> Result<()> {
    ensure!(
        !manifest.target.trim().is_empty(),
        "release target cannot be empty"
    );
    ensure!(
        manifest.size <= MAX_ARTIFACT_BYTES,
        "signed artifact size exceeds 128 MiB"
    );
    ensure!(manifest.size > 0, "signed artifact cannot be empty");
    ensure!(
        manifest.sha256.len() == 64
            && manifest
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "signed artifact SHA-256 must be 64 lowercase hexadecimal characters"
    );
    let url = Url::parse(&manifest.artifact_url).context("signed artifact URL is invalid")?;
    reject_url_credentials(&url)?;
    ensure!(
        url.fragment().is_none(),
        "update URLs cannot contain fragments"
    );
    Ok(())
}

fn parse_transport_url(raw: &str, allow_loopback_http: bool) -> Result<Url> {
    let url = Url::parse(raw).context("URL is invalid")?;
    validate_transport_url(&url, allow_loopback_http)?;
    Ok(url)
}

fn validate_transport_url(url: &Url, allow_loopback_http: bool) -> Result<()> {
    reject_url_credentials(url)?;
    ensure!(
        url.fragment().is_none(),
        "update URLs cannot contain fragments"
    );
    ensure!(url.host_str().is_some(), "update URL has no host");
    match url.scheme() {
        "https" => Ok(()),
        "http" if allow_loopback_http && is_ip_literal_loopback(url) => Ok(()),
        "http" => bail!("plain HTTP is allowed only for an injected IP-loopback test fixture"),
        _ => bail!("update URL must use HTTPS"),
    }
}

fn reject_url_credentials(url: &Url) -> Result<()> {
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "credentials in update URLs are forbidden"
    );
    Ok(())
}

fn is_ip_literal_loopback(url: &Url) -> bool {
    url.host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn set_executable(file: &fs::File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o700))
            .context("set staged update executable permissions")?;
    }
    Ok(())
}

fn ensure_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    ensure!(
        metadata.file_type().is_file(),
        "{label} must be a regular file"
    );
    Ok(())
}

fn verify_file(path: &Path, expected_size: u64, expected_digest: &str) -> Result<()> {
    let mut file = fs::File::open(path).context("open staged file for verification")?;
    let metadata = file.metadata().context("inspect staged file")?;
    ensure!(
        metadata.len() == expected_size,
        "staged file length mismatch"
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .context("read staged file for verification")?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    ensure!(
        format!("{:x}", digest.finalize()) == expected_digest,
        "staged file digest mismatch"
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

fn update_client_builder(allow_loopback_http: bool, github_assets: bool) -> reqwest::ClientBuilder {
    let policy = redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() > 5 {
            return attempt.error("too many update redirects");
        }
        let Some(first) = attempt.previous().first() else {
            return attempt.error("redirect has no original URL");
        };
        let allowed = if github_assets {
            crate::github_release::asset_redirect_allowed(first, attempt.url())
        } else {
            same_origin(first, attempt.url())
        };
        if !allowed {
            return attempt.error("cross-origin update redirect is forbidden");
        }
        if validate_transport_url(attempt.url(), allow_loopback_http).is_err() {
            return attempt.error("unsafe update redirect URL");
        }
        attempt.follow()
    });
    Client::builder()
        .redirect(policy)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .user_agent(concat!("hangang/", env!("CARGO_PKG_VERSION")))
}

#[cfg(test)]
#[path = "update_github_tests.rs"]
mod github_tests;
