//! File-backed, configuration-managed TLS certificate sets.
//!
//! Configuration contains only bounded identifiers, host names, and absolute
//! paths. PEM material is read into short-lived buffers and is never serialized.

use crate::{config::Snapshot, tls::SniCertificate};
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::{self, Metadata, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

const MAX_CERTIFICATES: usize = 1024;
const MAX_HOSTS_PER_CERTIFICATE: usize = 128;
const MAX_ID_BYTES: usize = 128;
const MAX_HOST_BYTES: usize = 253;
const MAX_PATH_BYTES: usize = 4096;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_PUBLIC_TOTAL_BYTES: usize = 1024 * 1024;
const FULL_VERIFY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateFiles {
    pub id: String,
    pub hosts: Vec<String>,
    /// Serve this pair only when SNI is absent or has no configured match.
    #[serde(default, skip_serializing_if = "is_false")]
    pub default: bool,
    /// Disabled material remains configured but is not loaded or served.
    #[serde(default = "enabled_by_default", skip_serializing_if = "is_true")]
    pub enabled: bool,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    /// Optional explicit status manifest published by hangang-acme-issuer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_status_file: Option<PathBuf>,
}
fn is_false(value: &bool) -> bool {
    !*value
}
fn enabled_by_default() -> bool {
    true
}
fn is_true(value: &bool) -> bool {
    *value
}

/// Validate certificate metadata without reading secret material from disk.
pub fn validate_set(certificates: &[CertificateFiles]) -> Result<()> {
    ensure!(
        certificates.len() <= MAX_CERTIFICATES,
        "at most 1024 TLS certificates are allowed"
    );
    let mut ids = HashSet::new();
    let mut hosts = HashSet::new();
    let mut default_seen = false;
    for certificate in certificates {
        ensure!(
            !certificate.id.is_empty()
                && certificate.id.len() <= MAX_ID_BYTES
                && certificate
                    .id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte)),
            "invalid TLS certificate id"
        );
        ensure!(
            ids.insert(certificate.id.as_str()),
            "duplicate TLS certificate id"
        );
        if certificate.default {
            ensure!(
                certificate.hosts.is_empty(),
                "default TLS certificate must not claim SNI hosts"
            );
            if certificate.enabled {
                ensure!(
                    !default_seen,
                    "at most one enabled default TLS certificate is allowed"
                );
                default_seen = true;
            }
        } else {
            ensure!(
                !certificate.hosts.is_empty()
                    && certificate.hosts.len() <= MAX_HOSTS_PER_CERTIFICATE,
                "TLS certificate hosts must contain 1..128 names"
            );
        }
        validate_path(&certificate.cert_file, "certificate")?;
        validate_path(&certificate.key_file, "private key")?;
        if let Some(path) = &certificate.issuer_status_file {
            validate_path(path, "issuer status")?;
        }
        for host in &certificate.hosts {
            validate_host(host)?;
            if certificate.enabled {
                ensure!(
                    hosts.insert(host.to_ascii_lowercase()),
                    "duplicate enabled TLS certificate host"
                );
            }
        }
    }
    Ok(())
}

/// Read and validate a complete certificate set. Empty input produces a TLS
/// configuration whose resolver rejects every SNI name.
pub fn load(certificates: &[CertificateFiles]) -> Result<rustls::ServerConfig> {
    let material = read_material(certificates)?;
    crate::tls::sni_server_config(material.certificates)
        .context("validate configured TLS certificate set")
}

/// Named public listener material is bounded independently of legacy TLS.
pub fn load_public(certificates: &[CertificateFiles]) -> Result<rustls::ServerConfig> {
    let material = read_material_with_limit(certificates, MAX_PUBLIC_TOTAL_BYTES)?;
    crate::tls::sni_server_config(material.certificates)
        .context("validate configured public TLS certificate set")
}

/// Poll certificate files and atomically replace only the still-current TLS
/// resolver. Invalid or partially replaced material retains the last good set.
pub async fn watch(active: Arc<ArcSwap<Snapshot>>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_attempt: Option<Attempt> = None;
    let mut last_observation: Option<Observation> = None;
    let mut last_error = String::new();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {}
        }
        let snapshot = active.load_full();
        let Some(target) = snapshot.certificates.clone() else {
            last_attempt = None;
            last_observation = None;
            last_error.clear();
            continue;
        };
        let files = snapshot.config.certificates.clone();
        let inspected_files = files.clone();
        let inspected = tokio::task::spawn_blocking(move || fingerprint(&inspected_files)).await;
        let fingerprint = match inspected {
            Ok(Ok(fingerprint)) => fingerprint,
            Ok(Err(error)) => {
                // A disappearance or nonregular replacement must force a full
                // verification as soon as usable files return.
                last_observation = None;
                report_once(&mut last_error, &error.to_string());
                continue;
            }
            Err(error) => {
                last_observation = None;
                report_once(
                    &mut last_error,
                    &format!("TLS metadata task failed: {error}"),
                );
                continue;
            }
        };
        let now = Instant::now();
        if last_observation.as_ref().is_some_and(|observation| {
            Arc::ptr_eq(&observation.target, &target)
                && observation.files == files
                && observation.fingerprint == fingerprint
                && now.duration_since(observation.checked_at) < FULL_VERIFY_INTERVAL
        }) {
            continue;
        }
        // Remember failed content reads and invalid material as well. An
        // unchanged bad file is retried by the bounded fallback, not every
        // 500 ms.
        last_observation = Some(Observation {
            target: target.clone(),
            files: files.clone(),
            fingerprint,
            checked_at: now,
        });
        let read_files = files.clone();
        let loaded = tokio::task::spawn_blocking(move || read_material(&read_files)).await;
        let material = match loaded {
            Ok(Ok(material)) => material,
            Ok(Err(error)) => {
                report_once(&mut last_error, &error.to_string());
                continue;
            }
            Err(error) => {
                report_once(
                    &mut last_error,
                    &format!("TLS material task failed: {error}"),
                );
                continue;
            }
        };
        if last_attempt.as_ref().is_some_and(|attempt| {
            Arc::ptr_eq(&attempt.target, &target)
                && attempt.files == files
                && attempt.digest == material.digest
        }) {
            continue;
        }
        last_attempt = Some(Attempt {
            target: target.clone(),
            files: files.clone(),
            digest: material.digest,
        });
        let parsed = tokio::task::spawn_blocking(move || {
            crate::tls::sni_server_config(material.certificates)
                .context("validate reloaded TLS certificate set")
        })
        .await;
        let config = match parsed {
            Ok(Ok(config)) => config,
            Ok(Err(error)) => {
                report_once(&mut last_error, &error.to_string());
                continue;
            }
            Err(error) => {
                report_once(
                    &mut last_error,
                    &format!("TLS validation task failed: {error}"),
                );
                continue;
            }
        };
        let current = active.load_full();
        let still_current = current.config.certificates == files
            && current
                .certificates
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &target));
        if still_current {
            target.store(Arc::new(config));
            last_error.clear();
        }
    }
}

/// Reload named public listeners independently; a failed set retains its last
/// verified resolver and cannot affect another listener.
pub async fn watch_public(active: Arc<ArcSwap<Snapshot>>, cancel: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut observations: std::collections::HashMap<String, Observation> = Default::default();
    let mut attempts: std::collections::HashMap<String, Attempt> = Default::default();
    let mut last_errors: std::collections::HashMap<String, String> = Default::default();
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {}
        }
        let snapshot = active.load_full();
        observations.retain(|id, _| snapshot.public_http_tls.contains_key(id));
        attempts.retain(|id, _| snapshot.public_http_tls.contains_key(id));
        last_errors.retain(|id, _| snapshot.public_http_tls.contains_key(id));
        for listener in snapshot
            .config
            .public_http
            .iter()
            .filter(|l| l.enabled && !l.certificates.is_empty())
        {
            let Some(target) = snapshot.public_http_tls.get(&listener.id).cloned() else {
                continue;
            };
            let id = listener.id.clone();
            let files = listener.certificates.clone();
            let inspected = files.clone();
            let Ok(Ok(fingerprint)) =
                tokio::task::spawn_blocking(move || fingerprint(&inspected)).await
            else {
                observations.remove(&id);
                continue;
            };
            let now = Instant::now();
            if observations.get(&id).is_some_and(|seen| {
                Arc::ptr_eq(&seen.target, &target)
                    && seen.files == files
                    && seen.fingerprint == fingerprint
                    && now.duration_since(seen.checked_at) < FULL_VERIFY_INTERVAL
            }) {
                continue;
            }
            observations.insert(
                id.clone(),
                Observation {
                    target: target.clone(),
                    files: files.clone(),
                    fingerprint,
                    checked_at: now,
                },
            );
            let checked = files.clone();
            let material = match tokio::task::spawn_blocking(move || {
                read_material_with_limit(&checked, MAX_PUBLIC_TOTAL_BYTES)
            })
            .await
            {
                Ok(Ok(material)) => material,
                Ok(Err(error)) => {
                    report_once(
                        last_errors.entry(id.clone()).or_default(),
                        &format!("public listener {id}: {error}"),
                    );
                    continue;
                }
                Err(error) => {
                    report_once(
                        last_errors.entry(id.clone()).or_default(),
                        &format!("public listener {id} TLS task failed: {error}"),
                    );
                    continue;
                }
            };
            if attempts.get(&id).is_some_and(|seen| {
                Arc::ptr_eq(&seen.target, &target)
                    && seen.files == files
                    && seen.digest == material.digest
            }) {
                continue;
            }
            attempts.insert(
                id.clone(),
                Attempt {
                    target: target.clone(),
                    files: files.clone(),
                    digest: material.digest,
                },
            );
            let Ok(Ok(config)) = tokio::task::spawn_blocking(move || {
                crate::tls::sni_server_config(material.certificates)
            })
            .await
            else {
                continue;
            };
            let current = active.load_full();
            if current
                .config
                .public_http
                .iter()
                .any(|l| l.enabled && l.id == id && l.certificates == files)
                && current
                    .public_http_tls
                    .get(&id)
                    .is_some_and(|slot| Arc::ptr_eq(slot, &target))
            {
                target.store(Arc::new(config));
                last_errors.remove(&id);
            }
        }
    }
}

struct Attempt {
    target: Arc<ArcSwap<rustls::ServerConfig>>,
    files: Vec<CertificateFiles>,
    digest: [u8; 32],
}

struct Observation {
    target: Arc<ArcSwap<rustls::ServerConfig>>,
    files: Vec<CertificateFiles>,
    fingerprint: MaterialFingerprint,
    checked_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MaterialFingerprint(Vec<FileFingerprint>);

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<std::time::SystemTime>,
    #[cfg(not(unix))]
    created: Option<std::time::SystemTime>,
}

struct LoadedMaterial {
    certificates: Vec<SniCertificate>,
    digest: [u8; 32],
}

fn fingerprint(certificates: &[CertificateFiles]) -> Result<MaterialFingerprint> {
    validate_set(certificates)?;
    let mut fingerprints = Vec::with_capacity(certificates.len().saturating_mul(2));
    for certificate in certificates {
        if !certificate.enabled {
            continue;
        }
        fingerprints.push(file_fingerprint(
            &certificate.cert_file,
            &certificate.id,
            "certificate",
        )?);
        fingerprints.push(file_fingerprint(
            &certificate.key_file,
            &certificate.id,
            "private key",
        )?);
    }
    Ok(MaterialFingerprint(fingerprints))
}

fn file_fingerprint(path: &Path, id: &str, kind: &str) -> Result<FileFingerprint> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("inspect TLS {kind} metadata for certificate {id}"))?;
    ensure!(
        metadata.is_file(),
        "TLS {kind} for certificate {id} is not a regular file"
    );
    Ok(FileFingerprint::from_metadata(&metadata))
}

impl FileFingerprint {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                len: metadata.len(),
                device: metadata.dev(),
                inode: metadata.ino(),
                modified_seconds: metadata.mtime(),
                modified_nanoseconds: metadata.mtime_nsec(),
                changed_seconds: metadata.ctime(),
                changed_nanoseconds: metadata.ctime_nsec(),
            }
        }
        #[cfg(not(unix))]
        {
            Self {
                len: metadata.len(),
                modified: metadata.modified().ok(),
                created: metadata.created().ok(),
            }
        }
    }
}

fn read_material(certificates: &[CertificateFiles]) -> Result<LoadedMaterial> {
    read_material_with_limit(certificates, MAX_TOTAL_BYTES)
}

fn read_material_with_limit(
    certificates: &[CertificateFiles],
    max_total_bytes: usize,
) -> Result<LoadedMaterial> {
    validate_set(certificates)?;
    let mut total = 0usize;
    let mut digest = Sha256::new();
    let mut material = Vec::with_capacity(certificates.len());
    for certificate in certificates {
        if !certificate.enabled {
            continue;
        }
        digest_field(&mut digest, certificate.id.as_bytes());
        digest_field(&mut digest, &[u8::from(certificate.default)]);
        for host in &certificate.hosts {
            digest_field(&mut digest, host.as_bytes());
        }
        digest_field(
            &mut digest,
            certificate.cert_file.as_os_str().as_encoded_bytes(),
        );
        digest_field(
            &mut digest,
            certificate.key_file.as_os_str().as_encoded_bytes(),
        );
        let cert_pem = read_bounded(&certificate.cert_file, &certificate.id, "certificate")?;
        total = total
            .checked_add(cert_pem.len())
            .context("TLS certificate set size overflow")?;
        ensure!(
            total <= max_total_bytes,
            "TLS certificate set exceeds {} MiB",
            max_total_bytes / (1024 * 1024)
        );
        let key_pem = read_bounded(&certificate.key_file, &certificate.id, "private key")?;
        total = total
            .checked_add(key_pem.len())
            .context("TLS certificate set size overflow")?;
        ensure!(
            total <= max_total_bytes,
            "TLS certificate set exceeds {} MiB",
            max_total_bytes / (1024 * 1024)
        );
        digest_field(&mut digest, &cert_pem);
        digest_field(&mut digest, &key_pem);
        material.push(SniCertificate {
            hosts: certificate.hosts.clone(),
            default: certificate.default,
            cert_pem,
            key_pem,
        });
    }
    Ok(LoadedMaterial {
        certificates: material,
        digest: digest.finalize().into(),
    })
}

pub(crate) fn read_bounded(path: &Path, id: &str, kind: &str) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A configured FIFO must not pin a blocking worker or configuration
        // transaction before its file type can be rejected.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("open TLS {kind} file for certificate {id}"))?;
    ensure!(
        file.metadata().context("inspect TLS material")?.is_file(),
        "TLS {kind} for certificate {id} is not a regular file"
    );
    #[cfg(test)]
    record_material_read(path);
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .context("read TLS material")?;
    ensure!(
        bytes.len() <= MAX_FILE_BYTES,
        "TLS {kind} for certificate {id} exceeds 1 MiB"
    );
    Ok(bytes)
}

fn validate_path(path: &Path, kind: &str) -> Result<()> {
    ensure!(path.is_absolute(), "TLS {kind} path must be absolute");
    ensure!(path != Path::new("/"), "TLS {kind} path must name a file");
    ensure!(
        path.as_os_str().as_encoded_bytes().len() <= MAX_PATH_BYTES,
        "TLS {kind} path exceeds 4096 bytes"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_))),
        "TLS {kind} path must not contain '.' or '..'"
    );
    Ok(())
}

fn validate_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty() && host.len() <= MAX_HOST_BYTES && host.is_ascii(),
        "invalid TLS certificate host"
    );
    let probe = if let Some(suffix) = host.strip_prefix("*.") {
        ensure!(
            !suffix.is_empty() && !suffix.contains('*'),
            "invalid TLS wildcard host"
        );
        format!("hangang-certificate-check.{suffix}")
    } else {
        ensure!(!host.contains('*'), "invalid TLS certificate host");
        host.to_owned()
    };
    ensure!(
        rustls::pki_types::ServerName::try_from(probe)
            .is_ok_and(|name| matches!(name, rustls::pki_types::ServerName::DnsName(_))),
        "invalid TLS certificate host"
    );
    Ok(())
}

fn digest_field(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn report_once(previous: &mut String, message: &str) {
    if previous != message {
        tracing::warn!(
            error = message,
            "TLS certificate reload rejected; retaining last good set"
        );
        *previous = message.to_owned();
    }
}

#[cfg(test)]
static MATERIAL_READS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<PathBuf, usize>>,
> = std::sync::OnceLock::new();

#[cfg(test)]
fn record_material_read(path: &Path) {
    let mut reads = MATERIAL_READS
        .get_or_init(Default::default)
        .lock()
        .expect("material read counts lock");
    *reads.entry(path.to_owned()).or_default() += 1;
}

#[cfg(test)]
fn material_reads(paths: &[&Path]) -> usize {
    let reads = MATERIAL_READS
        .get_or_init(Default::default)
        .lock()
        .expect("material read counts lock");
    paths
        .iter()
        .map(|path| reads.get(*path).copied().unwrap_or_default())
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Snapshot};

    #[tokio::test]
    async fn unchanged_files_are_not_read_on_each_metadata_poll() {
        let directory = tempfile::tempdir().unwrap();
        let pair = rcgen::generate_simple_self_signed(vec!["stable-watch.test".into()]).unwrap();
        let cert_file = directory.path().join("stable.crt.pem");
        let key_file = directory.path().join("stable.key.pem");
        fs::write(&cert_file, pair.cert.pem()).unwrap();
        fs::write(&key_file, pair.signing_key.serialize_pem()).unwrap();
        let certificate = CertificateFiles {
            id: "stable".into(),
            hosts: vec!["stable-watch.test".into()],
            default: false,
            enabled: true,
            cert_file: cert_file.clone(),
            key_file: key_file.clone(),
            issuer_status_file: None,
        };
        let snapshot = Snapshot::new(Config {
            certificates: vec![certificate],
            ..Config::default()
        })
        .unwrap();
        let baseline = material_reads(&[&cert_file, &key_file]);
        let active = Arc::new(ArcSwap::from_pointee(snapshot));
        let cancel = CancellationToken::new();
        let watcher = tokio::spawn(watch(active, cancel.clone()));

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if material_reads(&[&cert_file, &key_file]) > baseline {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("watcher should perform its initial content verification");
        let after_initial = material_reads(&[&cert_file, &key_file]);
        assert_eq!(after_initial, baseline + 2);
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert_eq!(
            material_reads(&[&cert_file, &key_file]),
            after_initial,
            "stable files should receive metadata polls without content reads"
        );

        cancel.cancel();
        watcher.await.unwrap();
    }
}
