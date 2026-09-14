//! Bounded, public-certificate-only metadata for the administrator inventory.
//! A configured path is not proof that its bytes are in the live TLS resolver.
use crate::certificates::CertificateFiles;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

pub const PAGE_LIMIT: usize = 64;
const MAX_STATUS_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
pub struct Inventory {
    pub revision: u64,
    pub listener_id: String,
    pub mode: &'static str,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub server_time_unix_ms: u64,
    pub certificates: Vec<Entry>,
    pub in_process_acme: Option<InProcessAcme>,
}

#[derive(Serialize)]
pub struct InProcessAcme {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub expires_unix_ms: Option<u64>,
    pub phase: String,
    pub tls_available: bool,
}

impl From<crate::acme_runtime::Status> for InProcessAcme {
    fn from(status: crate::acme_runtime::Status) -> Self {
        Self {
            enabled: status.enabled,
            domains: status.domains,
            expires_unix_ms: status
                .expires_unix
                .map(|seconds| seconds.saturating_mul(1000)),
            phase: status.phase,
            tls_available: status.tls_available,
        }
    }
}

#[derive(Serialize)]
pub struct Entry {
    pub id: String,
    pub configured_hosts: Vec<String>,
    pub default: bool,
    pub enabled: bool,
    pub source: &'static str,
    pub read_state: &'static str,
    pub san_dns: Vec<String>,
    pub issuer: Option<String>,
    pub not_before_unix_ms: Option<u64>,
    pub not_after_unix_ms: Option<u64>,
    pub fingerprint_sha256: Option<String>,
    pub tls_binding: &'static str,
    pub renewal: Option<Renewal>,
}

#[derive(Serialize)]
pub struct Renewal {
    pub state: &'static str,
    pub challenge: String,
    pub checked_at_unix_ms: u64,
    pub renew_before_unix_ms: Option<u64>,
    pub retry_next_unix_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerManifest {
    version: u8,
    manager: String,
    challenge: String,
    domains: Vec<String>,
    phase: String,
    certificate_fingerprint_sha256: Option<String>,
    expires_unix_ms: Option<u64>,
    checked_at_unix_ms: u64,
    renew_before_unix_ms: Option<u64>,
    retry_next_unix_ms: Option<u64>,
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub fn entries(files: &[CertificateFiles], configured_tls: bool, now: u64) -> Vec<Entry> {
    files
        .iter()
        .map(|file| entry(file, configured_tls, now))
        .collect()
}

fn entry(file: &CertificateFiles, configured_tls: bool, now: u64) -> Entry {
    let mut item = Entry {
        id: file.id.clone(),
        configured_hosts: file.hosts.clone(),
        default: file.default,
        enabled: file.enabled,
        source: "configured_file",
        read_state: "unavailable",
        san_dns: Vec::new(),
        issuer: None,
        not_before_unix_ms: None,
        not_after_unix_ms: None,
        fingerprint_sha256: None,
        tls_binding: if !file.enabled {
            "disabled"
        } else if configured_tls {
            "configured"
        } else {
            "unknown"
        },
        renewal: None,
    };
    let status = file
        .issuer_status_file
        .as_deref()
        .and_then(|path| read_status(path).ok());
    let bytes = match crate::certificates::read_bounded(&file.cert_file, &file.id, "certificate") {
        Ok(bytes) => bytes,
        Err(_) => return with_pending_status(item, status, &file.hosts, now),
    };
    item.read_state = "invalid";
    let Ok(der) = rustls_pemfile::certs(&mut std::io::Cursor::new(&bytes))
        .next()
        .transpose()
    else {
        return with_pending_status(item, status, &file.hosts, now);
    };
    let Some(der) = der else {
        return with_pending_status(item, status, &file.hosts, now);
    };
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(der.as_ref()) else {
        return with_pending_status(item, status, &file.hosts, now);
    };
    let san_dns = match parsed.subject_alternative_name() {
        Ok(Some(extension)) => extension
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                x509_parser::extensions::GeneralName::DNSName(name) => Some(name.to_string()),
                _ => None,
            })
            .filter(|name| name.len() <= 253 && name.is_ascii())
            .take(128)
            .collect(),
        _ => Vec::new(),
    };
    let fingerprint = format!("{:x}", Sha256::digest(der.as_ref()));
    let not_after = unix_millis(parsed.validity().not_after.timestamp());
    item.read_state = "ok";
    item.san_dns = san_dns;
    item.issuer = Some(parsed.issuer().to_string().chars().take(1024).collect());
    item.not_before_unix_ms = unix_millis(parsed.validity().not_before.timestamp());
    item.not_after_unix_ms = not_after;
    item.fingerprint_sha256 = Some(fingerprint.clone());
    if let Some(status) = status
        && valid_status(&status, &file.hosts)
        && status.certificate_fingerprint_sha256.as_deref() == Some(&fingerprint)
        && status.expires_unix_ms == not_after
    {
        item.source = "standalone_acme";
        item.renewal = Some(renewal(status, now));
    }
    item
}

fn with_pending_status(
    mut item: Entry,
    status: Option<IssuerManifest>,
    hosts: &[String],
    now: u64,
) -> Entry {
    if let Some(status) = status
        && valid_status(&status, hosts)
        && status.certificate_fingerprint_sha256.is_none()
        && status.expires_unix_ms.is_none()
    {
        item.source = "standalone_acme";
        item.renewal = Some(renewal(status, now));
    }
    item
}

fn valid_status(status: &IssuerManifest, hosts: &[String]) -> bool {
    status.version == 1
        && status.manager == "hangang-acme-issuer"
        && matches!(status.challenge.as_str(), "dns-01" | "http-01")
        && matches!(status.phase.as_str(), "ready" | "renewing" | "retrying")
        && same_hosts(&status.domains, hosts)
}

fn renewal(status: IssuerManifest, now: u64) -> Renewal {
    let stale = status.checked_at_unix_ms > now.saturating_add(30_000)
        || now.saturating_sub(status.checked_at_unix_ms) > 120_000;
    Renewal {
        state: if stale {
            "stale"
        } else if status.phase == "ready" {
            "ready"
        } else if status.phase == "renewing" {
            "renewing"
        } else {
            "retrying"
        },
        challenge: status.challenge,
        checked_at_unix_ms: status.checked_at_unix_ms,
        renew_before_unix_ms: status.renew_before_unix_ms,
        retry_next_unix_ms: status.retry_next_unix_ms,
    }
}

fn unix_millis(seconds: i64) -> Option<u64> {
    u64::try_from(seconds).ok()?.checked_mul(1000)
}

fn same_hosts(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left: Vec<_> = left.iter().map(|host| host.to_ascii_lowercase()).collect();
    let mut right: Vec<_> = right.iter().map(|host| host.to_ascii_lowercase()).collect();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

fn read_status(path: &Path) -> Result<IssuerManifest> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.permissions().mode() & 0o077 == 0,
        "issuer status is not a private owned regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_STATUS_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_STATUS_BYTES,
        "issuer status is too large"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn issuer_attribution_requires_explicit_private_matching_manifest() {
        let directory = tempfile::tempdir().unwrap();
        let pair = rcgen::generate_simple_self_signed(vec!["example.test".into()]).unwrap();
        let cert = directory.path().join("cert.pem");
        let status = directory.path().join("issuer-status.json");
        std::fs::write(&cert, pair.cert.pem()).unwrap();
        let der = rustls_pemfile::certs(&mut std::io::Cursor::new(pair.cert.pem()))
            .next()
            .unwrap()
            .unwrap();
        let fingerprint = format!("{:x}", Sha256::digest(der.as_ref()));
        let file = CertificateFiles {
            id: "one".into(),
            hosts: vec!["example.test".into()],
            default: false,
            enabled: true,
            cert_file: cert,
            key_file: directory.path().join("unused.key"),
            issuer_status_file: Some(status.clone()),
        };
        let now = now_unix_ms();
        let initial = entry(&file, true, now);
        assert_eq!(initial.read_state, "ok");
        assert_eq!(initial.source, "configured_file");
        let expires = initial.not_after_unix_ms.unwrap();
        let manifest = serde_json::json!({
            "version":1,"manager":"hangang-acme-issuer","challenge":"dns-01",
            "domains":["example.test"],"phase":"ready",
            "certificate_fingerprint_sha256":fingerprint,"expires_unix_ms":expires,
            "checked_at_unix_ms":now,"renew_before_unix_ms":now + 86_400_000,"retry_next_unix_ms":null
        });
        std::fs::write(&status, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o600)).unwrap();
        let attributed = entry(&file, true, now);
        assert_eq!(attributed.source, "standalone_acme");
        let renewal = attributed.renewal.unwrap();
        assert_eq!(renewal.state, "ready");
        assert_eq!(renewal.renew_before_unix_ms, Some(now + 86_400_000));
        let stale = entry(&file, true, now + 121_000);
        assert_eq!(stale.renewal.unwrap().state, "stale");
        let mut wrong = manifest;
        wrong["certificate_fingerprint_sha256"] = serde_json::json!("0".repeat(64));
        std::fs::write(&status, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert_eq!(entry(&file, true, now).source, "configured_file");
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(entry(&file, true, now).source, "configured_file");
    }

    #[test]
    fn first_issuance_pending_reports_only_registered_nonsecret_state() {
        let directory = tempfile::tempdir().unwrap();
        let status = directory.path().join("issuer-status.json");
        let now = now_unix_ms();
        let file = CertificateFiles {
            id: "pending".into(),
            hosts: vec!["pending.test".into()],
            default: false,
            enabled: true,
            cert_file: directory.path().join("not-issued.pem"),
            key_file: directory.path().join("not-issued.key"),
            issuer_status_file: Some(status.clone()),
        };
        std::fs::write(
            &status,
            serde_json::to_vec(&serde_json::json!({
                "version":1,"manager":"hangang-acme-issuer","challenge":"http-01",
                "domains":["pending.test"],"phase":"renewing",
                "certificate_fingerprint_sha256":null,"expires_unix_ms":null,
                "checked_at_unix_ms":now,"renew_before_unix_ms":null,"retry_next_unix_ms":null
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o600)).unwrap();
        let pending = entry(&file, false, now);
        assert_eq!(pending.source, "standalone_acme");
        assert_eq!(pending.read_state, "unavailable");
        assert!(pending.fingerprint_sha256.is_none());
        assert_eq!(pending.renewal.unwrap().state, "renewing");
    }
}
