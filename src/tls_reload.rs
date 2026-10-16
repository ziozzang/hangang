//! Certificate hot reload without inotify.
//!
//! Listener certificates (`--tls-cert`, `--admin-tls-cert`) are polled by
//! [`crate::tls::ReloadingTls`]. Client identities used for upstream mutual
//! TLS (native Hopae, the Pumgye authority, Sumunjang decisions) are polled
//! here: every interval the file contents are hashed; a changed and valid
//! certificate/key/CA set bumps the process-wide material generation and asks
//! its owners to rebuild their clients. New connections use the new identity,
//! existing connections finish with the old one. Invalid new material keeps
//! the previous identity, counts a rejection and raises the failing gauge.
//! Polling reads a few kilobytes per file per interval; inotify is never used
//! because inotify instances are scarce on shared Kubernetes nodes.
use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

/// Default poll interval for certificate material.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Current client-material generation. Snapshot preparation reuses a TLS
/// client only when it was built under the same generation.
pub fn generation() -> u64 {
    GENERATION.load(Ordering::Acquire)
}
pub(crate) fn bump() -> u64 {
    GENERATION.fetch_add(1, Ordering::AcqRel) + 1
}

/// Reload outcome counters for one material set, rendered as metrics.
#[derive(Debug, Default)]
pub struct Status {
    reloads: AtomicU64,
    rejected: AtomicU64,
    failing: AtomicBool,
    serial: Mutex<String>,
}
impl Status {
    pub fn reloaded(&self, serial: &str) {
        self.reloads.fetch_add(1, Ordering::Relaxed);
        self.failing.store(false, Ordering::Relaxed);
        *self.serial.lock().unwrap_or_else(|e| e.into_inner()) = serial.to_owned();
    }
    pub fn rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
        self.failing.store(true, Ordering::Relaxed);
    }
    /// Material could not be read; the previous identity stays in use.
    pub fn unreadable(&self) {
        self.failing.store(true, Ordering::Relaxed);
    }
    pub fn recovered(&self) {
        self.failing.store(false, Ordering::Relaxed);
    }
    pub fn set_serial(&self, serial: &str) {
        *self.serial.lock().unwrap_or_else(|e| e.into_inner()) = serial.to_owned();
    }
    pub fn reloads(&self) -> u64 {
        self.reloads.load(Ordering::Relaxed)
    }
    pub fn rejections(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
    pub fn failing(&self) -> bool {
        self.failing.load(Ordering::Relaxed)
    }
    pub fn serial(&self) -> String {
        self.serial
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Named statuses shared with the metrics endpoint.
#[derive(Debug, Default)]
pub struct Registry {
    entries: Mutex<BTreeMap<String, Arc<Status>>>,
}
impl Registry {
    pub fn status(&self, name: &str) -> Arc<Status> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(name.to_owned())
            .or_default()
            .clone()
    }
    pub fn render(&self, out: &mut String) {
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if entries.is_empty() {
            return;
        }
        let label = |name: &str| name.replace(['\\', '"', '\n'], "_");
        out.push_str("# HELP hangang_tls_reloads_total Certificate material reloaded without restart.\n# TYPE hangang_tls_reloads_total counter\n");
        for (name, status) in entries.iter() {
            out.push_str(&format!(
                "hangang_tls_reloads_total{{material=\"{}\"}} {}\n",
                label(name),
                status.reloads()
            ));
        }
        out.push_str("# HELP hangang_tls_reload_rejected_total New certificate material rejected; the previous material stays in use.\n# TYPE hangang_tls_reload_rejected_total counter\n");
        for (name, status) in entries.iter() {
            out.push_str(&format!(
                "hangang_tls_reload_rejected_total{{material=\"{}\"}} {}\n",
                label(name),
                status.rejections()
            ));
        }
        out.push_str("# HELP hangang_tls_reload_failing 1 while the material on disk is invalid and the previous material is still served (alert).\n# TYPE hangang_tls_reload_failing gauge\n");
        for (name, status) in entries.iter() {
            out.push_str(&format!(
                "hangang_tls_reload_failing{{material=\"{}\"}} {}\n",
                label(name),
                u8::from(status.failing())
            ));
        }
    }
}

/// One client identity: CA bundle, certificate chain and private key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Material {
    pub ca: PathBuf,
    pub certificate: PathBuf,
    pub key: PathBuf,
}
impl Material {
    fn digest(&self) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        for path in [&self.ca, &self.certificate, &self.key] {
            let bytes = crate::tls::read_bounded(path)?;
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(&bytes);
        }
        Ok(hasher.finalize().into())
    }
    /// Parse the set exactly as a client would use it.
    fn validate(&self) -> Result<String> {
        crate::tls::mutual_client(
            &self.ca,
            &self.certificate,
            &self.key,
            "validation.invalid",
            b"h2",
        )
        .context("client certificate material is invalid")?;
        let pem = crate::tls::read_bounded(&self.certificate)?;
        let chain =
            rustls_pemfile::certs(&mut pem.as_slice()).collect::<std::io::Result<Vec<_>>>()?;
        let key =
            rustls_pemfile::private_key(&mut crate::tls::read_bounded(&self.key)?.as_slice())?
                .context("private key missing")?;
        rustls::sign::CertifiedKey::from_der(chain, key, &rustls::crypto::ring::default_provider())
            .context("private key does not match the certificate")?;
        leaf_serial(&pem)
    }
}

/// Hex serial of the first certificate in a PEM chain.
pub fn leaf_serial(pem: &[u8]) -> Result<String> {
    let leaf = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .next()
        .context("certificate missing")??;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| anyhow::anyhow!("invalid certificate: {error}"))?;
    Ok(parsed.tbs_certificate.raw_serial_as_string())
}

/// Client identities referenced by a configuration.
pub fn config_material(config: &crate::config::Config) -> Vec<Material> {
    let mut found = std::collections::BTreeSet::new();
    for route in &config.http {
        if let Some(tls) = route
            .auth
            .as_ref()
            .and_then(|auth| auth.native.as_ref())
            .and_then(|native| native.tls.as_ref())
        {
            found.insert(Material {
                ca: tls.ca.clone(),
                certificate: tls.certificate.clone(),
                key: tls.key.clone(),
            });
        }
    }
    if let Some(tls) = config
        .pumgye_authority
        .as_ref()
        .and_then(|authority| authority.tls.as_ref())
    {
        found.insert(Material {
            ca: tls.ca.clone(),
            certificate: tls.certificate.clone(),
            key: tls.key.clone(),
        });
    }
    found.into_iter().collect()
}

/// What a poll decided for one material set.
#[derive(Debug, PartialEq, Eq)]
pub enum Change {
    Unchanged,
    Reloaded(String),
    Rejected(String),
}

/// Digest tracker for a set of materials.
#[derive(Default)]
pub struct Tracker {
    accepted: BTreeMap<Material, [u8; 32]>,
    rejected: BTreeMap<Material, [u8; 32]>,
}
impl Tracker {
    /// Record the digest the running clients were built from.
    pub fn adopt(&mut self, material: &Material) {
        if let Ok(digest) = material.digest() {
            self.accepted.insert(material.clone(), digest);
        }
    }
    /// Compare the files with the adopted digest. A new, valid set is adopted
    /// and reported; an invalid one is reported once per distinct content.
    pub fn poll(&mut self, material: &Material) -> Change {
        let digest = match material.digest() {
            Ok(digest) => digest,
            Err(error) => return Change::Rejected(format!("{error:#}")),
        };
        match self.accepted.get(material) {
            None => {
                self.accepted.insert(material.clone(), digest);
                return Change::Unchanged;
            }
            Some(previous) if *previous == digest => {
                self.rejected.remove(material);
                return Change::Unchanged;
            }
            Some(_) => {}
        }
        if self.rejected.get(material) == Some(&digest) {
            return Change::Unchanged;
        }
        match material.validate() {
            Ok(serial) => {
                self.accepted.insert(material.clone(), digest);
                self.rejected.remove(material);
                Change::Reloaded(serial)
            }
            Err(error) => {
                self.rejected.insert(material.clone(), digest);
                Change::Rejected(format!("{error:#}"))
            }
        }
    }
    /// True while the files hold content that was rejected.
    pub fn is_rejected(&self, material: &Material) -> bool {
        self.rejected.contains_key(material)
    }
    /// Forget sets no longer referenced.
    pub fn retain(&mut self, keep: &[Material]) {
        self.accepted.retain(|material, _| keep.contains(material));
        self.rejected.retain(|material, _| keep.contains(material));
    }
}

/// Callbacks a watcher drives.
#[async_trait::async_trait]
pub trait Owner: Send + Sync {
    /// Materials currently in use.
    fn materials(&self) -> Vec<Material>;
    /// Rebuild clients after `materials` changed on disk (already validated).
    async fn reload(&self) -> Result<()>;
}

/// Upstream client identities named by the active configuration; a rotation
/// rebuilds the snapshot's clients from the unchanged configuration.
pub struct ConfigOwner(pub Arc<crate::admin::Manager>);
#[async_trait::async_trait]
impl Owner for ConfigOwner {
    fn materials(&self) -> Vec<Material> {
        config_material(&self.0.active.load().config)
    }
    async fn reload(&self) -> Result<()> {
        self.0.refresh_tls_material().await
    }
}

/// The guard decision client identity.
pub struct GuardOwner(pub Arc<crate::guard::GuardClient>);
#[async_trait::async_trait]
impl Owner for GuardOwner {
    fn materials(&self) -> Vec<Material> {
        self.0.tls_material()
    }
    async fn reload(&self) -> Result<()> {
        self.0.reload_tls()
    }
}

/// Poll every owner's materials until cancelled.
pub async fn watch(
    owners: Vec<(String, Arc<dyn Owner>)>,
    registry: Arc<Registry>,
    interval: Duration,
    cancel: tokio_util::sync::CancellationToken,
) {
    if interval.is_zero() || owners.is_empty() {
        return;
    }
    let mut trackers: BTreeMap<String, Tracker> = BTreeMap::new();
    for (name, owner) in &owners {
        let tracker = trackers.entry(name.clone()).or_default();
        for material in owner.materials() {
            tracker.adopt(&material);
            if let Ok(pem) = crate::tls::read_bounded(&material.certificate)
                && let Ok(serial) = leaf_serial(&pem)
            {
                registry.status(name).set_serial(&serial);
            }
        }
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        tokio::select! { _ = cancel.cancelled() => break, _ = ticker.tick() => {} }
        for (name, owner) in &owners {
            let status = registry.status(name);
            let materials = owner.materials();
            let tracker = trackers.entry(name.clone()).or_default();
            tracker.retain(&materials);
            let mut changed = None;
            let mut failing = false;
            for material in &materials {
                let polled = {
                    let material = material.clone();
                    let mut moved = std::mem::take(tracker);
                    let result = tokio::task::spawn_blocking(move || {
                        let change = moved.poll(&material);
                        (moved, change)
                    })
                    .await;
                    match result {
                        Ok((back, change)) => {
                            *tracker = back;
                            change
                        }
                        Err(error) => Change::Rejected(format!("{error}")),
                    }
                };
                match polled {
                    Change::Unchanged => {}
                    Change::Reloaded(serial) => changed = Some(serial),
                    Change::Rejected(error) => {
                        failing = true;
                        status.rejected();
                        tracing::error!(material = %name, certificate = %material.certificate.display(), %error, "new TLS client material rejected; keeping the previous identity");
                    }
                }
            }
            failing |= materials.iter().any(|m| tracker.is_rejected(m));
            if let Some(serial) = changed {
                let generation = bump();
                match owner.reload().await {
                    Ok(()) => {
                        status.reloaded(&serial);
                        tracing::info!(material = %name, %serial, generation, "TLS client material reloaded without restart");
                    }
                    Err(error) => {
                        status.rejected();
                        tracing::error!(material = %name, %error, "TLS client material changed but clients could not be rebuilt; previous clients stay in use");
                    }
                }
            } else if !failing && status.failing() {
                status.recovered();
            }
        }
    }
}

/// True when `path` names one of the files of `materials`.
pub fn references(materials: &[Material], path: &Path) -> bool {
    materials
        .iter()
        .any(|m| m.ca == path || m.certificate == path || m.key == path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ca {
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
        pem: String,
    }
    fn write_pair(dir: &Path, name: &str, ca: &Ca) -> Material {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec![format!("{name}.example.test")]).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca.params, &ca.key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        std::fs::write(dir.join("tls.crt"), cert.pem()).unwrap();
        std::fs::write(dir.join("tls.key"), key.serialize_pem()).unwrap();
        std::fs::write(dir.join("ca.crt"), &ca.pem).unwrap();
        Material {
            ca: dir.join("ca.crt"),
            certificate: dir.join("tls.crt"),
            key: dir.join("tls.key"),
        }
    }
    fn ca() -> Ca {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["ca.example.test".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let pem = params.self_signed(&key).unwrap().pem();
        Ca { params, key, pem }
    }

    #[test]
    fn rotation_is_detected_validated_and_bad_material_is_rejected_once() {
        let dir = tempfile::tempdir().unwrap();
        let ca = ca();
        let material = write_pair(dir.path(), "first", &ca);
        let mut tracker = Tracker::default();
        tracker.adopt(&material);
        assert_eq!(tracker.poll(&material), Change::Unchanged);
        write_pair(dir.path(), "second", &ca);
        let Change::Reloaded(serial) = tracker.poll(&material) else {
            panic!("rotation not detected");
        };
        assert!(!serial.is_empty());
        assert_eq!(tracker.poll(&material), Change::Unchanged);
        // An unparsable key is rejected and reported once for that content.
        std::fs::write(dir.path().join("tls.key"), b"truncated key material\n").unwrap();
        assert!(matches!(tracker.poll(&material), Change::Rejected(_)));
        assert_eq!(tracker.poll(&material), Change::Unchanged);
        // A key that does not belong to the certificate is rejected too.
        let other = rcgen::KeyPair::generate().unwrap();
        std::fs::write(dir.path().join("tls.key"), other.serialize_pem()).unwrap();
        assert!(matches!(tracker.poll(&material), Change::Rejected(_)));
        // Fixing the files reloads again.
        write_pair(dir.path(), "third", &ca);
        assert!(matches!(tracker.poll(&material), Change::Reloaded(_)));
    }

    #[test]
    fn snapshot_rebuilds_clients_only_after_a_material_generation_change() {
        // SAFETY: test-only variable read by this test alone.
        unsafe { std::env::set_var("HANGANG_TLS_RELOAD_TEST_DECISION", "d".repeat(32)) };
        let config: crate::config::Config = serde_json::from_value(serde_json::json!({
            "pumgye_authority": {
                "decision_address": "127.0.0.1:9002",
                "management_address": "127.0.0.1:9003",
                "decision_token_env": "HANGANG_TLS_RELOAD_TEST_DECISION",
                "admin_token_env": "HANGANG_TLS_RELOAD_TEST_ADMIN_UNSET"
            }
        }))
        .unwrap();
        let first = crate::config::Snapshot::new(config.clone()).unwrap();
        let same = crate::config::Snapshot::replace(config.clone(), &first).unwrap();
        let (a, b) = (
            first.pumgye_remote.as_ref().unwrap(),
            same.pumgye_remote.as_ref().unwrap(),
        );
        assert!(Arc::ptr_eq(a, b), "unchanged material must reuse clients");
        bump();
        let rotated = crate::config::Snapshot::replace(config, &same).unwrap();
        let c = rotated.pumgye_remote.as_ref().unwrap();
        assert!(!Arc::ptr_eq(b, c), "a rotation must rebuild clients");
        assert_eq!(rotated.material_generation, generation());
    }

    #[test]
    fn registry_renders_reload_metrics() {
        let registry = Registry::default();
        let status = registry.status("guard");
        status.reloaded("0a");
        status.rejected();
        let mut out = String::new();
        registry.render(&mut out);
        assert!(out.contains("hangang_tls_reloads_total{material=\"guard\"} 1"));
        assert!(out.contains("hangang_tls_reload_rejected_total{material=\"guard\"} 1"));
        assert!(out.contains("hangang_tls_reload_failing{material=\"guard\"} 1"));
    }
}
