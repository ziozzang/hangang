//! Certificate replacement is validated before publication; existing sessions
//! retain their original TLS state. No key material enters the admin response.
use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwap;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::{
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub struct ReloadingTls {
    pub current: ArcSwap<ServerConfig>,
    files: Option<(PathBuf, PathBuf)>,
    /// Digest of the material currently published from `files`.
    published: std::sync::Mutex<Option<[u8; 32]>>,
    /// Number of reloads rejected because the material failed to parse.
    /// Identical rejected material is parsed only once.
    rejected: std::sync::atomic::AtomicU64,
}
enum Reload {
    Unchanged,
    Replaced([u8; 32], Box<ServerConfig>),
    Rejected([u8; 32], anyhow::Error),
}
fn pair_digest(cert: &[u8], key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((cert.len() as u64).to_le_bytes());
    hasher.update(cert);
    hasher.update((key.len() as u64).to_le_bytes());
    hasher.update(key);
    hasher.finalize().into()
}
impl ReloadingTls {
    pub fn new(cert: PathBuf, key: PathBuf) -> Result<Self> {
        let (cert_pem, key_pem) = (read_bounded(&cert)?, read_bounded(&key)?);
        let config = server_config(&cert_pem, &key_pem)?;
        Ok(Self {
            current: ArcSwap::from_pointee(config),
            files: Some((cert, key)),
            published: std::sync::Mutex::new(Some(pair_digest(&cert_pem, &key_pem))),
            rejected: std::sync::atomic::AtomicU64::new(0),
        })
    }
    pub fn dynamic(config: ServerConfig) -> Self {
        Self {
            current: ArcSwap::from_pointee(config),
            files: None,
            published: std::sync::Mutex::new(None),
            rejected: std::sync::atomic::AtomicU64::new(0),
        }
    }
    /// Reloads rejected by parsing since start; each distinct bad pair counts once.
    pub fn rejected_reloads(&self) -> u64 {
        self.rejected.load(std::sync::atomic::Ordering::Relaxed)
    }
    pub async fn watch(self: Arc<Self>, cancel: CancellationToken) {
        let Some((cert_path, key_path)) = &self.files else {
            return;
        };
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut rejected: Option<[u8; 32]> = None;
        let mut last_error = String::new();
        loop {
            tokio::select! {biased;_=cancel.cancelled()=>break,_=interval.tick()=>{}}
            let cert = cert_path.clone();
            let key = key_path.clone();
            let published = self.published.lock().map(|p| *p).unwrap_or(None);
            // Reading and parsing both run off the async executor. Material
            // whose digest matches the published pair or the last rejected pair
            // is not parsed again, so repeatedly bad files cost one parse.
            let result = tokio::task::spawn_blocking(move || -> Result<Reload> {
                let (cert, key) = (read_bounded(&cert)?, read_bounded(&key)?);
                let digest = pair_digest(&cert, &key);
                if Some(digest) == published || Some(digest) == rejected {
                    return Ok(Reload::Unchanged);
                }
                Ok(match server_config(&cert, &key) {
                    Ok(config) => Reload::Replaced(digest, Box::new(config)),
                    Err(error) => Reload::Rejected(digest, error),
                })
            })
            .await;
            match result {
                Ok(Ok(Reload::Replaced(digest, config))) => {
                    self.current.store(Arc::new(*config));
                    if let Ok(mut published) = self.published.lock() {
                        *published = Some(digest);
                    }
                    rejected = None;
                    last_error.clear();
                }
                Ok(Ok(Reload::Rejected(digest, error))) => {
                    rejected = Some(digest);
                    self.rejected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let text = error.to_string();
                    if text != last_error {
                        tracing::warn!(%error,"TLS reload rejected; keeping previous certificate");
                        last_error = text;
                    }
                }
                Ok(Ok(Reload::Unchanged)) => {}
                Ok(Err(error)) => {
                    let text = format!("{error:?}");
                    if text != last_error {
                        tracing::warn!(error=%text,"TLS material read failed");
                        last_error = text;
                    }
                }
                Err(join) => {
                    let text = format!("{join:?}");
                    if text != last_error {
                        tracing::warn!(error=%text,"TLS material read failed");
                        last_error = text;
                    }
                }
            }
        }
    }
}
fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .context("open TLS material")?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 1024 * 1024, "TLS material exceeds 1 MiB");
    Ok(bytes)
}
pub fn server_config(cert: &[u8], key: &[u8]) -> Result<ServerConfig> {
    let certificates =
        rustls_pemfile::certs(&mut Cursor::new(cert)).collect::<std::io::Result<Vec<_>>>()?;
    ensure!(!certificates.is_empty(), "certificate chain is empty");
    let key =
        rustls_pemfile::private_key(&mut Cursor::new(key))?.context("private key is missing")?;
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .context("invalid certificate/key pair")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}
pub fn client_config(extra_ca: Option<&Path>) -> Result<ClientConfig> {
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = extra_ca {
        let bytes = read_bounded(path)?;
        let certs =
            rustls_pemfile::certs(&mut Cursor::new(bytes)).collect::<std::io::Result<Vec<_>>>()?;
        ensure!(!certs.is_empty(), "upstream CA file is empty");
        for cert in certs {
            roots.add(cert)?;
        }
    }
    Ok(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
#[derive(Clone, Copy, Default)]
pub struct TransportInfo {
    pub tls: bool,
    /// Local port the client connected to, for X-Forwarded-Port generation.
    pub local_port: u16,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_invalid_material() {
        assert!(server_config(b"bad", b"bad").is_err());
        assert!(client_config(None).is_ok());
    }
    #[test]
    fn validates_matching_key_and_alpn() {
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let c = server_config(
            pair.cert.pem().as_bytes(),
            pair.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        assert_eq!(c.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
        let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        assert!(
            server_config(
                pair.cert.pem().as_bytes(),
                wrong.signing_key.serialize_pem().as_bytes()
            )
            .is_err()
        );
    }
}

/// A complete controller certificate set; no private material is serialized by
/// the management API. Replacing the set also removes deleted SNI names.
pub struct SniCertificate {
    pub hosts: Vec<String>,
    pub default: bool,
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}
#[derive(Debug, Default)]
struct SniResolver {
    exact: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    wildcard: std::collections::HashMap<String, Arc<rustls::sign::CertifiedKey>>,
    default: Option<Arc<rustls::sign::CertifiedKey>>,
}
impl SniResolver {
    fn for_name(&self, name: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let name = name.to_ascii_lowercase();
        let key = self.exact.get(&name).or_else(|| {
            let (label, suffix) = name.split_once('.')?;
            if label.is_empty() {
                return None;
            }
            self.wildcard.get(suffix)
        })?;
        let parsed =
            rustls::server::ParsedCertificate::try_from(key.end_entity_cert().ok()?).ok()?;
        let server_name = rustls::pki_types::ServerName::try_from(name).ok()?;
        rustls::client::verify_server_name(&parsed, &server_name).ok()?;
        Some(key.clone())
    }
}
impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        hello
            .server_name()
            .and_then(|name| self.for_name(name))
            .or_else(|| self.default.clone())
    }
}
pub fn sni_server_config(certificates: Vec<SniCertificate>) -> Result<ServerConfig> {
    ensure!(certificates.len() <= 1024, "too many TLS certificates");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut resolver = SniResolver::default();
    let mut bytes = 0usize;
    for certificate in certificates {
        bytes += certificate.cert_pem.len() + certificate.key_pem.len();
        ensure!(
            bytes <= 16 * 1024 * 1024,
            "TLS certificate set exceeds 16 MiB"
        );
        ensure!(
            (certificate.default && certificate.hosts.is_empty())
                || (!certificate.default
                    && !certificate.hosts.is_empty()
                    && certificate.hosts.len() <= 128),
            "invalid TLS host count or default certificate hosts"
        );
        let chain = rustls_pemfile::certs(&mut Cursor::new(&certificate.cert_pem))
            .collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(&certificate.key_pem))?
            .context("TLS private key is missing")?;
        let certified = Arc::new(rustls::sign::CertifiedKey::from_der(chain, key, &provider)?);
        if certificate.default {
            ensure!(
                resolver.default.is_none(),
                "at most one default TLS certificate is allowed"
            );
            resolver.default = Some(certified);
            continue;
        }
        for host in certificate.hosts {
            let host = host.to_ascii_lowercase();
            let probe = host
                .strip_prefix("*.")
                .map(|suffix| format!("hangang-certificate-check.{suffix}"))
                .unwrap_or_else(|| host.clone());
            let name =
                rustls::pki_types::ServerName::try_from(probe).context("invalid TLS host")?;
            let parsed = rustls::server::ParsedCertificate::try_from(certified.end_entity_cert()?)?;
            rustls::client::verify_server_name(&parsed, &name)
                .context("TLS certificate does not cover host")?;
            let (map, name) = if let Some(suffix) = host.strip_prefix("*.") {
                (&mut resolver.wildcard, suffix.to_owned())
            } else {
                (&mut resolver.exact, host)
            };
            if let Some(previous) = map.get(&name) {
                ensure!(
                    previous.cert == certified.cert,
                    "conflicting TLS certificate claims"
                );
            }
            map.insert(name, certified.clone());
        }
    }
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}
