//! Explicit-CA, certificate-bound identities for inbound TCP mTLS.
//!
//! `authorize_peer` is an application authorization step **after** rustls has
//! completed certificate-chain and (when configured) CRL verification. A
//! caller must not use it to authenticate an unverified certificate chain.
use std::{
    collections::HashSet,
    fs::File,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, ensure};
use rustls::{
    RootCertStore, ServerConfig,
    pki_types::{CertificateDer, CertificateRevocationListDer},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x509_parser::extensions::GeneralName;

const MAX_MATERIAL_BYTES: u64 = 1024 * 1024;
const MAX_CHAIN_CERTIFICATES: usize = 16;
const MAX_SPIFFE_ID_BYTES: usize = 2048;

fn default_handshake_timeout_ms() -> u64 {
    5_000
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_crl_file: Option<PathBuf>,
    pub allowed_uri_sans: Vec<String>,
    #[serde(default = "default_handshake_timeout_ms")]
    pub handshake_timeout_ms: u64,
}

impl Policy {
    /// Validate the policy's shape without touching the filesystem.
    pub fn validate(&self) -> Result<()> {
        for path in [
            Some(&self.cert_file),
            Some(&self.key_file),
            Some(&self.client_ca_file),
            self.client_crl_file.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            ensure!(path.is_absolute(), "mTLS material path must be absolute");
            let spelling = path.to_str().context("mTLS material path must be UTF-8")?;
            ensure!(
                spelling.starts_with('/')
                    && spelling[1..]
                        .split('/')
                        .all(|segment| !segment.is_empty() && segment != "." && segment != ".."),
                "mTLS material path must be normalized"
            );
        }
        ensure!(
            (1..=10_000).contains(&self.handshake_timeout_ms),
            "mTLS handshake_timeout_ms must be 1..=10000"
        );
        ensure!(
            (1..=128).contains(&self.allowed_uri_sans.len()),
            "mTLS allowed_uri_sans must contain 1..=128 identities"
        );
        let mut seen = HashSet::with_capacity(self.allowed_uri_sans.len());
        for uri in &self.allowed_uri_sans {
            validate_spiffe_id(uri)?;
            ensure!(seen.insert(uri), "duplicate mTLS URI SAN");
        }
        Ok(())
    }
}

/// A successfully authorized, exact SPIFFE URI identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    pub uri: String,
    /// Earliest UNIX-seconds expiry of the presented chain and configured CRLs.
    pub expires_at: u64,
}

pub struct Prepared {
    pub server_config: Arc<ServerConfig>,
    allowed: HashSet<String>,
    crl_expires_at: Option<u64>,
    fingerprint: [u8; 32],
}

impl Prepared {
    /// Read and validate all material once while preparing a candidate snapshot.
    pub fn load(policy: &Policy) -> Result<Self> {
        policy.validate()?;
        let cert_bytes = read_bounded(&policy.cert_file)?;
        let key_bytes = read_bounded(&policy.key_file)?;
        let ca_bytes = read_bounded(&policy.client_ca_file)?;
        let crl_bytes = policy
            .client_crl_file
            .as_ref()
            .map(|path| read_bounded(path))
            .transpose()?;

        let certs = rustls_pemfile::certs(&mut Cursor::new(&cert_bytes))
            .collect::<std::io::Result<Vec<_>>>()
            .context("invalid mTLS server certificate PEM")?;
        ensure!(
            !certs.is_empty() && certs.len() <= MAX_CHAIN_CERTIFICATES,
            "mTLS server certificate chain must contain 1..=16 certificates"
        );
        let now = unix_now()?;
        for cert in &certs {
            let (remaining, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|_| anyhow!("invalid mTLS server certificate"))?;
            ensure!(
                remaining.is_empty(),
                "trailing mTLS server certificate data"
            );
            ensure!(
                parsed.validity().not_before.timestamp() <= now as i64
                    && (now as i64) < parsed.validity().not_after.timestamp(),
                "mTLS server certificate is not currently valid"
            );
        }
        let key = rustls_pemfile::private_key(&mut Cursor::new(&key_bytes))
            .context("invalid mTLS server private-key PEM")?
            .context("mTLS server private key is missing")?;
        let ca_certs = rustls_pemfile::certs(&mut Cursor::new(&ca_bytes))
            .collect::<std::io::Result<Vec<_>>>()
            .context("invalid mTLS client CA PEM")?;
        ensure!(
            !ca_certs.is_empty() && ca_certs.len() <= MAX_CHAIN_CERTIFICATES,
            "mTLS client CA must contain 1..=16 certificates"
        );
        let mut roots = RootCertStore::empty();
        for cert in ca_certs {
            roots
                .add(cert)
                .context("invalid mTLS client CA certificate")?;
        }
        let mut verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        let mut crl_expires_at = None;
        if let Some(bytes) = crl_bytes.as_deref() {
            let crls = rustls_pemfile::crls(&mut Cursor::new(bytes))
                .collect::<std::io::Result<Vec<CertificateRevocationListDer<'static>>>>()
                .context("invalid mTLS client CRL PEM")?;
            ensure!(
                !crls.is_empty() && crls.len() <= 16,
                "mTLS client CRL file must contain 1..=16 lists"
            );
            for crl in &crls {
                let (remaining, parsed) = x509_parser::parse_x509_crl(crl.as_ref())
                    .map_err(|_| anyhow!("invalid mTLS client CRL"))?;
                ensure!(remaining.is_empty(), "trailing mTLS client CRL data");
                let next_update = parsed
                    .next_update()
                    .context("mTLS client CRL lacks nextUpdate")?
                    .timestamp();
                let next_update =
                    u64::try_from(next_update).context("mTLS client CRL has invalid nextUpdate")?;
                let this_update = u64::try_from(parsed.last_update().timestamp())
                    .context("mTLS client CRL has invalid thisUpdate")?;
                ensure!(
                    this_update <= now && this_update < next_update,
                    "mTLS client CRL is not currently valid"
                );
                ensure!(next_update > now, "mTLS client CRL has expired");
                crl_expires_at =
                    Some(crl_expires_at.map_or(next_update, |old: u64| old.min(next_update)));
            }
            // rustls defaults to rejecting unknown revocation status. Keep
            // chain-wide checks and require each CRL's nextUpdate to be live.
            verifier = verifier.with_crls(crls).enforce_revocation_expiration();
        }
        let verifier = verifier.build().context("invalid mTLS client verifier")?;
        let mut server_config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .context("invalid mTLS server certificate/key pair")?;
        server_config.session_storage = Arc::new(NoServerSessionStorage {});
        server_config.send_tls13_tickets = 0;
        server_config.max_early_data_size = 0;
        // The builder's default ticketer never produces tickets. It is left
        // unchanged, since that implementation is private in rustls.

        let mut digest = Sha256::new();
        digest.update(b"hangang-workload-tls-v1");
        let canonical_policy = serde_json::to_vec(policy)?;
        for part in [
            Some(canonical_policy.as_slice()),
            Some(cert_bytes.as_slice()),
            Some(key_bytes.as_slice()),
            Some(ca_bytes.as_slice()),
            crl_bytes.as_deref(),
        ] {
            match part {
                Some(bytes) => {
                    digest.update([1]);
                    digest.update((bytes.len() as u64).to_le_bytes());
                    digest.update(bytes);
                }
                None => digest.update([0]),
            }
        }
        Ok(Self {
            server_config: Arc::new(server_config),
            allowed: policy.allowed_uri_sans.iter().cloned().collect(),
            crl_expires_at,
            fingerprint: digest.finalize().into(),
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Authorize the peer presented by a successfully completed rustls handshake.
    pub fn authorize_peer(&self, certs: &[CertificateDer<'_>]) -> Result<Identity> {
        ensure!(
            !certs.is_empty() && certs.len() <= MAX_CHAIN_CERTIFICATES,
            "mTLS peer certificate chain must contain 1..=16 certificates"
        );
        let now = unix_now()?;
        let mut expires_at = self.crl_expires_at.unwrap_or(u64::MAX);
        let mut uri = None;
        for (index, cert) in certs.iter().enumerate() {
            ensure!(
                cert.as_ref().len() <= MAX_MATERIAL_BYTES as usize,
                "mTLS peer certificate exceeds 1 MiB"
            );
            let (remaining, parsed) = x509_parser::parse_x509_certificate(cert.as_ref())
                .map_err(|_| anyhow!("invalid mTLS peer certificate"))?;
            ensure!(remaining.is_empty(), "trailing mTLS peer certificate data");
            let not_before = parsed.validity().not_before.timestamp();
            let not_after = parsed.validity().not_after.timestamp();
            ensure!(
                not_before <= now as i64 && (now as i64) < not_after,
                "mTLS peer certificate is not currently valid"
            );
            let not_after = u64::try_from(not_after).context("invalid peer certificate expiry")?;
            expires_at = expires_at.min(not_after);
            if index == 0 {
                let san = parsed
                    .subject_alternative_name()
                    .map_err(|_| anyhow!("invalid mTLS URI SAN extension"))?
                    .context("mTLS peer certificate lacks URI SAN")?;
                let mut found = None;
                for name in &san.value.general_names {
                    if let GeneralName::URI(candidate) = name {
                        ensure!(found.is_none(), "mTLS peer has multiple URI SANs");
                        validate_spiffe_id(candidate)?;
                        found = Some((*candidate).to_owned());
                    }
                }
                uri = found;
            }
        }
        let uri = uri.context("mTLS peer certificate lacks URI SAN")?;
        ensure!(
            self.allowed.contains(&uri),
            "mTLS peer identity is not allowed"
        );
        ensure!(expires_at > now, "mTLS peer identity has expired");
        Ok(Identity { uri, expires_at })
    }
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("cannot open mTLS material {}", path.display()))?
        .take(MAX_MATERIAL_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_MATERIAL_BYTES as usize,
        "mTLS material exceeds 1 MiB"
    );
    Ok(bytes)
}

fn unix_now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock predates UNIX epoch")?
        .as_secs())
}

/// Validate a canonical SPIFFE URI without normalization that could collapse
/// two distinct certificate byte strings into one identity.
fn validate_spiffe_id(uri: &str) -> Result<()> {
    ensure!(
        uri.len() <= MAX_SPIFFE_ID_BYTES && uri.is_ascii(),
        "SPIFFE URI must be ASCII and at most 2048 bytes"
    );
    let rest = uri
        .strip_prefix("spiffe://")
        .context("mTLS identity must use canonical spiffe:// scheme")?;
    ensure!(
        !rest.contains(['?', '#', '%', '@', ':']),
        "SPIFFE URI contains forbidden URI syntax"
    );
    let (domain, path) = rest.split_once('/').map_or((rest, ""), |(d, p)| (d, p));
    ensure!(
        !domain.is_empty()
            && domain.len() <= 255
            && domain.bytes().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || b"._-".contains(&byte)),
        "SPIFFE trust domain is invalid"
    );
    if !path.is_empty() {
        for segment in path.split('/') {
            ensure!(
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment
                        .bytes()
                        .all(|byte| { byte.is_ascii_alphanumeric() || b"._-".contains(&byte) }),
                "SPIFFE path segment is invalid"
            );
        }
    } else {
        ensure!(!rest.ends_with('/'), "SPIFFE URI has a trailing slash");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, SanType};

    const ID: &str = "spiffe://example.org/ns/demo/sa/client";

    fn policy_with_material() -> (tempfile::TempDir, Policy) {
        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["server.example.org".into()]).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        std::fs::write(dir.path().join("server.pem"), server.cert.pem()).unwrap();
        std::fs::write(
            dir.path().join("server.key"),
            server.signing_key.serialize_pem(),
        )
        .unwrap();
        std::fs::write(dir.path().join("clients.pem"), ca.pem()).unwrap();
        let policy = Policy {
            cert_file: dir.path().join("server.pem"),
            key_file: dir.path().join("server.key"),
            client_ca_file: dir.path().join("clients.pem"),
            client_crl_file: None,
            allowed_uri_sans: vec![ID.to_owned()],
            handshake_timeout_ms: 5_000,
        };
        (dir, policy)
    }

    fn client_certificate(uris: &[&str]) -> CertificateDer<'static> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = uris
            .iter()
            .map(|uri| SanType::URI((*uri).try_into().unwrap()))
            .collect();
        let key = KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().der().clone()
    }

    #[test]
    fn policy_rejects_malformed_and_duplicate_identities() {
        let (_dir, mut policy) = policy_with_material();
        assert!(policy.validate().is_ok());
        for invalid in [
            "spiffe://EXAMPLE.org/ns/demo",
            "spiffe://example.org:443/ns/demo",
            "spiffe://user@example.org/ns/demo",
            "spiffe://example.org/ns/../demo",
            "spiffe://example.org/ns/%64emo",
            "spiffe://example.org/ns//demo",
            "spiffe://example.org/ns/demo/",
            "spiffe://example.org/ns/demo?query=1",
            "spiffe://example.org/ns/demo#fragment",
            "SPIFFE://example.org/ns/demo",
        ] {
            policy.allowed_uri_sans = vec![invalid.into()];
            assert!(policy.validate().is_err(), "accepted {invalid}");
        }
        policy.allowed_uri_sans = vec![ID.into(), ID.into()];
        assert!(policy.validate().is_err());
        policy.allowed_uri_sans = vec![ID.into()];
        policy.handshake_timeout_ms = 10_001;
        assert!(policy.validate().is_err());
        policy.handshake_timeout_ms = 5_000;
        for invalid_path in [
            "/etc/./server.pem",
            "/etc//server.pem",
            "/etc/../server.pem",
            "/etc/server.pem/",
        ] {
            policy.cert_file = invalid_path.into();
            assert!(policy.validate().is_err(), "accepted path {invalid_path}");
        }
        assert!(
            serde_json::from_value::<Policy>(serde_json::json!({
                "cert_file":"/a", "key_file":"/b", "client_ca_file":"/c",
                "allowed_uri_sans":[ID], "unknown": true
            }))
            .is_err()
        );
    }

    #[test]
    fn authorizes_one_exact_uri_and_rejects_ambiguous_or_unknown_uri() {
        let (_dir, policy) = policy_with_material();
        let prepared = Prepared::load(&policy).unwrap();
        assert_eq!(prepared.server_config.send_tls13_tickets, 0);
        assert_eq!(prepared.server_config.max_early_data_size, 0);
        assert!(!prepared.server_config.ticketer.enabled());
        let identity = prepared
            .authorize_peer(&[client_certificate(&[ID])])
            .unwrap();
        assert_eq!(identity.uri, ID);
        assert!(identity.expires_at > unix_now().unwrap());
        assert!(prepared.authorize_peer(&[]).is_err());
        assert!(prepared.authorize_peer(&[client_certificate(&[])]).is_err());
        assert!(
            prepared
                .authorize_peer(&[client_certificate(&[ID, "spiffe://example.org/other"])])
                .is_err()
        );
        assert!(
            prepared
                .authorize_peer(&[client_certificate(&["spiffe://example.org/other"])])
                .is_err()
        );
        assert!(
            prepared
                .authorize_peer(&[client_certificate(&["spiffe://example.org/ns/../demo"])])
                .is_err()
        );
    }

    #[test]
    fn material_fingerprint_changes_when_key_material_changes() {
        let (_dir, policy) = policy_with_material();
        let first = Prepared::load(&policy).unwrap();
        let second = Prepared::load(&policy).unwrap();
        assert_eq!(first.fingerprint(), second.fingerprint());
        let mut revised = policy.clone();
        revised.handshake_timeout_ms += 1;
        assert_ne!(
            first.fingerprint(),
            Prepared::load(&revised).unwrap().fingerprint()
        );
        let other_ca =
            rcgen::generate_simple_self_signed(vec!["other.example.org".into()]).unwrap();
        std::fs::write(&policy.client_ca_file, other_ca.cert.pem()).unwrap();
        assert_ne!(
            first.fingerprint(),
            Prepared::load(&policy).unwrap().fingerprint()
        );
        let other_server =
            rcgen::generate_simple_self_signed(vec!["server.example.org".into()]).unwrap();
        std::fs::write(&policy.cert_file, other_server.cert.pem()).unwrap();
        std::fs::write(&policy.key_file, other_server.signing_key.serialize_pem()).unwrap();
        assert_ne!(
            first.fingerprint(),
            Prepared::load(&policy).unwrap().fingerprint()
        );
    }

    #[test]
    fn malformed_and_oversize_material_fail_before_publication() {
        let (_dir, policy) = policy_with_material();
        std::fs::write(&policy.cert_file, b"not a certificate").unwrap();
        assert!(Prepared::load(&policy).is_err());
        std::fs::write(
            &policy.cert_file,
            vec![b'x'; MAX_MATERIAL_BYTES as usize + 1],
        )
        .unwrap();
        assert!(Prepared::load(&policy).is_err());
    }

    #[test]
    fn rejects_expired_leaf_even_after_prior_tls_verification() {
        let (_dir, policy) = policy_with_material();
        let prepared = Prepared::load(&policy).unwrap();
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![SanType::URI(ID.try_into().unwrap())];
        params.not_before = rcgen::date_time_ymd(2010, 1, 1);
        params.not_after = rcgen::date_time_ymd(2011, 1, 1);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        assert!(prepared.authorize_peer(&[cert.der().clone()]).is_err());
    }

    #[test]
    fn configured_crl_must_parse_and_have_live_next_update() {
        let (dir, mut policy) = policy_with_material();
        let crl_path = dir.path().join("clients.crl");
        policy.client_crl_file = Some(crl_path.clone());
        std::fs::write(&crl_path, b"not a CRL").unwrap();
        assert!(Prepared::load(&policy).is_err());

        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![rcgen::KeyUsagePurpose::CrlSign];
        let ca_key = KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let expired = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2010, 1, 1),
            next_update: rcgen::date_time_ymd(2011, 1, 1),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap();
        std::fs::write(&crl_path, expired.pem().unwrap()).unwrap();
        assert!(Prepared::load(&policy).is_err());
        let future = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2100, 1, 1),
            next_update: rcgen::date_time_ymd(2101, 1, 1),
            crl_number: 2u64.into(),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&issuer)
        .unwrap();
        std::fs::write(&crl_path, future.pem().unwrap()).unwrap();
        assert!(Prepared::load(&policy).is_err());
    }

    fn handshake_fixture() -> (
        tempfile::TempDir,
        Policy,
        tokio_rustls::TlsConnector,
        String,
    ) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let dir = tempfile::tempdir().unwrap();
        let server = rcgen::generate_simple_self_signed(vec!["server.example.org".into()]).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let ca_key = KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
        let mut client_params = CertificateParams::default();
        client_params.serial_number = Some(42u64.into());
        client_params.subject_alt_names = vec![SanType::URI(ID.try_into().unwrap())];
        client_params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client = client_params.signed_by(&client_key, &issuer).unwrap();

        let mut crl_params = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2035, 1, 1),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let valid_crl = crl_params.signed_by(&issuer).unwrap();
        crl_params.revoked_certs.push(rcgen::RevokedCertParams {
            serial_number: 42u64.into(),
            revocation_time: rcgen::date_time_ymd(2021, 1, 1),
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        });
        crl_params.crl_number = 2u64.into();
        let revoked_crl = crl_params.signed_by(&issuer).unwrap();

        std::fs::write(dir.path().join("server.pem"), server.cert.pem()).unwrap();
        std::fs::write(
            dir.path().join("server.key"),
            server.signing_key.serialize_pem(),
        )
        .unwrap();
        std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(dir.path().join("ca.crl"), valid_crl.pem().unwrap()).unwrap();
        let policy = Policy {
            cert_file: dir.path().join("server.pem"),
            key_file: dir.path().join("server.key"),
            client_ca_file: dir.path().join("ca.pem"),
            client_crl_file: Some(dir.path().join("ca.crl")),
            allowed_uri_sans: vec![ID.to_owned()],
            handshake_timeout_ms: 5_000,
        };

        let mut roots = RootCertStore::empty();
        roots.add(server.cert.der().clone()).unwrap();
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![client.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        )
        .unwrap();
        (
            dir,
            policy,
            tokio_rustls::TlsConnector::from(Arc::new(client_config)),
            revoked_crl.pem().unwrap(),
        )
    }

    async fn duplex_handshake(
        prepared: &Prepared,
        connector: &tokio_rustls::TlsConnector,
    ) -> Result<Identity> {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let acceptor = tokio_rustls::TlsAcceptor::from(prepared.server_config.clone());
        let server_task = async {
            let stream = acceptor.accept(server).await?;
            let certs = stream
                .get_ref()
                .1
                .peer_certificates()
                .context("rustls accepted a peer without certificates")?;
            prepared.authorize_peer(certs)
        };
        let client_task = connector.connect(
            rustls::pki_types::ServerName::try_from("server.example.org").unwrap(),
            client,
        );
        let (server_result, _client_result) = tokio::join!(server_task, client_task);
        server_result
    }

    #[tokio::test]
    async fn real_tls_handshake_accepts_unrevoked_and_rejects_revoked_client() {
        let (_dir, policy, connector, revoked_crl) = handshake_fixture();
        let allowed = Prepared::load(&policy).unwrap();
        let identity = duplex_handshake(&allowed, &connector).await.unwrap();
        assert_eq!(identity.uri, ID);

        // Reuse the very same client connector. A renewed server generation
        // that revokes this certificate must not be bypassed by resumption.
        std::fs::write(policy.client_crl_file.as_ref().unwrap(), revoked_crl).unwrap();
        let revoked = Prepared::load(&policy).unwrap();
        assert_ne!(allowed.fingerprint(), revoked.fingerprint());
        assert!(duplex_handshake(&revoked, &connector).await.is_err());
    }

    #[tokio::test]
    async fn crl_from_another_ca_never_authorizes_peer() {
        let (_dir, policy, connector, _) = handshake_fixture();
        let mut other_ca = CertificateParams::default();
        other_ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        other_ca.key_usages = vec![rcgen::KeyUsagePurpose::CrlSign];
        let other_key = KeyPair::generate().unwrap();
        let other_issuer = rcgen::Issuer::from_params(&other_ca, &other_key);
        let unrelated_crl = rcgen::CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2020, 1, 1),
            next_update: rcgen::date_time_ymd(2035, 1, 1),
            crl_number: 1u64.into(),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        }
        .signed_by(&other_issuer)
        .unwrap();
        std::fs::write(
            policy.client_crl_file.as_ref().unwrap(),
            unrelated_crl.pem().unwrap(),
        )
        .unwrap();
        if let Ok(prepared) = Prepared::load(&policy) {
            assert!(duplex_handshake(&prepared, &connector).await.is_err());
        }
    }
}
