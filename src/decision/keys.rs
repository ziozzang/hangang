//! Pseudonymization key epochs (ADR 0019 "Privacy").
//!
//! Each epoch owns a random 256-bit secret. Pseudonyms are
//! `HMAC-SHA-256(epoch pseudonym key, domain || value)` truncated to 80 bits;
//! sealed values are ChaCha20-Poly1305 under the epoch seal key with the event
//! ID as associated data. Removing an epoch from the key file destroys every
//! link between its pseudonyms/sealed values and people (crypto-shredding).
//!
//! All replicas of one deployment point at the same key file (a secret
//! reference) so pseudonyms correlate across nodes. Exactly one owner manages
//! it (`manage_keys`); other replicas only read it.

use anyhow::{Context, Result, bail, ensure};
use base64::Engine;
use hmac::{Hmac, Mac};
use ring::aead;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use zeroize::Zeroizing;

const FILE_VERSION: u32 = 1;
const DOMAIN: &[u8] = b"hangang.decision.v1\0";
pub const MIN_ROTATION_SECONDS: u64 = 3600;
pub const MAX_ROTATION_SECONDS: u64 = 30 * 86_400;
/// Hard maximum store retention plus one epoch: no key outlives its data.
pub const MAX_RETENTION_SECONDS: u64 = 90 * 86_400 + MAX_ROTATION_SECONDS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Domain {
    Ip,
    Prefix,
    Subject,
    Session,
}

impl Domain {
    fn label(self) -> &'static [u8] {
        match self {
            Domain::Ip => b"ip\0",
            Domain::Prefix => b"pfx\0",
            Domain::Subject => b"sub\0",
            Domain::Session => b"ses\0",
        }
    }
    pub fn prefix(self) -> &'static str {
        match self {
            Domain::Ip => hangang_decision_event::IP_REF,
            Domain::Prefix => hangang_decision_event::PREFIX_REF,
            Domain::Subject => hangang_decision_event::SUBJECT_REF,
            Domain::Session => hangang_decision_event::SESSION_REF,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEpoch {
    index: u64,
    key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    rotation_seconds: u64,
    epochs: Vec<FileEpoch>,
}

struct Epoch {
    secret: Zeroizing<[u8; 32]>,
    /// Pre-keyed HMAC state, cloned per pseudonym.
    pseudonym: Hmac<Sha256>,
    seal: aead::LessSafeKey,
}

fn derive(secret: &[u8; 32], label: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("HMAC accepts any key");
    mac.update(label);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

impl Epoch {
    fn new(secret: [u8; 32]) -> Self {
        let secret = Zeroizing::new(secret);
        let pseudonym_key = derive(&secret, b"hangang.decision.v1/pseudonym");
        let pseudonym = <Hmac<Sha256> as Mac>::new_from_slice(pseudonym_key.as_slice())
            .expect("HMAC accepts any key");
        let seal_key = derive(&secret, b"hangang.decision.v1/seal");
        let seal = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::CHACHA20_POLY1305, seal_key.as_slice())
                .expect("32-byte key"),
        );
        Self {
            secret,
            pseudonym,
            seal,
        }
    }
}

/// Immutable view of the key epochs; replaced atomically on change.
pub struct KeyRing {
    rotation_ms: u64,
    epochs: BTreeMap<u64, Epoch>,
}

/// Canonical prefix of an address: /24 for IPv4, /48 for IPv6.
pub fn prefix_bytes(ip: IpAddr) -> ([u8; 17], usize) {
    let mut out = [0u8; 17];
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            out[..3].copy_from_slice(&o[..3]);
            out[3] = 24;
            (out, 4)
        }
        IpAddr::V6(v6) => {
            let o = v6.octets();
            out[..6].copy_from_slice(&o[..6]);
            out[6] = 48;
            (out, 7)
        }
    }
}

pub fn ip_bytes(ip: IpAddr) -> ([u8; 16], usize) {
    let mut out = [0u8; 16];
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            out[..4].copy_from_slice(&v4.octets());
            (out, 4)
        }
        IpAddr::V6(v6) => {
            out.copy_from_slice(&v6.octets());
            (out, 16)
        }
    }
}

impl KeyRing {
    pub fn empty(rotation_seconds: u64) -> Self {
        Self {
            rotation_ms: rotation_seconds * 1000,
            epochs: BTreeMap::new(),
        }
    }

    pub fn rotation_ms(&self) -> u64 {
        self.rotation_ms
    }

    pub fn epoch_index(&self, time_ms: u64) -> u64 {
        time_ms / self.rotation_ms
    }

    pub fn has_epoch(&self, index: u64) -> bool {
        self.epochs.contains_key(&index)
    }

    pub fn epochs(&self) -> impl Iterator<Item = u64> + '_ {
        self.epochs.keys().copied()
    }

    /// Display label of an epoch start: a date for whole-day rotation,
    /// otherwise the UTC start minute.
    pub fn label(&self, index: u64) -> String {
        let start = index * self.rotation_ms;
        let text = hangang_decision_event::rfc3339_ms(start);
        if self.rotation_ms.is_multiple_of(86_400_000) {
            text[..10].to_owned()
        } else {
            format!("{}Z", &text[..16])
        }
    }

    /// `prefix~BASE32` pseudonym, or `None` when the epoch key is absent
    /// (never generated, or destroyed).
    pub fn pseudonym(&self, index: u64, domain: Domain, value: &[u8]) -> Option<String> {
        let epoch = self.epochs.get(&index)?;
        let mut mac = epoch.pseudonym.clone();
        mac.update(DOMAIN);
        mac.update(domain.label());
        mac.update(value);
        Some(hangang_decision_event::pseudonym(
            domain.prefix(),
            &mac.finalize().into_bytes(),
        ))
    }

    pub fn ip_ref(&self, index: u64, ip: IpAddr) -> Option<String> {
        let (bytes, len) = ip_bytes(ip);
        self.pseudonym(index, Domain::Ip, &bytes[..len])
    }

    pub fn prefix_ref(&self, index: u64, ip: IpAddr) -> Option<String> {
        let (bytes, len) = prefix_bytes(ip);
        self.pseudonym(index, Domain::Prefix, &bytes[..len])
    }

    pub fn subject_ref(&self, index: u64, subject: &[u8]) -> Option<String> {
        self.pseudonym(index, Domain::Subject, subject)
    }

    /// nonce || ciphertext || tag, bound to the event ID and field.
    pub fn seal(
        &self,
        index: u64,
        event_id: &[u8; 16],
        field: &[u8],
        plaintext: &[u8],
        rng: &SystemRandom,
    ) -> Option<Vec<u8>> {
        let epoch = self.epochs.get(&index)?;
        let mut nonce = [0u8; 12];
        rng.fill(&mut nonce).ok()?;
        let mut aad = Vec::with_capacity(16 + field.len());
        aad.extend_from_slice(event_id);
        aad.extend_from_slice(field);
        let mut out = Vec::with_capacity(12 + plaintext.len() + 16);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plaintext);
        let mut body = out.split_off(12);
        epoch
            .seal
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut body,
            )
            .ok()?;
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Opens a sealed value while its epoch key exists (reveal path).
    pub fn open(
        &self,
        index: u64,
        event_id: &[u8; 16],
        field: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        let epoch = self.epochs.get(&index)?;
        if sealed.len() < 12 + 16 {
            return None;
        }
        let nonce: [u8; 12] = sealed[..12].try_into().ok()?;
        let mut aad = Vec::with_capacity(16 + field.len());
        aad.extend_from_slice(event_id);
        aad.extend_from_slice(field);
        let mut body = sealed[12..].to_vec();
        let plain = epoch
            .seal
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(&aad),
                &mut body,
            )
            .ok()?;
        Some(plain.to_vec())
    }

    fn parse(text: &[u8], rotation_seconds: u64) -> Result<Self> {
        let file: File = serde_json::from_slice(text).context("decision key file")?;
        ensure!(
            file.version == FILE_VERSION,
            "unsupported decision key file version"
        );
        ensure!(
            file.rotation_seconds == rotation_seconds,
            "decision key file rotation differs from configuration"
        );
        ensure!(file.epochs.len() <= 4096, "too many decision key epochs");
        let mut ring = Self::empty(rotation_seconds);
        for epoch in file.epochs {
            let bytes = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(epoch.key.as_bytes())
                    .context("decision key encoding")?,
            );
            let secret: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("decision key must be 32 bytes"))?;
            ensure!(
                ring.epochs
                    .insert(epoch.index, Epoch::new(secret))
                    .is_none(),
                "duplicate decision key epoch"
            );
        }
        Ok(ring)
    }

    fn serialize(&self) -> Zeroizing<Vec<u8>> {
        let file = File {
            version: FILE_VERSION,
            rotation_seconds: self.rotation_ms / 1000,
            epochs: self
                .epochs
                .iter()
                .map(|(index, epoch)| FileEpoch {
                    index: *index,
                    key: base64::engine::general_purpose::STANDARD.encode(epoch.secret.as_slice()),
                })
                .collect(),
        };
        Zeroizing::new(serde_json::to_vec_pretty(&file).expect("serializable"))
    }

    /// Reads a key file. A missing file yields an empty ring.
    pub fn load(path: &Path, rotation_seconds: u64) -> Result<Self> {
        match std::fs::read(path) {
            Ok(text) => {
                let text = Zeroizing::new(text);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = std::fs::metadata(path)?.permissions().mode();
                    ensure!(
                        mode & 0o077 == 0,
                        "decision key file must not be readable by group or others"
                    );
                }
                Self::parse(&text, rotation_seconds)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(Self::empty(rotation_seconds))
            }
            Err(error) => Err(error).context("read decision key file"),
        }
    }

    /// Owner maintenance: ensures the current and next epoch keys exist and
    /// destroys every epoch whose end is older than `retention_ms`. Returns
    /// the new ring and the destroyed epoch indexes when anything changed.
    pub fn maintain(
        &self,
        now_ms: u64,
        retention_ms: u64,
        rng: &SystemRandom,
    ) -> Result<Option<(KeyRing, Vec<u64>)>> {
        let current = self.epoch_index(now_ms);
        let mut next = KeyRing::empty(self.rotation_ms / 1000);
        let mut destroyed = Vec::new();
        let mut changed = false;
        for (index, epoch) in &self.epochs {
            let end = (index + 1) * self.rotation_ms;
            if end.saturating_add(retention_ms) <= now_ms || *index > current + 1 {
                destroyed.push(*index);
                changed = true;
            } else {
                next.epochs.insert(*index, Epoch::new(*epoch.secret));
            }
        }
        for index in [current, current + 1] {
            if let std::collections::btree_map::Entry::Vacant(slot) = next.epochs.entry(index) {
                let mut secret = [0u8; 32];
                if rng.fill(&mut secret).is_err() {
                    bail!("secure random unavailable");
                }
                slot.insert(Epoch::new(secret));
                secret.fill(0);
                changed = true;
            }
        }
        Ok(changed.then_some((next, destroyed)))
    }

    /// Atomic 0600 replacement of the key file.
    pub fn store(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        let mut temp = tempfile::NamedTempFile::new_in(dir).context("decision key temp file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            temp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        temp.write_all(&self.serialize())?;
        temp.as_file().sync_all()?;
        temp.persist(path).context("persist decision key file")?;
        if let Ok(dir) = std::fs::File::open(dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring_at(now: u64, rng: &SystemRandom) -> KeyRing {
        KeyRing::empty(3600)
            .maintain(now, 7 * 86_400_000, rng)
            .unwrap()
            .unwrap()
            .0
    }

    #[test]
    fn pseudonyms_are_domain_separated_and_stable_within_an_epoch() {
        let rng = SystemRandom::new();
        let now = 1_760_605_964_512;
        let ring = ring_at(now, &rng);
        let epoch = ring.epoch_index(now);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        let a = ring.ip_ref(epoch, ip).unwrap();
        assert_eq!(a, ring.ip_ref(epoch, ip).unwrap());
        assert!(hangang_decision_event::is_pseudonym("ip", &a));
        // Same bytes in another domain never collide.
        let (bytes, len) = ip_bytes(ip);
        assert_ne!(ring.subject_ref(epoch, &bytes[..len]).unwrap()[4..], a[3..]);
        // Prefix groups a /24.
        assert_eq!(
            ring.prefix_ref(epoch, ip),
            ring.prefix_ref(epoch, "203.0.113.200".parse().unwrap())
        );
        assert_ne!(
            ring.prefix_ref(epoch, ip),
            ring.prefix_ref(epoch, "203.0.114.7".parse().unwrap())
        );
        // IPv4-mapped IPv6 is canonical.
        assert_eq!(
            ring.ip_ref(epoch, ip),
            ring.ip_ref(epoch, "::ffff:203.0.113.7".parse().unwrap())
        );
        // A different epoch yields an unlinkable pseudonym.
        assert_ne!(ring.ip_ref(epoch + 1, ip).unwrap(), a);
    }

    #[test]
    fn rotation_and_destruction_crypto_shred_old_epochs() {
        let rng = SystemRandom::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let t0 = 1_760_605_964_512u64;
        let retention = 2 * 3_600_000;
        let (ring, _) = KeyRing::load(&path, 3600)
            .unwrap()
            .maintain(t0, retention, &rng)
            .unwrap()
            .unwrap();
        ring.store(&path).unwrap();
        let old = ring.epoch_index(t0);
        let id = [7u8; 16];
        let subject_ref = ring.subject_ref(old, b"u_alice").unwrap();
        let sealed = ring.seal(old, &id, b"sub", b"u_alice", &rng).unwrap();
        assert_eq!(ring.open(old, &id, b"sub", &sealed).unwrap(), b"u_alice");
        // Bound to the event and field.
        assert!(ring.open(old, &[8; 16], b"sub", &sealed).is_none());
        assert!(ring.open(old, &id, b"ip", &sealed).is_none());

        // A replica reading the same file derives the same pseudonym.
        let replica = KeyRing::load(&path, 3600).unwrap();
        assert_eq!(replica.subject_ref(old, b"u_alice").unwrap(), subject_ref);

        // Past retention the epoch is destroyed in memory and on disk.
        let later = t0 + 4 * 3_600_000;
        let (ring, destroyed) = ring.maintain(later, retention, &rng).unwrap().unwrap();
        ring.store(&path).unwrap();
        assert!(destroyed.contains(&old));
        assert!(ring.subject_ref(old, b"u_alice").is_none());
        assert!(ring.open(old, &id, b"sub", &sealed).is_none());
        let reloaded = KeyRing::load(&path, 3600).unwrap();
        assert!(!reloaded.has_epoch(old));
        assert!(
            !std::fs::read_to_string(&path)
                .unwrap()
                .contains(&subject_ref)
        );
        // New epochs never reproduce the destroyed pseudonym.
        for epoch in reloaded.epochs() {
            assert_ne!(
                reloaded.subject_ref(epoch, b"u_alice").unwrap(),
                subject_ref
            );
        }
    }

    #[test]
    fn key_files_are_private_and_rotation_is_pinned() {
        let rng = SystemRandom::new();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys.json");
        let (ring, _) = KeyRing::empty(86_400)
            .maintain(1_760_605_964_512, 86_400_000, &rng)
            .unwrap()
            .unwrap();
        ring.store(&path).unwrap();
        assert_eq!(
            ring.label(ring.epoch_index(1_760_605_964_512)),
            "2025-10-16"
        );
        assert!(KeyRing::load(&path, 3600).is_err());
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(KeyRing::load(&path, 86_400).is_err());
        assert_eq!(KeyRing::empty(3600).label(0), "1970-01-01T00:00Z");
    }
}
