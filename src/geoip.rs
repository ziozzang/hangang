//! Bounded, offline country lookup from an operator-provided MaxMind MMDB.
//!
//! Loading and MMDB structural verification are synchronous and must be called
//! from a blocking worker. Country-code schema is checked per lookup, with
//! malformed records reported as errors. A loaded `Database` is immutable and
//! safe to share with requests; publication and fail-closed reloads belong to
//! the caller.

use std::{
    fs::{self, Metadata, OpenOptions},
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use maxminddb::{path, Reader};
use sha2::{Digest, Sha256};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(14 * 24 * 60 * 60);
pub const MAX_AGE: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// Safe, path-free failures for administrative status and admission decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeoIpError {
    InvalidLimits,
    InvalidPath,
    Unavailable,
    NotRegularFile,
    TooLarge,
    ChangedDuringRead,
    InvalidDatabase,
    UnsupportedDatabase,
    StaleDatabase,
    FutureDatabase,
    Clock,
    InvalidRecord,
}

impl GeoIpError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidLimits => "invalid_limits",
            Self::InvalidPath => "invalid_path",
            Self::Unavailable => "unavailable",
            Self::NotRegularFile => "not_regular_file",
            Self::TooLarge => "too_large",
            Self::ChangedDuringRead => "changed_during_read",
            Self::InvalidDatabase => "invalid_database",
            Self::UnsupportedDatabase => "unsupported_database",
            Self::StaleDatabase => "stale_database",
            Self::FutureDatabase => "future_database",
            Self::Clock => "clock",
            Self::InvalidRecord => "invalid_record",
        }
    }
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for GeoIpError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CountryCode([u8; 2]);

impl CountryCode {
    fn from_db(value: &str) -> Result<Self, GeoIpError> {
        let bytes = value.as_bytes();
        if bytes.len() == 2 && bytes.iter().all(u8::is_ascii_uppercase) {
            Ok(Self([bytes[0], bytes[1]]))
        } else {
            Err(GeoIpError::InvalidRecord)
        }
    }

    pub fn as_str(&self) -> &str {
        // `from_db` accepts only uppercase ASCII bytes.
        std::str::from_utf8(&self.0).expect("validated ASCII country code")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseStatus {
    pub database_type: String,
    pub ip_version: u16,
    pub build_epoch_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub loaded_at_unix_ms: u64,
    pub generation_sha256: String,
    pub file_bytes: u64,
}

pub struct Database {
    reader: Reader<Vec<u8>>,
    status: DatabaseStatus,
    build_time: SystemTime,
    expires_at: SystemTime,
    expires_deadline: Instant,
    freshness_failure: AtomicU8,
}

const FRESH: u8 = 0;
const EXPIRED: u8 = 1;
const CLOCK_REVERSED: u8 = 2;

impl Database {
    /// Loads and verifies one immutable generation. Call from `spawn_blocking`.
    /// Symlinks to regular files are permitted for atomic updater/Kubernetes
    /// layouts; the opened file and path are checked again after bounded read.
    pub fn load(
        path: &Path,
        max_file_bytes: u64,
        max_age: Duration,
    ) -> Result<Arc<Self>, GeoIpError> {
        Self::load_at(path, max_file_bytes, max_age, SystemTime::now())
    }

    pub(crate) fn load_at(
        path: &Path,
        max_file_bytes: u64,
        max_age: Duration,
        now: SystemTime,
    ) -> Result<Arc<Self>, GeoIpError> {
        // Capture both clocks before file reading and verification. Time spent
        // preparing the generation must consume, not extend, its lifetime.
        let load_instant = Instant::now();
        if max_file_bytes == 0
            || max_file_bytes > MAX_FILE_BYTES
            || max_age.is_zero()
            || max_age > MAX_AGE
        {
            return Err(GeoIpError::InvalidLimits);
        }
        if !path.is_absolute() {
            return Err(GeoIpError::InvalidPath);
        }
        let (bytes, stamp) = read_bounded(path, max_file_bytes)?;
        let file_bytes = bytes.len() as u64;
        let generation_sha256 = format!("{:x}", Sha256::digest(&bytes));
        let reader = Reader::from_source(bytes).map_err(|_| GeoIpError::InvalidDatabase)?;
        reader.verify().map_err(|_| GeoIpError::InvalidDatabase)?;
        let metadata = reader.metadata();
        if metadata.ip_version != 6
            || !matches!(
                metadata.database_type.as_str(),
                "GeoIP2-Country" | "GeoLite2-Country"
            )
        {
            return Err(GeoIpError::UnsupportedDatabase);
        }
        let loaded_at_unix_ms = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GeoIpError::Clock)?
            .as_millis()
            .try_into()
            .map_err(|_| GeoIpError::Clock)?;
        let build_time = UNIX_EPOCH
            .checked_add(Duration::from_secs(metadata.build_epoch))
            .ok_or(GeoIpError::Clock)?;
        let expires_at = build_time.checked_add(max_age).ok_or(GeoIpError::Clock)?;
        let age = now
            .duration_since(build_time)
            .map_err(|_| GeoIpError::FutureDatabase)?;
        if age > max_age {
            return Err(GeoIpError::StaleDatabase);
        }
        let remaining = expires_at
            .duration_since(now)
            .map_err(|_| GeoIpError::StaleDatabase)?;
        let expires_deadline = load_instant
            .checked_add(remaining)
            .ok_or(GeoIpError::Clock)?;
        let path_after_verify = fs::metadata(path).map_err(|_| GeoIpError::ChangedDuringRead)?;
        if !same_file_stamp(&stamp, &path_after_verify) {
            return Err(GeoIpError::ChangedDuringRead);
        }
        Ok(Arc::new(Self {
            status: DatabaseStatus {
                database_type: metadata.database_type.clone(),
                ip_version: metadata.ip_version,
                build_epoch_unix_seconds: metadata.build_epoch,
                expires_at_unix_seconds: metadata
                    .build_epoch
                    .checked_add(max_age.as_secs())
                    .ok_or(GeoIpError::Clock)?,
                loaded_at_unix_ms,
                generation_sha256,
                file_bytes,
            },
            reader,
            build_time,
            expires_at,
            expires_deadline,
            freshness_failure: AtomicU8::new(FRESH),
        }))
    }

    pub fn status(&self) -> &DatabaseStatus {
        &self.status
    }

    /// A failed freshness check is latched for this immutable generation. A
    /// later wall-clock correction cannot re-enable an expired country mapping.
    pub fn check_freshness(&self) -> Result<(), GeoIpError> {
        self.check_freshness_at(SystemTime::now(), Instant::now())
    }

    fn check_freshness_at(&self, now: SystemTime, instant: Instant) -> Result<(), GeoIpError> {
        let existing = self.freshness_failure.load(Ordering::Acquire);
        if existing != FRESH {
            return Err(freshness_error(existing));
        }
        let observed = if instant >= self.expires_deadline || now > self.expires_at {
            EXPIRED
        } else if now < self.build_time {
            CLOCK_REVERSED
        } else {
            FRESH
        };
        if observed != FRESH {
            let _ = self.freshness_failure.compare_exchange(
                FRESH,
                observed,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
        let final_state = self.freshness_failure.load(Ordering::Acquire);
        if final_state == FRESH {
            Ok(())
        } else {
            Err(freshness_error(final_state))
        }
    }

    /// Returns `None` for non-public or unrepresented addresses. Decode errors
    /// are distinct so policy callers can fail closed rather than allow an
    /// unknown record. No network or file access occurs here.
    pub fn lookup(&self, address: IpAddr) -> Result<Option<CountryCode>, GeoIpError> {
        self.lookup_at(address, SystemTime::now())
    }

    fn lookup_at(
        &self,
        address: IpAddr,
        now: SystemTime,
    ) -> Result<Option<CountryCode>, GeoIpError> {
        self.check_freshness_at(now, Instant::now())?;
        let address = match address {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(v6)),
            other => other,
        };
        if non_public(address) {
            return Ok(None);
        }
        let result = self
            .reader
            .lookup(address)
            .map_err(|_| GeoIpError::InvalidRecord)?;
        let code: Option<&str> = result
            .decode_path(&path!["country", "iso_code"])
            .map_err(|_| GeoIpError::InvalidRecord)?;
        code.map(CountryCode::from_db).transpose()
    }
}

fn freshness_error(state: u8) -> GeoIpError {
    if state == CLOCK_REVERSED {
        GeoIpError::FutureDatabase
    } else {
        GeoIpError::StaleDatabase
    }
}

fn read_bounded(path: &Path, max_file_bytes: u64) -> Result<(Vec<u8>, Metadata), GeoIpError> {
    let path_before = fs::metadata(path).map_err(|_| GeoIpError::Unavailable)?;
    if !path_before.is_file() {
        return Err(GeoIpError::NotRegularFile);
    }
    if path_before.len() > max_file_bytes {
        return Err(GeoIpError::TooLarge);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|_| GeoIpError::Unavailable)?;
    let before = file.metadata().map_err(|_| GeoIpError::Unavailable)?;
    if !before.is_file() {
        return Err(GeoIpError::NotRegularFile);
    }
    if before.len() > max_file_bytes {
        return Err(GeoIpError::TooLarge);
    }
    if !same_file_stamp(&path_before, &before) {
        return Err(GeoIpError::ChangedDuringRead);
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(max_file_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| GeoIpError::Unavailable)?;
    if bytes.len() as u64 > max_file_bytes {
        return Err(GeoIpError::TooLarge);
    }
    let after = file.metadata().map_err(|_| GeoIpError::Unavailable)?;
    let path_after = fs::metadata(path).map_err(|_| GeoIpError::ChangedDuringRead)?;
    if !same_file_stamp(&before, &after) || !same_file_stamp(&before, &path_after) {
        return Err(GeoIpError::ChangedDuringRead);
    }
    if bytes.len() as u64 != before.len() {
        return Err(GeoIpError::ChangedDuringRead);
    }
    Ok((bytes, path_after))
}

fn same_file_stamp(a: &Metadata, b: &Metadata) -> bool {
    if !a.is_file() || !b.is_file() || a.len() != b.len() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.mtime() == b.mtime()
            && a.mtime_nsec() == b.mtime_nsec()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        a.modified().ok() == b.modified().ok()
    }
}

/// Conservative fixed filtering of non-public ranges before consulting the
/// country database. This is intentionally not a continuously updated IANA
/// registry; an unrepresented public address also returns `None`.
fn non_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => non_public_v4(v4),
        IpAddr::V6(v6) => non_public_v6(v6),
    }
}

fn non_public_v4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    const BLOCKS: &[(u32, u8)] = &[
        (0x0000_0000, 8),  // Current-network/unspecified
        (0x0a00_0000, 8),  // RFC 1918
        (0x6440_0000, 10), // Shared address space
        (0x7f00_0000, 8),  // Loopback
        (0xa9fe_0000, 16), // Link local
        (0xac10_0000, 12), // RFC 1918
        (0xc000_0000, 24), // IETF protocol assignments
        (0xc000_0200, 24), // Documentation
        (0xc058_6300, 24), // Deprecated 6to4 relay anycast
        (0xc0a8_0000, 16), // RFC 1918
        (0xc612_0000, 15), // Benchmarking
        (0xc633_6400, 24), // Documentation
        (0xcb00_7100, 24), // Documentation
        (0xe000_0000, 4),  // Multicast
        (0xf000_0000, 4),  // Reserved/broadcast
    ];
    BLOCKS.iter().any(|(base, bits)| {
        let mask = u32::MAX << (32 - bits);
        value & mask == *base
    })
}

fn non_public_v6(address: Ipv6Addr) -> bool {
    let value = u128::from(address);
    const BLOCKS: &[(u128, u8)] = &[
        (0x2001_0000_0000_0000_0000_0000_0000_0000, 23), // IETF protocol space
        (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32), // Documentation
        (0x2002_0000_0000_0000_0000_0000_0000_0000, 16), // 6to4
        (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20), // Documentation
    ];
    // 2000::/3 is the current global-unicast allocation. All other prefixes
    // include unspecified, loopback, IPv4-compatible, ULA, link-local and
    // multicast forms that have no reliable country meaning here.
    value >> 125 != 0b001
        || BLOCKS.iter().any(|(base, bits)| {
            let mask = u128::MAX << (128 - bits);
            value & mask == *base
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, net::IpAddr};

    const FAKE_DB: &[u8] = include_bytes!("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");
    const CITY_DB: &[u8] = include_bytes!("../tests/fixtures/geoip/GeoIP2-City-Test.mmdb");
    const IPV4_DB: &[u8] = include_bytes!("../tests/fixtures/geoip/MaxMind-DB-test-ipv4-24.mmdb");

    fn fixture_time(bytes: &[u8]) -> SystemTime {
        let reader = Reader::from_source(bytes.to_vec()).unwrap();
        UNIX_EPOCH + Duration::from_secs(reader.metadata().build_epoch + 60)
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, SystemTime) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("country.mmdb");
        fs::write(&path, FAKE_DB).unwrap();
        let now = fixture_time(FAKE_DB);
        (dir, path, now)
    }

    fn load_fixture() -> (tempfile::TempDir, Arc<Database>, SystemTime) {
        let (dir, path, now) = fixture();
        let database = Database::load_at(&path, DEFAULT_MAX_FILE_BYTES, DEFAULT_MAX_AGE, now)
            .expect("fake Country test database should verify");
        (dir, database, now)
    }

    #[test]
    fn country_field_is_used_for_ipv4_ipv6_and_mapped_ipv4() {
        let (_dir, database, now) = load_fixture();
        for address in ["81.2.69.160", "::ffff:81.2.69.160"] {
            assert_eq!(
                database
                    .lookup_at(address.parse::<IpAddr>().unwrap(), now)
                    .unwrap()
                    .unwrap()
                    .as_str(),
                "GB" // Registered country in fixture is US.
            );
        }
        assert_eq!(
            database
                .lookup_at("2001:220::".parse().unwrap(), now)
                .unwrap()
                .unwrap()
                .as_str(),
            "SE" // Registered country in fixture is DE.
        );
        assert_eq!(
            database
                .lookup_at("2001:220::1".parse().unwrap(), now)
                .unwrap()
                .unwrap()
                .as_str(),
            "KR"
        );
    }

    #[test]
    fn private_special_and_unrepresented_addresses_are_unknown() {
        let (_dir, database, now) = load_fixture();
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "198.51.100.1",
            "192.88.99.1",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "3fff::1",
            "2002::1",
            "::ffff:127.0.0.1",
            "8.8.8.8",
        ] {
            assert_eq!(
                database.lookup_at(address.parse().unwrap(), now).unwrap(),
                None,
                "{address}"
            );
        }
    }

    #[test]
    fn bounded_file_and_type_validation_do_not_reveal_path() {
        let (dir, path, now) = fixture();
        assert_eq!(
            Database::load_at(&path, (FAKE_DB.len() - 1) as u64, MAX_AGE, now)
                .err()
                .unwrap(),
            GeoIpError::TooLarge
        );
        let directory_error = Database::load_at(dir.path(), MAX_FILE_BYTES, MAX_AGE, now)
            .err()
            .unwrap();
        assert_eq!(directory_error, GeoIpError::NotRegularFile);
        assert!(!directory_error
            .to_string()
            .contains(dir.path().to_str().unwrap()));
        let bad = dir.path().join("bad.mmdb");
        fs::write(&bad, b"not an MMDB").unwrap();
        assert_eq!(
            Database::load_at(&bad, MAX_FILE_BYTES, MAX_AGE, now)
                .err()
                .unwrap(),
            GeoIpError::InvalidDatabase
        );
        let link = dir.path().join("link.mmdb");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&path, &link).unwrap();
            Database::load_at(&link, MAX_FILE_BYTES, MAX_AGE, now).unwrap();
        }
    }

    #[test]
    fn rejects_city_and_ipv4_only_databases() {
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [("city", CITY_DB), ("ipv4", IPV4_DB)] {
            let path = dir.path().join(format!("{name}.mmdb"));
            fs::write(&path, bytes).unwrap();
            assert_eq!(
                Database::load_at(&path, MAX_FILE_BYTES, MAX_AGE, fixture_time(bytes))
                    .err()
                    .unwrap(),
                GeoIpError::UnsupportedDatabase,
                "{name}"
            );
        }
    }

    #[test]
    fn loaded_generation_is_immutable_after_path_replacement() {
        let (dir, path, now) = fixture();
        let database = Database::load_at(&path, MAX_FILE_BYTES, MAX_AGE, now).unwrap();
        let replacement = dir.path().join("replacement.mmdb");
        fs::write(&replacement, b"invalid replacement").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            Database::load_at(&path, MAX_FILE_BYTES, MAX_AGE, now)
                .err()
                .unwrap(),
            GeoIpError::InvalidDatabase
        );
        assert_eq!(
            database
                .lookup_at("81.2.69.160".parse().unwrap(), now)
                .unwrap()
                .unwrap()
                .as_str(),
            "GB"
        );
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_before_opening_it() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("country.mmdb");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert_eq!(
            Database::load_at(&fifo, MAX_FILE_BYTES, MAX_AGE, fixture_time(FAKE_DB))
                .err()
                .unwrap(),
            GeoIpError::NotRegularFile
        );
    }

    #[test]
    fn stale_and_future_database_timestamps_fail_closed() {
        let (_dir, path, now) = fixture();
        assert_eq!(
            Database::load_at(&path, MAX_FILE_BYTES, Duration::from_secs(30), now)
                .err()
                .unwrap(),
            GeoIpError::StaleDatabase
        );
        assert_eq!(
            Database::load_at(
                &path,
                MAX_FILE_BYTES,
                MAX_AGE,
                now - Duration::from_secs(61),
            )
            .err()
            .unwrap(),
            GeoIpError::FutureDatabase
        );
        let database = Database::load_at(&path, MAX_FILE_BYTES, MAX_AGE, now).unwrap();
        assert_eq!(
            database.lookup_at("81.2.69.160".parse().unwrap(), now + MAX_AGE,),
            Err(GeoIpError::StaleDatabase)
        );
    }

    #[test]
    fn expired_generation_cannot_revive_after_wall_clock_moves_back() {
        let (_dir, database, now) = load_fixture();
        let address = "81.2.69.160".parse().unwrap();
        assert_eq!(
            database.lookup_at(address, now).unwrap().unwrap().as_str(),
            "GB"
        );
        assert_eq!(
            database.lookup_at(address, database.expires_at + Duration::from_secs(1)),
            Err(GeoIpError::StaleDatabase)
        );
        assert_eq!(
            database.lookup_at(address, now),
            Err(GeoIpError::StaleDatabase)
        );
    }

    #[test]
    fn monotonic_deadline_rejects_even_when_wall_clock_remains_fresh() {
        let (_dir, database, now) = load_fixture();
        assert_eq!(
            database.check_freshness_at(now, database.expires_deadline),
            Err(GeoIpError::StaleDatabase)
        );
        assert_eq!(
            database.check_freshness_at(now, Instant::now()),
            Err(GeoIpError::StaleDatabase)
        );
    }

    #[test]
    fn clock_reversal_is_latched_for_the_loaded_generation() {
        let (_dir, database, now) = load_fixture();
        assert_eq!(
            database
                .check_freshness_at(database.build_time - Duration::from_secs(1), Instant::now()),
            Err(GeoIpError::FutureDatabase)
        );
        assert_eq!(
            database.check_freshness_at(now, Instant::now()),
            Err(GeoIpError::FutureDatabase)
        );
    }

    #[test]
    fn status_identifies_generation_without_file_path() {
        let (_dir, database, _) = load_fixture();
        let status = database.status();
        assert_eq!(status.database_type, "GeoIP2-Country");
        assert_eq!(status.ip_version, 6);
        assert_eq!(status.file_bytes, FAKE_DB.len() as u64);
        assert_eq!(status.generation_sha256.len(), 64);
    }
}
