//! Bounded TLS ClientHello inspection for TCP SNI passthrough routing.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::io::{AsyncRead, AsyncReadExt};

const MIB: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 16 * 1024;
const MAX_HANDSHAKE_RECORDS: usize = 256;

fn default_max_client_hello_bytes() -> usize {
    65_536
}

fn default_hello_timeout_ms() -> u64 {
    3_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniMatch {
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub host_regexes: Vec<String>,
    #[serde(default = "default_max_client_hello_bytes")]
    pub max_client_hello_bytes: usize,
    #[serde(default = "default_hello_timeout_ms")]
    pub hello_timeout_ms: u64,
}

impl SniMatch {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (1..=128).contains(&(self.hosts.len() + self.host_regexes.len())),
            "SNI hosts and host_regexes must contain 1..128 patterns"
        );
        ensure!(
            (1..=MIB).contains(&self.max_client_hello_bytes),
            "SNI max_client_hello_bytes must be 1..1048576"
        );
        ensure!(
            (1..=30_000).contains(&self.hello_timeout_ms),
            "SNI hello_timeout_ms must be 1..30000"
        );
        let mut total = 0_usize;
        let mut unique = HashSet::new();
        for host in &self.hosts {
            let canonical = canonical_pattern(host)?;
            total = total
                .checked_add(host.len())
                .context("SNI host configuration size overflow")?;
            ensure!(total <= 8192, "SNI host configuration exceeds 8192 bytes");
            ensure!(unique.insert(canonical), "duplicate SNI host");
        }
        for pattern in &self.host_regexes {
            ensure!(
                !pattern.is_empty() && pattern.len() <= 1024,
                "SNI regex must contain 1..1024 bytes"
            );
            total += pattern.len();
            ensure!(total <= 8192, "SNI host configuration exceeds 8192 bytes");
            ensure!(
                unique.insert(format!("regex:{pattern}")),
                "duplicate SNI host regex"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub server_name: String,
    /// Complete TLS records consumed while finding the ClientHello. These bytes
    /// must be forwarded verbatim before proxying the remainder of the stream.
    pub consumed: Vec<u8>,
}

/// Read complete plaintext handshake records until the first ClientHello is
/// available. The aggregate record bytes, including five-byte record headers,
/// never exceed `max_bytes`.
pub async fn read_client_hello<R>(reader: &mut R, max_bytes: usize) -> Result<ClientHello>
where
    R: AsyncRead + Unpin,
{
    ensure!(max_bytes > 0, "ClientHello byte limit must be positive");
    let mut consumed = Vec::with_capacity(max_bytes.min(16 * 1024));
    let mut handshake = Vec::new();
    let mut expected_handshake = None;
    let mut record_count = 0_usize;

    loop {
        record_count += 1;
        ensure!(
            record_count <= MAX_HANDSHAKE_RECORDS,
            "ClientHello exceeds 256 TLS records"
        );
        let header_start = consumed.len();
        read_bounded(reader, &mut consumed, 5, max_bytes).await?;
        let header = &consumed[header_start..header_start + 5];
        ensure!(
            header[0] == 22,
            "TLS record before ClientHello is not a handshake"
        );
        ensure!(
            header[1] == 3 && header[2] <= 4,
            "invalid TLS record version"
        );
        let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        ensure!(
            (1..=MAX_RECORD_BYTES).contains(&record_len),
            "invalid TLS handshake record length"
        );
        let payload_start = consumed.len();
        read_bounded(reader, &mut consumed, record_len, max_bytes).await?;
        handshake
            .try_reserve(record_len)
            .context("allocate ClientHello parser buffer")?;
        handshake.extend_from_slice(&consumed[payload_start..payload_start + record_len]);

        if handshake.len() >= 4 && expected_handshake.is_none() {
            ensure!(handshake[0] == 1, "first TLS handshake is not ClientHello");
            let body_len = (usize::from(handshake[1]) << 16)
                | (usize::from(handshake[2]) << 8)
                | usize::from(handshake[3]);
            let total = body_len
                .checked_add(4)
                .context("ClientHello length overflow")?;
            ensure!(
                total <= max_bytes,
                "ClientHello exceeds configured byte limit"
            );
            expected_handshake = Some(total);
        }

        if let Some(expected) = expected_handshake
            && handshake.len() >= expected
        {
            let server_name = parse_client_hello(&handshake[4..expected])?;
            return Ok(ClientHello {
                server_name,
                consumed,
            });
        }
    }
}

async fn read_bounded<R>(
    reader: &mut R,
    output: &mut Vec<u8>,
    amount: usize,
    max_bytes: usize,
) -> Result<()>
where
    R: AsyncRead + Unpin,
{
    let end = output
        .len()
        .checked_add(amount)
        .context("ClientHello size overflow")?;
    ensure!(
        end <= max_bytes,
        "ClientHello exceeds configured byte limit"
    );
    output
        .try_reserve(amount)
        .context("allocate ClientHello record buffer")?;
    let start = output.len();
    output.resize(end, 0);
    if let Err(error) = reader.read_exact(&mut output[start..end]).await {
        output.truncate(start);
        return Err(error).context("read TLS ClientHello");
    }
    Ok(())
}

fn parse_client_hello(body: &[u8]) -> Result<String> {
    let mut input = Cursor::new(body);
    input.take(2, "ClientHello legacy version")?;
    input.take(32, "ClientHello random")?;
    let session_len = usize::from(input.u8("ClientHello session id length")?);
    ensure!(session_len <= 32, "invalid ClientHello session id length");
    input.take(session_len, "ClientHello session id")?;

    let cipher_len = usize::from(input.u16("ClientHello cipher suites length")?);
    ensure!(
        cipher_len >= 2 && cipher_len % 2 == 0,
        "invalid ClientHello cipher suites"
    );
    input.take(cipher_len, "ClientHello cipher suites")?;

    let compression_len = usize::from(input.u8("ClientHello compression methods length")?);
    ensure!(
        compression_len > 0,
        "invalid ClientHello compression methods"
    );
    input.take(compression_len, "ClientHello compression methods")?;

    let extensions_len = usize::from(input.u16("ClientHello extensions length")?);
    ensure!(
        extensions_len == input.remaining(),
        "invalid ClientHello extensions length"
    );
    let mut extensions = Cursor::new(input.take(extensions_len, "ClientHello extensions")?);
    let mut seen_extensions = HashSet::new();
    let mut server_name = None;
    while extensions.remaining() > 0 {
        let extension_type = extensions.u16("ClientHello extension type")?;
        ensure!(
            seen_extensions.insert(extension_type),
            "duplicate ClientHello extension"
        );
        let length = usize::from(extensions.u16("ClientHello extension length")?);
        let value = extensions.take(length, "ClientHello extension body")?;
        if extension_type == 0 {
            ensure!(server_name.is_none(), "duplicate SNI extension");
            server_name = Some(parse_server_name(value)?);
        }
    }
    server_name.context("ClientHello does not contain SNI")
}

fn parse_server_name(value: &[u8]) -> Result<String> {
    let mut extension = Cursor::new(value);
    let list_len = usize::from(extension.u16("SNI name list length")?);
    ensure!(
        list_len == extension.remaining(),
        "invalid SNI name list length"
    );
    ensure!(list_len > 0, "empty SNI name list");
    let mut seen_types = HashSet::new();
    let mut host = None;
    while extension.remaining() > 0 {
        let name_type = extension.u8("SNI name type")?;
        ensure!(seen_types.insert(name_type), "duplicate SNI name type");
        let name_len = usize::from(extension.u16("SNI name length")?);
        let name = extension.take(name_len, "SNI name")?;
        ensure!(!name.is_empty(), "empty SNI name");
        if name_type == 0 {
            let name = std::str::from_utf8(name).context("SNI hostname is not ASCII")?;
            ensure!(name.is_ascii(), "SNI hostname is not ASCII");
            host = Some(canonical_hostname(name)?);
        }
    }
    host.context("SNI does not contain a hostname")
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn take(&mut self, amount: usize, field: &str) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(amount)
            .with_context(|| format!("{field} length overflow"))?;
        if end > self.bytes.len() {
            bail!("truncated {field}");
        }
        let value = &self.bytes[self.position..end];
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self, field: &str) -> Result<u8> {
        Ok(self.take(1, field)?[0])
    }

    fn u16(&mut self, field: &str) -> Result<u16> {
        let bytes = self.take(2, field)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }
}

/// Validate a route pattern; certificate identities use their separate strict validator.
pub fn canonical_pattern(pattern: &str) -> Result<String> {
    crate::host_match::validate_pattern(pattern)?;
    if crate::host_match::is_glob(pattern) {
        canonical_hostname(&pattern.replace(['*', '?'], "a"))?;
        Ok(pattern.to_ascii_lowercase())
    } else {
        canonical_hostname(pattern)
    }
}

pub fn canonical_hostname(host: &str) -> Result<String> {
    ensure!(
        !host.is_empty() && host.len() <= 253,
        "invalid SNI hostname length"
    );
    ensure!(host.is_ascii(), "SNI hostname must be ASCII");
    ensure!(
        !host.ends_with('.'),
        "SNI hostname must not have a trailing dot"
    );
    ensure!(
        host.parse::<std::net::IpAddr>().is_err(),
        "SNI hostname must not be an IP address"
    );
    for label in host.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid SNI label length"
        );
        ensure!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-'),
            "invalid SNI hostname"
        );
    }
    Ok(host.to_ascii_lowercase())
}

/// Match a route glob against a canonical ClientHello DNS hostname.
pub fn pattern_matches(pattern: &str, server_name: &str) -> bool {
    crate::host_match::matches(pattern, server_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni = Vec::new();
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&sni);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&0x1301_u16.to_be_bytes());
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![1, 0, 0, 0];
        let length = body.len();
        handshake[1] = ((length >> 16) & 0xff) as u8;
        handshake[2] = ((length >> 8) & 0xff) as u8;
        handshake[3] = (length & 0xff) as u8;
        handshake.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[tokio::test]
    async fn reads_fragmented_records_and_preserves_wire_bytes() {
        let original = hello("API.Example.COM");
        let handshake = &original[5..];
        let split = 11;
        let mut records = vec![22, 3, 1];
        records.extend_from_slice(&(split as u16).to_be_bytes());
        records.extend_from_slice(&handshake[..split]);
        records.extend_from_slice(&[22, 3, 3]);
        records.extend_from_slice(&((handshake.len() - split) as u16).to_be_bytes());
        records.extend_from_slice(&handshake[split..]);
        let mut input = &records[..];
        let parsed = read_client_hello(&mut input, 1024).await.unwrap();
        assert_eq!(parsed.server_name, "api.example.com");
        assert_eq!(parsed.consumed, records);
    }

    #[tokio::test]
    async fn rejects_truncation_limit_and_duplicate_extensions() {
        let complete = hello("one.example.com");
        let mut truncated = &complete[..complete.len() - 1];
        assert!(read_client_hello(&mut truncated, 1024).await.is_err());
        let mut limited = &complete[..];
        assert!(
            read_client_hello(&mut limited, complete.len() - 1)
                .await
                .is_err()
        );

        let mut duplicate = complete.clone();
        let sni_extension = duplicate[52..].to_vec();
        duplicate.extend_from_slice(&sni_extension);
        let record_len = duplicate.len() - 5;
        duplicate[3..5].copy_from_slice(&(record_len as u16).to_be_bytes());
        let handshake_len = duplicate.len() - 9;
        duplicate[6] = ((handshake_len >> 16) & 0xff) as u8;
        duplicate[7] = ((handshake_len >> 8) & 0xff) as u8;
        duplicate[8] = (handshake_len & 0xff) as u8;
        let ext_len =
            u16::from_be_bytes([duplicate[50], duplicate[51]]) as usize + sni_extension.len();
        duplicate[50..52].copy_from_slice(&(ext_len as u16).to_be_bytes());
        let mut input = &duplicate[..];
        assert!(read_client_hello(&mut input, 1024).await.is_err());
    }

    #[tokio::test]
    async fn rejects_more_than_256_tiny_handshake_records() {
        let handshake_prefix = [1, 0, 3, 232]; // ClientHello body length 1000.
        let mut records = Vec::new();
        for index in 0..=MAX_HANDSHAKE_RECORDS {
            records.extend_from_slice(&[22, 3, 1, 0, 1]);
            records.push(handshake_prefix.get(index).copied().unwrap_or(0));
        }
        let mut input = &records[..];
        let error = read_client_hello(&mut input, 4096).await.unwrap_err();
        assert!(error.to_string().contains("256 TLS records"), "{error:#}");
    }

    #[test]
    fn validates_patterns_and_one_label_wildcards() {
        let settings = SniMatch {
            host_regexes: Vec::new(),
            hosts: vec!["EXAMPLE.com".into(), "*.svc.example.com".into()],
            max_client_hello_bytes: 65_536,
            hello_timeout_ms: 3_000,
        };
        assert!(settings.validate().is_ok());
        assert!(pattern_matches("*.example.com", "api.example.com"));
        assert!(!pattern_matches("*.example.com", "a.api.example.com"));
        assert!(!pattern_matches("*.example.com", "example.com"));
        assert!(pattern_matches("f??.bar.com", "foo.bar.com"));
        assert!(!pattern_matches("f??.bar.com", "fooo.bar.com"));
        assert!(canonical_pattern("a.*.example.com").is_ok());
        assert!(canonical_pattern("*.com").is_ok());
        for invalid in [
            "",
            "a..example.com",
            "a[bc].example.com",
            "a/.example.com",
            "bad_.example.com",
            "127.0.0.1",
        ] {
            assert!(canonical_pattern(invalid).is_err(), "{invalid}");
        }
    }
}
