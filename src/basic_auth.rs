//! Bounded parsing and constant-work verification for native HTTP Basic auth.

use anyhow::{Context, Result, ensure};
use base64::Engine;
use hyper::{
    HeaderMap, header,
    header::{HeaderName, HeaderValue},
};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const MAX_USERNAME_BYTES: usize = 255;
const MIN_SALT_BYTES: usize = 16;
const MAX_SALT_BYTES: usize = 64;
const MAX_DECODED_BYTES: usize = 4096;
const MAX_ENCODED_BYTES: usize = 5464;
const MAX_SUFFIX_BYTES: usize = 255;
const MAX_IDENTITY_BYTES: usize = 4096;
const MAX_IDENTITY_HEADERS: usize = 16;
const SHA1_SUFFIX_PREFIX: &str = "v1:sha1-suffix:";

pub type IdentityHeaders = Vec<(HeaderName, Option<HeaderValue>)>;

pub struct Prepared {
    credentials: Vec<PreparedCredential>,
    reserved_headers: Vec<HeaderName>,
}

struct PreparedCredential {
    username_hash: [u8; 32],
    password: PreparedPassword,
    identity_headers: Vec<(HeaderName, Option<HeaderValue>)>,
}

enum PreparedPassword {
    Sha256 {
        salt: [u8; MAX_SALT_BYTES],
        salt_len: u8,
        hash: [u8; 32],
    },
    Sha1Suffix {
        suffix: [u8; MAX_SUFFIX_BYTES],
        suffix_len: u8,
        hash: [u8; 20],
    },
}

/// Authenticated identity produced by a prepared Basic credential.
pub struct Authenticated {
    pub username: String,
    /// A `None` value means the named client-supplied header must be cleared.
    pub identity_headers: Vec<(HeaderName, Option<HeaderValue>)>,
}

pub fn prepare(basic: &crate::config::BasicAuth) -> Result<Prepared> {
    let mut credentials = Vec::with_capacity(basic.credentials.len());
    for credential in &basic.credentials {
        credentials.push(parse_prepared(credential)?);
    }
    let mut reserved_headers: Vec<HeaderName> = credentials
        .iter()
        .flat_map(|credential| {
            credential
                .identity_headers
                .iter()
                .map(|(name, _)| name.clone())
        })
        .collect();
    reserved_headers.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    reserved_headers.dedup();
    Ok(Prepared {
        credentials,
        reserved_headers,
    })
}

impl Prepared {
    pub fn reserved_headers(&self) -> &[HeaderName] {
        &self.reserved_headers
    }
}

/// Produce a `username:salt_hex:sha256_hex` credential with a fresh 16-byte
/// random salt, for `basic_auth.credentials`. Used by the CLI and the
/// administration API; the password never leaves the process.
pub fn hash_credential(username: &str, password: &str) -> Result<String> {
    validate_username(username)?;
    ensure!(
        !password.is_empty() && password.len() <= 1024,
        "basic-auth password must contain 1..1024 bytes"
    );
    let mut salt = [0u8; 16];
    let provider = rustls::crypto::ring::default_provider();
    provider
        .secure_random
        .fill(&mut salt)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    Ok(format!("{username}:{}:{}", hex(&salt), hex(&digest)))
}

pub fn validate_username(username: &str) -> Result<()> {
    ensure!(
        !username.is_empty()
            && username.len() <= MAX_USERNAME_BYTES
            && !username.contains(':')
            && username.trim() == username
            && username.chars().all(|character| !character.is_control()),
        "basic-auth username must contain 1..255 non-control bytes, no colon, and no surrounding whitespace"
    );
    Ok(())
}

/// Parse the legacy `username:salt_hex:sha256_hex` credential format.
pub fn parse_credential(entry: &str) -> Result<(&str, Vec<u8>, Vec<u8>)> {
    let mut parts = entry.splitn(3, ':');
    let username = parts.next().unwrap_or("");
    let salt = parts.next().context("credential missing salt")?;
    let hash = parts.next().context("credential missing hash")?;
    validate_username(username)?;
    ensure!(
        (MIN_SALT_BYTES * 2..=MAX_SALT_BYTES * 2).contains(&salt.len()),
        "credential salt must contain 16..64 bytes"
    );
    ensure!(
        hash.len() == 64,
        "credential hash must be 32-byte SHA-256 hex"
    );
    let salt = hex_decode(salt).context("credential salt is not valid hex")?;
    let hash = hex_decode(hash).context("credential hash is not valid hex")?;
    Ok((username, salt, hash))
}

/// Inspect a native or versioned compatibility credential during config
/// validation without exposing its password digest.
pub fn credential_metadata(entry: &str) -> Result<(String, IdentityHeaders)> {
    let prepared = parse_prepared(entry)?;
    let username = if let Some(encoded) = entry.strip_prefix(SHA1_SUFFIX_PREFIX) {
        let username = encoded.split(':').next().unwrap_or_default();
        decode_text(username, "username")?
    } else {
        parse_credential(entry)?.0.to_owned()
    };
    Ok((username, prepared.identity_headers))
}

fn parse_prepared(entry: &str) -> Result<PreparedCredential> {
    if !entry.starts_with(SHA1_SUFFIX_PREFIX) {
        let (username, salt, password_hash) = parse_credential(entry)?;
        let mut padded_salt = [0_u8; MAX_SALT_BYTES];
        padded_salt[..salt.len()].copy_from_slice(&salt);
        return Ok(PreparedCredential {
            username_hash: Sha256::digest(username.as_bytes()).into(),
            password: PreparedPassword::Sha256 {
                salt: padded_salt,
                salt_len: salt.len() as u8,
                hash: password_hash
                    .try_into()
                    .expect("validated SHA-256 digest length"),
            },
            identity_headers: Vec::new(),
        });
    }

    let mut parts = entry.split(':');
    ensure!(parts.next() == Some("v1"), "invalid credential version");
    ensure!(
        parts.next() == Some("sha1-suffix"),
        "invalid credential algorithm"
    );
    let username = decode_text(parts.next().unwrap_or_default(), "username")?;
    validate_username(&username)?;
    let suffix = decode_bytes(parts.next().unwrap_or_default(), "suffix")?;
    ensure!(
        !suffix.is_empty() && suffix.len() <= MAX_SUFFIX_BYTES,
        "credential suffix must contain 1..255 bytes"
    );
    let hash = parts.next().context("credential missing hash")?;
    ensure!(
        hash.len() == 40,
        "credential hash must be 20-byte SHA-1 hex"
    );
    let hash: [u8; 20] = hex_decode(hash)
        .context("credential hash is not valid hex")?
        .try_into()
        .expect("validated SHA-1 digest length");
    let identity = parts.next().context("credential missing identity map")?;
    ensure!(parts.next().is_none(), "credential has unexpected fields");
    let identity = decode_bytes(identity, "identity map")?;
    ensure!(
        identity.len() <= MAX_IDENTITY_BYTES,
        "credential identity map exceeds 4096 bytes"
    );
    let identity: std::collections::BTreeMap<String, Option<String>> =
        serde_json::from_slice(&identity).context("credential identity map is invalid JSON")?;
    ensure!(
        identity.len() <= MAX_IDENTITY_HEADERS,
        "credential identity map exceeds 16 headers"
    );
    let identity_headers: Vec<(HeaderName, Option<HeaderValue>)> = identity
        .into_iter()
        .map(|(name, value)| {
            let name: HeaderName = name.parse().context("invalid identity header name")?;
            ensure!(
                !matches!(
                    name.as_str(),
                    "authorization"
                        | "proxy-authorization"
                        | "host"
                        | "connection"
                        | "content-length"
                        | "transfer-encoding"
                        | "upgrade"
                        | "te"
                        | "trailer"
                        | "keep-alive"
                        | "proxy-connection"
                ),
                "unsafe identity header name"
            );
            let value = value
                .map(|value| HeaderValue::from_str(&value).context("invalid identity header value"))
                .transpose()?;
            Ok((name, value))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut unique = std::collections::HashSet::new();
    for (name, _) in &identity_headers {
        ensure!(unique.insert(name), "duplicate credential identity header");
    }
    let mut padded_suffix = [0_u8; MAX_SUFFIX_BYTES];
    padded_suffix[..suffix.len()].copy_from_slice(&suffix);
    Ok(PreparedCredential {
        username_hash: Sha256::digest(username.as_bytes()).into(),
        password: PreparedPassword::Sha1Suffix {
            suffix: padded_suffix,
            suffix_len: suffix.len() as u8,
            hash,
        },
        identity_headers,
    })
}

fn decode_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    ensure!(!value.is_empty(), "credential {field} is empty");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("credential {field} is not base64url"))
}

fn decode_text(value: &str, field: &str) -> Result<String> {
    String::from_utf8(decode_bytes(value, field)?)
        .with_context(|| format!("credential {field} is not UTF-8"))
}

/// Verify one unambiguous Basic authorization value. Every prepared username
/// digest is scanned, then exactly one real or dummy password digest is
/// computed, so unknown usernames do not take the former short path.
pub fn verify(prepared: &Prepared, headers: &HeaderMap) -> Option<Authenticated> {
    let (user, password) = parse_basic_header(headers, &header::AUTHORIZATION)?;
    verify_credentials(prepared, &user, &password).0
}

/// Proxy-Authorization takes precedence only if it names a known credential.
/// A known username with an incorrect password does not fall back to the
/// Authorization header.
pub fn verify_with_proxy(prepared: &Prepared, headers: &HeaderMap) -> Option<Authenticated> {
    if let Some((user, password)) = parse_basic_header(headers, &header::PROXY_AUTHORIZATION) {
        let (verified, known) = verify_credentials(prepared, &user, &password);
        if known {
            return verified;
        }
    }
    verify(prepared, headers)
}

fn parse_basic_header(headers: &HeaderMap, name: &HeaderName) -> Option<(String, String)> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, encoded) = value.split_once(char::is_whitespace)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let encoded = encoded.trim();
    if encoded.is_empty()
        || encoded.len() > MAX_ENCODED_BYTES
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    if decoded.len() > MAX_DECODED_BYTES {
        return None;
    }
    let text = std::str::from_utf8(&decoded).ok()?;
    let (submitted_user, password) = text.split_once(':')?;
    if submitted_user.is_empty() {
        return None;
    }
    Some((submitted_user.to_owned(), password.to_owned()))
}

fn verify_credentials(
    prepared: &Prepared,
    submitted_user: &str,
    password: &str,
) -> (Option<Authenticated>, bool) {
    let submitted_user_hash = Sha256::digest(submitted_user.as_bytes());
    let mut matched_username = Choice::from(0);
    let mut selected_salt = [0x5a_u8; MAX_SALT_BYTES];
    let mut selected_salt_len = MIN_SALT_BYTES as u8;
    let mut expected_sha256 = [0_u8; 32];
    let mut selected_suffix = [0xa5_u8; MAX_SUFFIX_BYTES];
    let mut selected_suffix_len = 16_u8;
    let mut expected_sha1 = [0_u8; 20];
    let mut sha256_selected = Choice::from(0);
    let mut sha1_selected = Choice::from(0);
    let mut selected_index = 0_u64;
    for (index, credential) in prepared.credentials.iter().enumerate() {
        let matched = credential.username_hash.ct_eq(&submitted_user_hash);
        matched_username |= matched;
        selected_index = u64::conditional_select(&selected_index, &(index as u64), matched);
        match &credential.password {
            PreparedPassword::Sha256 {
                salt,
                salt_len,
                hash,
            } => {
                sha256_selected |= matched;
                for (selected, candidate) in selected_salt.iter_mut().zip(salt) {
                    *selected = u8::conditional_select(selected, candidate, matched);
                }
                selected_salt_len = u8::conditional_select(&selected_salt_len, salt_len, matched);
                for (selected, candidate) in expected_sha256.iter_mut().zip(hash) {
                    *selected = u8::conditional_select(selected, candidate, matched);
                }
            }
            PreparedPassword::Sha1Suffix {
                suffix,
                suffix_len,
                hash,
            } => {
                sha1_selected |= matched;
                for (selected, candidate) in selected_suffix.iter_mut().zip(suffix) {
                    *selected = u8::conditional_select(selected, candidate, matched);
                }
                selected_suffix_len =
                    u8::conditional_select(&selected_suffix_len, suffix_len, matched);
                for (selected, candidate) in expected_sha1.iter_mut().zip(hash) {
                    *selected = u8::conditional_select(selected, candidate, matched);
                }
            }
        }
    }
    let mut password_hash = Sha256::new();
    password_hash.update(&selected_salt[..usize::from(selected_salt_len)]);
    password_hash.update(password.as_bytes());
    let actual = password_hash.finalize();
    let native_valid = actual.as_slice().ct_eq(&expected_sha256) & sha256_selected;
    let mut sha1 = sha1_smol::Sha1::new();
    sha1.update(password.as_bytes());
    sha1.update(&selected_suffix[..usize::from(selected_suffix_len)]);
    let actual_sha1 = sha1.digest().bytes();
    let suffix_valid = actual_sha1.ct_eq(&expected_sha1) & sha1_selected;
    let authenticated = matched_username & (native_valid | suffix_valid);
    (
        bool::from(authenticated).then(|| Authenticated {
            username: submitted_user.to_owned(),
            identity_headers: prepared.credentials[selected_index as usize]
                .identity_headers
                .clone(),
        }),
        bool::from(matched_username),
    )
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) || bytes.is_empty() {
        return None;
    }
    bytes
        .chunks_exact(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(username: &str, password: &str, salt: &[u8]) -> String {
        let mut hash = Sha256::new();
        hash.update(salt);
        hash.update(password.as_bytes());
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        format!("{username}:{}:{}", hex(salt), hex(&hash.finalize()))
    }

    fn settings(credentials: Vec<String>) -> crate::config::BasicAuth {
        crate::config::BasicAuth {
            realm: "restricted".into(),
            credentials,
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: Some("x-user".into()),
        }
    }

    #[test]
    fn rejects_unbounded_or_malformed_legacy_fields() {
        let valid_hash = "00".repeat(32);
        for entry in [
            format!("user:{}:{valid_hash}", "00".repeat(15)),
            format!("user:{}:{valid_hash}", "00".repeat(65)),
            format!(" bad:{}:{valid_hash}", "00".repeat(16)),
            format!("bad\nuser:{}:{valid_hash}", "00".repeat(16)),
            format!("{}:{}:{valid_hash}", "a".repeat(256), "00".repeat(16)),
            format!("user:{}:{valid_hash}", "aé".repeat(16)),
            format!("user:{}:{}", "00".repeat(16), "aé".repeat(16)),
        ] {
            assert!(parse_credential(&entry).is_err(), "accepted {entry:?}");
        }
    }

    #[test]
    fn scheme_is_case_insensitive_and_duplicate_values_fail_closed() {
        let basic = settings(vec![credential("alice", "secret", b"0123456789abcdef")]);
        let prepared = prepare(&basic).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:secret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("bAsIc {encoded}").parse().unwrap(),
        );
        assert_eq!(verify(&prepared, &headers).unwrap().username, "alice");
        headers.append(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        assert!(verify(&prepared, &headers).is_none());
    }

    #[test]
    fn correct_password_and_username_are_both_required() {
        let basic = settings(vec![
            credential("alice", "secret", b"0123456789abcdef"),
            credential("bob", "different", b"fedcba9876543210"),
        ]);
        let prepared = prepare(&basic).unwrap();
        for (value, expected) in [
            ("alice:secret", Some("alice")),
            ("alice:different", None),
            ("unknown:secret", None),
        ] {
            let mut headers = HeaderMap::new();
            let encoded = base64::engine::general_purpose::STANDARD.encode(value);
            headers.insert(
                header::AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
            assert_eq!(
                verify(&prepared, &headers).map(|v| v.username),
                expected.map(str::to_owned)
            );
        }
    }

    #[test]
    fn maximum_prepared_set_verifies_last_and_unknown_users() {
        let credentials = (0..4096)
            .map(|index| {
                credential(
                    &format!("user-{index}"),
                    &format!("password-{index}"),
                    b"0123456789abcdef",
                )
            })
            .collect();
        let prepared = prepare(&settings(credentials)).unwrap();
        for value in ["user-4095:password-4095", "unknown:password-4095"] {
            let mut headers = HeaderMap::new();
            let encoded = base64::engine::general_purpose::STANDARD.encode(value);
            headers.insert(
                header::AUTHORIZATION,
                format!("Basic {encoded}").parse().unwrap(),
            );
            assert_eq!(
                verify(&prepared, &headers).is_some(),
                value.starts_with("user-")
            );
        }
    }

    fn suffix_credential(username: &str, password: &str, suffix: &str) -> String {
        let encoded = |value: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        let mut sha = sha1_smol::Sha1::new();
        sha.update(password.as_bytes());
        sha.update(suffix.as_bytes());
        let identity = serde_json::json!({
            "X-Consumer-ID": suffix,
            "X-Consumer-Custom-ID": null,
            "X-Consumer-Username": "tester",
            "X-Credential-Identifier": username,
            "X-Anonymous-Consumer": null
        });
        format!(
            "v1:sha1-suffix:{}:{}:{}:{}",
            encoded(username.as_bytes()),
            encoded(suffix.as_bytes()),
            sha.digest(),
            encoded(identity.to_string().as_bytes())
        )
    }

    #[test]
    fn versioned_suffix_sha1_matches_legacy_store_and_prepares_identity() {
        let credential = suffix_credential("compat", "s3cret", "consumer-uuid");
        let prepared = prepare(&settings(vec![credential.clone()])).unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode("compat:s3cret");
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {encoded}").parse().unwrap(),
        );
        let verified = verify(&prepared, &headers).unwrap();
        assert_eq!(verified.username, "compat");
        assert_eq!(verified.identity_headers.len(), 5);
        assert!(verified.identity_headers.iter().any(|(name, value)| {
            name == "x-consumer-id" && value.as_ref().is_some_and(|value| value == "consumer-uuid")
        }));
        assert!(
            verified
                .identity_headers
                .iter()
                .any(|(name, value)| { name == "x-anonymous-consumer" && value.is_none() })
        );
        assert!(
            prepared
                .reserved_headers()
                .iter()
                .any(|name| name == "x-anonymous-consumer")
        );
        let wrong = base64::engine::general_purpose::STANDARD.encode("compat:wrong");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {wrong}").parse().unwrap(),
        );
        assert!(verify(&prepared, &headers).is_none());
        let unknown = base64::engine::general_purpose::STANDARD.encode("missing:s3cret");
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {unknown}").parse().unwrap(),
        );
        assert!(verify(&prepared, &headers).is_none());
        assert!(credential_metadata(&credential).is_ok());
    }

    #[test]
    fn proxy_authorization_precedes_known_user_but_unknown_name_falls_back() {
        let prepared = prepare(&settings(vec![suffix_credential(
            "compat", "secret", "consumer",
        )]))
        .unwrap();
        let encoded = |value| base64::engine::general_purpose::STANDARD.encode(value);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", encoded("compat:secret"))
                .parse()
                .unwrap(),
        );
        headers.insert(
            header::PROXY_AUTHORIZATION,
            format!("Basic {}", encoded("compat:wrong"))
                .parse()
                .unwrap(),
        );
        assert!(verify_with_proxy(&prepared, &headers).is_none());
        headers.insert(
            header::PROXY_AUTHORIZATION,
            format!("Basic {}", encoded("unknown:wrong"))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            verify_with_proxy(&prepared, &headers).unwrap().username,
            "compat"
        );
        headers.insert(
            header::PROXY_AUTHORIZATION,
            format!("Basic {}", encoded("compat:secret"))
                .parse()
                .unwrap(),
        );
        headers.insert(
            header::AUTHORIZATION,
            format!("Basic {}", encoded("compat:wrong"))
                .parse()
                .unwrap(),
        );
        assert_eq!(
            verify_with_proxy(&prepared, &headers).unwrap().username,
            "compat"
        );
    }

    #[test]
    fn compatibility_map_rejects_case_duplicate_identity_names() {
        let mut identity = serde_json::Map::new();
        identity.insert(
            "X-Consumer-ID".into(),
            serde_json::Value::String("one".into()),
        );
        identity.insert(
            "x-consumer-id".into(),
            serde_json::Value::String("two".into()),
        );
        let entry = format!(
            "v1:sha1-suffix:{}:{}:{}:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("user"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("suffix"),
            "00".repeat(20),
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(serde_json::Value::Object(identity).to_string())
        );
        assert!(credential_metadata(&entry).is_err());
    }
}
