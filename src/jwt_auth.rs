//! Bounded RFC 9068 access-token verification against issuer-owned public JWKs.
//!
//! Key acquisition is deliberately outside this module. A caller must bind a
//! static JWKS or a remote provider to the configured issuer before passing a
//! PreparedKey here. No unverified token field selects a URL or a trust root.

use anyhow::{Result, bail, ensure};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Number, Value};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

const MAX_JWKS_BYTES: usize = 128 * 1024;
const MAX_KEYS: usize = 32;
const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_HEADER_BYTES: usize = 2048;
const MAX_CLAIMS_BYTES: usize = 8192;
const MAX_KEY_ID: usize = 128;
const MAX_IDENTITY_BYTES: usize = 255;
const MAX_ATTRIBUTES: usize = 32;
const MAX_ATTRIBUTE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JwtAlgorithm {
    #[serde(rename = "RS256")]
    RS256,
    #[serde(rename = "PS256")]
    PS256,
    #[serde(rename = "ES256")]
    ES256,
    #[serde(rename = "EdDSA")]
    EdDSA,
}

impl JwtAlgorithm {
    fn library(self) -> Algorithm {
        match self {
            Self::RS256 => Algorithm::RS256,
            Self::PS256 => Algorithm::PS256,
            Self::ES256 => Algorithm::ES256,
            Self::EdDSA => Algorithm::EdDSA,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::RS256),
            "PS256" => Some(Self::PS256),
            "ES256" => Some(Self::ES256),
            "EdDSA" => Some(Self::EdDSA),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JwtProfile {
    Rfc9068,
}

fn default_leeway() -> u64 {
    0
}
fn default_lifetime() -> u64 {
    3600
}
fn default_scope_claim() -> String {
    "scope".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JwtConfig {
    pub issuer: String,
    pub audiences: Vec<String>,
    pub profile: JwtProfile,
    pub algorithms: Vec<JwtAlgorithm>,
    #[serde(default = "default_leeway")]
    pub leeway_seconds: u64,
    #[serde(default = "default_lifetime")]
    pub max_lifetime_seconds: u64,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub required_groups: Vec<String>,
}

impl JwtConfig {
    pub fn validate(&self) -> Result<()> {
        let issuer: reqwest::Url = self.issuer.parse()?;
        ensure!(
            issuer.scheme() == "https"
                && issuer.host_str().is_some()
                && issuer.username().is_empty()
                && issuer.password().is_none()
                && issuer.query().is_none()
                && issuer.fragment().is_none()
                && self.issuer.len() <= 512,
            "JWT issuer must be a bounded HTTPS URL"
        );
        ensure!(
            !self.audiences.is_empty() && self.audiences.len() <= 8,
            "JWT audiences must contain 1..8 values"
        );
        let mut audiences = HashSet::new();
        for audience in &self.audiences {
            ensure!(valid_identity(audience), "invalid JWT audience");
            ensure!(audiences.insert(audience), "duplicate JWT audience");
        }
        ensure!(
            !self.algorithms.is_empty() && self.algorithms.len() <= 4,
            "JWT algorithms must contain 1..4 asymmetric algorithms"
        );
        let mut algorithms = HashSet::new();
        for algorithm in &self.algorithms {
            ensure!(algorithms.insert(algorithm), "duplicate JWT algorithm");
        }
        ensure!(
            self.leeway_seconds <= 60,
            "JWT leeway must be 0..60 seconds"
        );
        ensure!(
            (1..=86_400).contains(&self.max_lifetime_seconds),
            "JWT max_lifetime_seconds must be 1..86400"
        );
        for claim in [&self.scope_claim, &self.groups_claim] {
            ensure!(
                !claim.is_empty()
                    && claim.len() <= 64
                    && claim.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
                    })
                    && !matches!(
                        claim.as_str(),
                        "iss" | "aud" | "exp" | "sub" | "iat" | "nbf" | "jti" | "client_id"
                    ),
                "invalid JWT attribute claim name"
            );
        }
        ensure!(
            self.scope_claim != self.groups_claim,
            "JWT scope/groups claims conflict"
        );
        validate_required(&self.required_scopes, true)?;
        validate_required(&self.required_groups, false)?;
        Ok(())
    }

    /// Authorization is deliberately separate from signature/claim validity.
    /// Callers can return 403 for an authenticated token lacking permissions.
    pub fn allows(&self, verified: &Verified) -> bool {
        self.required_scopes
            .iter()
            .all(|required| verified.scopes.contains(required))
            && self
                .required_groups
                .iter()
                .all(|required| verified.groups.contains(required))
    }
}

fn validate_required(values: &[String], scopes: bool) -> Result<()> {
    ensure!(
        values.len() <= MAX_ATTRIBUTES,
        "too many required JWT attributes"
    );
    let mut seen = HashSet::new();
    for value in values {
        ensure!(
            valid_attribute(value, scopes),
            "invalid required JWT attribute"
        );
        ensure!(seen.insert(value), "duplicate required JWT attribute");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRequest {
    pub kid: String,
    pub algorithm: JwtAlgorithm,
}

#[derive(Debug, Clone)]
pub struct PreparedKey {
    kid: String,
    algorithm: JwtAlgorithm,
    key: DecodingKey,
}

impl PreparedKey {
    pub fn kid(&self) -> &str {
        &self.kid
    }
    pub fn algorithm(&self) -> JwtAlgorithm {
        self.algorithm
    }
}

#[derive(Debug, Clone, Default)]
pub struct PreparedKeys {
    keys: HashMap<String, Arc<PreparedKey>>,
}

impl PreparedKeys {
    pub fn from_jwks_json(bytes: &[u8], allowed: &[JwtAlgorithm]) -> Result<Self> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_JWKS_BYTES,
            "JWKS exceeds 128 KiB"
        );
        ensure!(
            !allowed.is_empty() && allowed.len() <= 4,
            "invalid JWKS algorithms"
        );
        let value = strict_json(bytes)?;
        let object = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("JWKS must be an object"))?;
        ensure!(
            object.len() == 1,
            "JWKS contains unsupported top-level fields"
        );
        let entries = object
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("JWKS keys must be an array"))?;
        ensure!(
            !entries.is_empty() && entries.len() <= MAX_KEYS,
            "JWKS needs 1..32 keys"
        );
        let mut keys = HashMap::with_capacity(entries.len());
        for value in entries {
            let key = prepare_jwk(value, allowed)?;
            ensure!(
                keys.insert(key.kid.clone(), Arc::new(key)).is_none(),
                "duplicate JWKS kid"
            );
        }
        Ok(Self { keys })
    }

    pub fn get(&self, kid: &str, algorithm: JwtAlgorithm) -> Option<Arc<PreparedKey>> {
        self.keys
            .get(kid)
            .filter(|key| key.algorithm == algorithm)
            .cloned()
    }

    pub fn get_for(&self, kid: &str, algorithm: JwtAlgorithm) -> Option<Arc<PreparedKey>> {
        self.get(kid, algorithm)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

fn prepare_jwk(value: &Value, allowed: &[JwtAlgorithm]) -> Result<PreparedKey> {
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("JWK must be an object"))?;
    const FIELDS: &[&str] = &[
        "kty", "kid", "alg", "use", "key_ops", "n", "e", "crv", "x", "y", "x5c", "x5t", "x5t#S256",
    ];
    ensure!(
        object.keys().all(|key| FIELDS.contains(&key.as_str())),
        "JWK has private or unsupported fields"
    );
    let field = |name| {
        object
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("JWK missing string field {name}"))
    };
    let kid = field("kid")?;
    ensure!(valid_kid(kid), "invalid JWK kid");
    let algorithm = JwtAlgorithm::from_name(field("alg")?)
        .ok_or_else(|| anyhow::anyhow!("unsupported JWK algorithm"))?;
    ensure!(
        allowed.contains(&algorithm),
        "JWK algorithm is not configured"
    );
    if let Some(use_value) = object.get("use") {
        ensure!(use_value.as_str() == Some("sig"), "JWK use must be sig");
    }
    if let Some(ops) = object.get("key_ops") {
        ensure!(
            ops.as_array()
                .is_some_and(|items| items.len() == 1 && items[0] == "verify"),
            "JWK key_ops must be verify"
        );
    }
    for name in ["x5t", "x5t#S256"] {
        if let Some(value) = object.get(name) {
            ensure!(
                value
                    .as_str()
                    .is_some_and(|text| !text.is_empty() && text.len() <= 256),
                "invalid JWK certificate metadata"
            );
        }
    }
    if let Some(chain) = object.get("x5c") {
        ensure!(
            chain.as_array().is_some_and(|items| items.len() <= 4
                && items.iter().all(|entry| entry
                    .as_str()
                    .is_some_and(|text| !text.is_empty() && text.len() <= 8192))),
            "invalid JWK certificate metadata"
        );
    }
    let key = match (field("kty")?, algorithm) {
        ("RSA", JwtAlgorithm::RS256 | JwtAlgorithm::PS256) => {
            ensure!(
                object
                    .keys()
                    .all(|name| !matches!(name.as_str(), "crv" | "x" | "y")),
                "RSA JWK has non-RSA components"
            );
            let n = field("n")?;
            let e = field("e")?;
            let modulus = decode_url(n, 512)?;
            let exponent = decode_url(e, 8)?;
            let bits = modulus.len().saturating_mul(8).saturating_sub(
                modulus
                    .first()
                    .map_or(8, |byte| byte.leading_zeros() as usize),
            );
            ensure!(
                (2048..=4096).contains(&bits) && modulus.last().is_some_and(|byte| byte & 1 == 1),
                "RSA modulus must be odd and 2048..4096 bits"
            );
            ensure!(exponent == [1, 0, 1], "RSA exponent must be 65537");
            DecodingKey::from_rsa_components(n, e)?
        }
        ("EC", JwtAlgorithm::ES256) => {
            ensure!(
                object
                    .keys()
                    .all(|name| !matches!(name.as_str(), "n" | "e")),
                "EC JWK has non-EC components"
            );
            ensure!(field("crv")? == "P-256", "ES256 requires P-256");
            let x = field("x")?;
            let y = field("y")?;
            ensure!(
                decode_url(x, 32)?.len() == 32 && decode_url(y, 32)?.len() == 32,
                "ES256 coordinates must be 32 bytes"
            );
            DecodingKey::from_ec_components(x, y)?
        }
        ("OKP", JwtAlgorithm::EdDSA) => {
            ensure!(
                object
                    .keys()
                    .all(|name| !matches!(name.as_str(), "n" | "e" | "y")),
                "OKP JWK has non-OKP components"
            );
            ensure!(field("crv")? == "Ed25519", "EdDSA requires Ed25519");
            let x = field("x")?;
            ensure!(
                decode_url(x, 32)?.len() == 32,
                "Ed25519 public key must be 32 bytes"
            );
            DecodingKey::from_ed_components(x)?
        }
        _ => bail!("JWK type and algorithm disagree"),
    };
    // The library's verifier factory parses the actual public key. This
    // rejects invalid EC points and malformed RSA/Ed25519 keys during
    // candidate preparation, before the key set becomes authoritative.
    let _ = (jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER.verifier_factory)(
        &algorithm.library(),
        &key,
    )?;
    Ok(PreparedKey {
        kid: kid.to_owned(),
        algorithm,
        key,
    })
}

fn valid_kid(kid: &str) -> bool {
    !kid.is_empty()
        && kid.len() <= MAX_KEY_ID
        // A kid is an opaque exact-match key, not a route ID or URL segment.
        && kid
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte))
}

fn decode_url(encoded: &str, max: usize) -> Result<Vec<u8>> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= max.saturating_mul(4).div_ceil(3),
        "invalid JWK component size"
    );
    let decoded = URL_SAFE_NO_PAD.decode(encoded)?;
    ensure!(
        decoded.len() <= max && URL_SAFE_NO_PAD.encode(&decoded) == encoded,
        "noncanonical JWK component"
    );
    Ok(decoded)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub subject: String,
    pub issuer: String,
    pub audiences: Vec<String>,
    pub client_id: String,
    pub jti: String,
    pub scopes: Vec<String>,
    pub groups: Vec<String>,
    pub issued_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    Invalid,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid access token")
    }
}
impl std::error::Error for VerifyError {}

pub struct JwtVerifier {
    config: JwtConfig,
}

impl JwtVerifier {
    pub fn prepare(config: JwtConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &JwtConfig {
        &self.config
    }

    pub fn key_request(&self, token: &str) -> std::result::Result<KeyRequest, VerifyError> {
        let parts = split_token(token)?;
        let header = parse_header(parts.0)?;
        if !self.config.algorithms.contains(&header.algorithm) {
            return Err(VerifyError::Invalid);
        }
        let claims = decode_segment(parts.1, MAX_CLAIMS_BYTES)?;
        if !strict_json(&claims)
            .map_err(|_| VerifyError::Invalid)?
            .is_object()
        {
            return Err(VerifyError::Invalid);
        }
        let signature = decode_segment(parts.2, 512)?;
        let valid_signature_size = match header.algorithm {
            JwtAlgorithm::RS256 | JwtAlgorithm::PS256 => (256..=512).contains(&signature.len()),
            JwtAlgorithm::ES256 | JwtAlgorithm::EdDSA => signature.len() == 64,
        };
        if !valid_signature_size {
            return Err(VerifyError::Invalid);
        }
        Ok(header)
    }

    pub fn verify(
        &self,
        token: &str,
        key: &PreparedKey,
        now_unix: u64,
    ) -> std::result::Result<Verified, VerifyError> {
        let (_, claims, _) = split_token(token)?;
        let requested = self.key_request(token)?;
        if requested.kid != key.kid
            || requested.algorithm != key.algorithm
            || !self.config.algorithms.contains(&key.algorithm)
        {
            return Err(VerifyError::Invalid);
        }
        // The library performs the asymmetric signature operation. All claim
        // validation below uses a separate strict duplicate-free parse and an
        // injected clock, never the library's process-clock defaults.
        let mut validation = Validation::new(key.algorithm.library());
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        jsonwebtoken::decode::<Value>(token, &key.key, &validation)
            .map_err(|_| VerifyError::Invalid)?;
        let claims = decode_segment(claims, MAX_CLAIMS_BYTES)?;
        let claims = strict_json(&claims).map_err(|_| VerifyError::Invalid)?;
        self.validate_claims(&claims, now_unix)
    }

    fn validate_claims(
        &self,
        claims: &Value,
        now: u64,
    ) -> std::result::Result<Verified, VerifyError> {
        let invalid = VerifyError::Invalid;
        let object = claims.as_object().ok_or(invalid)?;
        let text = |name: &str| -> std::result::Result<&str, VerifyError> {
            object
                .get(name)
                .and_then(Value::as_str)
                .filter(|value| valid_identity(value))
                .ok_or(invalid)
        };
        let issuer = object
            .get("iss")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or(invalid)?;
        if issuer != self.config.issuer {
            return Err(invalid);
        }
        let subject = text("sub")?;
        let client_id = text("client_id")?;
        let jti = text("jti")?;
        let audiences = parse_audiences(object.get("aud").ok_or(invalid)?)?;
        if !audiences
            .iter()
            .any(|audience| self.config.audiences.contains(audience))
        {
            return Err(invalid);
        }
        let exp = object.get("exp").and_then(Value::as_u64).ok_or(invalid)?;
        let iat = object.get("iat").and_then(Value::as_u64).ok_or(invalid)?;
        if exp <= iat
            || exp.saturating_sub(iat) > self.config.max_lifetime_seconds
            || exp.saturating_add(self.config.leeway_seconds) <= now
            || iat > now.saturating_add(self.config.leeway_seconds)
        {
            return Err(invalid);
        }
        if let Some(nbf) = object.get("nbf") {
            let nbf = nbf.as_u64().ok_or(invalid)?;
            if nbf > exp || nbf > now.saturating_add(self.config.leeway_seconds) {
                return Err(invalid);
            }
        }
        let scopes = parse_scopes(object.get(&self.config.scope_claim))?;
        let groups = parse_groups(object.get(&self.config.groups_claim))?;
        Ok(Verified {
            subject: subject.into(),
            issuer: issuer.into(),
            audiences,
            client_id: client_id.into(),
            jti: jti.into(),
            scopes,
            groups,
            issued_at: iat,
            expires_at: exp,
        })
    }
}

fn split_token(token: &str) -> std::result::Result<(&str, &str, &str), VerifyError> {
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES || !token.is_ascii() {
        return Err(VerifyError::Invalid);
    }
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(claims), Some(signature), None)
            if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
        {
            Ok((header, claims, signature))
        }
        _ => Err(VerifyError::Invalid),
    }
}

fn decode_segment(segment: &str, max: usize) -> std::result::Result<Vec<u8>, VerifyError> {
    if segment.len() > max.saturating_mul(4).div_ceil(3) {
        return Err(VerifyError::Invalid);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| VerifyError::Invalid)?;
    if decoded.len() > max || URL_SAFE_NO_PAD.encode(&decoded) != segment {
        return Err(VerifyError::Invalid);
    }
    Ok(decoded)
}

fn parse_header(segment: &str) -> std::result::Result<KeyRequest, VerifyError> {
    let header = decode_segment(segment, MAX_HEADER_BYTES)?;
    let header = strict_json(&header).map_err(|_| VerifyError::Invalid)?;
    let object = header.as_object().ok_or(VerifyError::Invalid)?;
    if object.len() != 3
        || object
            .keys()
            .any(|name| !matches!(name.as_str(), "alg" | "kid" | "typ"))
    {
        return Err(VerifyError::Invalid);
    }
    let alg = object
        .get("alg")
        .and_then(Value::as_str)
        .and_then(JwtAlgorithm::from_name)
        .ok_or(VerifyError::Invalid)?;
    let kid = object
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| valid_kid(kid))
        .ok_or(VerifyError::Invalid)?;
    let typ = object
        .get("typ")
        .and_then(Value::as_str)
        .ok_or(VerifyError::Invalid)?;
    if !typ.eq_ignore_ascii_case("at+jwt") && !typ.eq_ignore_ascii_case("application/at+jwt") {
        return Err(VerifyError::Invalid);
    }
    Ok(KeyRequest {
        kid: kid.into(),
        algorithm: alg,
    })
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn valid_attribute(value: &str, scope: bool) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ATTRIBUTE_BYTES
        && value.trim() == value
        && !value.chars().any(char::is_control)
        && (!scope
            || value
                .bytes()
                .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\'))
}

fn parse_audiences(value: &Value) -> std::result::Result<Vec<String>, VerifyError> {
    let invalid = VerifyError::Invalid;
    let values: Vec<&str> = if let Some(one) = value.as_str() {
        vec![one]
    } else {
        value
            .as_array()
            .ok_or(invalid)?
            .iter()
            .map(|v| v.as_str().ok_or(invalid))
            .collect::<std::result::Result<_, _>>()?
    };
    if values.is_empty() || values.len() > 16 || values.iter().any(|v| !valid_identity(v)) {
        return Err(invalid);
    }
    let mut seen = HashSet::new();
    if !values.iter().all(|value| seen.insert(*value)) {
        return Err(invalid);
    }
    Ok(values.into_iter().map(str::to_owned).collect())
}

fn parse_scopes(value: Option<&Value>) -> std::result::Result<Vec<String>, VerifyError> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let raw = value.as_str().ok_or(VerifyError::Invalid)?;
    if raw.is_empty() {
        return Ok(vec![]);
    }
    let scopes: Vec<_> = raw.split(' ').collect();
    if scopes.len() > MAX_ATTRIBUTES || scopes.iter().any(|scope| !valid_attribute(scope, true)) {
        return Err(VerifyError::Invalid);
    }
    let mut seen = HashSet::new();
    if !scopes.iter().all(|scope| seen.insert(*scope)) {
        return Err(VerifyError::Invalid);
    }
    Ok(scopes.into_iter().map(str::to_owned).collect())
}

fn parse_groups(value: Option<&Value>) -> std::result::Result<Vec<String>, VerifyError> {
    let Some(value) = value else {
        return Ok(vec![]);
    };
    let values = value.as_array().ok_or(VerifyError::Invalid)?;
    if values.len() > MAX_ATTRIBUTES {
        return Err(VerifyError::Invalid);
    }
    let mut seen = HashSet::new();
    let mut groups = Vec::with_capacity(values.len());
    for value in values {
        let group = value
            .as_str()
            .filter(|group| valid_attribute(group, false))
            .ok_or(VerifyError::Invalid)?;
        if !seen.insert(group) {
            return Err(VerifyError::Invalid);
        }
        groups.push(group.to_owned());
    }
    Ok(groups)
}

/// Parse JSON while rejecting duplicate member names at every nesting level.
/// The caller must enforce a byte limit before invoking this helper.
pub(crate) fn strict_json(bytes: &[u8]) -> Result<Value> {
    ensure!(bytes.len() <= MAX_JWKS_BYTES, "strict JSON exceeds 128 KiB");
    Ok(serde_json::from_slice::<StrictValue>(bytes)?.0)
}

/// Duplicate-free JSON value for configuration fields that serde would
/// otherwise materialize as `Value` and silently collapse duplicate keys.
pub(crate) struct StrictValue(pub(crate) Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("duplicate-free JSON")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                value: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E: serde::de::Error>(
                self,
                value: i64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }
            fn visit_u64<E: serde::de::Error>(
                self,
                value: u64,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }
            fn visit_f64<E: serde::de::Error>(
                self,
                value: f64,
            ) -> std::result::Result<Self::Value, E> {
                Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("nonfinite number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                value: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.into())))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                value: String,
            ) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                    values.insert(key, value.0);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPrivateKey, traits::PublicKeyParts};

    fn config() -> JwtConfig {
        JwtConfig {
            issuer: "https://issuer.example.test/".into(),
            audiences: vec!["api://hangang".into()],
            profile: JwtProfile::Rfc9068,
            algorithms: vec![JwtAlgorithm::EdDSA],
            leeway_seconds: 0,
            max_lifetime_seconds: 3600,
            scope_claim: "scope".into(),
            groups_claim: "groups".into(),
            required_scopes: vec!["billing:read".into()],
            required_groups: vec!["ops".into()],
        }
    }

    fn key_material() -> (SigningKey, PreparedKeys) {
        let signing = SigningKey::from_bytes(&[42; 32]);
        let jwks = serde_json::json!({"keys":[{
            "kty":"OKP", "crv":"Ed25519", "kid":"signer-1", "alg":"EdDSA",
            "use":"sig", "key_ops":["verify"],
            "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes())
        }]});
        let keys =
            PreparedKeys::from_jwks_json(jwks.to_string().as_bytes(), &[JwtAlgorithm::EdDSA])
                .unwrap();
        (signing, keys)
    }

    fn claims() -> Value {
        serde_json::json!({
            "iss":"https://issuer.example.test/", "aud":"api://hangang", "sub":"alice",
            "client_id":"client-1", "jti":"token-1", "iat":1000, "exp":1300,
            "scope":"billing:read profile", "groups":["ops", "staff"]
        })
    }

    fn signed(signing: &SigningKey, header: &str, claims: &str) -> String {
        let message = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(claims)
        );
        let signature = signing.sign(message.as_bytes());
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
    }

    fn token(signing: &SigningKey, claims: &Value) -> String {
        signed(
            signing,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"at+jwt"}"#,
            &claims.to_string(),
        )
    }

    #[test]
    fn valid_access_token_is_bound_to_issuer_audience_key_and_permissions() {
        let verifier = JwtVerifier::prepare(config()).unwrap();
        let (signing, keys) = key_material();
        let access_token = token(&signing, &claims());
        let requested = verifier.key_request(&access_token).unwrap();
        assert_eq!(requested.kid, "signer-1");
        assert_eq!(requested.algorithm, JwtAlgorithm::EdDSA);
        let key = keys.get_for(&requested.kid, requested.algorithm).unwrap();
        let verified = verifier.verify(&access_token, &key, 1100).unwrap();
        assert_eq!(verified.subject, "alice");
        assert_eq!(verified.expires_at, 1300);
        assert_eq!(verified.client_id, "client-1");
        assert!(verifier.config().allows(&verified));
        let wrong_signing = SigningKey::from_bytes(&[43; 32]);
        let wrong_jwks = serde_json::json!({"keys":[{
            "kty":"OKP", "crv":"Ed25519", "kid":"signer-1", "alg":"EdDSA",
            "x":URL_SAFE_NO_PAD.encode(wrong_signing.verifying_key().to_bytes())
        }]});
        let wrong_keys =
            PreparedKeys::from_jwks_json(wrong_jwks.to_string().as_bytes(), &[JwtAlgorithm::EdDSA])
                .unwrap();
        assert_eq!(
            verifier.verify(
                &access_token,
                &wrong_keys.get("signer-1", JwtAlgorithm::EdDSA).unwrap(),
                1100
            ),
            Err(VerifyError::Invalid)
        );
        let mut reduced = claims();
        reduced["scope"] = serde_json::json!("profile");
        let token = token(&signing, &reduced);
        let verified = verifier.verify(&token, &key, 1100).unwrap();
        assert!(
            !verifier.config().allows(&verified),
            "valid but unauthorized is 403 at the caller"
        );
    }

    #[test]
    fn header_confusion_and_duplicate_claims_are_rejected() {
        let verifier = JwtVerifier::prepare(config()).unwrap();
        let (signing, keys) = key_material();
        let key = keys.get("signer-1", JwtAlgorithm::EdDSA).unwrap();
        let mut broken = token(&signing, &claims());
        broken.push('x');
        assert_eq!(
            verifier.verify(&broken, &key, 1100),
            Err(VerifyError::Invalid)
        );
        for header in [
            r#"{"alg":"none","kid":"signer-1","typ":"at+jwt"}"#,
            r#"{"alg":"HS256","kid":"signer-1","typ":"at+jwt"}"#,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"JWT"}"#,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"at+jwt","jku":"https://evil.test"}"#,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"at+jwt","crit":["b64"]}"#,
            r#"{"alg":"EdDSA","alg":"RS256","kid":"signer-1","typ":"at+jwt"}"#,
        ] {
            let token = signed(&signing, header, &claims().to_string());
            assert_eq!(
                verifier.key_request(&token),
                Err(VerifyError::Invalid),
                "{header}"
            );
        }
        let claim_text = claims()
            .to_string()
            .replace("\"sub\":\"alice\"", "\"sub\":\"alice\",\"sub\":\"bob\"");
        let duplicate_token = signed(
            &signing,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"at+jwt"}"#,
            &claim_text,
        );
        assert_eq!(
            verifier.key_request(&duplicate_token),
            Err(VerifyError::Invalid)
        );
        assert_eq!(
            verifier.verify(&duplicate_token, &key, 1100),
            Err(VerifyError::Invalid)
        );
        let token = format!("{}=", token(&signing, &claims()));
        assert_eq!(verifier.key_request(&token), Err(VerifyError::Invalid));
        let token = signed(
            &signing,
            r#"{"alg":"EdDSA","kid":"signer-1","typ":"application/at+jwt"}"#,
            &claims().to_string(),
        );
        assert!(verifier.verify(&token, &key, 1100).is_ok());
    }

    #[test]
    fn temporal_and_required_rfc9068_claims_fail_closed() {
        let verifier = JwtVerifier::prepare(config()).unwrap();
        let (signing, keys) = key_material();
        let key = keys.get("signer-1", JwtAlgorithm::EdDSA).unwrap();
        for (name, replacement) in [
            ("exp", Value::from(1099)),
            ("iat", Value::from(1200)),
            ("aud", Value::from("other-api")),
            ("iss", Value::from("https://other.test/")),
            ("sub", Value::from("")),
            ("client_id", Value::Null),
            ("jti", Value::Null),
        ] {
            let mut claims = claims();
            claims[name] = replacement;
            assert_eq!(
                verifier.verify(&token(&signing, &claims), &key, 1100),
                Err(VerifyError::Invalid),
                "{name}"
            );
        }
        let mut candidate = claims();
        candidate["exp"] = Value::from(9000);
        assert_eq!(
            verifier.verify(&token(&signing, &candidate), &key, 1100),
            Err(VerifyError::Invalid)
        );
        let mut candidate = claims();
        candidate["nbf"] = Value::from(1200);
        assert_eq!(
            verifier.verify(&token(&signing, &candidate), &key, 1100),
            Err(VerifyError::Invalid)
        );
        let mut candidate = claims();
        candidate["groups"] = Value::from("ops");
        assert_eq!(
            verifier.verify(&token(&signing, &candidate), &key, 1100),
            Err(VerifyError::Invalid)
        );
    }

    #[test]
    fn jwks_rejects_duplicates_private_keys_wrong_algorithms_and_weak_rsa() {
        let (_, keys) = key_material();
        assert_eq!(keys.len(), 1);
        assert!(keys.get_for("signer-1", JwtAlgorithm::RS256).is_none());
        for jwks in [
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"x","alg":"EdDSA","x":"AA","d":"AA"}]}"#,
            r#"{"keys":[{"kty":"RSA","kid":"x","alg":"RS256","n":"AQ","e":"AQAB"}]}"#,
            r#"{"keys":[{"kty":"OKP","crv":"P-256","kid":"x","alg":"EdDSA","x":"AA"}]}"#,
            r#"{"keys":[],"keys":[]}"#,
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"x","kid":"y","alg":"EdDSA","x":"AA"}]}"#,
        ] {
            assert!(
                PreparedKeys::from_jwks_json(
                    jwks.as_bytes(),
                    &[JwtAlgorithm::RS256, JwtAlgorithm::EdDSA]
                )
                .is_err(),
                "{jwks}"
            );
        }
    }

    #[test]
    fn rsa_and_pss_valid_signatures_and_wrong_keys() {
        let mut rng = rand::rngs::OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let wrong = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der = private.to_pkcs1_der().unwrap();
        let signing = jsonwebtoken::EncodingKey::from_rsa_der(der.as_bytes());
        let jwks = serde_json::json!({"keys":[
            {"kty":"RSA", "kid":"rsa+main/1=", "alg":"RS256",
             "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
             "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())},
            {"kty":"RSA", "kid":"pss", "alg":"PS256",
             "n":URL_SAFE_NO_PAD.encode(private.n().to_bytes_be()),
             "e":URL_SAFE_NO_PAD.encode(private.e().to_bytes_be())}
        ]});
        let wrong_jwks = serde_json::json!({"keys":[
            {"kty":"RSA", "kid":"rsa+main/1=", "alg":"RS256",
             "n":URL_SAFE_NO_PAD.encode(wrong.n().to_bytes_be()),
             "e":URL_SAFE_NO_PAD.encode(wrong.e().to_bytes_be())},
            {"kty":"RSA", "kid":"pss", "alg":"PS256",
             "n":URL_SAFE_NO_PAD.encode(wrong.n().to_bytes_be()),
             "e":URL_SAFE_NO_PAD.encode(wrong.e().to_bytes_be())}
        ]});
        let keys = PreparedKeys::from_jwks_json(
            jwks.to_string().as_bytes(),
            &[JwtAlgorithm::RS256, JwtAlgorithm::PS256],
        )
        .unwrap();
        let wrong_keys = PreparedKeys::from_jwks_json(
            wrong_jwks.to_string().as_bytes(),
            &[JwtAlgorithm::RS256, JwtAlgorithm::PS256],
        )
        .unwrap();
        let mut config = config();
        config.algorithms = vec![JwtAlgorithm::RS256, JwtAlgorithm::PS256];
        let verifier = JwtVerifier::prepare(config).unwrap();
        for (alg, kid) in [(Algorithm::RS256, "rsa+main/1="), (Algorithm::PS256, "pss")] {
            let mut header = jsonwebtoken::Header::new(alg);
            header.typ = Some("at+jwt".into());
            header.kid = Some(kid.into());
            let token = jsonwebtoken::encode(&header, &claims(), &signing).unwrap();
            let request = verifier.key_request(&token).unwrap();
            let key = keys.get(&request.kid, request.algorithm).unwrap();
            assert_eq!(
                verifier.verify(&token, &key, 1100).unwrap().subject,
                "alice"
            );
            let wrong_key = wrong_keys.get(&request.kid, request.algorithm).unwrap();
            assert_eq!(
                verifier.verify(&token, &wrong_key, 1100),
                Err(VerifyError::Invalid)
            );
        }
    }

    #[test]
    fn es256_valid_signature_and_invalid_public_point() {
        use p256::{SecretKey, elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePrivateKey};
        let mut rng = rand::rngs::OsRng;
        let private = SecretKey::random(&mut rng);
        let wrong = SecretKey::random(&mut rng);
        let point = private.public_key().to_encoded_point(false);
        let wrong_point = wrong.public_key().to_encoded_point(false);
        let key_json = |kid: &str, point: &p256::EncodedPoint| {
            serde_json::json!({"kty":"EC", "crv":"P-256", "kid":kid, "alg":"ES256",
                "x":URL_SAFE_NO_PAD.encode(point.x().unwrap()),
                "y":URL_SAFE_NO_PAD.encode(point.y().unwrap())})
        };
        let jwks = serde_json::json!({"keys":[key_json("ec-main", &point)]});
        let wrong_jwks = serde_json::json!({"keys":[key_json("ec-main", &wrong_point)]});
        let keys =
            PreparedKeys::from_jwks_json(jwks.to_string().as_bytes(), &[JwtAlgorithm::ES256])
                .unwrap();
        let wrong_keys =
            PreparedKeys::from_jwks_json(wrong_jwks.to_string().as_bytes(), &[JwtAlgorithm::ES256])
                .unwrap();
        let der = private.to_pkcs8_der().unwrap();
        let signing = jsonwebtoken::EncodingKey::from_ec_der(der.as_bytes());
        let mut header = jsonwebtoken::Header::new(Algorithm::ES256);
        header.typ = Some("at+jwt".into());
        header.kid = Some("ec-main".into());
        let token = jsonwebtoken::encode(&header, &claims(), &signing).unwrap();
        let mut config = config();
        config.algorithms = vec![JwtAlgorithm::ES256];
        let verifier = JwtVerifier::prepare(config).unwrap();
        assert!(
            verifier
                .verify(
                    &token,
                    &keys.get("ec-main", JwtAlgorithm::ES256).unwrap(),
                    1100
                )
                .is_ok()
        );
        assert_eq!(
            verifier.verify(
                &token,
                &wrong_keys.get("ec-main", JwtAlgorithm::ES256).unwrap(),
                1100
            ),
            Err(VerifyError::Invalid)
        );
        let invalid = serde_json::json!({"keys":[{
            "kty":"EC", "crv":"P-256", "kid":"not-on-curve", "alg":"ES256",
            "x":URL_SAFE_NO_PAD.encode([0u8;32]), "y":URL_SAFE_NO_PAD.encode([0u8;32])
        }]});
        assert!(
            PreparedKeys::from_jwks_json(invalid.to_string().as_bytes(), &[JwtAlgorithm::ES256])
                .is_err()
        );
    }

    #[test]
    fn long_valid_issuer_and_bounded_opaque_kid_are_accepted() {
        let issuer = format!("https://issuer.example.test/{}", "a".repeat(260));
        assert!(issuer.len() > MAX_IDENTITY_BYTES);
        let mut config = config();
        config.issuer = issuer.clone();
        let verifier = JwtVerifier::prepare(config).unwrap();
        let (signing, keys) = key_material();
        let mut claims = claims();
        claims["iss"] = Value::String(issuer);
        let token = token(&signing, &claims);
        let key = keys.get("signer-1", JwtAlgorithm::EdDSA).unwrap();
        assert!(verifier.verify(&token, &key, 1100).is_ok());
        assert!(valid_kid("issuer+opaque/id="));
    }
}
