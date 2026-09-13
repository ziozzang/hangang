//! A bounded, fail-closed resource authorization primitive for protected HTTP routes.
//!
//! This module does not establish a principal. Callers must pass evidence produced by
//! the configured Basic verifier or the configured external authorization response,
//! never a client request header or a Lua mutation. Host/path namespace admission is
//! a separate gateway-wide step that must happen before ordinary route predicates.

use anyhow::{Result, ensure};
use hyper::{HeaderMap, header::HeaderName};
use serde::{Deserialize, Deserializer, Serialize, de::Error};
use std::collections::HashSet;

const MAX_RESOURCE_ID: usize = 128;
const MAX_PATH: usize = 2048;
const MAX_SUBJECT_HEADER: usize = 128;
const MAX_SUBJECT: usize = 255;
const MAX_RULES: usize = 32;
const MAX_SUBJECTS_PER_RULE: usize = 32;
const MAX_METHODS_PER_RULE: usize = 16;
const MAX_POLICY_ITEMS: usize = 512;
const MAX_POLICY_TEXT: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    /// Opaque audit/policy identifier; route host and path predicates define its URL namespace.
    pub resource_id: String,
    /// Explicit first step for removing a protected namespace. A disabled
    /// policy remains structurally valid and bound to authentication so an
    /// older editor cannot erase its intent by omitting the field.
    #[serde(default = "enforce_default", skip_serializing_if = "is_enforced")]
    pub enforce: bool,
    pub principal: PrincipalSource,
    /// An empty list deliberately denies every principal.
    pub allow: Vec<AllowRule>,
}

fn enforce_default() -> bool {
    true
}

fn is_enforced(value: &bool) -> bool {
    *value
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum PrincipalSource {
    Basic,
    Jwt,
    External { subject_header: String },
}

impl<'de> Deserialize<'de> for PrincipalSource {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            source: String,
            #[serde(default)]
            subject_header: Option<String>,
        }
        let wire = Wire::deserialize(deserializer)?;
        match (wire.source.as_str(), wire.subject_header) {
            ("basic", None) => Ok(Self::Basic),
            ("jwt", None) => Ok(Self::Jwt),
            ("external", Some(subject_header)) => Ok(Self::External { subject_header }),
            ("basic", Some(_)) => Err(D::Error::custom("basic principal has no subject_header")),
            ("external", None) => Err(D::Error::custom("external principal needs subject_header")),
            _ => Err(D::Error::custom("invalid resource principal source")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowRule {
    /// Case-sensitive, exact authenticated subjects. `*` has no wildcard meaning.
    pub subjects: Vec<String>,
    /// Exact uppercase HTTP methods, or an explicit `*` for every method.
    pub methods: Vec<String>,
}

pub enum PrincipalEvidence<'a> {
    Basic(&'a str),
    Jwt(&'a crate::jwt_auth::Verified),
    External(&'a HeaderMap),
}

impl ResourcePolicy {
    /// Validate the wire document and the route's authenticated principal source.
    /// The caller also validates the route's `access_mode == protected` contract.
    pub fn validate_binding(
        &self,
        basic_auth: Option<&crate::config::BasicAuth>,
        external_auth: Option<&crate::config::ExternalAuth>,
    ) -> Result<()> {
        self.validate_binding_with_jwt(basic_auth, external_auth, None)
    }
    pub fn validate_binding_with_jwt(
        &self,
        basic_auth: Option<&crate::config::BasicAuth>,
        external_auth: Option<&crate::config::ExternalAuth>,
        jwt_auth: Option<&crate::jwt_runtime::JwtAuth>,
    ) -> Result<()> {
        ensure!(
            !self.resource_id.is_empty()
                && self.resource_id.len() <= MAX_RESOURCE_ID
                && self.resource_id.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
                }),
            "resource_id must contain 1..128 ASCII ID characters"
        );
        ensure!(
            external_auth.is_none_or(|auth| !auth.terminal_response),
            "resource policy cannot use external auth terminal_response"
        );
        match &self.principal {
            PrincipalSource::Jwt => ensure!(
                jwt_auth.is_some(),
                "resource principal jwt requires jwt_auth"
            ),
            PrincipalSource::Basic => {
                ensure!(
                    basic_auth.is_some(),
                    "resource principal basic requires basic_auth"
                );
            }
            PrincipalSource::External { subject_header } => {
                ensure!(
                    !subject_header.is_empty() && subject_header.len() <= MAX_SUBJECT_HEADER,
                    "resource subject_header must contain 1..128 bytes"
                );
                let header = subject_header.parse::<HeaderName>()?;
                ensure!(
                    external_auth.is_some_and(|auth| auth
                        .response_headers
                        .iter()
                        .any(|name| { name.eq_ignore_ascii_case(header.as_str()) })),
                    "resource external subject_header must be an auth response_header"
                );
            }
        }
        ensure!(
            self.allow.len() <= MAX_RULES,
            "too many resource allow rules"
        );
        let mut items = 0usize;
        let mut text = self.resource_id.len();
        for rule in &self.allow {
            ensure!(
                !rule.subjects.is_empty() && rule.subjects.len() <= MAX_SUBJECTS_PER_RULE,
                "resource rule needs 1..32 subjects"
            );
            ensure!(
                !rule.methods.is_empty() && rule.methods.len() <= MAX_METHODS_PER_RULE,
                "resource rule needs 1..16 methods"
            );
            let mut subjects = HashSet::new();
            for subject in &rule.subjects {
                ensure!(
                    valid_subject(
                        subject,
                        matches!(self.principal, PrincipalSource::External { .. })
                    ),
                    "invalid resource subject"
                );
                ensure!(subjects.insert(subject), "duplicate resource subject");
                text = text.saturating_add(subject.len());
            }
            let mut methods = HashSet::new();
            for method in &rule.methods {
                ensure!(valid_method(method), "invalid resource method");
                ensure!(methods.insert(method), "duplicate resource method");
                text = text.saturating_add(method.len());
            }
            ensure!(
                !rule.methods.iter().any(|method| method == "*") || methods.len() == 1,
                "resource method '*' must be the only method in its rule"
            );
            items = items.saturating_add(rule.subjects.len() + rule.methods.len());
        }
        ensure!(
            items <= MAX_POLICY_ITEMS && text <= MAX_POLICY_TEXT,
            "resource policy exceeds bounded item or text limits"
        );
        Ok(())
    }

    /// Evaluate a principal established by the selected authenticator. No matching
    /// rule, missing/duplicated external identity, or source mismatch denies access.
    pub fn allows(&self, method: &str, evidence: PrincipalEvidence<'_>) -> bool {
        let subject = match (&self.principal, evidence) {
            (PrincipalSource::Jwt, PrincipalEvidence::Jwt(verified)) => verified.subject.as_str(),
            (PrincipalSource::Basic, PrincipalEvidence::Basic(subject)) => subject,
            (
                PrincipalSource::External { subject_header },
                PrincipalEvidence::External(headers),
            ) => {
                let Ok(header) = subject_header.parse::<HeaderName>() else {
                    return false;
                };
                let mut values = headers.get_all(header).iter();
                let Some(first) = values.next() else {
                    return false;
                };
                if values.next().is_some() {
                    return false;
                }
                let Ok(subject) = std::str::from_utf8(first.as_bytes()) else {
                    return false;
                };
                subject
            }
            _ => return false,
        };
        if !valid_subject(
            subject,
            matches!(self.principal, PrincipalSource::External { .. }),
        ) || !valid_method(method)
        {
            return false;
        }
        self.allow.iter().any(|rule| {
            rule.subjects.iter().any(|allowed| allowed == subject)
                && rule
                    .methods
                    .iter()
                    .any(|allowed| allowed == "*" || allowed == method)
        })
    }
}

fn valid_subject(subject: &str, external_header: bool) -> bool {
    !subject.is_empty()
        && subject.len() <= MAX_SUBJECT
        && subject.trim() == subject
        && !subject.chars().any(char::is_control)
        // A comma can denote a proxy-merged list even in one external header
        // field. Basic usernames are verified as a single UTF-8 credential and
        // may legitimately contain a comma.
        && (!external_header || !subject.contains(','))
}

fn valid_method(method: &str) -> bool {
    method == "*"
        || (!method.is_empty()
            && method.len() <= 32
            && method
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-'))
}

/// Canonicalize an HTTP path before matching a protected resource namespace.
///
/// This decodes percent escapes exactly once and requires valid UTF-8. Raw or
/// encoded slash/backslash aliases, encoded percent (double decoding), control
/// bytes, query/fragment delimiters, semicolon path parameters, dot traversal,
/// and repeated slashes are rejected rather than interpreted differently by
/// an upstream. Ordinary Unicode, colon, at-sign and other RFC path punctuation
/// remain usable. Query is excluded: callers pass `uri.path()`, not
/// `path_and_query()`.
pub fn canonical_path(path: &str) -> Result<String> {
    ensure!(
        path.starts_with('/') && path.len() <= MAX_PATH,
        "resource path must start with / and contain at most 2048 bytes"
    );
    let mut output = Vec::with_capacity(path.len());
    let mut input = path.bytes();
    while let Some(byte) = input.next() {
        let decoded = if byte == b'%' {
            let hi = input.next().and_then(hex_digit);
            let lo = input.next().and_then(hex_digit);
            match (hi, lo) {
                (Some(hi), Some(lo)) => (hi << 4) | lo,
                _ => anyhow::bail!("invalid resource path escape"),
            }
        } else {
            byte
        };
        ensure!(
            !matches!(decoded, b'\\' | b'%' | b'?' | b'#' | b';' | 0..=31 | 127)
                && (decoded != b'/' || byte == b'/'),
            "ambiguous or unsupported resource path byte"
        );
        output.push(decoded);
    }
    let output = String::from_utf8(output)?;
    ensure!(
        !output.chars().any(char::is_control),
        "resource path contains Unicode control character"
    );
    ensure!(
        !output.contains("//"),
        "resource path has repeated separators"
    );
    ensure!(
        !output
            .split('/')
            .any(|segment| segment == "." || segment == ".."),
        "resource path has dot segment"
    );
    Ok(output)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    fn policy() -> ResourcePolicy {
        ResourcePolicy {
            resource_id: "billing.read".into(),
            enforce: true,
            principal: PrincipalSource::External {
                subject_header: "x-auth-subject".into(),
            },
            allow: vec![AllowRule {
                subjects: vec!["alice".into()],
                methods: vec!["GET".into(), "HEAD".into()],
            }],
        }
    }

    fn auth() -> crate::config::ExternalAuth {
        crate::config::ExternalAuth {
            url: "http://127.0.0.1/authorize".into(),
            request_headers: vec![],
            response_headers: vec!["X-Auth-Subject".into()],
            timeout_ms: 1000,
            forward_response: false,
            terminal_response: false,
        }
    }

    #[test]
    fn wire_round_trip_and_deny_by_default() {
        let p = policy();
        p.validate_binding(None, Some(&auth())).unwrap();
        let encoded = serde_json::to_value(&p).unwrap();
        assert_eq!(encoded["principal"]["source"], "external");
        assert!(encoded.get("enforce").is_none());
        assert_eq!(
            serde_json::from_value::<ResourcePolicy>(encoded).unwrap(),
            p
        );
        let mut disabled = p.clone();
        disabled.enforce = false;
        assert_eq!(serde_json::to_value(&disabled).unwrap()["enforce"], false);
        disabled.validate_binding(None, Some(&auth())).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-subject", HeaderValue::from_static("alice"));
        assert!(p.allows("GET", PrincipalEvidence::External(&headers)));
        assert!(!p.allows("POST", PrincipalEvidence::External(&headers)));
        assert!(!p.allows("GET", PrincipalEvidence::Basic("alice")));
        headers.append("x-auth-subject", HeaderValue::from_static("bob"));
        assert!(!p.allows("GET", PrincipalEvidence::External(&headers)));
        headers.clear();
        assert!(!p.allows("GET", PrincipalEvidence::External(&headers)));
    }

    #[test]
    fn external_subject_utf8_is_exact_and_invalid_encoding_is_denied() {
        let mut p = policy();
        p.allow[0].subjects = vec!["사용자".into()];
        p.validate_binding(None, Some(&auth())).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-auth-subject",
            HeaderValue::from_bytes("사용자".as_bytes()).unwrap(),
        );
        assert!(p.allows("GET", PrincipalEvidence::External(&headers)));
        headers.insert("x-auth-subject", HeaderValue::from_bytes(&[0xff]).unwrap());
        assert!(!p.allows("GET", PrincipalEvidence::External(&headers)));
    }

    #[test]
    fn authenticator_binding_is_explicit() {
        let mut p = policy();
        assert!(p.validate_binding(None, None).is_err());
        let mut wrong = auth();
        wrong.response_headers = vec!["x-other".into()];
        assert!(p.validate_binding(None, Some(&wrong)).is_err());
        let mut terminal = auth();
        terminal.terminal_response = true;
        assert!(p.validate_binding(None, Some(&terminal)).is_err());
        p.principal = PrincipalSource::External {
            subject_header: format!("x-{}", "a".repeat(127)),
        };
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        p.principal = PrincipalSource::Basic;
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        let basic = crate::config::BasicAuth {
            realm: "test".into(),
            credentials: vec![],
            hide_credentials: true,
            accept_proxy_authorization: false,
            identity_header: None,
        };
        p.validate_binding(Some(&basic), None).unwrap();
        assert!(p.validate_binding(Some(&basic), Some(&terminal)).is_err());
        assert!(p.allows("GET", PrincipalEvidence::Basic("alice")));
    }

    #[test]
    fn external_merged_subject_fails_closed_but_basic_utf8_is_exact() {
        let p = policy();
        let mut headers = HeaderMap::new();
        headers.insert("x-auth-subject", HeaderValue::from_static("alice,bob"));
        assert!(!p.allows("GET", PrincipalEvidence::External(&headers)));
        let mut basic = p.clone();
        basic.principal = PrincipalSource::Basic;
        basic.allow[0].subjects = vec!["고객,팀".into()];
        assert!(basic.allows("GET", PrincipalEvidence::Basic("고객,팀")));
        assert!(!basic.allows("GET", PrincipalEvidence::Basic("고객")));
        assert!(
            serde_json::from_value::<ResourcePolicy>(serde_json::json!({
                "resource_id":"x", "principal":{"source":"basic","subject_header":"x"}, "allow":[]
            }))
            .is_err()
        );
    }

    #[test]
    fn method_and_size_validation_rejects_ambiguous_rules() {
        let mut p = policy();
        p.allow[0].methods = vec!["get".into()];
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        p.allow[0].methods = vec!["*".into(), "GET".into()];
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        p.allow[0].methods = vec!["*".into()];
        p.allow[0].subjects = vec!["a".repeat(256)];
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        p.allow[0].subjects = vec!["alice".into()];
        p.validate_binding(None, Some(&auth())).unwrap();
        p.allow[0].subjects = vec!["last,first".into()];
        assert!(p.validate_binding(None, Some(&auth())).is_err());
        p.principal = PrincipalSource::Basic;
        p.validate_binding(
            Some(&crate::config::BasicAuth {
                realm: "test".into(),
                credentials: vec![],
                hide_credentials: false,
                accept_proxy_authorization: false,
                identity_header: None,
            }),
            None,
        )
        .unwrap();
        assert!(p.allows("GET", PrincipalEvidence::Basic("last,first")));
    }

    #[test]
    fn canonicalization_closes_encoded_and_dot_aliases() {
        assert_eq!(canonical_path("/").unwrap(), "/");
        assert_eq!(canonical_path("/ad%6din/x%7e").unwrap(), "/admin/x~");
        assert_eq!(
            canonical_path("/한%EA%B8%80:a@b!$&'()*+,=").unwrap(),
            "/한글:a@b!$&'()*+,="
        );
        for path in [
            "/public/../private",
            "/public/%2e%2e/private",
            "/public/%252e%252e/private",
            "/public%2fprivate",
            "/public\\private",
            "//private",
            "/public/%zz",
            "/public/%C0%AFprivate",
            "/public/%2Fprivate",
            "/public/%5cprivate",
            "/public/%3Fprivate",
            "/public/%23private",
            "/public/%3Bprivate",
            "/public/%00private",
            "/public;private",
            "/private?as=public",
        ] {
            assert!(canonical_path(path).is_err(), "{path}");
        }
        assert!(canonical_path(&format!("/{}", "x".repeat(MAX_PATH))).is_err());
        assert!(canonical_path("/%ED%A0%80").is_err());
    }
}
