//! Route-local country admission from a verified offline GeoIP result.
//!
//! The caller owns database availability and lookup errors. Only a successful
//! lookup's country or explicit `None` for an unrepresented address reaches
//! this module; treating a database error as unknown would weaken admission.

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt};

use crate::geoip::CountryCode;

pub const MAX_COUNTRY_CODES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownAction {
    Allow,
    Deny,
}

/// A country rule belongs to one HTTP or TCP route. There is no implicit
/// process-wide country filter. Disabling enforcement retains and validates
/// the configured rule, but admission callers should skip GeoIP lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny: Vec<String>,
    pub on_unknown: UnknownAction,
    #[serde(default = "enforce_default", skip_serializing_if = "is_enforced")]
    pub enforce: bool,
}

fn enforce_default() -> bool {
    true
}

fn is_enforced(value: &bool) -> bool {
    *value
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    Empty,
    TooManyCountryCodes,
    InvalidCountryCode,
    DuplicateCountryCode,
    UnknownCannotSatisfyAllowlist,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "country policy requires at least one allow or deny country",
            Self::TooManyCountryCodes => "country policy has too many country codes",
            Self::InvalidCountryCode => "country policy requires two uppercase ASCII letters",
            Self::DuplicateCountryCode => "country policy repeats a country code within a list",
            Self::UnknownCannotSatisfyAllowlist => {
                "unknown country cannot be allowed when an allowlist is configured"
            }
        })
    }
}

impl std::error::Error for PolicyError {}

impl Policy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        self.compile().map(|_| ())
    }

    pub fn compile(&self) -> Result<CompiledCountryPolicy, PolicyError> {
        if self.allow.is_empty() && self.deny.is_empty() {
            return Err(PolicyError::Empty);
        }
        if self.allow.len().saturating_add(self.deny.len()) > MAX_COUNTRY_CODES {
            return Err(PolicyError::TooManyCountryCodes);
        }
        if !self.allow.is_empty() && self.on_unknown == UnknownAction::Allow {
            return Err(PolicyError::UnknownCannotSatisfyAllowlist);
        }
        let mut allow = HashSet::with_capacity(self.allow.len());
        let mut deny = HashSet::with_capacity(self.deny.len());
        for (source, target) in [(&self.allow, &mut allow), (&self.deny, &mut deny)] {
            for code in source {
                if !valid_country_code(code) {
                    return Err(PolicyError::InvalidCountryCode);
                }
                if !target.insert(code.clone()) {
                    return Err(PolicyError::DuplicateCountryCode);
                }
            }
        }
        Ok(CompiledCountryPolicy {
            allow,
            deny,
            on_unknown: self.on_unknown,
            enforce: self.enforce,
        })
    }
}

fn valid_country_code(value: &str) -> bool {
    value.len() == 2 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

/// A prepared route policy. `None` is only a successful database lookup of
/// an unknown, private, or unrepresented address; DB errors never enter here.
#[derive(Clone, Debug)]
pub struct CompiledCountryPolicy {
    allow: HashSet<String>,
    deny: HashSet<String>,
    on_unknown: UnknownAction,
    enforce: bool,
}

impl CompiledCountryPolicy {
    pub fn enforced(&self) -> bool {
        self.enforce
    }

    pub fn evaluate(&self, country: Option<CountryCode>) -> bool {
        self.evaluate_code(country.as_ref().map(CountryCode::as_str))
    }

    fn evaluate_code(&self, country: Option<&str>) -> bool {
        if !self.enforce {
            return true;
        }
        let Some(country) = country else {
            return self.on_unknown == UnknownAction::Allow;
        };
        !self.deny.contains(country) && (self.allow.is_empty() || self.allow.contains(country))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, to_value};

    fn policy(allow: &[&str], deny: &[&str], on_unknown: UnknownAction) -> Policy {
        Policy {
            allow: allow.iter().map(|code| (*code).to_owned()).collect(),
            deny: deny.iter().map(|code| (*code).to_owned()).collect(),
            on_unknown,
            enforce: true,
        }
    }

    #[test]
    fn strict_wire_requires_unknown_action_and_omits_default_enforcement() {
        assert!(serde_json::from_value::<Policy>(json!({"allow":["US"]})).is_err());
        assert!(
            serde_json::from_value::<Policy>(json!({
                "allow":["US"], "on_unknown":"deny", "future_option":true
            }))
            .is_err()
        );
        let parsed: Policy = serde_json::from_value(json!({
            "allow":["US"], "on_unknown":"deny"
        }))
        .unwrap();
        assert!(parsed.enforce);
        assert_eq!(
            to_value(&parsed).unwrap(),
            json!({
                "allow":["US"], "on_unknown":"deny"
            })
        );
        let disabled: Policy = serde_json::from_value(json!({
            "deny":["RU"], "on_unknown":"allow", "enforce":false
        }))
        .unwrap();
        assert!(!disabled.enforce);
        assert_eq!(
            to_value(disabled).unwrap(),
            json!({
                "deny":["RU"], "on_unknown":"allow", "enforce":false
            })
        );
    }

    #[test]
    fn deny_wins_known_overlap_and_unknown_is_explicit() {
        let compiled = policy(&["US", "KR"], &["US"], UnknownAction::Deny)
            .compile()
            .unwrap();
        assert!(!compiled.evaluate_code(Some("US")));
        assert!(compiled.evaluate_code(Some("KR")));
        assert!(!compiled.evaluate_code(Some("GB")));
        assert!(!compiled.evaluate(None));

        let deny_only = policy(&[], &["RU"], UnknownAction::Allow)
            .compile()
            .unwrap();
        assert!(deny_only.evaluate_code(Some("KR")));
        assert!(!deny_only.evaluate_code(Some("RU")));
        assert!(deny_only.evaluate(None));
    }

    #[test]
    fn enforced_allowlist_never_accepts_unknown_even_when_disabled_rule_is_stored() {
        let mut invalid = policy(&["US"], &[], UnknownAction::Allow);
        assert_eq!(
            invalid.validate(),
            Err(PolicyError::UnknownCannotSatisfyAllowlist)
        );
        invalid.enforce = false;
        assert_eq!(
            invalid.validate(),
            Err(PolicyError::UnknownCannotSatisfyAllowlist)
        );

        let mut disabled = policy(&["US"], &["KR"], UnknownAction::Deny);
        disabled.enforce = false;
        let compiled = disabled.compile().unwrap();
        assert!(!compiled.enforced());
        assert!(compiled.evaluate(None));
        assert!(compiled.evaluate_code(Some("KR")));
    }

    #[test]
    fn codes_are_exact_uppercase_and_bounded_per_list() {
        for code in ["U", "USA", "us", "U1", "ÜS", "U S", ""] {
            let invalid = policy(&[code], &[], UnknownAction::Deny);
            assert_eq!(
                invalid.validate(),
                Err(PolicyError::InvalidCountryCode),
                "{code:?}"
            );
        }
        let duplicate_allow = policy(&["US", "US"], &[], UnknownAction::Deny);
        assert_eq!(
            duplicate_allow.validate(),
            Err(PolicyError::DuplicateCountryCode)
        );
        let duplicate_deny = policy(&[], &["RU", "RU"], UnknownAction::Deny);
        assert_eq!(
            duplicate_deny.validate(),
            Err(PolicyError::DuplicateCountryCode)
        );
        assert_eq!(
            policy(&[], &[], UnknownAction::Deny).validate(),
            Err(PolicyError::Empty)
        );

        let mut too_many = policy(&[], &[], UnknownAction::Deny);
        too_many.allow = vec!["US".to_owned(); MAX_COUNTRY_CODES + 1];
        assert_eq!(too_many.validate(), Err(PolicyError::TooManyCountryCodes));

        let exactly_at_limit = Policy {
            allow: (0..MAX_COUNTRY_CODES)
                .map(|index| {
                    let first = char::from(b'A' + (index / 26) as u8);
                    let second = char::from(b'A' + (index % 26) as u8);
                    format!("{first}{second}")
                })
                .collect(),
            deny: Vec::new(),
            on_unknown: UnknownAction::Deny,
            enforce: true,
        };
        exactly_at_limit.validate().unwrap();

        // Cross-list overlap is deliberate and is resolved by deny precedence.
        policy(&["US"], &["US"], UnknownAction::Deny)
            .validate()
            .unwrap();
    }
}
