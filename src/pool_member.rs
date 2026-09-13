//! Pool-member wire model. Routes deserialize the enum, but validation rejects
//! named members until lifecycle publication and runtime admission are wired.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Legacy address or explicitly identified member in the same `backends`
/// array. A route must use exactly one variant for every entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Backend {
    Legacy(String),
    Member(PoolMember),
}

impl Backend {
    pub fn address(&self) -> &str {
        match self {
            Self::Legacy(address) => address,
            Self::Member(member) => &member.address,
        }
    }

    pub fn id(&self) -> Option<&str> {
        match self {
            Self::Legacy(_) => None,
            Self::Member(member) => Some(&member.id),
        }
    }

    pub fn weight(&self) -> u16 {
        match self {
            Self::Legacy(_) => 1,
            Self::Member(member) => member.weight,
        }
    }
}

impl From<String> for Backend {
    fn from(address: String) -> Self {
        Self::Legacy(address)
    }
}

impl From<&str> for Backend {
    fn from(address: &str) -> Self {
        Self::Legacy(address.to_owned())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolMember {
    pub id: String,
    pub address: String,
    #[serde(
        default = "default_weight",
        deserialize_with = "deserialize_weight",
        skip_serializing_if = "is_default_weight"
    )]
    pub weight: u16,
    #[serde(default, skip_serializing_if = "is_serving")]
    pub desired_state: DesiredState,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    #[default]
    Serving,
    Draining,
    Maintenance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Legacy,
    Named,
}

fn default_weight() -> u16 {
    1
}

fn deserialize_weight<'de, D>(deserializer: D) -> std::result::Result<u16, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let weight = u16::deserialize(deserializer)?;
    if !(1..=1000).contains(&weight) {
        return Err(serde::de::Error::custom(
            "pool member weight must be 1..1000",
        ));
    }
    Ok(weight)
}

fn is_default_weight(weight: &u16) -> bool {
    *weight == 1
}

fn is_serving(state: &DesiredState) -> bool {
    *state == DesiredState::Serving
}

impl PoolMember {
    pub fn validate(&self) -> Result<()> {
        let id = self.id.as_bytes();
        ensure!(
            (1..=64).contains(&id.len())
                && id[0].is_ascii_alphanumeric()
                && id[1..].iter().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b'-')
                }),
            "pool member id must be 1..64 ASCII bytes using A-Z, a-z, 0-9, '.', '_' or '-' and start with a letter or digit"
        );
        ensure!(
            !self.address.is_empty() && self.address.trim() == self.address,
            "pool member address must be nonempty without surrounding whitespace"
        );
        ensure!(
            (1..=1000).contains(&self.weight),
            "pool member weight must be 1..1000"
        );
        Ok(())
    }
}

/// Validate collection shape without resolving addresses or mutating state.
/// HTTP/TCP address syntax remains the responsibility of each route validator.
/// Object members cannot use legacy index-aligned `balance.weights`.
pub fn validate_backends(backends: &[Backend], legacy_weights: &[u16]) -> Result<BackendKind> {
    ensure!(
        (1..=128).contains(&backends.len()),
        "pool needs 1..128 backends"
    );
    match &backends[0] {
        Backend::Legacy(_) => {
            ensure!(
                backends
                    .iter()
                    .all(|backend| matches!(backend, Backend::Legacy(_))),
                "pool cannot mix string and object backends"
            );
            ensure!(
                legacy_weights.is_empty() || legacy_weights.len() == backends.len(),
                "legacy weights must match backend count"
            );
            ensure!(
                legacy_weights
                    .iter()
                    .all(|weight| (1..=1000).contains(weight)),
                "legacy backend weights must be 1..1000"
            );
            Ok(BackendKind::Legacy)
        }
        Backend::Member(_) => {
            ensure!(
                legacy_weights.is_empty(),
                "object backend weights conflict with balance.weights"
            );
            let mut ids = HashSet::with_capacity(backends.len());
            let mut addresses = HashSet::with_capacity(backends.len());
            for backend in backends {
                let Backend::Member(member) = backend else {
                    anyhow::bail!("pool cannot mix string and object backends");
                };
                member.validate()?;
                ensure!(ids.insert(member.id.as_str()), "duplicate pool member id");
                ensure!(
                    addresses.insert(member.address.as_str()),
                    "duplicate pool member address"
                );
            }
            Ok(BackendKind::Named)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn named(id: &str, address: &str) -> Backend {
        Backend::Member(PoolMember {
            id: id.into(),
            address: address.into(),
            weight: 1,
            desired_state: DesiredState::Serving,
        })
    }

    #[test]
    fn staged_members_are_not_accepted_as_live_route_configuration() {
        // Remove this staging guard only when runtime/publish admission gates
        // enforce every desired state, including Lua and retries.
        for state in ["serving", "draining", "maintenance"] {
            let member = serde_json::json!({"id":"origin", "address":"http://127.0.0.1:8080", "desired_state":state});
            let typed: Backend = serde_json::from_value(member.clone()).unwrap();
            validate_backends(&[typed], &[]).unwrap();
            let document = serde_json::json!({"http":[{"id":"route", "backends":[member]}]});
            let mut config: crate::config::Config = serde_json::from_value(document).unwrap();
            assert!(config.has_named_members());
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("named pool members are not activated")
            );
            config.http[0].enabled = false;
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("named pool members are not activated")
            );
            let document = serde_json::json!({"tcp":[{"id":"stream", "listen":"127.0.0.1:9000",
                "backends":[{"id":"origin", "address":"127.0.0.1:8080", "desired_state":state}]}]});
            let mut config: crate::config::Config = serde_json::from_value(document).unwrap();
            assert!(config.has_named_members());
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("named pool members are not activated")
            );
            config.tcp[0].enabled = false;
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .to_string()
                    .contains("named pool members are not activated")
            );
        }
    }

    #[test]
    fn accessors_and_legacy_conversions_keep_address_semantics() {
        let legacy = Backend::from("http://a.example");
        assert_eq!(legacy.address(), "http://a.example");
        assert_eq!(legacy.id(), None);
        assert_eq!(legacy.weight(), 1);
        assert_eq!(serde_json::to_value(&legacy).unwrap(), "http://a.example");
        let named = Backend::Member(PoolMember {
            id: "stable-a".into(),
            address: "http://b.example".into(),
            weight: 7,
            desired_state: DesiredState::Serving,
        });
        assert_eq!(named.address(), "http://b.example");
        assert_eq!(named.id(), Some("stable-a"));
        assert_eq!(named.weight(), 7);
    }

    #[test]
    fn legacy_string_arrays_round_trip_without_conversion() {
        let wire = json!(["https://a.example:443", "https://b.example:443"]);
        let backends: Vec<Backend> = serde_json::from_value(wire.clone()).unwrap();
        let legacy_config: crate::config::Config = serde_json::from_value(json!({
            "http": [{"id": "legacy", "backends": wire.clone()}]
        }))
        .unwrap();
        assert!(!legacy_config.has_named_members());
        legacy_config.validate().unwrap();
        assert_eq!(
            validate_backends(&backends, &[3, 1]).unwrap(),
            BackendKind::Legacy
        );
        assert_eq!(serde_json::to_value(backends).unwrap(), wire);
        let duplicates: Vec<Backend> =
            serde_json::from_value(json!(["https://a", "https://a"])).unwrap();
        assert_eq!(
            validate_backends(&duplicates, &[]).unwrap(),
            BackendKind::Legacy
        );
    }

    #[test]
    fn object_defaults_and_explicit_states_round_trip() {
        let backends: Vec<Backend> = serde_json::from_value(json!([
            {"id":"blue", "address":"https://a.example:443"},
            {"id":"green", "address":"https://b.example:443", "weight":3,
             "desired_state":"maintenance"},
            {"id":"yellow", "address":"https://c.example:443",
             "desired_state":"draining"}
        ]))
        .unwrap();
        assert_eq!(
            validate_backends(&backends, &[]).unwrap(),
            BackendKind::Named
        );
        let serialized = serde_json::to_value(&backends).unwrap();
        assert!(serialized[0].get("weight").is_none());
        assert!(serialized[0].get("desired_state").is_none());
        assert_eq!(serialized[1]["weight"], 3);
        assert_eq!(serialized[1]["desired_state"], "maintenance");
        assert_eq!(serialized[2]["desired_state"], "draining");
        assert_eq!(
            serde_json::from_value::<Vec<Backend>>(serialized).unwrap(),
            backends
        );
    }

    #[test]
    fn invalid_member_shapes_and_unknown_values_are_rejected() {
        for value in [
            json!({"address":"https://a"}),
            json!({"id":"a", "address":"https://a", "extra":true}),
            json!({"id":"a", "address":"https://a", "desired_state":"paused"}),
            json!({"id":"a", "address":"https://a", "weight":-1}),
            json!({"id":"a", "address":"https://a", "weight":1001}),
        ] {
            assert!(serde_json::from_value::<Backend>(value).is_err());
        }
        assert!(serde_json::from_value::<Backend>(Value::Null).is_err());
    }

    #[test]
    fn collection_validation_rejects_mixed_duplicate_or_conflicting_members() {
        assert!(validate_backends(&[], &[]).is_err());
        assert!(validate_backends(&vec![named("a", "https://a"); 129], &[]).is_err());
        assert!(
            validate_backends(&[named("a", "https://a"), Backend::Legacy("x".into())], &[])
                .is_err()
        );
        assert!(
            validate_backends(&[Backend::Legacy("x".into()), named("a", "https://a")], &[])
                .is_err()
        );
        assert!(validate_backends(&[named("a", "https://a")], &[1]).is_err());
        assert!(
            validate_backends(&[named("a", "https://a"), named("a", "https://b")], &[]).is_err()
        );
        assert!(
            validate_backends(&[named("a", "https://a"), named("b", "https://a")], &[]).is_err()
        );
        assert!(validate_backends(&[Backend::Legacy("x".into())], &[1, 2]).is_err());
        assert!(validate_backends(&[Backend::Legacy("x".into())], &[0]).is_err());
    }

    #[test]
    fn id_and_weight_validation_is_bounded_and_byte_exact() {
        for id in [
            "",
            "-bad",
            "bad/name",
            "white space",
            "한글",
            &"a".repeat(65),
        ] {
            let Backend::Member(member) = named(id, "https://a") else {
                unreachable!()
            };
            assert!(member.validate().is_err(), "id should be rejected: {id}");
        }
        for id in ["A", "a-_.Z9", &"a".repeat(64)] {
            let Backend::Member(member) = named(id, "https://a") else {
                unreachable!()
            };
            member.validate().unwrap();
        }
        assert!(
            validate_backends(&[named("A", "https://a"), named("a", "https://b")], &[]).is_ok()
        );
        let Backend::Member(mut member) = named("a", "https://a") else {
            unreachable!()
        };
        member.weight = 0;
        assert!(member.validate().is_err());
        member.weight = 1000;
        member.validate().unwrap();
        member.address = " https://a".into();
        assert!(member.validate().is_err());
    }
}
