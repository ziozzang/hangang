//! Bounded selection of completed raw TCP connection metadata.
//!
//! This affects only the recent-history ring. It never changes connection
//! admission, routing, active tracking, aggregate counters or TCP payloads.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
};

const MAX_POLICY_BYTES: usize = 64 * 1024;
const MAX_RULES: usize = 64;
const MAX_ENTRIES: usize = 64;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    #[default]
    Record,
    Drop,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub default_action: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub action: Action,
    #[serde(rename = "match")]
    pub criteria: Criteria,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Criteria {
    #[serde(default)]
    pub listen_addresses: Vec<SocketAddr>,
    #[serde(default)]
    pub peer_cidrs: Vec<ipnet::IpNet>,
    #[serde(default)]
    pub route_ids: Vec<String>,
    #[serde(default)]
    pub route_matched: Option<bool>,
    #[serde(default)]
    pub outcomes: Vec<crate::tcp_history::Outcome>,
}

/// Already validated and owned by a prepared configuration generation.
#[derive(Debug)]
pub struct CompiledPolicy {
    default_action: Action,
    rules: Vec<Rule>,
}

#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub listen: SocketAddr,
    pub peer_ip: IpAddr,
    pub route_id: Option<&'a str>,
    pub route_matched: bool,
    pub outcome: crate::tcp_history::Outcome,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_POLICY_BYTES,
            "settings.tcp_recent_recording exceeds 64 KiB"
        );
        ensure!(
            self.rules.len() <= MAX_RULES,
            "too many TCP recording rules"
        );
        let mut ids = HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            ensure!(valid_id(&rule.id, 64), "invalid TCP recording rule id");
            ensure!(ids.insert(&rule.id), "duplicate TCP recording rule id");
            let c = &rule.criteria;
            for count in [
                c.listen_addresses.len(),
                c.peer_cidrs.len(),
                c.route_ids.len(),
                c.outcomes.len(),
            ] {
                ensure!(count <= MAX_ENTRIES, "too many TCP recording match entries");
            }
            ensure!(
                c.route_matched != Some(false) || c.route_ids.is_empty(),
                "unmatched routes cannot have route ids"
            );
            for id in &c.route_ids {
                ensure!(valid_id(id, 128), "invalid TCP recording route id");
            }
        }
        Ok(())
    }

    pub fn validate_listeners(&self, configured: &[crate::config::TcpRoute]) -> Result<()> {
        self.validate()?;
        let addresses: HashSet<_> = configured.iter().map(|route| route.listen).collect();
        for address in self
            .rules
            .iter()
            .flat_map(|rule| &rule.criteria.listen_addresses)
        {
            ensure!(
                addresses.contains(address),
                "TCP recording listen address is not a configured raw TCP socket: {address}"
            );
        }
        Ok(())
    }

    pub fn compile(&self) -> Result<CompiledPolicy> {
        self.validate()?;
        Ok(CompiledPolicy {
            default_action: self.default_action,
            rules: self.rules.clone(),
        })
    }
}

impl CompiledPolicy {
    /// Rules use first-match order. Populated fields combine with AND;
    /// alternatives inside each list combine with OR.
    pub fn action(&self, input: Input<'_>) -> Action {
        self.rules
            .iter()
            .find(|rule| rule.criteria.matches(input))
            .map_or(self.default_action, |rule| rule.action)
    }
}

impl Criteria {
    fn matches(&self, input: Input<'_>) -> bool {
        (self.listen_addresses.is_empty() || self.listen_addresses.contains(&input.listen))
            && (self.peer_cidrs.is_empty()
                || self
                    .peer_cidrs
                    .iter()
                    .any(|cidr| cidr.contains(&input.peer_ip.to_canonical())))
            && (self.route_ids.is_empty()
                || input
                    .route_id
                    .is_some_and(|id| self.route_ids.iter().any(|expected| expected == id)))
            && self
                .route_matched
                .is_none_or(|value| value == input.route_matched)
            && (self.outcomes.is_empty() || self.outcomes.contains(&input.outcome))
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(
        listen: &str,
        peer_ip: &str,
        route_id: Option<&'a str>,
        outcome: crate::tcp_history::Outcome,
    ) -> Input<'a> {
        Input {
            listen: listen.parse().unwrap(),
            peer_ip: peer_ip.parse().unwrap(),
            route_id,
            route_matched: route_id.is_some(),
            outcome,
        }
    }

    #[test]
    fn first_match_and_canonical_peer_and_outcome() {
        let policy: Policy = serde_json::from_str(
            r#"{
          "default_action":"drop", "rules":[
            {"id":"specific", "action":"record", "match":{
              "listen_addresses":["127.0.0.1:11235"],
              "peer_cidrs":["192.0.2.0/24"], "route_ids":["raw"],
              "route_matched":true, "outcomes":["eof","idle_timeout"]}},
            {"id":"fallback", "action":"drop", "match":{}}
          ]}"#,
        )
        .unwrap();
        let compiled = policy.compile().unwrap();
        assert_eq!(
            compiled.action(input(
                "127.0.0.1:11235",
                "::ffff:192.0.2.5",
                Some("raw"),
                crate::tcp_history::Outcome::Eof
            )),
            Action::Record
        );
        assert_eq!(
            compiled.action(input(
                "127.0.0.1:11236",
                "192.0.2.5",
                Some("raw"),
                crate::tcp_history::Outcome::Eof
            )),
            Action::Drop
        );
        assert_eq!(
            compiled.action(input(
                "127.0.0.1:11235",
                "192.0.2.5",
                Some("raw"),
                crate::tcp_history::Outcome::DialFailed
            )),
            Action::Drop
        );
    }

    #[test]
    fn rejects_invalid_and_oversized_rules() {
        for value in [
            serde_json::json!({"rules":[{"id":"bad/id","action":"drop","match":{}}]}),
            serde_json::json!({"rules":[{"id":"same","action":"drop","match":{}},
                                         {"id":"same","action":"record","match":{}}]}),
            serde_json::json!({"rules":[{"id":"x","action":"record",
                                         "match":{"route_matched":false,"route_ids":["raw"]}}]}),
            serde_json::json!({"rules":[{"id":"x","action":"record",
                                         "match":{"outcomes":["not_an_outcome"]}}]}),
            serde_json::json!({"rules":[{"id":"x","action":"record",
                                         "match":{"peer_cidrs":["bad"]}}]}),
        ] {
            let parsed = serde_json::from_value::<Policy>(value);
            assert!(
                parsed
                    .as_ref()
                    .map_or(true, |policy| policy.validate().is_err())
            );
        }
        let mut policy = Policy::default();
        for index in 0..65 {
            policy.rules.push(Rule {
                id: format!("r{index}"),
                action: Action::Drop,
                criteria: Criteria::default(),
            });
        }
        assert!(policy.validate().is_err());
        policy.rules.truncate(1);
        policy.rules[0].criteria.route_ids = vec!["x".into(); 65];
        assert!(policy.validate().is_err());
    }

    #[test]
    fn config_accepts_only_configured_raw_listener_and_roundtrips() {
        let source = serde_json::json!({
            "settings": {"tcp_recent_recording": {"default_action":"drop", "rules":[
                {"id":"socket", "action":"record", "match":{
                    "listen_addresses":["127.0.0.1:11235"], "outcomes":["no_route"]}}
            ]}},
            "tcp": [{"id":"raw", "listen":"127.0.0.1:11235",
                     "backends":["127.0.0.1:11234"]}]
        });
        let config: crate::config::Config = serde_json::from_value(source).unwrap();
        config.validate().unwrap();
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(
            json["settings"]["tcp_recent_recording"]["rules"][0]["match"]["outcomes"],
            serde_json::json!(["no_route"])
        );
        let restored: crate::config::Config = serde_json::from_value(json).unwrap();
        assert_eq!(restored, config);
        let mut unknown = config.clone();
        unknown
            .settings
            .tcp_recent_recording
            .as_mut()
            .unwrap()
            .rules[0]
            .criteria
            .listen_addresses = vec!["127.0.0.1:11335".parse().unwrap()];
        assert!(
            unknown
                .validate()
                .unwrap_err()
                .to_string()
                .contains("configured raw TCP socket")
        );
        let legacy = crate::config::Config::default();
        assert!(
            serde_json::to_value(legacy).unwrap()["settings"]
                .get("tcp_recent_recording")
                .is_none()
        );
    }
}
