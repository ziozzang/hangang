//! Bounded, native selection of completed HTTP response-head metadata.
//!
//! This policy controls observation only. It never changes admission, routing,
//! authentication, aggregate metrics, or the response sent to the client.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

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
    pub methods: Vec<String>,
    #[serde(default)]
    pub route_ids: Vec<String>,
    #[serde(default)]
    pub route_matched: Option<bool>,
    #[serde(default)]
    pub status_ranges: Vec<StatusRange>,
    #[serde(default)]
    pub path_prefixes: Vec<String>,
    #[serde(default)]
    pub peer_cidrs: Vec<ipnet::IpNet>,
    #[serde(default)]
    pub client_cidrs: Vec<ipnet::IpNet>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRange {
    pub min: u16,
    pub max: u16,
}

/// Already validated and owned by a prepared configuration generation.
#[derive(Debug)]
pub struct CompiledPolicy {
    default_action: Action,
    rules: Vec<Rule>,
}

#[derive(Clone, Copy)]
pub struct Input<'a> {
    pub method: &'a str,
    /// The complete URI path, before any traffic-record truncation.
    pub path: &'a str,
    pub route_id: Option<&'a str>,
    pub status: u16,
    pub peer_ip: IpAddr,
    pub client_ip: IpAddr,
}

impl Policy {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_POLICY_BYTES,
            "settings.http_recording exceeds 64 KiB"
        );
        ensure!(
            self.rules.len() <= MAX_RULES,
            "too many HTTP recording rules"
        );
        let mut ids = HashSet::with_capacity(self.rules.len());
        for rule in &self.rules {
            ensure!(valid_id(&rule.id, 64), "invalid HTTP recording rule id");
            ensure!(ids.insert(&rule.id), "duplicate HTTP recording rule id");
            let c = &rule.criteria;
            for len in [
                c.methods.len(),
                c.route_ids.len(),
                c.status_ranges.len(),
                c.path_prefixes.len(),
                c.peer_cidrs.len(),
                c.client_cidrs.len(),
            ] {
                ensure!(len <= MAX_ENTRIES, "too many HTTP recording match entries");
            }
            ensure!(
                c.route_matched != Some(false) || c.route_ids.is_empty(),
                "unmatched routes cannot have route ids"
            );
            for method in &c.methods {
                ensure!(valid_method(method), "invalid HTTP recording method");
            }
            for id in &c.route_ids {
                ensure!(valid_id(id, 128), "invalid HTTP recording route id");
            }
            for range in &c.status_ranges {
                ensure!(
                    (100..=599).contains(&range.min)
                        && (100..=599).contains(&range.max)
                        && range.min <= range.max,
                    "invalid HTTP recording status range"
                );
            }
            for prefix in &c.path_prefixes {
                ensure!(
                    prefix.starts_with('/')
                        && prefix.len() <= 256
                        && prefix
                            .bytes()
                            .all(|b| b.is_ascii_graphic() && b != b'?' && b != b'#'),
                    "invalid HTTP recording path prefix"
                );
            }
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
    /// First matching rule wins. Each populated field is conjunctive, while
    /// alternatives within a field are disjunctive. Empty fields are wildcards.
    pub fn action(&self, input: Input<'_>) -> Action {
        self.rules
            .iter()
            .find(|rule| rule.criteria.matches(input))
            .map_or(self.default_action, |rule| rule.action)
    }
}

impl Criteria {
    fn matches(&self, input: Input<'_>) -> bool {
        (self.methods.is_empty() || self.methods.iter().any(|m| m == input.method))
            && (self.route_ids.is_empty()
                || input
                    .route_id
                    .is_some_and(|id| self.route_ids.iter().any(|r| r == id)))
            && self
                .route_matched
                .is_none_or(|matched| matched == input.route_id.is_some())
            && (self.status_ranges.is_empty()
                || self
                    .status_ranges
                    .iter()
                    .any(|r| r.min <= input.status && input.status <= r.max))
            && (self.path_prefixes.is_empty()
                || self.path_prefixes.iter().any(|p| input.path.starts_with(p)))
            && (self.peer_cidrs.is_empty()
                || self
                    .peer_cidrs
                    .iter()
                    .any(|net| net.contains(&input.peer_ip)))
            && (self.client_cidrs.is_empty()
                || self
                    .client_cidrs
                    .iter()
                    .any(|net| net.contains(&input.client_ip)))
    }
}

fn valid_id(value: &str, max: usize) -> bool {
    (1..=max).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn valid_method(value: &str) -> bool {
    (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(method: &'a str, path: &'a str, route_id: Option<&'a str>) -> Input<'a> {
        Input {
            method,
            path,
            route_id,
            status: 503,
            peer_ip: "192.0.2.1".parse().unwrap(),
            client_ip: "198.51.100.3".parse().unwrap(),
        }
    }

    #[test]
    fn first_match_and_peer_client_are_distinct() {
        let policy: Policy = serde_json::from_str(r#"{
            "default_action":"drop", "rules":[
              {"id":"peer", "action":"record", "match":{"methods":["POST"],"peer_cidrs":["192.0.2.0/24"],"client_cidrs":["198.51.100.0/24"],"path_prefixes":["/private/"]}},
              {"id":"all", "action":"drop", "match":{}}
            ]}"#).unwrap();
        let compiled = policy.compile().unwrap();
        assert_eq!(
            compiled.action(input("POST", "/private/a", Some("r"))),
            Action::Record
        );
        assert_eq!(
            compiled.action(input("POST", "/privateX", Some("r"))),
            Action::Drop
        );
        assert_eq!(
            compiled.action(input("GET", "/private/a", Some("r"))),
            Action::Drop
        );
        let mut wrong_client = input("POST", "/private/a", Some("r"));
        wrong_client.client_ip = "203.0.113.1".parse().unwrap();
        assert_eq!(compiled.action(wrong_client), Action::Drop);
    }

    #[test]
    fn validates_bounds_and_unmatched_route_conflict() {
        let mut policy = Policy::default();
        let rule = Rule {
            id: "one".into(),
            action: Action::Drop,
            criteria: Criteria::default(),
        };
        policy.rules.push(rule.clone());
        policy.rules.push(rule);
        assert!(policy.validate().is_err());
        policy.rules.pop();
        policy.rules[0].criteria.route_matched = Some(false);
        policy.rules[0].criteria.route_ids.push("r".into());
        assert!(policy.validate().is_err());
        policy.rules[0].criteria.route_ids.clear();
        policy.rules[0].criteria.path_prefixes.push("x".repeat(300));
        assert!(policy.validate().is_err());
        policy.rules[0].criteria.path_prefixes = vec!["/ok".into()];
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn method_tokens_are_case_sensitive() {
        let policy = Policy {
            default_action: Action::Drop,
            rules: vec![Rule {
                id: "lower".into(),
                action: Action::Record,
                criteria: Criteria {
                    methods: vec!["customMethod".into()],
                    ..Criteria::default()
                },
            }],
        };
        let compiled = policy.compile().unwrap();
        assert_eq!(
            compiled.action(input("customMethod", "/", None)),
            Action::Record
        );
        assert_eq!(
            compiled.action(input("CUSTOMMETHOD", "/", None)),
            Action::Drop
        );
    }

    /// Pure matcher release diagnostic; excludes parse, compile, HTTP and ring.
    #[test]
    #[ignore]
    fn recording_matcher_release_diagnostic() {
        assert!(!std::hint::black_box(cfg!(debug_assertions)));
        const N: usize = 100_000;
        let baseline = Policy::default().compile().unwrap();
        let mut policy = Policy::default();
        for index in 0..64 {
            policy.rules.push(Rule {
                id: format!("rule-{index}"),
                action: Action::Drop,
                criteria: Criteria {
                    methods: vec!["LONGCUSTOMMETHOD17".into()],
                    path_prefixes: vec!["/private/".into()],
                    status_ranges: vec![StatusRange { min: 503, max: 503 }],
                    peer_cidrs: vec!["192.0.2.0/24".parse().unwrap()],
                    client_cidrs: vec![
                        if index == 63 {
                            "2001:db8::/32"
                        } else {
                            "2001:db9::/32"
                        }
                        .parse()
                        .unwrap(),
                    ],
                    ..Criteria::default()
                },
            });
        }
        let worst = policy.compile().unwrap();
        let mut sample = input("LONGCUSTOMMETHOD17", "/private/data", Some("r"));
        sample.client_ip = "2001:db8::1".parse().unwrap();
        assert_eq!(baseline.action(sample), Action::Record);
        assert_eq!(worst.action(sample), Action::Drop);
        for (name, matcher, expected) in [
            ("empty_record", &baseline, Action::Record),
            ("last_match_64", &worst, Action::Drop),
        ] {
            let started = std::time::Instant::now();
            for _ in 0..N {
                assert_eq!(
                    std::hint::black_box(matcher.action(std::hint::black_box(sample))),
                    expected
                );
            }
            let elapsed = started.elapsed();
            eprintln!(
                "recording matcher {name}: {N} checks, {:?}, {:.0} checks/s (pure matcher only)",
                elapsed,
                N as f64 / elapsed.as_secs_f64()
            );
        }
    }
}
