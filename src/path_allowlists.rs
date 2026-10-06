//! URL-local allowlists using verified client IP and one owned GeoIP result.
use anyhow::{Result, ensure};
use hyper::Request;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub include_subpaths: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_cidrs: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_countries: Vec<String>,
}

fn country_policy(rule: &Rule) -> crate::country_policy::Policy {
    crate::country_policy::Policy {
        allow: rule.allow_countries.clone(),
        deny: Vec::new(),
        on_unknown: crate::country_policy::UnknownAction::Deny,
        enforce: true,
    }
}

pub fn validate(rules: &[Rule]) -> Result<()> {
    ensure!(
        rules.len() <= 128,
        "path allowlists allow at most 128 rules"
    );
    crate::path_blocks::validate(
        &rules
            .iter()
            .map(|rule| crate::path_blocks::Rule {
                path: rule.path.clone(),
                hosts: rule.hosts.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    let mut text = 0usize;
    for (index, rule) in rules.iter().enumerate() {
        ensure!(
            !rules[..index].contains(rule),
            "duplicate path allowlist rule"
        );
        ensure!(
            !rule.allow_cidrs.is_empty() || !rule.allow_countries.is_empty(),
            "path allowlist requires IP ranges or countries"
        );
        ensure!(
            rule.allow_cidrs.len() <= 1024,
            "path allowlist allows at most 1024 IP ranges"
        );
        ensure!(
            rule.allow_countries.len() <= 256,
            "path allowlist allows at most 256 countries"
        );
        if !rule.allow_countries.is_empty() {
            country_policy(rule).validate()?;
        }
        for (index, cidr) in rule.allow_cidrs.iter().enumerate() {
            ensure!(
                !rule.allow_cidrs[..index].contains(cidr),
                "duplicate path allowlist IP range"
            );
        }
        text = text.saturating_add(rule.path.len());
        for host in &rule.hosts {
            text = text.saturating_add(host.len());
        }
        for cidr in &rule.allow_cidrs {
            text = text.saturating_add(cidr.to_string().len());
        }
        for country in &rule.allow_countries {
            text = text.saturating_add(country.len());
        }
        ensure!(text <= 32 * 1024, "path allowlists exceed 32 KiB");
    }
    Ok(())
}

#[derive(Debug)]
pub struct Compiled {
    selector: crate::path_blocks::Rule,
    include_subpaths: bool,
    allow_cidrs: Vec<IpNet>,
    countries: Option<crate::country_policy::CompiledCountryPolicy>,
}

pub(crate) fn prepare(rules: &[Rule]) -> Result<Vec<Arc<Compiled>>> {
    validate(rules)?;
    rules
        .iter()
        .map(|rule| {
            Ok(Arc::new(Compiled {
                selector: crate::path_blocks::Rule {
                    path: rule.path.clone(),
                    hosts: rule.hosts.clone(),
                },
                include_subpaths: rule.include_subpaths,
                allow_cidrs: rule.allow_cidrs.clone(),
                countries: if rule.allow_countries.is_empty() {
                    None
                } else {
                    Some(country_policy(rule).compile()?)
                },
            }))
        })
        .collect()
}

fn country_admit(
    policy: &crate::country_policy::CompiledCountryPolicy,
    observed: &crate::country_observation::Observation,
) -> Result<(), u16> {
    let country = observed.policy_country().map_err(|_| 503u16)?;
    if !policy.evaluate_code(country) {
        return Err(403);
    }
    Ok(())
}

/// All matching allowlists apply. When IP ranges and countries are both
/// present, both must pass. Country is captured once, never from a header;
/// its returned owned observation must also serve later route policy checks.
pub(crate) fn check<B>(
    compiled: &[Arc<Compiled>],
    request: &Request<B>,
    forwarded_host: Option<&str>,
    verified_ip: IpAddr,
    slot: Option<&Arc<crate::geoip_runtime::Slot>>,
) -> Result<Option<crate::country_observation::Observation>, u16> {
    let ip = verified_ip.to_canonical();
    let mut observed = None;
    for rule in compiled {
        if !crate::path_blocks::selector_matches(
            &rule.selector,
            request,
            forwarded_host,
            rule.include_subpaths,
        )? {
            continue;
        }
        if !rule.allow_cidrs.is_empty() && !rule.allow_cidrs.iter().any(|net| net.contains(&ip)) {
            return Err(403);
        }
        if let Some(policy) = &rule.countries {
            let country =
                observed.get_or_insert_with(|| crate::country_observation::capture(slot, ip));
            country_admit(policy, country)?;
        }
    }
    Ok(observed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::country_observation::{Observation, State};

    fn rule() -> Rule {
        Rule {
            path: "/login".into(),
            hosts: vec![],
            include_subpaths: false,
            allow_cidrs: vec!["192.0.2.0/24".parse().unwrap()],
            allow_countries: vec![],
        }
    }
    fn request(path: &str, host: &str) -> Request<()> {
        Request::builder()
            .uri(path)
            .header("host", host)
            .body(())
            .unwrap()
    }
    fn admitted(rules: &[Arc<Compiled>], path: &str, ip: &str) -> Result<Option<Observation>, u16> {
        check(
            rules,
            &request(path, "app.example"),
            None,
            ip.parse().unwrap(),
            None,
        )
    }

    #[test]
    fn validation_rejects_empty_duplicates_bad_codes_and_oversized_text() {
        validate(&[rule()]).unwrap();
        assert!(validate(&[rule(), rule()]).is_err());
        let mut empty = rule();
        empty.allow_cidrs.clear();
        assert!(validate(&[empty]).is_err());
        for codes in [
            vec!["gb".into()],
            vec!["GB".into(), "GB".into()],
            vec!["BAD".into()],
        ] {
            let mut invalid = rule();
            invalid.allow_countries = codes;
            assert!(validate(&[invalid]).is_err());
        }
        let mut repeated = rule();
        repeated.allow_cidrs.push(repeated.allow_cidrs[0]);
        assert!(validate(&[repeated]).is_err());
        let mut oversized = rule();
        oversized.allow_cidrs = vec!["0.0.0.0/0".parse().unwrap(); 1025];
        assert!(validate(&[oversized]).is_err());
        let many: Vec<_> = (0..40)
            .map(|index| {
                let mut r = rule();
                r.path = format!("/{index}{}", "x".repeat(900));
                r
            })
            .collect();
        assert!(validate(&many).is_err());
        assert!(
            serde_json::from_value::<Rule>(
                serde_json::json!({"path":"/login","allow_cidrs":["invalid"]})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<Rule>(
                serde_json::json!({"path":"/login","allow_cidrs":["192.0.2.0/24"],"unknown":true})
            )
            .is_err()
        );
    }

    #[test]
    fn verified_cidrs_apply_to_aliases_and_canonical_mapped_ips_only() {
        let rules = prepare(&[rule()]).unwrap();
        assert_eq!(admitted(&rules, "/login", "192.0.2.7"), Ok(None));
        assert_eq!(
            admitted(&rules, "/log%69n?ignored=yes", "::ffff:192.0.2.7"),
            Ok(None)
        );
        assert_eq!(admitted(&rules, "/login", "198.51.100.7"), Err(403));
        assert_eq!(
            admitted(&rules, "/login/image.png", "198.51.100.7"),
            Ok(None)
        );
        assert_eq!(admitted(&rules, "/login-news", "198.51.100.7"), Ok(None));
        for path in [
            "/login%2fa",
            "/public/../login",
            "/%256cogin",
            "//login",
            "/login;parameter",
        ] {
            assert_eq!(admitted(&rules, path, "192.0.2.7"), Err(400), "{path}");
        }
        let mut descendants = rule();
        descendants.include_subpaths = true;
        let children = prepare(&[descendants]).unwrap();
        assert_eq!(
            admitted(&children, "/login/image.png", "198.51.100.7"),
            Err(403)
        );
        let mut forged = request("/login", "app.example");
        forged
            .headers_mut()
            .insert("x-forwarded-for", "192.0.2.7".parse().unwrap());
        assert_eq!(
            check(&rules, &forged, None, "198.51.100.7".parse().unwrap(), None),
            Err(403)
        );
    }

    #[test]
    fn overlapping_rules_intersect_and_trusted_host_scoping_is_conservative() {
        let mut broad = rule();
        broad.hosts = vec!["app.example".into()];
        let mut narrower = broad.clone();
        narrower.allow_cidrs = vec!["192.0.2.0/25".parse().unwrap()];
        let rules = prepare(&[broad, narrower]).unwrap();
        assert_eq!(admitted(&rules, "/login", "192.0.2.200"), Err(403));
        assert_eq!(admitted(&rules, "/login", "192.0.2.7"), Ok(None));
        let other = request("/login", "other.example");
        let outsider = "198.51.100.7".parse().unwrap();
        assert_eq!(check(&rules, &other, None, outsider, None), Ok(None));
        assert_eq!(
            check(&rules, &other, Some("app.example.:443"), outsider, None),
            Err(403)
        );
    }

    #[test]
    fn country_unknown_and_unavailability_cannot_satisfy_an_allowlist() {
        let mut country = rule();
        country.allow_countries = vec!["GB".into()];
        let rules = prepare(&[country]).unwrap();
        // Country whitelist does not make an outsider's IP acceptable (AND).
        assert_eq!(admitted(&rules, "/login", "198.51.100.7"), Err(403));
        assert_eq!(admitted(&rules, "/login", "192.0.2.7"), Err(503));
        let policy = rules[0].countries.as_ref().unwrap();
        let known = Observation {
            state: State::Known,
            country: Some("GB".into()),
            generation_sha256: Some("a".repeat(64)),
            error_code: None,
        };
        assert_eq!(country_admit(policy, &known), Ok(()));
        let mut wrong = known.clone();
        wrong.country = Some("KR".into());
        assert_eq!(country_admit(policy, &wrong), Err(403));
        let unknown = Observation {
            state: State::Unknown,
            country: None,
            ..known.clone()
        };
        assert_eq!(country_admit(policy, &unknown), Err(403));
        let unavailable = Observation {
            state: State::Unavailable,
            country: None,
            error_code: Some("pending".into()),
            generation_sha256: None,
        };
        assert_eq!(country_admit(policy, &unavailable), Err(503));
        let mut forged = request("/login", "app.example");
        forged
            .headers_mut()
            .insert("x-country", "GB".parse().unwrap());
        assert_eq!(
            check(&rules, &forged, None, "192.0.2.7".parse().unwrap(), None),
            Err(503)
        );
    }

    #[tokio::test]
    async fn real_geoip_lookup_returns_owned_evidence_and_denies_pending_or_unknown() {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use tokio_util::sync::CancellationToken;
        let mut bytes = include_bytes!("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb").to_vec();
        const MARKER: &[u8] = b"build_epoch\x04\x02";
        let offsets: Vec<_> = bytes
            .windows(MARKER.len())
            .enumerate()
            .filter_map(|(index, part)| (part == MARKER).then_some(index + MARKER.len()))
            .collect();
        assert_eq!(offsets.len(), 1);
        let epoch = u32::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 3600,
        )
        .unwrap();
        bytes[offsets[0]..offsets[0] + 4].copy_from_slice(&epoch.to_be_bytes());
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("country.mmdb");
        std::fs::write(&path, bytes).unwrap();
        let slot = crate::geoip_runtime::Slot::new(crate::geoip_runtime::Source {
            file: path,
            max_file_bytes: 32 * 1024 * 1024,
            max_age_days: 1,
            reload_interval_seconds: 1,
        })
        .unwrap();
        let mut country_only = rule();
        country_only.allow_cidrs.clear();
        country_only.allow_countries = vec!["GB".into()];
        let country_rules = prepare(&[country_only.clone()]).unwrap();
        let public: IpAddr = "81.2.69.160".parse().unwrap();
        let login = request("/login", "app.example");
        assert_eq!(
            check(&country_rules, &login, None, public, Some(&slot)),
            Err(503)
        );
        let cancel = CancellationToken::new();
        let watcher = tokio::spawn(crate::geoip_runtime::watch(
            slot.clone(),
            Arc::new(|_| true),
            cancel.clone(),
        ));
        tokio::time::timeout(Duration::from_secs(5), async {
            while slot.load().is_none() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let mut intersect = country_only.clone();
        intersect.allow_cidrs = vec!["81.2.69.0/24".parse().unwrap()];
        let both = prepare(&[country_only, intersect]).unwrap();
        let observed = check(&both, &login, None, public, Some(&slot))
            .unwrap()
            .unwrap();
        assert_eq!(observed.state, State::Known);
        assert_eq!(observed.country.as_deref(), Some("GB"));
        assert_eq!(
            observed.generation_sha256.as_deref().map(str::len),
            Some(64)
        );
        assert_eq!(
            check(
                &country_rules,
                &login,
                None,
                "127.0.0.1".parse().unwrap(),
                Some(&slot)
            ),
            Err(403)
        );
        cancel.cancel();
        watcher.await.unwrap();
        let weak = Arc::downgrade(&slot);
        drop(slot);
        assert!(
            weak.upgrade().is_none(),
            "returned evidence must not retain the GeoIP runtime generation"
        );
        assert_eq!(observed.country.as_deref(), Some("GB"));
    }
}
