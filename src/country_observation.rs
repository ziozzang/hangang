//! One owned country lookup result for route admission, telemetry, and Lua.
//!
//! It contains only bounded values. In particular, retaining an observation
//! for a long request or TCP stream cannot retain a GeoIP database generation.

use std::{net::IpAddr, sync::Arc};

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::geoip_runtime::Slot;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    NotChecked,
    NotConfigured,
    Known,
    Unknown,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyUnavailable;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct Observation {
    pub state: State,
    pub country: Option<String>,
    pub generation_sha256: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationWire {
    #[serde(default)]
    state: State,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    generation_sha256: Option<String>,
    #[serde(default)]
    error_code: Option<String>,
}

impl<'de> Deserialize<'de> for Observation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = ObservationWire::deserialize(deserializer)?;
        let observation = Self {
            state: wire.state,
            country: wire.country,
            generation_sha256: wire.generation_sha256,
            error_code: wire.error_code,
        };
        observation.validate().map_err(D::Error::custom)?;
        Ok(observation)
    }
}

impl Observation {
    /// Validate even locally constructed values before using them at an IPC
    /// boundary. Deserialization calls this automatically.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.country.as_ref().is_some_and(|country| {
            country.len() != 2 || !country.bytes().all(|byte| byte.is_ascii_uppercase())
        }) {
            return Err("country must be two uppercase ASCII letters");
        }
        if self.generation_sha256.as_ref().is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        }) {
            return Err("generation_sha256 must be lowercase SHA-256 hex");
        }
        if self
            .error_code
            .as_ref()
            .is_some_and(|code| !valid_error_code(code))
        {
            return Err("error_code must be a safe GeoIP provider code");
        }
        match self.state {
            State::NotChecked | State::NotConfigured
                if self.country.is_none()
                    && self.generation_sha256.is_none()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            State::Known
                if self.country.is_some()
                    && self.generation_sha256.is_some()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            State::Unknown
                if self.country.is_none()
                    && self.generation_sha256.is_some()
                    && self.error_code.is_none() =>
            {
                Ok(())
            }
            State::Unavailable if self.country.is_none() && self.error_code.is_some() => Ok(()),
            _ => Err("country observation fields conflict with state"),
        }
    }

    /// Only a successful lookup can become policy input. A missing, pending,
    /// stale, or failed database must never be interpreted as unknown country.
    pub fn policy_country(&self) -> Result<Option<&str>, PolicyUnavailable> {
        self.validate().map_err(|_| PolicyUnavailable)?;
        match self.state {
            State::Known => self.country.as_deref().ok_or(PolicyUnavailable).map(Some),
            State::Unknown => Ok(None),
            State::NotChecked | State::NotConfigured | State::Unavailable => Err(PolicyUnavailable),
        }
    }
}

fn valid_error_code(code: &str) -> bool {
    matches!(
        code,
        "pending"
            | "invalid_limits"
            | "invalid_path"
            | "unavailable"
            | "not_regular_file"
            | "too_large"
            | "changed_during_read"
            | "invalid_database"
            | "unsupported_database"
            | "stale_database"
            | "future_database"
            | "clock"
            | "invalid_record"
    )
}

/// Capture one immutable database generation and discard its Arc before
/// returning. `None` is a missing configured source; a configured but unready
/// source is `Unavailable`, not a successful unknown-country lookup.
pub fn capture(slot: Option<&Arc<Slot>>, ip: IpAddr) -> Observation {
    let Some(slot) = slot else {
        return Observation {
            state: State::NotConfigured,
            ..Observation::default()
        };
    };
    let Some(database) = slot.load() else {
        // A status read can race with publication of the next generation. It
        // is used only for a safe error code, never to infer availability or
        // attach a digest from a generation this lookup did not acquire.
        let code = slot.status().error_code.unwrap_or("pending");
        return Observation {
            state: State::Unavailable,
            error_code: Some(code.to_owned()),
            ..Observation::default()
        };
    };
    let digest = database.status().generation_sha256.clone();
    match database.lookup(ip) {
        Ok(Some(country)) => Observation {
            state: State::Known,
            country: Some(country.as_str().to_owned()),
            generation_sha256: Some(digest),
            error_code: None,
        },
        Ok(None) => Observation {
            state: State::Unknown,
            country: None,
            generation_sha256: Some(digest),
            error_code: None,
        },
        Err(error) => Observation {
            state: State::Unavailable,
            country: None,
            generation_sha256: Some(digest),
            error_code: Some(error.code().to_owned()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::geoip_runtime::{self, Source};
    use serde_json::{Value, json};
    use std::{
        path::Path,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    use tokio_util::sync::CancellationToken;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/geoip/GeoIP2-Country-Test.mmdb");

    fn fresh_fixture() -> Vec<u8> {
        let mut bytes = FIXTURE.to_vec();
        const MARKER: &[u8] = b"build_epoch\x04\x02";
        let offsets = bytes
            .windows(MARKER.len())
            .enumerate()
            .filter_map(|(index, part)| (part == MARKER).then_some(index + MARKER.len()))
            .collect::<Vec<_>>();
        assert_eq!(offsets.len(), 1);
        let epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3_600;
        bytes[offsets[0]..offsets[0] + 4]
            .copy_from_slice(&u32::try_from(epoch).unwrap().to_be_bytes());
        bytes
    }

    fn source(path: &Path) -> Source {
        Source {
            file: path.to_owned(),
            max_file_bytes: 32 * 1024 * 1024,
            max_age_days: 1,
            reload_interval_seconds: 1,
        }
    }

    #[test]
    fn strict_deserialization_checks_every_state_and_bounded_values() {
        let digest = "a".repeat(64);
        let valid = [
            json!({}),
            json!({"state":"not_configured"}),
            json!({"state":"known","country":"GB","generation_sha256":digest}),
            json!({"state":"unknown","generation_sha256":digest}),
            json!({"state":"unavailable","error_code":"pending"}),
            json!({"state":"unavailable","error_code":"invalid_record",
                "generation_sha256":digest}),
        ];
        for value in valid {
            let parsed: Observation = serde_json::from_value(value).unwrap();
            parsed.validate().unwrap();
            let again: Observation =
                serde_json::from_value(serde_json::to_value(&parsed).unwrap()).unwrap();
            assert_eq!(parsed, again);
        }
        let invalid: [Value; 12] = [
            json!({"state":"known","country":"GB"}),
            json!({"state":"known","country":"G1","generation_sha256":digest}),
            json!({"state":"unknown","country":"GB","generation_sha256":digest}),
            json!({"state":"unknown"}),
            json!({"state":"unavailable","error_code":"pending","country":"GB"}),
            json!({"state":"unavailable","error_code":"/private/path"}),
            json!({"state":"unavailable"}),
            json!({"state":"not_checked","generation_sha256":digest}),
            json!({"state":"not_configured","error_code":"pending"}),
            json!({"state":"known","country":"GB","generation_sha256":"A".repeat(64)}),
            json!({"state":"known","country":"GB","generation_sha256":digest,
                "future_field":true}),
            json!({"state":"future"}),
        ];
        for value in invalid {
            assert!(
                serde_json::from_value::<Observation>(value.clone()).is_err(),
                "{value}"
            );
        }
        assert_eq!(
            Observation::default().policy_country(),
            Err(PolicyUnavailable)
        );
    }

    #[tokio::test]
    async fn captures_known_mapped_unknown_and_unavailable_without_retaining_slot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("country.mmdb");
        std::fs::write(&path, fresh_fixture()).unwrap();
        let slot = geoip_runtime::Slot::new(source(&path)).unwrap();
        let public = "81.2.69.160".parse().unwrap();
        assert_eq!(capture(None, public).state, State::NotConfigured);
        let pending = capture(Some(&slot), public);
        assert_eq!(pending.state, State::Unavailable);
        assert_eq!(pending.error_code.as_deref(), Some("pending"));
        assert_eq!(pending.policy_country(), Err(PolicyUnavailable));

        let cancel = CancellationToken::new();
        let watcher = tokio::spawn(geoip_runtime::watch(
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
        let known = capture(Some(&slot), public);
        assert_eq!(known.state, State::Known);
        assert_eq!(known.country.as_deref(), Some("GB"));
        assert_eq!(known.policy_country(), Ok(Some("GB")));
        assert_eq!(known.generation_sha256.as_deref().map(str::len), Some(64));
        let mapped = capture(Some(&slot), "::ffff:81.2.69.160".parse().unwrap());
        assert_eq!(mapped.country, known.country);
        assert_eq!(mapped.generation_sha256, known.generation_sha256);
        let private = capture(Some(&slot), "127.0.0.1".parse().unwrap());
        assert_eq!(private.state, State::Unknown);
        assert_eq!(private.policy_country(), Ok(None));
        assert_eq!(private.generation_sha256, known.generation_sha256);

        let replacement = dir.path().join("replacement.mmdb");
        std::fs::write(&replacement, b"damaged fixture").unwrap();
        std::fs::rename(replacement, &path).unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while slot.status().ready {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let failed = capture(Some(&slot), public);
        assert_eq!(failed.state, State::Unavailable);
        assert_eq!(failed.error_code.as_deref(), Some("invalid_database"));
        assert_eq!(failed.generation_sha256, None);
        assert_eq!(failed.policy_country(), Err(PolicyUnavailable));

        cancel.cancel();
        watcher.await.unwrap();
        let weak = Arc::downgrade(&slot);
        drop(slot);
        assert!(
            weak.upgrade().is_none(),
            "observations retained a GeoIP slot"
        );
        assert_eq!(known.country.as_deref(), Some("GB"));
    }
}
