//! Bounded GeoIP observation counters. Route IDs, addresses, database digests
//! and error details never become Prometheus labels.

use std::{
    array,
    fmt::Write,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::country_observation::{Observation, State};

const PROTOCOLS: [&str; 2] = ["http", "tcp"];
const LOOKUP_RESULTS: [&str; 3] = ["known", "unknown", "unavailable"];
const ADMISSION_RESULTS: [&str; 3] = ["allowed", "denied", "unavailable"];
const COUNTRY_COUNT: usize = 26 * 26;
const UNKNOWN_COUNTRY: usize = COUNTRY_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Http,
    Tcp,
}

impl Protocol {
    fn index(self) -> usize {
        match self {
            Self::Http => 0,
            Self::Tcp => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allowed,
    Denied,
    Unavailable,
}

impl Decision {
    fn index(self) -> usize {
        match self {
            Self::Allowed => 0,
            Self::Denied => 1,
            Self::Unavailable => 2,
        }
    }
}

/// The country dimension is exactly 676 uppercase two-letter slots plus one
/// unknown slot, per protocol. A malformed observation creates no series.
pub struct Counters {
    lookups: [[AtomicU64; 3]; 2],
    countries: [[AtomicU64; COUNTRY_COUNT + 1]; 2],
    admissions: [[AtomicU64; 3]; 2],
}

impl Default for Counters {
    fn default() -> Self {
        Self {
            lookups: array::from_fn(|_| array::from_fn(|_| AtomicU64::new(0))),
            countries: array::from_fn(|_| array::from_fn(|_| AtomicU64::new(0))),
            admissions: array::from_fn(|_| array::from_fn(|_| AtomicU64::new(0))),
        }
    }
}

fn country_index(code: &str) -> Option<usize> {
    let [first, second] = code.as_bytes() else {
        return None;
    };
    if !first.is_ascii_uppercase() || !second.is_ascii_uppercase() {
        return None;
    }
    Some(usize::from(first - b'A') * 26 + usize::from(second - b'A'))
}

impl Counters {
    /// Count a completed lookup and, only for an enforced route policy, its
    /// admission decision. A passive database failure has `decision: None`.
    pub fn observe(
        &self,
        protocol: Protocol,
        observation: &Observation,
        decision: Option<Decision>,
    ) {
        if observation.validate().is_err() {
            return;
        }
        let (lookup, country) = match observation.state {
            State::NotChecked | State::NotConfigured => return,
            State::Known => {
                let Some(index) = observation.country.as_deref().and_then(country_index) else {
                    return;
                };
                (0, Some(index))
            }
            State::Unknown => (1, Some(UNKNOWN_COUNTRY)),
            State::Unavailable => (2, None),
        };
        let protocol = protocol.index();
        self.lookups[protocol][lookup].fetch_add(1, Ordering::Relaxed);
        if let Some(country) = country {
            self.countries[protocol][country].fetch_add(1, Ordering::Relaxed);
        }
        if let Some(decision) = decision {
            self.admissions[protocol][decision.index()].fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Append only finite label values. Zero-valued country slots are omitted
    /// to keep routine scrapes small; their upper bound remains fixed.
    pub fn render(&self, output: &mut String) {
        output.push_str("# HELP hangang_geoip_lookups_total Completed node-local country lookups.\n# TYPE hangang_geoip_lookups_total counter\n");
        for (protocol, name) in PROTOCOLS.iter().enumerate() {
            for (result, label) in LOOKUP_RESULTS.iter().enumerate() {
                let count = self.lookups[protocol][result].load(Ordering::Relaxed);
                let _ = writeln!(
                    output,
                    "hangang_geoip_lookups_total{{protocol=\"{name}\",result=\"{label}\"}} {count}"
                );
            }
        }

        output.push_str("# HELP hangang_geoip_country_requests_total Completed country lookups by finite country code.\n# TYPE hangang_geoip_country_requests_total counter\n");
        for (protocol, name) in PROTOCOLS.iter().enumerate() {
            for index in 0..COUNTRY_COUNT {
                let count = self.countries[protocol][index].load(Ordering::Relaxed);
                if count == 0 {
                    continue;
                }
                let first =
                    char::from(b'A' + u8::try_from(index / 26).expect("bounded country index"));
                let second =
                    char::from(b'A' + u8::try_from(index % 26).expect("bounded country index"));
                let _ = writeln!(
                    output,
                    "hangang_geoip_country_requests_total{{protocol=\"{name}\",country=\"{first}{second}\"}} {count}"
                );
            }
            let unknown = self.countries[protocol][UNKNOWN_COUNTRY].load(Ordering::Relaxed);
            if unknown != 0 {
                let _ = writeln!(
                    output,
                    "hangang_geoip_country_requests_total{{protocol=\"{name}\",country=\"unknown\"}} {unknown}"
                );
            }
        }

        output.push_str("# HELP hangang_geoip_admission_total Enforced country admission decisions.\n# TYPE hangang_geoip_admission_total counter\n");
        for (protocol, name) in PROTOCOLS.iter().enumerate() {
            for (decision, label) in ADMISSION_RESULTS.iter().enumerate() {
                let count = self.admissions[protocol][decision].load(Ordering::Relaxed);
                let _ = writeln!(
                    output,
                    "hangang_geoip_admission_total{{protocol=\"{name}\",decision=\"{label}\"}} {count}"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(state: State, country: Option<&str>) -> Observation {
        Observation {
            state,
            country: country.map(str::to_owned),
            generation_sha256: match state {
                State::Known | State::Unknown => Some("a".repeat(64)),
                _ => None,
            },
            error_code: (state == State::Unavailable).then(|| "pending".to_owned()),
        }
    }

    fn value(output: &str, name: &str, labels: &str) -> Option<u64> {
        output.lines().find_map(|line| {
            let rest = line
                .strip_prefix(name)?
                .strip_prefix(labels)?
                .strip_prefix(' ')?;
            rest.parse().ok()
        })
    }

    #[test]
    fn zero_and_skipped_states_have_no_country_series_or_admissions() {
        let counters = Counters::default();
        counters.observe(
            Protocol::Http,
            &observation(State::NotChecked, None),
            Some(Decision::Allowed),
        );
        counters.observe(
            Protocol::Tcp,
            &observation(State::NotConfigured, None),
            Some(Decision::Denied),
        );
        let mut text = String::new();
        counters.render(&mut text);
        assert_eq!(
            value(
                &text,
                "hangang_geoip_lookups_total",
                "{protocol=\"http\",result=\"known\"}"
            ),
            Some(0)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_admission_total",
                "{protocol=\"tcp\",decision=\"denied\"}"
            ),
            Some(0)
        );
        assert!(!text.contains("hangang_geoip_country_requests_total{protocol="));
    }

    #[test]
    fn fixed_country_slots_and_protocols_count_known_unknown_and_unavailable_separately() {
        let counters = Counters::default();
        let known = observation(State::Known, Some("KR"));
        counters.observe(Protocol::Http, &known, Some(Decision::Allowed));
        counters.observe(Protocol::Http, &known, Some(Decision::Denied)); // A mapped address has the same country slot.
        counters.observe(Protocol::Tcp, &known, Some(Decision::Allowed));
        counters.observe(
            Protocol::Tcp,
            &observation(State::Unknown, None),
            Some(Decision::Denied),
        );
        counters.observe(Protocol::Http, &observation(State::Unavailable, None), None);
        counters.observe(
            Protocol::Tcp,
            &observation(State::Unavailable, None),
            Some(Decision::Unavailable),
        );
        let mut text = String::new();
        counters.render(&mut text);
        assert_eq!(
            value(
                &text,
                "hangang_geoip_country_requests_total",
                "{protocol=\"http\",country=\"KR\"}"
            ),
            Some(2)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_country_requests_total",
                "{protocol=\"tcp\",country=\"KR\"}"
            ),
            Some(1)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_country_requests_total",
                "{protocol=\"tcp\",country=\"unknown\"}"
            ),
            Some(1)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_lookups_total",
                "{protocol=\"http\",result=\"unavailable\"}"
            ),
            Some(1)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_admission_total",
                "{protocol=\"http\",decision=\"unavailable\"}"
            ),
            Some(0)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_admission_total",
                "{protocol=\"tcp\",decision=\"unavailable\"}"
            ),
            Some(1)
        );
        assert!(!text.contains("pending"));
        assert!(!text.contains("aaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn malformed_country_or_observation_does_not_create_labels_or_counters() {
        let counters = Counters::default();
        for code in ["kr", "A1", "ABC", "K\"R", "🇰🇷"] {
            counters.observe(
                Protocol::Http,
                &observation(State::Known, Some(code)),
                Some(Decision::Allowed),
            );
        }
        let mut text = String::new();
        counters.render(&mut text);
        assert_eq!(
            value(
                &text,
                "hangang_geoip_lookups_total",
                "{protocol=\"http\",result=\"known\"}"
            ),
            Some(0)
        );
        assert_eq!(
            value(
                &text,
                "hangang_geoip_admission_total",
                "{protocol=\"http\",decision=\"allowed\"}"
            ),
            Some(0)
        );
        assert!(!text.contains("country=\"kr\""));
        assert!(!text.contains("K\\\"R"));
    }
}
