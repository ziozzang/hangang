//! The signed risk context Hangang sends to Hopae on verify (Hopae ADR-0023,
//! `GATEWAY_CONTRACT.md` "Risk context"): Sumunjang's network evidence for
//! the request, mapped to a level, as
//! `v1.<b64url(claims)>.<b64url(HMAC-SHA256)>` bound to the verify call's
//! method, client address and `x-original-url`.
//!
//! Only routes whose `auth.risk_context` is set send it, only to their
//! authorization service (HTTP forward-auth or HOP1), never upstream; a
//! client-supplied header of the same name is removed at the edge. Without
//! evidence (Sumunjang unavailable, an older Sumunjang, a non-gRPC
//! transport) the header is omitted.

use std::collections::BTreeSet;
use std::net::IpAddr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The verify request header.
pub const HEADER: &str = "x-hopae-risk-context";
const DOMAIN: &str = "hopae-risk-context.v1\n";

/// Contexts sent, by level, and omitted, by cause.
pub const SENT_TOTAL: &str = "hangang_risk_context_sent_total";
pub const OMITTED_TOTAL: &str = "hangang_risk_context_omitted_total";

/// Sumunjang's evidence for one evaluation (`NetworkEvidence`, additive
/// `include_evidence` of the Network gRPC service).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub reason_code: String,
    /// `DecidingStage`: 1 observe, 2 allowlist, 3 rule, 4 block, 5 default.
    pub deciding_stage: i32,
    pub asn: u32,
    /// ISO 3166-1 alpha-2, empty when unknown.
    pub country: String,
    /// What enforcement would decide: 1 allow, 2 deny.
    pub enforce_verdict: i32,
    pub enforce_reason_code: String,
    pub observe: bool,
    pub revision: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Low,
    Elevated,
    High,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Low => "low",
            Level::Elevated => "elevated",
            Level::High => "high",
        }
    }
}

/// The mapping thresholds (Hopae's contract table, made configurable).
#[derive(Clone, Debug, Default)]
pub struct Thresholds {
    /// Reason codes (decision or would-be enforcement) that are `elevated`.
    pub elevated_reasons: BTreeSet<String>,
    /// Countries (upper case) whose requests are `elevated`.
    pub elevated_countries: BTreeSet<String>,
    /// ASNs whose requests are `elevated`.
    pub elevated_asns: BTreeSet<u32>,
    /// A request allowed only by the policy's default (no allowlist or rule
    /// matched; in observe mode the would-be enforcement's `sumunjang.allow.default`)
    /// is `elevated`.
    pub unlisted_elevated: bool,
}

/// The signing key and thresholds.
pub struct Settings {
    key: zeroize::Zeroizing<Vec<u8>>,
    pub thresholds: Thresholds,
}

impl std::fmt::Debug for Settings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("thresholds", &self.thresholds)
            .finish_non_exhaustive()
    }
}

fn token_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

impl Settings {
    /// `key` is the dedicated risk-context key (32 to 4096 bytes).
    pub fn new(key: Vec<u8>, thresholds: Thresholds) -> anyhow::Result<Settings> {
        anyhow::ensure!(
            (32..=4096).contains(&key.len()),
            "risk context key must be 32 to 4096 bytes"
        );
        anyhow::ensure!(
            thresholds
                .elevated_countries
                .iter()
                .all(|c| c.len() == 2 && c.bytes().all(|b| b.is_ascii_uppercase())),
            "risk elevated countries are ISO 3166-1 alpha-2 upper case"
        );
        anyhow::ensure!(
            thresholds.elevated_reasons.iter().all(|r| token_ok(r)),
            "risk elevated reasons are Sumunjang reason codes"
        );
        Ok(Settings {
            key: zeroize::Zeroizing::new(key),
            thresholds,
        })
    }

    /// The contract's level mapping: what enforcement would deny (seen in
    /// observe mode) is `high`; a configured reason, country or ASN, or a
    /// default-only allow when configured, is `elevated`; else `low`.
    pub fn level(&self, e: &Evidence) -> Level {
        let t = &self.thresholds;
        if e.enforce_verdict == 2 {
            return Level::High;
        }
        if t.elevated_reasons.contains(&e.reason_code)
            || t.elevated_reasons.contains(&e.enforce_reason_code)
            || (!e.country.is_empty() && t.elevated_countries.contains(&e.country))
            || (e.asn != 0 && t.elevated_asns.contains(&e.asn))
            || (t.unlisted_elevated
                && (e.deciding_stage == 5 || e.enforce_reason_code == "sumunjang.allow.default"))
        {
            return Level::Elevated;
        }
        Level::Low
    }

    /// The claims for `e` at `iat` (only contract members, bounded).
    pub fn claims(&self, e: &Evidence, iat: i64) -> (Level, serde_json::Value) {
        let level = self.level(e);
        let reason = if token_ok(&e.reason_code) {
            e.reason_code.as_str()
        } else {
            "sumunjang.unknown"
        };
        let mut claims = serde_json::json!({
            "iat": iat,
            "level": level.as_str(),
            "source": "sumunjang",
            "mode": if e.observe { "observe" } else { "enforce" },
            "reason": reason,
            "rev": e.revision,
        });
        if e.asn != 0 {
            claims["asn"] = e.asn.into();
        }
        claims["country"] =
            if e.country.len() == 2 && e.country.bytes().all(|b| b.is_ascii_uppercase()) {
                e.country.clone().into()
            } else {
                "XX".into()
            };
        (level, claims)
    }

    /// The header value for these exact claims bytes and request inputs.
    pub fn sign_bytes(&self, claims: &[u8], method: &str, ip: IpAddr, url: &str) -> String {
        sign(&self.key, claims, method, ip, url)
    }
}

/// `v1.<P>.<T>` per the contract.
pub fn sign(key: &[u8], claims: &[u8], method: &str, ip: IpAddr, url: &str) -> String {
    let payload = URL_SAFE_NO_PAD.encode(claims);
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key");
    m.update(DOMAIN.as_bytes());
    m.update(payload.as_bytes());
    m.update(b"\n");
    m.update(method.as_bytes());
    m.update(b"\n");
    m.update(ip.to_string().as_bytes());
    m.update(b"\n");
    m.update(url.as_bytes());
    format!(
        "v1.{payload}.{}",
        URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
    )
}

/// Build the header for a verify call whose headers are `h` (the values
/// Hopae binds: `x-original-method`, `x-forwarded-for`, `x-original-url`).
pub fn header_for(
    settings: &Settings,
    evidence: &Evidence,
    h: &hyper::HeaderMap,
    now: i64,
) -> Option<(Level, hyper::header::HeaderValue)> {
    let one = |name: &str| {
        let mut it = h.get_all(name).iter();
        let v = it.next()?.to_str().ok()?;
        it.next().is_none().then_some(v)
    };
    let method = one("x-original-method").unwrap_or("GET");
    let ip: IpAddr = one("x-forwarded-for")?.trim().parse().ok()?;
    let url = one("x-original-url")?;
    let (level, claims) = settings.claims(evidence, now);
    let value = settings.sign_bytes(claims.to_string().as_bytes(), method, ip, url);
    (value.len() <= 1024)
        .then(|| hyper::header::HeaderValue::from_str(&value).ok())
        .flatten()
        .map(|v| (level, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"risk-context-key-0123456789abcdef-current";

    /// Hopae's documented test vector (GATEWAY_CONTRACT.md "Risk context"),
    /// reproduced byte for byte.
    #[test]
    fn the_contract_test_vector_is_reproduced() {
        let claims = br#"{"iat":1800000000,"level":"elevated","source":"sumunjang","mode":"enforce","reason":"sumunjang.asn_reputation","score":70,"asn":64500,"country":"KR","zones":["corp-vpn"],"rev":418}"#;
        assert_eq!(
            sign(
                KEY,
                claims,
                "GET",
                "192.0.2.10".parse().unwrap(),
                "https://app.example.test/admin/x"
            ),
            "v1.eyJpYXQiOjE4MDAwMDAwMDAsImxldmVsIjoiZWxldmF0ZWQiLCJzb3VyY2UiOiJzdW11bmphbmciLCJtb2RlIjoiZW5mb3JjZSIsInJlYXNvbiI6InN1bXVuamFuZy5hc25fcmVwdXRhdGlvbiIsInNjb3JlIjo3MCwiYXNuIjo2NDUwMCwiY291bnRyeSI6IktSIiwiem9uZXMiOlsiY29ycC12cG4iXSwicmV2Ijo0MTh9.oIlJD45LbUbFg80GNO6g_delXTIQ_7m2lVOgtIPcDZQ"
        );
    }

    fn evidence() -> Evidence {
        Evidence {
            reason_code: "sumunjang.allow.rule".into(),
            deciding_stage: 3,
            asn: 64500,
            country: "KR".into(),
            enforce_verdict: 1,
            enforce_reason_code: "sumunjang.allow.rule".into(),
            observe: false,
            revision: 7,
        }
    }

    #[test]
    fn evidence_maps_to_levels_by_the_thresholds() {
        let s = Settings::new(
            KEY.to_vec(),
            Thresholds {
                elevated_reasons: ["sumunjang.deny.block_source".to_string()].into(),
                elevated_countries: ["RU".to_string()].into(),
                elevated_asns: [64666].into(),
                unlisted_elevated: true,
            },
        )
        .unwrap();
        assert_eq!(s.level(&evidence()), Level::Low);
        let mut e = evidence();
        e.observe = true;
        e.enforce_verdict = 2;
        e.enforce_reason_code = "sumunjang.deny.rule".into();
        assert_eq!(s.level(&e), Level::High, "what enforcement would deny");
        for change in [
            |e: &mut Evidence| e.country = "RU".into(),
            |e: &mut Evidence| e.asn = 64666,
            |e: &mut Evidence| e.deciding_stage = 5,
            |e: &mut Evidence| {
                // Observe mode: the stage is `observe`; the would-be code tells.
                e.deciding_stage = 1;
                e.observe = true;
                e.enforce_reason_code = "sumunjang.allow.default".into();
            },
            |e: &mut Evidence| e.enforce_reason_code = "sumunjang.deny.block_source".into(),
        ] {
            let mut e = evidence();
            change(&mut e);
            assert_eq!(s.level(&e), Level::Elevated);
        }
        assert!(Settings::new(b"short".to_vec(), Thresholds::default()).is_err());
        assert!(
            Settings::new(
                KEY.to_vec(),
                Thresholds {
                    elevated_countries: ["kr".to_string()].into(),
                    ..Thresholds::default()
                }
            )
            .is_err()
        );
    }

    #[test]
    fn the_header_is_bound_to_the_verify_call_and_holds_only_contract_claims() {
        let s = Settings::new(KEY.to_vec(), Thresholds::default()).unwrap();
        let mut h = hyper::HeaderMap::new();
        h.insert("x-original-method", "POST".parse().unwrap());
        h.insert("x-forwarded-for", "192.0.2.10".parse().unwrap());
        h.insert(
            "x-original-url",
            "https://app.example.test/a?b=1".parse().unwrap(),
        );
        let (level, v) = header_for(&s, &evidence(), &h, 1_800_000_000).unwrap();
        assert_eq!(level, Level::Low);
        let v = v.to_str().unwrap();
        let payload = v.split('.').nth(1).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({"iat": 1_800_000_000, "level": "low", "source": "sumunjang", "mode": "enforce",
                               "reason": "sumunjang.allow.rule", "rev": 7, "asn": 64500, "country": "KR"})
        );
        let expected = sign(
            KEY,
            claims.to_string().as_bytes(),
            "POST",
            "192.0.2.10".parse().unwrap(),
            "https://app.example.test/a?b=1",
        );
        assert_eq!(v, expected);
        // No bindable inputs: no header.
        let mut missing = h.clone();
        missing.remove("x-original-url");
        assert!(header_for(&s, &evidence(), &missing, 0).is_none());
        let mut twice = h.clone();
        twice.append("x-forwarded-for", "198.51.100.1".parse().unwrap());
        assert!(header_for(&s, &evidence(), &twice, 0).is_none());
        // Unknown country and an invalid reason are normalised.
        let mut e = evidence();
        e.country = String::new();
        e.reason_code = "Not A Code".into();
        let (_, c) = s.claims(&e, 0);
        assert_eq!(
            (c["country"].as_str(), c["reason"].as_str()),
            (Some("XX"), Some("sumunjang.unknown"))
        );
    }
}
