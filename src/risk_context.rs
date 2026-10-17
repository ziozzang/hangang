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

/// Largest header value (the contract's bound).
pub const MAX_VALUE: usize = 2048;

/// A Sumunjang (Pumgye) zone id: `[A-Za-z0-9_.:-]{1,128}`, case-sensitive.
pub fn zone_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
}

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
    /// Network zone ids containing the address (at most 8, id order).
    pub zones: Vec<String>,
    /// Coarse risk score (0–100 in tens) and stage; `None` when Sumunjang did
    /// not compute them (stage unspecified).
    pub risk: Option<(u8, RiskStage)>,
}

/// Sumunjang's suspicion stage (`RiskStage`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskStage {
    Normal = 1,
    Watch = 2,
    Suspicious = 3,
    High = 4,
    Blocked = 5,
}

impl RiskStage {
    pub fn from_wire(v: i32) -> Option<RiskStage> {
        Some(match v {
            1 => RiskStage::Normal,
            2 => RiskStage::Watch,
            3 => RiskStage::Suspicious,
            4 => RiskStage::High,
            5 => RiskStage::Blocked,
            _ => return None,
        })
    }
    pub fn parse(s: &str) -> Option<RiskStage> {
        Some(match s {
            "normal" => RiskStage::Normal,
            "watch" => RiskStage::Watch,
            "suspicious" => RiskStage::Suspicious,
            "high" => RiskStage::High,
            "blocked" => RiskStage::Blocked,
            _ => return None,
        })
    }
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
    /// A Sumunjang risk stage at or above this is `elevated`.
    pub elevated_stage: Option<RiskStage>,
    /// A Sumunjang risk stage at or above this is `high`.
    pub high_stage: Option<RiskStage>,
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
        let stage = e.risk.map(|(_, stage)| stage);
        let at_least = |t: Option<RiskStage>| t.is_some_and(|t| stage.is_some_and(|s| s >= t));
        if e.enforce_verdict == 2 || at_least(t.high_stage) {
            return Level::High;
        }
        if at_least(t.elevated_stage) {
            return Level::Elevated;
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
        // Every zone, as Sumunjang reported it (the evidence was checked
        // against the zone id alphabet when it was received).
        if !e.zones.is_empty() {
            claims["zones"] = e.zones.iter().take(8).cloned().collect::<Vec<_>>().into();
        }
        if let Some((score, _)) = e.risk {
            claims["score"] = (score.min(100) / 10 * 10).into();
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
    (value.len() <= MAX_VALUE)
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
            zones: vec![],
            risk: None,
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
                ..Thresholds::default()
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

    #[test]
    fn zones_score_and_stage() {
        let s = Settings::new(
            KEY.to_vec(),
            Thresholds {
                elevated_stage: Some(RiskStage::Suspicious),
                high_stage: Some(RiskStage::High),
                ..Thresholds::default()
            },
        )
        .unwrap();
        let mut e = evidence();
        e.zones = vec!["corp-vpn".into(), "Legacy:Zone".into(), "lab".into()];
        e.risk = Some((30, RiskStage::Watch));
        assert_eq!(s.level(&e), Level::Low);
        let (_, c) = s.claims(&e, 0);
        assert_eq!(
            c["zones"],
            serde_json::json!(["corp-vpn", "Legacy:Zone", "lab"]),
            "case-sensitive ids with colons are kept"
        );
        assert_eq!(c["score"], 30);
        e.risk = Some((50, RiskStage::Suspicious));
        assert_eq!(s.level(&e), Level::Elevated);
        e.risk = Some((100, RiskStage::Blocked));
        assert_eq!(s.level(&e), Level::High);
        // No stage computed: no score claim and no stage-based level.
        e.risk = None;
        e.zones = (0..12).map(|i| format!("z{i}")).collect();
        let (level, c) = s.claims(&e, 0);
        assert_eq!(level, Level::Low);
        assert!(c.get("score").is_none());
        assert_eq!(c["zones"].as_array().unwrap().len(), 8);
        // Without stage thresholds the stage does not change the level.
        let plain = Settings::new(KEY.to_vec(), Thresholds::default()).unwrap();
        e.risk = Some((100, RiskStage::High));
        assert_eq!(plain.level(&e), Level::Low);
    }

    /// Hopae's second documented vector (zones with upper case and colons).
    #[test]
    fn the_contract_zone_vector_is_reproduced() {
        let claims = br#"{"iat":1800000000,"level":"low","source":"sumunjang","mode":"observe","reason":"sumunjang.observe.mode","score":20,"country":"KR","zones":["Corp:VPN","legacy.orders.1"],"rev":5}"#;
        assert_eq!(
            sign(
                KEY,
                claims,
                "GET",
                "192.0.2.10".parse().unwrap(),
                "https://app.example.test/admin/x"
            ),
            "v1.eyJpYXQiOjE4MDAwMDAwMDAsImxldmVsIjoibG93Iiwic291cmNlIjoic3VtdW5qYW5nIiwibW9kZSI6Im9ic2VydmUiLCJyZWFzb24iOiJzdW11bmphbmcub2JzZXJ2ZS5tb2RlIiwic2NvcmUiOjIwLCJjb3VudHJ5IjoiS1IiLCJ6b25lcyI6WyJDb3JwOlZQTiIsImxlZ2FjeS5vcmRlcnMuMSJdLCJyZXYiOjV9.MOFgcPWLbPgy37fmi01OJnwX7tm6enJ1T5b2lxlLGWA"
        );
        assert!(zone_ok("Corp:VPN") && !zone_ok("corp vpn") && !zone_ok(&"a".repeat(129)));
    }

    #[test]
    fn eight_long_zones_fit_the_header() {
        let s = Settings::new(KEY.to_vec(), Thresholds::default()).unwrap();
        let mut e = evidence();
        e.zones = (0..8).map(|i| format!("{i}{}", "Z".repeat(127))).collect();
        e.risk = Some((100, RiskStage::High));
        let mut h = hyper::HeaderMap::new();
        h.insert("x-forwarded-for", "192.0.2.10".parse().unwrap());
        h.insert(
            "x-original-url",
            "https://app.example.test/admin/x".parse().unwrap(),
        );
        let (_, v) = header_for(&s, &e, &h, 0).expect("not omitted");
        assert!(v.len() <= MAX_VALUE);
    }
}
