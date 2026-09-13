//! Bounded parsing of the HTTP `Accept-Language` preference signal.
//!
//! RFC 9110 §12.5.4 delegates range syntax and matching to RFC 4647. This
//! module implements RFC 4647 *basic filtering*, not extended filtering or
//! lookup. Quality precedence, duplicate rejection, and malformed-header
//! handling below are explicit gateway policy choices; neither RFC defines a
//! unique weighted-selection algorithm for overlapping ranges.
//!
//! Language preferences are client-controlled. They are not a country,
//! location, or authenticated identity signal.

use std::{error::Error, fmt};

pub const MAX_HEADER_BYTES: usize = 4_096;
pub const MAX_RANGES: usize = 32;
pub const MAX_RANGE_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanguageError {
    HeaderTooLong,
    TooManyRanges,
    InvalidSyntax,
    DuplicateRange,
    InvalidTag,
}

impl fmt::Display for LanguageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::HeaderTooLong => "Accept-Language exceeds its bounded size",
            Self::TooManyRanges => "Accept-Language has too many ranges",
            Self::InvalidSyntax => "Accept-Language has invalid syntax",
            Self::DuplicateRange => "Accept-Language repeats a language range",
            Self::InvalidTag => "configured language tag is invalid",
        };
        f.write_str(message)
    }
}

impl Error for LanguageError {}

/// The absent field is distinct from a present but empty field/list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderState {
    Missing,
    Present(Preferences),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preference {
    /// Lowercase RFC 4647 basic range, or the sole wildcard `*`.
    pub range: String,
    /// RFC 9110 qvalue in thousandths; zero explicitly excludes a match.
    pub quality: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preferences {
    entries: Vec<Preference>,
}

/// Namespace for parsing one or several `Accept-Language` field lines.
pub struct AcceptLanguage;

impl AcceptLanguage {
    /// Combining field lines with commas follows HTTP's list-field model.
    /// Total bytes include the virtual commas. Empty elements, duplicate
    /// ranges, and malformed members reject the entire signal so no subset
    /// can silently acquire a different policy meaning.
    pub fn parse_values<'a>(
        values: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<HeaderState, LanguageError> {
        let mut bytes = Vec::new();
        let mut seen = false;
        for value in values {
            let extra = value.len() + usize::from(seen);
            if bytes.len().saturating_add(extra) > MAX_HEADER_BYTES {
                return Err(LanguageError::HeaderTooLong);
            }
            if seen {
                bytes.push(b',');
            }
            bytes.extend_from_slice(value);
            seen = true;
        }
        if !seen {
            return Ok(HeaderState::Missing);
        }
        if trim_ows(&bytes).is_empty() {
            return Ok(HeaderState::Present(Preferences {
                entries: Vec::new(),
            }));
        }
        let mut entries: Vec<Preference> = Vec::new();
        for member in bytes.split(|byte| *byte == b',') {
            if entries.len() == MAX_RANGES {
                return Err(LanguageError::TooManyRanges);
            }
            let member = trim_ows(member);
            if member.is_empty() {
                return Err(LanguageError::InvalidSyntax);
            }
            let mut parts = member.split(|byte| *byte == b';');
            let range = trim_ows(parts.next().expect("split yields one member"));
            if !valid_basic_range(range, true) {
                return Err(LanguageError::InvalidSyntax);
            }
            let quality = match parts.next() {
                Some(weight) => parse_weight(trim_ows(weight))?,
                None => 1_000,
            };
            if parts.next().is_some() {
                return Err(LanguageError::InvalidSyntax);
            }
            let range = String::from_utf8(range.iter().map(u8::to_ascii_lowercase).collect())
                .expect("validated basic range is ASCII");
            if entries.iter().any(|entry| entry.range == range) {
                return Err(LanguageError::DuplicateRange);
            }
            entries.push(Preference { range, quality });
        }
        Ok(HeaderState::Present(Preferences { entries }))
    }
}

impl Preferences {
    pub fn entries(&self) -> &[Preference] {
        &self.entries
    }

    /// Effective quality of one *offered* tag. The longest matching concrete
    /// range wins; `*` applies only when no concrete range matches. This
    /// specificity rule makes q=0 exclusions stable against broad fallback.
    pub fn quality_for(&self, tag: &str) -> Result<u16, LanguageError> {
        if !valid_basic_range(tag.as_bytes(), false) {
            return Err(LanguageError::InvalidTag);
        }
        let tag = tag.to_ascii_lowercase();
        let mut selected: Option<(usize, u16)> = None;
        let mut wildcard = None;
        for entry in &self.entries {
            if entry.range == "*" {
                wildcard = Some(entry.quality);
            } else if basic_filter_validated(&entry.range, &tag)
                && selected.is_none_or(|(length, _)| entry.range.len() > length)
            {
                selected = Some((entry.range.len(), entry.quality));
            }
        }
        Ok(selected.map(|(_, q)| q).or(wildcard).unwrap_or(0))
    }

    /// Whether any configured offered tag is acceptable (effective q > 0).
    pub fn any_acceptable(&self, tags: &[&str]) -> Result<bool, LanguageError> {
        let mut found = false;
        for tag in tags {
            found |= self.quality_for(tag)? > 0;
        }
        Ok(found)
    }

    /// Whether an offered tag has the header's highest nonzero qvalue. Equal
    /// qvalues tie; header order is not treated as a reliable priority.
    /// This is an explicit policy helper, not RFC 4647 Lookup negotiation.
    pub fn preferred(&self, tags: &[&str]) -> Result<bool, LanguageError> {
        let highest = self
            .entries
            .iter()
            .map(|entry| entry.quality)
            .max()
            .unwrap_or(0);
        let mut found = false;
        for tag in tags {
            found |= highest > 0 && self.quality_for(tag)? == highest;
        }
        Ok(found)
    }
}

/// RFC 4647 §3.3.1 basic filtering, including a subtag boundary. This takes
/// a requested *range* first and an offered *tag* second; reversing them can
/// make a route blocklist silently miss a language.
pub fn basic_filter(range: &str, tag: &str) -> Result<bool, LanguageError> {
    if !valid_basic_range(range.as_bytes(), true) {
        return Err(LanguageError::InvalidSyntax);
    }
    if !valid_basic_range(tag.as_bytes(), false) {
        return Err(LanguageError::InvalidTag);
    }
    Ok(basic_filter_validated(
        &range.to_ascii_lowercase(),
        &tag.to_ascii_lowercase(),
    ))
}

fn basic_filter_validated(range: &str, tag: &str) -> bool {
    range == "*"
        || tag == range
        || tag
            .strip_prefix(range)
            .is_some_and(|rest| rest.starts_with('-'))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn valid_basic_range(value: &[u8], wildcard: bool) -> bool {
    if value == b"*" {
        return wildcard;
    }
    if value.is_empty() || value.len() > MAX_RANGE_BYTES {
        return false;
    }
    let mut subtags = value.split(|byte| *byte == b'-');
    let Some(first) = subtags.next() else {
        return false;
    };
    !first.is_empty()
        && first.len() <= 8
        && first.iter().all(u8::is_ascii_alphabetic)
        && subtags.all(|subtag| {
            !subtag.is_empty() && subtag.len() <= 8 && subtag.iter().all(u8::is_ascii_alphanumeric)
        })
}

fn parse_weight(value: &[u8]) -> Result<u16, LanguageError> {
    if value.len() < 3 || !value[0].eq_ignore_ascii_case(&b'q') || value[1] != b'=' {
        return Err(LanguageError::InvalidSyntax);
    }
    let number = &value[2..];
    let (whole, fraction) = match number {
        [whole] => (*whole, &[][..]),
        [whole, b'.', rest @ ..] if rest.len() <= 3 => (*whole, rest),
        _ => return Err(LanguageError::InvalidSyntax),
    };
    if !fraction.iter().all(u8::is_ascii_digit) {
        return Err(LanguageError::InvalidSyntax);
    }
    match whole {
        b'0' => {
            let mut q = 0;
            let mut scale = 100;
            for digit in fraction {
                q += u16::from(digit - b'0') * scale;
                scale /= 10;
            }
            Ok(q)
        }
        b'1' if fraction.iter().all(|digit| *digit == b'0') => Ok(1_000),
        _ => Err(LanguageError::InvalidSyntax),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(values: &[&[u8]]) -> Preferences {
        match AcceptLanguage::parse_values(values.iter().copied()).unwrap() {
            HeaderState::Present(preferences) => preferences,
            HeaderState::Missing => panic!("expected present header"),
        }
    }

    #[test]
    fn missing_empty_and_multiple_lines_are_distinct() {
        assert_eq!(
            AcceptLanguage::parse_values([]).unwrap(),
            HeaderState::Missing
        );
        assert!(parsed(&[b" \t"]).entries().is_empty());
        assert_eq!(
            parsed(&[b"EN-us;q=0.8", b" ko ; Q=1 "]).entries(),
            &[
                Preference {
                    range: "en-us".into(),
                    quality: 800
                },
                Preference {
                    range: "ko".into(),
                    quality: 1_000
                },
            ]
        );
        assert_eq!(
            AcceptLanguage::parse_values([&b"en,,fr"[..]]),
            Err(LanguageError::InvalidSyntax)
        );
        assert_eq!(
            AcceptLanguage::parse_values([&b""[..], &b"en"[..]]),
            Err(LanguageError::InvalidSyntax)
        );
    }

    #[test]
    fn basic_filter_uses_case_insensitive_subtag_boundaries_and_direction() {
        assert!(basic_filter("KO", "ko-KR").unwrap());
        assert!(!basic_filter("ko-KR", "ko").unwrap());
        assert!(!basic_filter("en", "english").unwrap());
        assert!(basic_filter("en-GB", "EN-gb-oxendict").unwrap());
        assert!(!basic_filter("de-DE", "de-Deva").unwrap());
        assert!(basic_filter("*", "zh-Hant").unwrap());
        assert_eq!(
            basic_filter("en-*", "en-US"),
            Err(LanguageError::InvalidSyntax)
        );
    }

    #[test]
    fn qzero_specificity_and_wildcard_do_not_reopen_exclusions() {
        let p = parsed(&[b"*;q=0.7, en;q=0, en-US;q=0.9"]);
        assert_eq!(p.quality_for("fr").unwrap(), 700);
        assert_eq!(p.quality_for("en").unwrap(), 0);
        assert_eq!(p.quality_for("en-GB").unwrap(), 0);
        assert_eq!(p.quality_for("en-US").unwrap(), 900);
        assert_eq!(p.quality_for("en-US-posix").unwrap(), 900);
        assert!(p.any_acceptable(&["en-US"]).unwrap());
        assert!(!p.any_acceptable(&["en-GB"]).unwrap());
        assert!(p.preferred(&["en-US"]).unwrap());
        assert!(!p.preferred(&["fr"]).unwrap());
    }

    #[test]
    fn preferred_uses_highest_q_with_equal_weight_ties_not_header_order() {
        let p = parsed(&[b"fr;q=1, en;q=1, ko;q=0.8"]);
        assert!(p.preferred(&["en-US"]).unwrap());
        assert!(p.preferred(&["fr-CA"]).unwrap());
        assert!(!p.preferred(&["ko-KR"]).unwrap());
        assert!(p.any_acceptable(&["ko-KR"]).unwrap());
        assert!(!parsed(&[b"*;q=0"]).preferred(&["ko"]).unwrap());
    }

    #[test]
    fn duplicate_and_malformed_members_fail_entire_header() {
        for value in [
            &b"en,en;q=0"[..],
            &b"EN,en"[..],
            &b"en;q=0.1234"[..],
            &b"en;q=1.001"[..],
            &b"en;q=.5"[..],
            &b"en;q=00"[..],
            &b"en;q=0.5;q=0"[..],
            &b"en;q =0.5"[..],
            &b"en-US-"[..],
            &b"-en"[..],
            &b"en-*"[..],
            &b"en;Q=bad"[..],
            &b"en,\nfr"[..],
            &b"ko-\xff"[..],
        ] {
            assert!(AcceptLanguage::parse_values([value]).is_err(), "{value:?}");
        }
        assert_eq!(
            AcceptLanguage::parse_values([&b"EN,en"[..]]),
            Err(LanguageError::DuplicateRange)
        );
    }

    #[test]
    fn bounds_cover_total_header_range_count_and_offered_tag() {
        assert_eq!(
            AcceptLanguage::parse_values([vec![b'a'; MAX_HEADER_BYTES + 1].as_slice()]),
            Err(LanguageError::HeaderTooLong)
        );
        let many = (0..=MAX_RANGES)
            .map(|i| format!("x-{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            AcceptLanguage::parse_values([many.as_bytes()]),
            Err(LanguageError::TooManyRanges)
        );
        let long = format!("en-{}", "a".repeat(MAX_RANGE_BYTES));
        assert_eq!(
            AcceptLanguage::parse_values([long.as_bytes()]),
            Err(LanguageError::InvalidSyntax)
        );
        assert_eq!(
            parsed(&[b"ko"]).quality_for("ko-ü"),
            Err(LanguageError::InvalidTag)
        );
    }
}
