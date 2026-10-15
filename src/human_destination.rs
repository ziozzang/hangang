//! Human-only actual selected origin data. This hash grants no authority.
//! The final forwarding authority, TLS policy and request headers remain pinned
//! independently by the actual route/request owner; Host is not an H1 v2 slot.
use hyper::Uri;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"hangang-human-origin-v1\0";
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Refused;
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Origin {
    scheme: &'static str,
    host: String,
    port: u16,
}
impl Origin {
    pub(crate) fn parse(uri: &Uri) -> Result<Self, Refused> {
        let scheme = match uri.scheme_str() {
            Some(s) if s.eq_ignore_ascii_case("http") => "http",
            Some(s) if s.eq_ignore_ascii_case("https") => "https",
            _ => return Err(Refused),
        };
        let authority = uri.authority().ok_or(Refused)?.as_str();
        if authority.contains(['@', '%']) || !authority.is_ascii() {
            return Err(Refused);
        }
        let (host, suffix) = if let Some(rest) = authority.strip_prefix('[') {
            let (host, suffix) = rest.split_once(']').ok_or(Refused)?;
            let ip: std::net::Ipv6Addr = host.parse().map_err(|_| Refused)?;
            (ip.to_string(), suffix)
        } else {
            let (host, suffix) = authority
                .find(':')
                .map_or((authority, ""), |i| (&authority[..i], &authority[i..]));
            if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
                (ip.to_string(), suffix)
            } else {
                let host = host.strip_suffix('.').unwrap_or(host);
                let numeric = host.split('.').all(|part| {
                    (!part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
                        || part
                            .strip_prefix("0x")
                            .or_else(|| part.strip_prefix("0X"))
                            .is_some_and(|s| {
                                !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                });
                if host.is_empty()
                    || host.len() > 253
                    || numeric
                    || host.split('.').any(|label| {
                        label.is_empty()
                            || label.len() > 63
                            || label.starts_with('-')
                            || label.ends_with('-')
                            || !label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    })
                {
                    return Err(Refused);
                }
                (host.to_ascii_lowercase(), suffix)
            }
        };
        let port = if suffix.is_empty() {
            if scheme == "https" { 443 } else { 80 }
        } else {
            let text = suffix.strip_prefix(':').ok_or(Refused)?;
            if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Refused);
            }
            let port = text.parse::<u16>().map_err(|_| Refused)?;
            if port == 0 {
                return Err(Refused);
            }
            port
        };
        Ok(Self { scheme, host, port })
    }
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        for value in [self.scheme.as_bytes(), self.host.as_bytes()] {
            hash.update(
                u32::try_from(value.len())
                    .expect("bounded origin field")
                    .to_be_bytes(),
            );
            hash.update(value);
        }
        hash.update(self.port.to_be_bytes());
        hash.finalize().into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn digest(uri: &str) -> String {
        Origin::parse(&uri.parse().unwrap())
            .unwrap()
            .digest()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    #[test]
    fn independent_python_golden_origins_and_canonical_equivalence() {
        // Python hashlib over DOMAIN + LP32(scheme/host) + BE16(effective port).
        assert_eq!(
            digest("http://example.com/a?x=1"),
            "1a33d412f7d384d6cce94da703411edca0ac94ef6c0a1d263023b705b5007265"
        );
        assert_eq!(
            digest("https://example.com/"),
            "3bec84b484ca801e66e385ffb120ca85a2e8f2506ed76873fd07ec7616c7c0b6"
        );
        assert_eq!(
            digest("https://[2001:db8::1]:8443/x"),
            "0d46ceecaadfb692130e42c70f8b23bcf281b6832b83a0316fbb3055aeef918c"
        );
        assert_eq!(
            digest("http://192.0.2.1:8080/"),
            "a9202689c5e5ddaf99ad10b1314ca64ff38526e07ad63f4a398acb3517382ef9"
        );
        assert_eq!(
            digest("http://example.com/"),
            digest("http://EXAMPLE.COM.:80/other?ignored=yes")
        );
        assert_eq!(
            digest("https://example.com/"),
            digest("https://EXAMPLE.COM:0443/")
        );
        assert_eq!(
            digest("https://[2001:db8::1]:8443/"),
            digest("https://[2001:0DB8:0:0:0:0:0:1]:8443/")
        );
        assert_ne!(
            digest("http://example.com/"),
            digest("https://example.com:80/")
        );
        assert_ne!(
            digest("https://example.com/"),
            digest("https://other.example/")
        );
    }
    #[test]
    fn malformed_or_ambiguous_origins_refuse() {
        for text in [
            "/relative",
            "ftp://example.com/",
            "http://user@example.com/",
            "http://example.com:0/",
            "http://example.com:65536/",
            "http://example.com:/",
            "http://example.com:abc/",
            "http://127.1/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "http://0X7F000001/",
            "http://[fe80::1%25eth0]/",
            "http://bad..example/",
            "http://-bad.example/",
            "http://bad_.example/",
        ] {
            if let Ok(uri) = text.parse::<Uri>() {
                assert_eq!(Origin::parse(&uri), Err(Refused), "{text}");
            }
        }
    }
}
