//! Strict parsing for identity supplied by explicitly trusted HTTP proxies.

use hyper::{HeaderMap, header::HeaderName};
use std::net::IpAddr;

const MAX_FORWARDED_HOPS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidForwardedHeader;

pub fn is_trusted(ip: IpAddr, trusted: &[ipnet::IpNet]) -> bool {
    let ip = ip.to_canonical();
    trusted.iter().any(|network| network.contains(&ip))
}

/// Select the rightmost non-trusted XFF hop. A present malformed chain is an
/// error instead of falling back to the trusted socket peer and weakening IP
/// policy. IPv4-mapped IPv6 entries are canonicalized before trust checks.
pub fn client_ip_from_forwarded(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
) -> Result<IpAddr, InvalidForwardedHeader> {
    let name = HeaderName::from_static("x-forwarded-for");
    let values = headers.get_all(name);
    let mut forwarded = Vec::new();
    for value in values.iter() {
        let value = value.to_str().map_err(|_| InvalidForwardedHeader)?;
        for item in value.split(',') {
            let item = item.trim();
            if item.is_empty() || forwarded.len() == MAX_FORWARDED_HOPS {
                return Err(InvalidForwardedHeader);
            }
            let ip = item
                .parse::<IpAddr>()
                .map_err(|_| InvalidForwardedHeader)?
                .to_canonical();
            forwarded.push(ip);
        }
    }
    let peer = peer.to_canonical();
    for ip in forwarded.iter().rev() {
        if !is_trusted(*ip, trusted) {
            return Ok(*ip);
        }
    }
    Ok(forwarded.first().copied().unwrap_or(peer))
}

/// Accept one exact proxy-supplied scheme. Comma lists, duplicates, empty or
/// malformed values conservatively become HTTP so a TLS proxy hop cannot make
/// an original plaintext request bypass a route's TLS requirement.
pub fn forwarded_proto(headers: &HeaderMap, transport_tls: bool) -> &'static str {
    let name = HeaderName::from_static("x-forwarded-proto");
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return if transport_tls { "https" } else { "http" };
    };
    if values.next().is_some() {
        return "http";
    }
    let Ok(value) = value.to_str() else {
        return "http";
    };
    if value.eq_ignore_ascii_case("https") {
        "https"
    } else {
        "http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::HeaderValue;

    #[test]
    fn canonicalizes_mapped_hops_before_recursive_trust_selection() {
        let trusted = vec![
            "127.0.0.0/8".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.7, ::ffff:10.0.0.9"),
        );
        assert_eq!(
            client_ip_from_forwarded("::ffff:127.0.0.1".parse().unwrap(), &headers, &trusted),
            Ok("203.0.113.7".parse().unwrap())
        );
    }

    #[test]
    fn malformed_empty_or_oversized_xff_fails_closed() {
        for value in ["203.0.113.7,", "unknown", "203.0.113.7:1234"] {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
            assert!(client_ip_from_forwarded("127.0.0.1".parse().unwrap(), &headers, &[]).is_err());
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&vec!["192.0.2.1"; 257].join(",")).unwrap(),
        );
        assert!(client_ip_from_forwarded("127.0.0.1".parse().unwrap(), &headers, &[]).is_err());
    }

    #[test]
    fn forwarded_proto_rejects_ambiguous_values_as_plaintext() {
        for value in ["http", "HTTP", "https, http", " https", "ftp", ""] {
            let mut headers = HeaderMap::new();
            headers.insert("x-forwarded-proto", HeaderValue::from_str(value).unwrap());
            assert_eq!(forwarded_proto(&headers, true), "http", "{value:?}");
        }
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-proto", HeaderValue::from_static("HTTPS"));
        assert_eq!(forwarded_proto(&headers, false), "https");
        headers.append("x-forwarded-proto", HeaderValue::from_static("https"));
        assert_eq!(forwarded_proto(&headers, true), "http");
        assert_eq!(forwarded_proto(&HeaderMap::new(), true), "https");
    }
}
