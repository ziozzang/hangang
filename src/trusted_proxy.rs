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

/// Identity from an RFC 7239 `Forwarded` header sent by a trusted proxy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedIdentity {
    pub client_ip: IpAddr,
    /// `proto` of the selected element; `None` falls back to the transport.
    pub proto: Option<&'static str>,
    /// `host` of the selected element. The caller validates it as an
    /// authority before it can become URL text.
    pub host: Option<String>,
}

/// Whether any `X-Forwarded-*` identity field is present. Those fields keep
/// precedence over `Forwarded` so existing deployments do not change meaning
/// when a front proxy sends both families.
pub fn has_x_forwarded(headers: &HeaderMap) -> bool {
    [
        "x-forwarded-for",
        "x-forwarded-proto",
        "x-forwarded-host",
        "x-forwarded-port",
    ]
    .iter()
    .any(|name| headers.contains_key(*name))
}

/// Parse every `Forwarded` field strictly and select the rightmost element
/// whose `for` is not a trusted proxy, the same walk as `X-Forwarded-For`.
/// `proto` and `host` come from that same element, because they describe the
/// request that hop received. Returns `Ok(None)` when no field is present.
///
/// Rejected (the caller answers 400): malformed quoting or escapes, an
/// unbracketed IPv6 or bracketed non-IPv6 node, obfuscated (`_x`) or
/// `unknown` nodes and ports, a repeated parameter within one element, an
/// element without `for`, a `proto` other than `http`/`https`, an empty
/// element, and more than 256 elements.
pub fn forwarded_identity(
    headers: &HeaderMap,
    trusted: &[ipnet::IpNet],
) -> Result<Option<ForwardedIdentity>, InvalidForwardedHeader> {
    let mut elements = Vec::new();
    for value in headers.get_all(hyper::header::FORWARDED).iter() {
        let value = value.to_str().map_err(|_| InvalidForwardedHeader)?;
        parse_forwarded_field(value, &mut elements)?;
    }
    if elements.is_empty() {
        return Ok(None);
    }
    let selected = elements
        .iter()
        .rev()
        .find(|element| !is_trusted(element.client_ip, trusted))
        .or(elements.first())
        .cloned();
    Ok(selected)
}

fn parse_forwarded_field(
    value: &str,
    elements: &mut Vec<ForwardedIdentity>,
) -> Result<(), InvalidForwardedHeader> {
    let mut rest = value.trim_matches(is_ows);
    loop {
        if elements.len() == MAX_FORWARDED_HOPS {
            return Err(InvalidForwardedHeader);
        }
        let (element, tail) = parse_forwarded_element(rest)?;
        elements.push(element);
        let tail = tail.trim_start_matches(is_ows);
        if tail.is_empty() {
            return Ok(());
        }
        rest = tail
            .strip_prefix(',')
            .ok_or(InvalidForwardedHeader)?
            .trim_start_matches(is_ows);
    }
}

fn parse_forwarded_element(
    mut rest: &str,
) -> Result<(ForwardedIdentity, &str), InvalidForwardedHeader> {
    let mut client_ip = None;
    let mut proto = None;
    let mut host = None;
    let mut by_seen = false;
    let mut extensions = Vec::new();
    loop {
        let name_len = rest
            .bytes()
            .position(|byte| !is_tchar(byte))
            .unwrap_or(rest.len());
        if name_len == 0 {
            return Err(InvalidForwardedHeader);
        }
        let name = rest[..name_len].to_ascii_lowercase();
        rest = rest[name_len..]
            .strip_prefix('=')
            .ok_or(InvalidForwardedHeader)?;
        let (value, tail) = parse_forwarded_value(rest)?;
        rest = tail;
        match name.as_str() {
            "for" if client_ip.is_none() => client_ip = Some(parse_node(&value)?),
            "by" if !by_seen => {
                parse_node(&value)?;
                by_seen = true;
            }
            "proto" if proto.is_none() => {
                proto = Some(if value.eq_ignore_ascii_case("https") {
                    "https"
                } else if value.eq_ignore_ascii_case("http") {
                    "http"
                } else {
                    return Err(InvalidForwardedHeader);
                })
            }
            "host" if host.is_none() && !value.is_empty() => host = Some(value),
            "for" | "by" | "proto" | "host" => return Err(InvalidForwardedHeader),
            _ if extensions.contains(&name) => return Err(InvalidForwardedHeader),
            _ => extensions.push(name),
        }
        let after = rest.trim_start_matches(is_ows);
        match after.strip_prefix(';') {
            Some(next) => rest = next.trim_start_matches(is_ows),
            None => {
                rest = after;
                break;
            }
        }
    }
    let client_ip = client_ip.ok_or(InvalidForwardedHeader)?;
    Ok((
        ForwardedIdentity {
            client_ip,
            proto,
            host,
        },
        rest,
    ))
}

/// A token or a quoted string without escapes or control bytes.
fn parse_forwarded_value(rest: &str) -> Result<(String, &str), InvalidForwardedHeader> {
    if let Some(quoted) = rest.strip_prefix('"') {
        let end = quoted.find('"').ok_or(InvalidForwardedHeader)?;
        let value = &quoted[..end];
        if value.is_empty()
            || value
                .bytes()
                .any(|byte| byte == b'\\' || byte.is_ascii_control())
        {
            return Err(InvalidForwardedHeader);
        }
        return Ok((value.to_owned(), &quoted[end + 1..]));
    }
    let len = rest
        .bytes()
        .position(|byte| !is_tchar(byte))
        .unwrap_or(rest.len());
    if len == 0 {
        return Err(InvalidForwardedHeader);
    }
    Ok((rest[..len].to_owned(), &rest[len..]))
}

/// `IPv4[:port]` or `"[IPv6][:port]"`. Obfuscated identifiers and `unknown`
/// cannot be checked against trusted CIDRs or IP policy, so they fail closed.
fn parse_node(value: &str) -> Result<IpAddr, InvalidForwardedHeader> {
    let (ip, port) = if let Some(inner) = value.strip_prefix('[') {
        let (ip, tail) = inner.split_once(']').ok_or(InvalidForwardedHeader)?;
        let ip = ip
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| InvalidForwardedHeader)?;
        let port = match tail {
            "" => None,
            tail => Some(tail.strip_prefix(':').ok_or(InvalidForwardedHeader)?),
        };
        (IpAddr::V6(ip), port)
    } else {
        let (ip, port) = match value.split_once(':') {
            Some((ip, port)) => (ip, Some(port)),
            None => (value, None),
        };
        let ip = ip
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| InvalidForwardedHeader)?;
        (IpAddr::V4(ip), port)
    };
    if let Some(port) = port
        && (port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().map_or(true, |port| port == 0))
    {
        return Err(InvalidForwardedHeader);
    }
    Ok(ip.to_canonical())
}

fn is_ows(c: char) -> bool {
    c == ' ' || c == '\t'
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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

    fn forwarded(values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(
                hyper::header::FORWARDED,
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    fn identity(values: &[&str]) -> Result<Option<ForwardedIdentity>, InvalidForwardedHeader> {
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        forwarded_identity(&forwarded(values), &trusted)
    }

    #[test]
    fn forwarded_absent_is_not_an_error() {
        assert_eq!(identity(&[]), Ok(None));
    }

    #[test]
    fn forwarded_selects_rightmost_untrusted_element_with_its_proto_and_host() {
        let selected = identity(&[
            "for=192.0.2.60;proto=https;host=app.example, for=10.1.2.3;proto=http;host=internal",
        ])
        .unwrap()
        .unwrap();
        assert_eq!(selected.client_ip, "192.0.2.60".parse::<IpAddr>().unwrap());
        assert_eq!(selected.proto, Some("https"));
        assert_eq!(selected.host.as_deref(), Some("app.example"));
    }

    #[test]
    fn forwarded_fields_on_separate_lines_form_one_list() {
        let selected = identity(&["for=198.51.100.17", "for=10.0.0.2"])
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.client_ip,
            "198.51.100.17".parse::<IpAddr>().unwrap()
        );
        // When every hop is trusted the first element is the client, as in XFF.
        let selected = identity(&["for=10.0.0.9, for=10.0.0.2"]).unwrap().unwrap();
        assert_eq!(selected.client_ip, "10.0.0.9".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_accepts_quoted_ports_ipv6_brackets_and_case_insensitive_names() {
        let selected = identity(&[r#"For="[2001:db8:cafe::17]:4711"; PROTO=HTTPS; by=10.0.0.1"#])
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.client_ip,
            "2001:db8:cafe::17".parse::<IpAddr>().unwrap()
        );
        assert_eq!(selected.proto, Some("https"));
        let selected = identity(&[r#"for="192.0.2.43:47011";ext=token"#])
            .unwrap()
            .unwrap();
        assert_eq!(selected.client_ip, "192.0.2.43".parse::<IpAddr>().unwrap());
        assert_eq!(selected.proto, None);
        // IPv4-mapped IPv6 is canonicalized before the trust walk.
        let selected = identity(&[r#"for="[::ffff:10.0.0.5]""#]).unwrap().unwrap();
        assert_eq!(selected.client_ip, "10.0.0.5".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn forwarded_rejects_obfuscated_and_unknown_nodes() {
        for value in [
            "for=unknown",
            "for=_hidden",
            r#"for="_hidden:1234""#,
            r#"for="192.0.2.43:_port""#,
            "for=192.0.2.43;by=_proxy",
        ] {
            assert!(identity(&[value]).is_err(), "{value}");
        }
    }

    #[test]
    fn forwarded_rejects_bad_quoting_and_bracketing() {
        for value in [
            r#"for="192.0.2.43"#,
            r#"for="""#,
            r#"for="192.0.2\.43""#,
            "for=[2001:db8::1]",
            "for=2001:db8::1",
            r#"for="[2001:db8::1""#,
            r#"for="[192.0.2.43]""#,
            r#"for="[2001:db8::1]:0""#,
            r#"for="192.0.2.43:65536""#,
            r#"for="192.0.2.43"x"#,
        ] {
            assert!(identity(&[value]).is_err(), "{value}");
        }
    }

    #[test]
    fn forwarded_rejects_duplicate_parameters_in_one_element() {
        for value in [
            "for=192.0.2.1;for=192.0.2.2",
            "for=192.0.2.1;proto=http;proto=https",
            "for=192.0.2.1;host=a.example;host=b.example",
            "for=192.0.2.1;by=10.0.0.1;by=10.0.0.2",
            "for=192.0.2.1;ext=1;EXT=2",
        ] {
            assert!(identity(&[value]).is_err(), "{value}");
        }
        // The same parameter in different elements is a normal chain.
        assert!(identity(&["for=192.0.2.1;proto=https, for=10.0.0.1;proto=http"]).is_ok());
    }

    #[test]
    fn forwarded_rejects_missing_for_bad_proto_empty_and_oversized_lists() {
        for value in [
            "proto=https",
            "for=192.0.2.1;proto=ftp",
            "for=192.0.2.1;proto=",
            "for=192.0.2.1,",
            ", for=192.0.2.1",
            "for=192.0.2.1,,for=192.0.2.2",
            "for=192.0.2.1;",
            "for",
            "",
        ] {
            assert!(identity(&[value]).is_err(), "{value:?}");
        }
        let long = vec!["for=192.0.2.1"; 257].join(",");
        assert!(identity(&[&long]).is_err());
        let limit = vec!["for=192.0.2.1"; 256].join(",");
        assert!(identity(&[&limit]).is_ok());
    }

    #[test]
    fn x_forwarded_presence_is_detected_per_identity_field() {
        assert!(!has_x_forwarded(&forwarded(&["for=192.0.2.1"])));
        for name in [
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, HeaderValue::from_static("1"));
            assert!(has_x_forwarded(&headers), "{name}");
        }
    }
}
