//! PROXY protocol version 2 acceptance on the public listener.
//!
//! Only peers inside the configured trusted load balancer CIDRs may (and
//! must) open a connection with a PROXY v2 header; their header supplies the
//! client address used for every later decision (trusted forwarding headers,
//! Sumunjang admission, Pumgye network conditions, logs). Connections from
//! any other peer are served as direct connections with their socket address
//! and no header is parsed, so an untrusted client can never choose its own
//! address. Version 1 (text) headers are not accepted.
use anyhow::{Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const SIGNATURE: [u8; 12] = *b"\r\n\r\n\0\r\nQUIT\n";
/// Address block plus TLVs. Larger headers are refused.
pub const MAX_HEADER_BYTES: usize = 4096;
pub const HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Trusted sources for PROXY v2 headers on one listener.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    trusted: Vec<ipnet::IpNet>,
}
impl Policy {
    pub fn new(trusted: Vec<ipnet::IpNet>) -> Result<Option<Self>> {
        if trusted.is_empty() {
            return Ok(None);
        }
        ensure!(trusted.len() <= 64, "at most 64 PROXY protocol CIDRs");
        Ok(Some(Self { trusted }))
    }
    pub fn trusts(&self, peer: IpAddr) -> bool {
        let peer = canonical(peer);
        self.trusted.iter().any(|net| net.contains(&peer))
    }
    /// The effective client address of a newly accepted connection. Reads
    /// exactly the header bytes from a trusted peer (never any payload), with
    /// a deadline; an untrusted peer is returned unchanged without reading.
    pub async fn accept<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        peer: SocketAddr,
    ) -> Result<SocketAddr> {
        self.accept_within(stream, peer, HEADER_TIMEOUT).await
    }
    async fn accept_within<S: AsyncRead + Unpin>(
        &self,
        stream: &mut S,
        peer: SocketAddr,
        deadline: std::time::Duration,
    ) -> Result<SocketAddr> {
        if !self.trusts(peer.ip()) {
            return Ok(peer);
        }
        match tokio::time::timeout(deadline, read_header(stream)).await {
            Ok(Ok(Some(source))) => Ok(source),
            // LOCAL command (load balancer health check) or an unspecified
            // family: the connection is the load balancer's own.
            Ok(Ok(None)) => Ok(peer),
            Ok(Err(error)) => Err(error),
            Err(_) => bail!("PROXY protocol header timed out"),
        }
    }
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        other => other,
    }
}

/// Read one PROXY v2 header. `Some(source)` for a proxied TCP connection,
/// `None` for LOCAL or an unspecified family.
pub async fn read_header<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Option<SocketAddr>> {
    let mut fixed = [0u8; 16];
    stream.read_exact(&mut fixed).await?;
    ensure!(
        fixed[..12] == SIGNATURE,
        "missing PROXY protocol v2 signature"
    );
    let length = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
    ensure!(
        length <= MAX_HEADER_BYTES,
        "PROXY protocol header too large"
    );
    let mut rest = vec![0u8; length];
    stream.read_exact(&mut rest).await?;
    parse(&fixed, &rest)
}

fn parse(fixed: &[u8; 16], rest: &[u8]) -> Result<Option<SocketAddr>> {
    ensure!(fixed[12] >> 4 == 2, "unsupported PROXY protocol version");
    let command = fixed[12] & 0x0f;
    let family = fixed[13] >> 4;
    let transport = fixed[13] & 0x0f;
    match command {
        0 => return Ok(None),
        1 => {}
        _ => bail!("unsupported PROXY protocol command"),
    }
    match (family, transport) {
        (0, _) => Ok(None),
        (1, 1) => {
            ensure!(rest.len() >= 12, "short PROXY protocol IPv4 address block");
            let ip = Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]);
            let port = u16::from_be_bytes([rest[8], rest[9]]);
            Ok(Some(SocketAddr::new(IpAddr::V4(ip), port)))
        }
        (2, 1) => {
            ensure!(rest.len() >= 36, "short PROXY protocol IPv6 address block");
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&rest[..16]);
            let ip = canonical(IpAddr::V6(Ipv6Addr::from(octets)));
            let port = u16::from_be_bytes([rest[32], rest[33]]);
            Ok(Some(SocketAddr::new(ip, port)))
        }
        _ => bail!("PROXY protocol supports only TCP over IPv4 or IPv6"),
    }
}

/// Encode a PROXY v2 header (tests and qualification tools).
pub fn encode(source: SocketAddr, destination: SocketAddr) -> Vec<u8> {
    let mut out = SIGNATURE.to_vec();
    out.push(0x21);
    match (source, destination) {
        (SocketAddr::V4(src), SocketAddr::V4(dst)) => {
            out.push(0x11);
            out.extend_from_slice(&12u16.to_be_bytes());
            out.extend_from_slice(&src.ip().octets());
            out.extend_from_slice(&dst.ip().octets());
            out.extend_from_slice(&src.port().to_be_bytes());
            out.extend_from_slice(&dst.port().to_be_bytes());
        }
        _ => {
            let v6 = |a: SocketAddr| match a.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            out.push(0x21);
            out.extend_from_slice(&36u16.to_be_bytes());
            out.extend_from_slice(&v6(source).octets());
            out.extend_from_slice(&v6(destination).octets());
            out.extend_from_slice(&source.port().to_be_bytes());
            out.extend_from_slice(&destination.port().to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy::new(vec!["10.0.0.0/8".parse().unwrap()])
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn trusted_peer_supplies_the_client_address_and_payload_is_untouched() {
        let source: SocketAddr = "203.0.113.7:51000".parse().unwrap();
        let mut bytes = encode(source, "10.1.1.1:443".parse().unwrap());
        bytes.extend_from_slice(b"GET / HTTP/1.1\r\n");
        let mut reader = &bytes[..];
        let peer = "10.2.3.4:4000".parse().unwrap();
        assert_eq!(policy().accept(&mut reader, peer).await.unwrap(), source);
        assert_eq!(reader, b"GET / HTTP/1.1\r\n");

        let v6: SocketAddr = "[2001:db8::7]:443".parse().unwrap();
        let bytes = encode(v6, "[2001:db8::1]:443".parse().unwrap());
        assert_eq!(policy().accept(&mut &bytes[..], peer).await.unwrap(), v6);
    }

    #[tokio::test]
    async fn untrusted_peer_is_never_parsed() {
        let bytes = encode(
            "198.51.100.1:1".parse().unwrap(),
            "10.1.1.1:443".parse().unwrap(),
        );
        let mut reader = &bytes[..];
        let peer: SocketAddr = "192.0.2.9:4000".parse().unwrap();
        assert_eq!(policy().accept(&mut reader, peer).await.unwrap(), peer);
        assert_eq!(reader.len(), bytes.len(), "nothing may be consumed");
    }

    #[tokio::test]
    async fn trusted_peer_without_a_valid_header_is_refused() {
        let peer = "10.2.3.4:4000".parse().unwrap();
        // Plain HTTP from the load balancer: the header is mandatory.
        assert!(
            policy()
                .accept(&mut &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..], peer)
                .await
                .is_err()
        );
        // Version 1 text header.
        assert!(
            policy()
                .accept(
                    &mut &b"PROXY TCP4 1.1.1.1 2.2.2.2 1 2\r\n\r\n\r\n"[..],
                    peer
                )
                .await
                .is_err()
        );
        // Truncated address block.
        let mut bytes = encode(
            "203.0.113.7:1".parse().unwrap(),
            "10.1.1.1:443".parse().unwrap(),
        );
        bytes.truncate(20);
        assert!(policy().accept(&mut &bytes[..], peer).await.is_err());
        // Oversized length.
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert!(policy().accept(&mut &bytes[..], peer).await.is_err());
        // UDP transport.
        let mut bytes = encode(
            "203.0.113.7:1".parse().unwrap(),
            "10.1.1.1:443".parse().unwrap(),
        );
        bytes[13] = 0x12;
        assert!(policy().accept(&mut &bytes[..], peer).await.is_err());
    }

    #[tokio::test]
    async fn local_command_keeps_the_load_balancer_address() {
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x20, 0x00, 0x00, 0x00]);
        let peer = "10.2.3.4:4000".parse().unwrap();
        assert_eq!(policy().accept(&mut &bytes[..], peer).await.unwrap(), peer);
    }

    #[tokio::test]
    async fn mapped_ipv6_peer_matches_ipv4_trust() {
        let source: SocketAddr = "203.0.113.7:1".parse().unwrap();
        let bytes = encode(source, "10.1.1.1:443".parse().unwrap());
        let peer: SocketAddr = "[::ffff:10.2.3.4]:4000".parse().unwrap();
        assert_eq!(
            policy().accept(&mut &bytes[..], peer).await.unwrap(),
            source
        );
        assert!(Policy::new(Vec::new()).unwrap().is_none());
    }

    #[tokio::test]
    async fn a_silent_trusted_peer_times_out() {
        let (_client, mut server) = tokio::io::duplex(64);
        let peer = "10.2.3.4:4000".parse().unwrap();
        let deadline = std::time::Duration::from_millis(50);
        assert!(
            policy()
                .accept_within(&mut server, peer, deadline)
                .await
                .is_err()
        );
    }
}
