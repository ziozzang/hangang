//! HOP1 bounded native verification codec. This file is shared verbatim with
//! Hangang; provider and session logic is deliberately not part of this codec.
use std::io::{self, ErrorKind};
pub const MAGIC: [u8; 4] = *b"HOP1";
pub const MAX_FRAME: usize = 128 * 1024;
pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_BODY: usize = 64 * 1024;
#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
}
fn invalid() -> io::Error {
    io::Error::new(ErrorKind::InvalidData, "invalid native verify frame")
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if input.len() < n {
        return Err(invalid());
    }
    let (a, b) = input.split_at(n);
    *input = b;
    Ok(a)
}
fn u16_at(input: &mut &[u8]) -> io::Result<usize> {
    Ok(u16::from_be_bytes(take(input, 2)?.try_into().unwrap()) as usize)
}
fn u32_at(input: &mut &[u8]) -> io::Result<usize> {
    Ok(u32::from_be_bytes(take(input, 4)?.try_into().unwrap()) as usize)
}
pub fn frame_header(id: u64, len: usize) -> io::Result<[u8; 16]> {
    if len == 0 || len > MAX_FRAME {
        return Err(invalid());
    }
    let mut h = [0; 16];
    h[..4].copy_from_slice(&MAGIC);
    h[4..12].copy_from_slice(&id.to_be_bytes());
    h[12..].copy_from_slice(&(len as u32).to_be_bytes());
    Ok(h)
}
pub fn parse_header(h: [u8; 16]) -> io::Result<(u64, usize)> {
    if h[..4] != MAGIC {
        return Err(invalid());
    }
    let id = u64::from_be_bytes(h[4..12].try_into().unwrap());
    let n = u32::from_be_bytes(h[12..].try_into().unwrap()) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(invalid());
    }
    Ok((id, n))
}
fn encode_headers(headers: &[(String, Vec<u8>)], out: &mut Vec<u8>) -> io::Result<()> {
    if headers.len() > MAX_HEADERS {
        return Err(invalid());
    }
    out.extend_from_slice(&(headers.len() as u16).to_be_bytes());
    let start = out.len();
    for (name, value) in headers {
        if name.is_empty() || name.len() > 128 || value.len() > 16384 {
            return Err(invalid());
        }
        out.extend_from_slice(&(name.len() as u16).to_be_bytes());
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(value);
    }
    if out.len() - start > MAX_HEADER_BYTES {
        return Err(invalid());
    }
    Ok(())
}
fn decode_headers(input: &mut &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
    let n = u16_at(input)?;
    if n > MAX_HEADERS {
        return Err(invalid());
    }
    let start = input.len();
    let mut headers = Vec::with_capacity(n);
    for _ in 0..n {
        let a = u16_at(input)?;
        let b = u32_at(input)?;
        if a == 0 || a > 128 || b > 16384 {
            return Err(invalid());
        }
        let name = std::str::from_utf8(take(input, a)?)
            .map_err(|_| invalid())?
            .to_owned();
        let value = take(input, b)?.to_vec();
        headers.push((name, value));
        if start - input.len() > MAX_HEADER_BYTES {
            return Err(invalid());
        }
    }
    Ok(headers)
}
pub fn encode_request(headers: &[(String, Vec<u8>)]) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_headers(headers, &mut out)?;
    Ok(out)
}
pub fn decode_request(bytes: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
    let mut input = bytes;
    let out = decode_headers(&mut input)?;
    if !input.is_empty() {
        return Err(invalid());
    }
    Ok(out)
}
pub fn encode_reply(reply: &Reply) -> io::Result<Vec<u8>> {
    if !(200..=599).contains(&reply.status) || reply.body.len() > MAX_BODY {
        return Err(invalid());
    }
    let mut out = Vec::new();
    out.extend_from_slice(&reply.status.to_be_bytes());
    encode_headers(&reply.headers, &mut out)?;
    out.extend_from_slice(&(reply.body.len() as u32).to_be_bytes());
    out.extend_from_slice(&reply.body);
    if out.len() > MAX_FRAME {
        return Err(invalid());
    }
    Ok(out)
}
pub fn decode_reply(bytes: &[u8]) -> io::Result<Reply> {
    let mut input = bytes;
    let status = u16_at(&mut input)? as u16;
    if !(200..=599).contains(&status) {
        return Err(invalid());
    }
    let headers = decode_headers(&mut input)?;
    let len = u32_at(&mut input)?;
    if len > MAX_BODY {
        return Err(invalid());
    }
    let body = take(&mut input, len)?.to_vec();
    if !input.is_empty() {
        return Err(invalid());
    }
    Ok(Reply {
        status,
        headers,
        body,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_duplicate_and_non_utf8_values() {
        let headers = vec![
            ("cookie".into(), b"a=1".to_vec()),
            ("cookie".into(), vec![255]),
        ];
        let bytes = encode_request(&headers).unwrap();
        assert!(decode_request(&bytes).unwrap() == headers);
        let reply = Reply {
            status: 302,
            headers,
            body: vec![0, 255],
        };
        assert!(decode_reply(&encode_reply(&reply).unwrap()).unwrap() == reply);
    }
    #[test]
    fn rejects_truncation_trailing_bytes_and_excess_limits() {
        let b = encode_request(&[("cookie".into(), b"a=1".to_vec())]).unwrap();
        for n in 0..b.len() {
            assert!(decode_request(&b[..n]).is_err());
        }
        let mut extra = b;
        extra.push(0);
        assert!(decode_request(&extra).is_err());
        assert!(encode_request(&vec![("x".into(), vec![]); 65]).is_err());
        assert!(frame_header(1, MAX_FRAME + 1).is_err());
        assert!(frame_header(1, 0).is_err());
    }
    #[test]
    fn header_is_network_order_and_version_bound() {
        let h = frame_header(7, 42).unwrap();
        assert_eq!(h[..4], *b"HOP1");
        assert_eq!(parse_header(h).unwrap(), (7, 42));
        let mut bad = h;
        bad[3] = b'2';
        assert!(parse_header(bad).is_err());
    }
}
