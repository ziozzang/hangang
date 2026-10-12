//! Incremental, bounded multipart metadata inspection; file bytes are discarded.
//! The caller retains/replays original bytes and enforces the complete body limit.
use std::collections::HashSet;

const MAX_HEADERS: usize = 4096;
const MAX_PARTS: usize = 256;
const MAX_FIELD_BYTES: usize = 65536;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Field {
    pub name: String,
    pub value: String,
    pub file: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Opening,
    Headers,
    Body,
    Closing,
}
struct Part {
    name: String,
    file: bool,
    value: Vec<u8>,
}
impl Part {
    fn append(&mut self, bytes: &[u8], max: usize) -> Result<(), u16> {
        if self.file {
            return Ok(());
        }
        if bytes.len() > max.saturating_sub(self.value.len()) {
            return Err(413);
        }
        self.value.extend_from_slice(bytes);
        Ok(())
    }
    fn finish(self) -> Result<Field, u16> {
        Ok(Field {
            name: self.name,
            value: String::from_utf8(self.value).map_err(|_| 400u16)?,
            file: self.file,
        })
    }
}

pub(crate) struct Parser {
    marker: Vec<u8>,
    delimiter: Vec<u8>,
    state: State,
    /// At most a delimiter plus closing suffix and CR lookahead, or final CRLF.
    pending: Vec<u8>,
    headers: Vec<u8>,
    part: Option<Part>,
    fields: Vec<Field>,
    max_field_bytes: usize,
    failed: Option<u16>,
    line_tail: Vec<u8>,
    before_line_tail: Option<u8>,
}
impl Parser {
    pub fn new(boundary: &str, max_field_bytes: usize) -> Result<Self, u16> {
        if boundary.is_empty()
            || boundary.len() > 70
            || !boundary
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"'()+_,-./:=?".contains(&b))
            || !(1..=MAX_FIELD_BYTES).contains(&max_field_bytes)
        {
            return Err(400);
        }
        let marker = format!("--{boundary}").into_bytes();
        let delimiter = format!("\r\n--{boundary}").into_bytes();
        Ok(Self {
            pending: Vec::with_capacity(delimiter.len() + 4),
            marker,
            delimiter,
            state: State::Opening,
            headers: Vec::with_capacity(MAX_HEADERS + 4),
            part: None,
            fields: Vec::new(),
            max_field_bytes,
            failed: None,
            line_tail: Vec::new(),
            before_line_tail: None,
        })
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), u16> {
        if let Some(status) = self.failed {
            return Err(status);
        }
        let result = self.feed_inner(bytes);
        if let Err(status) = result {
            self.failed = Some(status);
        }
        result
    }
    fn feed_inner(&mut self, bytes: &[u8]) -> Result<(), u16> {
        self.reject_bare_lf_boundaries(bytes)?;
        let mut offset = 0;
        while offset < bytes.len() {
            match self.state {
                State::Opening => {
                    let byte = bytes[offset];
                    offset += 1;
                    if self.pending.len() < self.marker.len()
                        && byte != self.marker[self.pending.len()]
                    {
                        return Err(400);
                    }
                    self.pending.push(byte);
                    if self.pending.len() == self.marker.len() + 2 {
                        match &self.pending[self.marker.len()..] {
                            b"\r\n" => self.state = State::Headers,
                            b"--" => self.state = State::Closing,
                            _ => return Err(400),
                        }
                        self.pending.clear();
                    }
                }
                State::Headers => {
                    self.headers.push(bytes[offset]);
                    offset += 1;
                    if self.headers.ends_with(b"\r\n\r\n") {
                        let end = self.headers.len() - 4;
                        if end > MAX_HEADERS {
                            return Err(413);
                        }
                        if self.fields.len() >= MAX_PARTS {
                            return Err(413);
                        }
                        self.part = Some(parse_headers(&self.headers[..end])?);
                        self.headers.clear();
                        self.state = State::Body;
                    } else if self.headers.len() >= MAX_HEADERS + 4 {
                        return Err(413);
                    }
                }
                State::Body => {
                    // Most binary bytes never enter the rolling boundary buffer.
                    if self.pending.is_empty() {
                        let rest = &bytes[offset..];
                        if let Some(index) = memchr::memchr(b'\r', rest) {
                            self.append(&rest[..index])?;
                            offset += index;
                        } else {
                            self.append(rest)?;
                            break;
                        }
                    }
                    let byte = bytes[offset];
                    offset += 1;
                    let length = self.pending.len();
                    if length < self.delimiter.len() {
                        if byte == self.delimiter[length] {
                            self.pending.push(byte);
                        } else {
                            self.flush_pending()?;
                            self.restart_or_append(byte)?;
                        }
                    } else if length == self.delimiter.len() {
                        if byte == b'\r' || byte == b'-' {
                            self.pending.push(byte);
                        } else {
                            // PHP truncates field/file data at this full
                            // prefix even when the suffix is not valid MIME.
                            // Reject the ambiguity rather than inspect a
                            // different control value than the upstream.
                            return Err(400);
                        }
                    } else if length == self.delimiter.len() + 1 {
                        let suffix = self.pending[self.delimiter.len()];
                        if suffix == b'\r' && byte == b'\n' {
                            self.fields.push(self.part.take().ok_or(400u16)?.finish()?);
                            self.pending.clear();
                            self.state = State::Headers;
                        } else if suffix == b'-' && byte == b'-' {
                            // A closing marker needs EOF or CRLF; defer until
                            // its suffix or finish() validates that framing.
                            self.pending.push(byte);
                        } else {
                            return Err(400);
                        }
                    } else if length == self.delimiter.len() + 2 {
                        if byte == b'\r' {
                            self.pending.push(byte);
                        } else {
                            return Err(400);
                        }
                    } else if byte == b'\n' {
                        self.fields.push(self.part.take().ok_or(400u16)?.finish()?);
                        self.pending.clear();
                        self.pending.extend_from_slice(b"\r\n");
                        self.state = State::Closing;
                    } else {
                        return Err(400);
                    }
                }
                State::Closing => {
                    let expected = b"\r\n";
                    if self.pending.len() == expected.len()
                        || bytes[offset] != expected[self.pending.len()]
                    {
                        return Err(400);
                    }
                    self.pending.push(bytes[offset]);
                    offset += 1;
                }
            }
        }
        Ok(())
    }
    fn reject_bare_lf_boundaries(&mut self, bytes: &[u8]) -> Result<(), u16> {
        if bytes.is_empty() {
            return Ok(());
        }
        let marker = &self.delimiter[1..];
        let ambiguous = |input: &[u8], before: Option<u8>| {
            memchr::memmem::find_iter(input, marker).any(|index| {
                let preceding = if index == 0 {
                    before
                } else {
                    Some(input[index - 1])
                };
                preceding != Some(b'\r')
            })
        };
        let keep = marker.len();
        let mut bridge = self.line_tail.clone();
        bridge.extend_from_slice(&bytes[..bytes.len().min(keep)]);
        if ambiguous(&bridge, self.before_line_tail)
            || ambiguous(bytes, self.line_tail.last().copied())
        {
            // PHP accepts LF-only delimiters. Ignoring them as file data
            // would hide controls the upstream instead sees as another part.
            return Err(400);
        }
        if bytes.len() >= keep {
            self.before_line_tail = if bytes.len() > keep {
                Some(bytes[bytes.len() - keep - 1])
            } else {
                self.line_tail.last().copied()
            };
            self.line_tail.clear();
            self.line_tail
                .extend_from_slice(&bytes[bytes.len() - keep..]);
        } else {
            self.line_tail.extend_from_slice(bytes);
            let remove = self.line_tail.len().saturating_sub(keep);
            if remove > 0 {
                self.before_line_tail = Some(self.line_tail[remove - 1]);
                self.line_tail.drain(..remove);
            }
        }
        Ok(())
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), u16> {
        self.part
            .as_mut()
            .ok_or(400u16)?
            .append(bytes, self.max_field_bytes)
    }
    fn flush_pending(&mut self) -> Result<(), u16> {
        // Boundaries contain no internal CR. A mismatched prefix therefore has
        // no suffix that can start another delimiter; only the new byte can.
        self.part
            .as_mut()
            .ok_or(400u16)?
            .append(&self.pending, self.max_field_bytes)?;
        self.pending.clear();
        Ok(())
    }
    fn restart_or_append(&mut self, byte: u8) -> Result<(), u16> {
        if byte == b'\r' {
            self.pending.push(byte);
            Ok(())
        } else {
            self.append(&[byte])
        }
    }
    pub fn finish(mut self) -> Result<Vec<Field>, u16> {
        if let Some(status) = self.failed {
            return Err(status);
        }
        if self.state == State::Body
            && self.pending.len() == self.delimiter.len() + 2
            && self.pending.starts_with(&self.delimiter)
            && self.pending.ends_with(b"--")
        {
            self.fields.push(self.part.take().ok_or(400u16)?.finish()?);
            self.pending.clear();
            self.state = State::Closing;
        }
        if self.state != State::Closing || !matches!(self.pending.as_slice(), b"" | b"\r\n") {
            return Err(400);
        }
        Ok(self.fields)
    }
}

fn parse_headers(bytes: &[u8]) -> Result<Part, u16> {
    let headers = std::str::from_utf8(bytes).map_err(|_| 400u16)?;
    let mut seen = HashSet::new();
    let mut disposition = None;
    for line in headers.split("\r\n") {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        let name = hyper::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| 400u16)?;
        if !seen.insert(name.clone()) || value.chars().any(char::is_control) {
            return Err(400);
        }
        match name.as_str() {
            "content-disposition" => disposition = Some(value.trim()),
            "content-type" => {}
            _ => return Err(400),
        }
    }
    let (name, file) = parse_disposition(disposition.ok_or(400u16)?)?;
    Ok(Part {
        name,
        file,
        value: Vec::new(),
    })
}
fn token(byte: u8) -> bool {
    byte.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?={}".contains(&byte)
}
fn parse_disposition(raw: &str) -> Result<(String, bool), u16> {
    let (kind, rest) = raw.split_once(';').ok_or(400u16)?;
    if !kind.trim().eq_ignore_ascii_case("form-data") {
        return Err(400);
    }
    let bytes = rest.as_bytes();
    let mut offset = 0;
    let mut name = None;
    let mut file = false;
    let mut attributes = HashSet::new();
    while offset < bytes.len() {
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        let start = offset;
        while offset < bytes.len() && token(bytes[offset]) {
            offset += 1;
        }
        if offset == start {
            return Err(400);
        }
        let attribute = rest[start..offset].to_ascii_lowercase();
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        if offset == bytes.len() || bytes[offset] != b'=' || !attributes.insert(attribute.clone()) {
            return Err(400);
        }
        offset += 1;
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        let value;
        if offset < bytes.len() && bytes[offset] == b'"' {
            offset += 1;
            let start = offset;
            while offset < bytes.len() && bytes[offset] != b'"' {
                // Reject quoted-pair differences between PHP and MIME parsers.
                if bytes[offset] == b'\\' {
                    return Err(400);
                }
                offset += 1;
            }
            if offset == bytes.len() {
                return Err(400);
            }
            value = &rest[start..offset];
            offset += 1;
        } else {
            let start = offset;
            while offset < bytes.len() && token(bytes[offset]) {
                offset += 1;
            }
            if offset == start {
                return Err(400);
            }
            value = &rest[start..offset];
        }
        match attribute.as_str() {
            "name" => {
                if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
                    return Err(400);
                }
                name = Some(value.to_owned());
            }
            "filename" => file = true,
            _ => return Err(400),
        }
        while offset < bytes.len() && bytes[offset] == b' ' {
            offset += 1;
        }
        if offset < bytes.len() {
            if bytes[offset] != b';' {
                return Err(400);
            }
            offset += 1;
            if offset == bytes.len() {
                return Err(400);
            }
        }
    }
    Ok((name.ok_or(400u16)?, file))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn body(file: &[u8], text: &[u8]) -> Vec<u8> {
        let mut result=b"--Boundary\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"file;name.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec();
        result.extend_from_slice(file);
        result.extend_from_slice(
            b"\r\n--Boundary\r\nContent-Disposition: form-data; name=\"late_control\"\r\n\r\n",
        );
        result.extend_from_slice(text);
        result.extend_from_slice(b"\r\n--Boundary--\r\n");
        result
    }
    #[test]
    fn every_split_and_one_byte_feeds_capture_late_control_after_binary_file() {
        let bytes=body(b"binary\0\xff\r\n--BoundarX\r\n--Boundar-!\r\n--Boundar\rX\r\n--BoundarY\r\r\n--BoundarX",b"last-value");
        for split in 0..=bytes.len() {
            let mut parser = Parser::new("Boundary", 65536).unwrap();
            parser.feed(&bytes[..split]).unwrap();
            parser.feed(&bytes[split..]).unwrap();
            assert_eq!(
                parser.finish().unwrap(),
                vec![
                    Field {
                        name: "upload".into(),
                        value: String::new(),
                        file: true
                    },
                    Field {
                        name: "late_control".into(),
                        value: "last-value".into(),
                        file: false
                    }
                ],
                "split {split}"
            );
        }
        let mut parser = Parser::new("Boundary", 65536).unwrap();
        for byte in &bytes {
            parser.feed(&[*byte]).unwrap();
        }
        assert_eq!(parser.finish().unwrap()[1].value, "last-value");
    }
    #[test]
    fn false_boundary_candidates_are_preserved_in_text_without_losing_new_start() {
        let cases = [
            b"\r\n--BoundarX".as_slice(),
            b"\r\n--Boundar-\r\n--BoundarX",
            b"\r\n--Boundar\r\r\n--BoundarX",
            b"\r\n--BoundarY",
            b"\r\r\n--BoundarX",
        ];
        for input in cases {
            let bytes = body(b"", input);
            let mut parser = Parser::new("Boundary", 65536).unwrap();
            for byte in bytes {
                parser.feed(&[byte]).unwrap();
            }
            assert_eq!(parser.finish().unwrap()[1].value.as_bytes(), input);
        }
    }
    #[test]
    fn full_boundary_prefix_ambiguities_cannot_hide_php_control_values() {
        let ambiguous = [
            b"user\r\n--BoundaryX\r\nignored".as_slice(),
            b"user\r\n--Boundary-!",
            b"user\r\n--Boundary\rX",
            b"user\r\n--Boundary--X",
            b"user\r\n--Boundary--\rX",
            b"user\r\n--Boundary ",
        ];
        for value in ambiguous {
            for file in [false, true] {
                let bytes = if file {
                    body(value, b"safe")
                } else {
                    body(b"safe", value)
                };
                for split in 0..=bytes.len() {
                    let mut parser = Parser::new("Boundary", 65536).unwrap();
                    assert_eq!(
                        parser
                            .feed(&bytes[..split])
                            .and_then(|()| parser.feed(&bytes[split..])),
                        Err(400),
                        "file={file}, split={split}"
                    );
                }
            }
        }
    }
    #[test]
    fn huge_binary_file_is_not_retained_by_parser() {
        let start = body(b"", b"value");
        let separator = start.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        let mut parser = Parser::new("Boundary", 8).unwrap();
        parser.feed(&start[..separator]).unwrap();
        let chunk = vec![b'x'; 1024 * 1024];
        for _ in 0..32 {
            parser.feed(&chunk).unwrap();
            assert!(parser.part.as_ref().unwrap().value.is_empty());
            assert!(parser.pending.len() <= parser.delimiter.len() + 4);
        }
        parser.feed(&start[separator..]).unwrap();
        assert_eq!(parser.finish().unwrap()[1].value, "value");
    }
    #[test]
    fn truncated_closing_invalid_headers_and_epilogues_fail_closed() {
        let valid = body(b"data", b"ok");
        for length in 0..valid.len() {
            if length == valid.len() - 2 {
                continue;
            }
            let mut parser = Parser::new("Boundary", 65536).unwrap();
            if parser.feed(&valid[..length]).is_ok() {
                assert!(parser.finish().is_err(), "accepted truncation {length}");
            }
        }
        let mut parser = Parser::new("Boundary", 65536).unwrap();
        parser.feed(&valid[..valid.len() - 2]).unwrap();
        parser.finish().unwrap();
        for input in [b"--Boundary\n".as_slice(),b"preamble\r\n--Boundary--",b"--Boundary\r\nContent-Disposition: form-data; name=\"x\"; name=\"y\"\r\n\r\na\r\n--Boundary--",b"--Boundary\r\nContent-Disposition: form-data; name=\"x\\y\"\r\n\r\na\r\n--Boundary--",b"--Boundary\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Disposition: form-data; name=\"y\"\r\n\r\na\r\n--Boundary--"] {
            let mut parser=Parser::new("Boundary",65536).unwrap();assert!(parser.feed(input).is_err()||parser.finish().is_err());
        }
        for suffix in [b"x".as_slice(), b"\r\nx", b"\n", b"\r"] {
            let mut bytes = valid[..valid.len() - 2].to_vec();
            bytes.extend_from_slice(suffix);
            let mut parser = Parser::new("Boundary", 65536).unwrap();
            assert!(parser.feed(&bytes).is_err() || parser.finish().is_err());
        }
    }
    #[test]
    fn field_header_part_and_constructor_limits_are_enforced() {
        let bytes = body(b"", b"ninebytes");
        let mut parser = Parser::new("Boundary", 8).unwrap();
        assert_eq!(parser.feed(&bytes), Err(413));
        assert_eq!(parser.feed(b""), Err(413));
        assert!(matches!(parser.finish(), Err(413)));
        let mut parser = Parser::new("Boundary", 8).unwrap();
        let headers = format!(
            "--Boundary\r\nContent-Disposition: form-data; name=\"x\"\r\nContent-Type: {}",
            "x".repeat(4096)
        );
        assert_eq!(parser.feed(headers.as_bytes()), Err(413));
        let mut bytes = Vec::new();
        for _ in 0..257 {
            bytes.extend_from_slice(
                b"--Boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\na\r\n",
            );
        }
        bytes.extend_from_slice(b"--Boundary--\r\n");
        let mut parser = Parser::new("Boundary", 8).unwrap();
        assert_eq!(parser.feed(&bytes), Err(413));
        for (boundary, max) in [
            ("", 8),
            ("bad boundary", 8),
            ("Boundary", 0),
            ("Boundary", 65537),
        ] {
            assert!(Parser::new(boundary, max).is_err());
        }
        assert!(Parser::new(&"x".repeat(71), 8).is_err());
    }
    #[test]
    fn malformed_utf8_text_fails_but_arbitrary_file_bytes_and_empty_multipart_are_valid() {
        let mut parser = Parser::new("Boundary", 8).unwrap();
        assert_eq!(parser.feed(&body(b"\xff\x00", b"\xff")), Err(400));
        for closing in [b"--Boundary--".as_slice(), b"--Boundary--\r\n"] {
            let mut parser = Parser::new("Boundary", 8).unwrap();
            parser.feed(closing).unwrap();
            assert!(parser.finish().unwrap().is_empty());
        }
    }
    #[test]
    fn lf_only_hidden_parts_are_rejected_even_inside_binary_payload() {
        let bytes = body(
            b"file\n--Boundary\nContent-Disposition: form-data; name=\"mode\"\n\nuser",
            b"safe",
        );
        for split in 0..=bytes.len() {
            let mut parser = Parser::new("Boundary", 65536).unwrap();
            let outcome = parser
                .feed(&bytes[..split])
                .and_then(|()| parser.feed(&bytes[split..]));
            assert_eq!(outcome, Err(400), "split {split}");
        }
    }
}
