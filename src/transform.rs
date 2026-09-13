use anyhow::{Context, Result, bail, ensure};
use quick_xml::events::{BytesEnd, BytesText, Event};
use quick_xml::{Reader, Writer};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::io::{self, Write};

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const MAX_LIMIT: usize = 1024 * 1024;
const MAX_LUA_BYTES: usize = 16 * 1024;

/// A configured runtime input, intermediate, or output byte limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LimitExceeded;

impl fmt::Display for LimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("transform size limit exceeded")
    }
}

impl std::error::Error for LimitExceeded {}

fn default_body_limit() -> usize {
    65_536
}

fn default_timeout_ms() -> u64 {
    5_000
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransformMode {
    #[default]
    Buffered,
    Lines,
    Ndjson,
    Sse,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    Replace { from: String, to: String },
    JsonSet { pointer: String, value: Value },
    JsonRemove { pointer: String },
    XmlSetText { path: String, value: String },
    XmlRemove { path: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BodyTransform {
    #[serde(default)]
    pub mode: TransformMode,
    #[serde(default)]
    pub operations: Vec<Operation>,
    #[serde(default)]
    pub lua: Option<String>,
    #[serde(default = "default_body_limit")]
    pub max_buffer_bytes: usize,
    #[serde(default = "default_body_limit")]
    pub max_output_bytes: usize,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub set_headers: BTreeMap<String, String>,
    #[serde(default)]
    pub remove_headers: Vec<String>,
}

impl Default for BodyTransform {
    fn default() -> Self {
        Self {
            mode: TransformMode::Buffered,
            operations: Vec::new(),
            lua: None,
            max_buffer_bytes: default_body_limit(),
            max_output_bytes: default_body_limit(),
            timeout_ms: default_timeout_ms(),
            set_headers: BTreeMap::new(),
            remove_headers: Vec::new(),
        }
    }
}

impl BodyTransform {
    /// True if this transform's header rules set or remove `name`
    /// (case-insensitive). Used to keep authentication identity headers out of
    /// reach of a later request transform.
    pub fn mutates_header(&self, name: &str) -> bool {
        self.set_headers
            .keys()
            .chain(self.remove_headers.iter())
            .any(|configured| configured.eq_ignore_ascii_case(name))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.operations.len() <= 32,
            "at most 32 transform operations are allowed"
        );
        ensure!(
            self.set_headers.len() + self.remove_headers.len() <= 32,
            "at most 32 transform header mutations are allowed"
        );
        ensure!(
            (1..=MAX_LIMIT).contains(&self.max_buffer_bytes),
            "max_buffer_bytes must be 1..1048576"
        );
        ensure!(
            (1..=MAX_LIMIT).contains(&self.max_output_bytes),
            "max_output_bytes must be 1..1048576"
        );
        ensure!(
            (1..=30_000).contains(&self.timeout_ms),
            "timeout_ms must be 1..30000"
        );

        if let Some(script) = &self.lua {
            ensure!(script.len() <= MAX_LUA_BYTES, "Lua script exceeds 16 KiB");
            ensure!(
                self.max_buffer_bytes <= MAX_LUA_BYTES && self.max_output_bytes <= MAX_LUA_BYTES,
                "Lua transforms require buffer and output limits <=16 KiB"
            );
        }

        let mut has_json = false;
        let mut has_xml = false;
        let mut config_bytes = 0usize;
        for operation in &self.operations {
            match operation {
                Operation::Replace { from, to } => {
                    ensure!(!from.is_empty(), "replace source must not be empty");
                    add_config_bytes(&mut config_bytes, from.len())?;
                    add_config_bytes(&mut config_bytes, to.len())?;
                }
                Operation::JsonSet { pointer, value } => {
                    has_json = true;
                    parse_json_pointer(pointer).context("invalid json_set pointer")?;
                    add_config_bytes(&mut config_bytes, pointer.len())?;
                    add_config_bytes(&mut config_bytes, json_encoded_len(value)?)?;
                }
                Operation::JsonRemove { pointer } => {
                    has_json = true;
                    ensure!(
                        !pointer.is_empty(),
                        "json_remove cannot remove the document root"
                    );
                    parse_json_pointer(pointer).context("invalid json_remove pointer")?;
                    add_config_bytes(&mut config_bytes, pointer.len())?;
                }
                Operation::XmlSetText { path, value } => {
                    has_xml = true;
                    parse_xml_path(path).context("invalid xml_set_text path")?;
                    ensure!(
                        value.chars().all(valid_xml_character),
                        "xml_set_text value contains an invalid XML character"
                    );
                    add_config_bytes(&mut config_bytes, path.len())?;
                    add_config_bytes(&mut config_bytes, value.len())?;
                }
                Operation::XmlRemove { path } => {
                    has_xml = true;
                    let parts = parse_xml_path(path).context("invalid xml_remove path")?;
                    ensure!(
                        parts.len() > 1,
                        "xml_remove cannot remove the document root"
                    );
                    add_config_bytes(&mut config_bytes, path.len())?;
                }
            }
        }
        ensure!(
            !has_json || !has_xml,
            "JSON and XML operations cannot be mixed"
        );

        let mut names = HashSet::new();
        for (name, value) in &self.set_headers {
            let canonical = validate_header_name(name)?;
            validate_set_header_name(name, &canonical)?;
            ensure!(
                names.insert(canonical),
                "duplicate transform header name: {name}"
            );
            validate_header_value(value)?;
            add_config_bytes(&mut config_bytes, name.len())?;
            add_config_bytes(&mut config_bytes, value.len())?;
        }
        for name in &self.remove_headers {
            let canonical = validate_header_name(name)?;
            ensure!(
                names.insert(canonical),
                "duplicate transform header name: {name}"
            );
            add_config_bytes(&mut config_bytes, name.len())?;
        }
        if let Some(script) = &self.lua {
            add_config_bytes(&mut config_bytes, script.len())?;
        }
        ensure!(
            config_bytes <= MAX_CONFIG_BYTES,
            "transform configuration exceeds 64 KiB"
        );
        Ok(())
    }

    /// Applies the configured native operations to one complete record.
    ///
    /// Streaming modes split bodies into records outside this function. XML text
    /// replacement replaces all content and descendants of every exact path match.
    pub fn apply_native(&self, input: &[u8]) -> Result<Vec<u8>> {
        self.validate()?;
        self.apply_validated_native(input)
    }

    /// Applies native operations after this configuration has already passed
    /// [`BodyTransform::validate`]. Intended for per-record streaming hot paths.
    pub(crate) fn apply_validated_native(&self, input: &[u8]) -> Result<Vec<u8>> {
        if input.len() > self.max_buffer_bytes {
            return Err(LimitExceeded.into());
        }

        let mut current = input.to_vec();
        if self.operations.is_empty() && self.lua.is_none() && current.len() > self.max_output_bytes
        {
            return Err(LimitExceeded.into());
        }
        for operation in &self.operations {
            current = match operation {
                Operation::Replace { from, to } => replace_bounded(
                    &current,
                    from.as_bytes(),
                    to.as_bytes(),
                    self.max_output_bytes,
                )?,
                Operation::JsonSet { pointer, value } => {
                    transform_json(&current, self.max_output_bytes, |document| {
                        json_set(document, pointer, value.clone())
                    })?
                }
                Operation::JsonRemove { pointer } => {
                    transform_json(&current, self.max_output_bytes, |document| {
                        json_remove(document, pointer)
                    })?
                }
                Operation::XmlSetText { path, value } => transform_xml(
                    &current,
                    &parse_xml_path(path)?,
                    XmlAction::SetText(value),
                    self.max_output_bytes,
                )?,
                Operation::XmlRemove { path } => transform_xml(
                    &current,
                    &parse_xml_path(path)?,
                    XmlAction::Remove,
                    self.max_output_bytes,
                )?,
            };
            if current.len() > self.max_output_bytes {
                return Err(LimitExceeded.into());
            }
        }
        Ok(current)
    }
}

fn add_config_bytes(total: &mut usize, amount: usize) -> Result<()> {
    *total = total
        .checked_add(amount)
        .context("transform configuration size overflow")?;
    ensure!(
        *total <= MAX_CONFIG_BYTES,
        "transform configuration exceeds 64 KiB"
    );
    Ok(())
}

fn validate_header_name(name: &str) -> Result<String> {
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte) }),
        "invalid transform header name: {name}"
    );
    let lower = name.to_ascii_lowercase();
    Ok(lower)
}

fn validate_set_header_name(name: &str, lower: &str) -> Result<()> {
    let forbidden = matches!(
        lower,
        "connection"
            | "content-encoding"
            | "content-length"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "http2-settings"
            | "forwarded"
            | "via"
            | "x-real-ip"
            | "range"
            | "accept-ranges"
            | "content-range"
            | "if-range"
            | "etag"
            | "last-modified"
            | "if-match"
            | "if-none-match"
            | "if-modified-since"
            | "if-unmodified-since"
            | "content-md5"
            | "digest"
            | "content-digest"
            | "repr-digest"
            | "signature"
            | "signature-input"
    ) || lower.starts_with("x-forwarded-")
        || lower.starts_with("sec-websocket-");
    ensure!(!forbidden, "unsafe transform header mutation: {name}");
    Ok(())
}

fn validate_header_value(value: &str) -> Result<()> {
    ensure!(
        value
            .bytes()
            .all(|byte| byte == b'\t' || (byte >= 0x20 && byte != 0x7f)),
        "invalid transform header value"
    );
    Ok(())
}

struct CountingWriter {
    bytes: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("serialized value is too large"))?;
        if self.bytes > MAX_CONFIG_BYTES {
            return Err(io::Error::other("serialized value exceeds 64 KiB"));
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn json_encoded_len(value: &Value) -> Result<usize> {
    let mut writer = CountingWriter { bytes: 0 };
    serde_json::to_writer(&mut writer, value).context("measure json_set value")?;
    Ok(writer.bytes)
}

fn parse_json_pointer(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(
        pointer.starts_with('/'),
        "JSON pointer must be empty or start with '/'"
    );
    pointer[1..]
        .split('/')
        .map(|part| {
            let mut decoded = String::with_capacity(part.len());
            let mut chars = part.chars();
            while let Some(character) = chars.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match chars.next() {
                    Some('0') => decoded.push('~'),
                    Some('1') => decoded.push('/'),
                    _ => bail!("invalid '~' escape in JSON pointer"),
                }
            }
            Ok(decoded)
        })
        .collect()
}

fn parse_array_index(token: &str, length: usize) -> Result<usize> {
    ensure!(
        token == "0"
            || (!token.starts_with('0') && token.bytes().all(|byte| byte.is_ascii_digit())),
        "invalid JSON array index: {token}"
    );
    let index = token
        .parse::<usize>()
        .context("JSON array index is too large")?;
    ensure!(index < length, "JSON array index is out of bounds: {index}");
    Ok(index)
}

fn json_parent_mut<'a>(mut value: &'a mut Value, parts: &[String]) -> Result<&'a mut Value> {
    for part in parts {
        value = match value {
            Value::Object(object) => object
                .get_mut(part)
                .with_context(|| format!("JSON pointer parent does not exist: {part}"))?,
            Value::Array(array) => {
                let index = parse_array_index(part, array.len())?;
                &mut array[index]
            }
            _ => bail!("JSON pointer traverses a scalar value"),
        };
    }
    Ok(value)
}

fn json_set(document: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let parts = parse_json_pointer(pointer)?;
    if parts.is_empty() {
        *document = value;
        return Ok(());
    }
    let (last, parent_parts) = parts.split_last().expect("nonempty pointer");
    match json_parent_mut(document, parent_parts)? {
        Value::Object(object) => {
            object.insert(last.clone(), value);
        }
        Value::Array(array) => {
            let index = parse_array_index(last, array.len())?;
            array[index] = value;
        }
        _ => bail!("JSON pointer parent is a scalar value"),
    }
    Ok(())
}

fn json_remove(document: &mut Value, pointer: &str) -> Result<()> {
    let parts = parse_json_pointer(pointer)?;
    ensure!(
        !parts.is_empty(),
        "json_remove cannot remove the document root"
    );
    let (last, parent_parts) = parts.split_last().expect("nonempty pointer");
    match json_parent_mut(document, parent_parts)? {
        Value::Object(object) => {
            ensure!(
                object.remove(last).is_some(),
                "JSON pointer target does not exist"
            );
        }
        Value::Array(array) => {
            let index = parse_array_index(last, array.len())?;
            array.remove(index);
        }
        _ => bail!("JSON pointer parent is a scalar value"),
    }
    Ok(())
}

struct LimitedOutput {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl LimitedOutput {
    fn new(limit: usize, initial_capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(initial_capacity.min(limit)),
            limit,
            exceeded: false,
        }
    }
}

impl Write for LimitedOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let new_len = self
            .bytes
            .len()
            .checked_add(buffer.len())
            .ok_or_else(|| io::Error::other("transform output size overflow"))?;
        if new_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other(LimitExceeded));
        }
        if new_len > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(new_len - self.bytes.len())
                .map_err(|error| io::Error::other(error.to_string()))?;
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn transform_json(
    input: &[u8],
    limit: usize,
    transform: impl FnOnce(&mut Value) -> Result<()>,
) -> Result<Vec<u8>> {
    let mut document: Value =
        serde_json::from_slice(input).context("parse transform JSON input")?;
    transform(&mut document)?;
    let mut output = LimitedOutput::new(limit, input.len());
    let serialized = serde_json::to_writer(&mut output, &document);
    if output.exceeded {
        return Err(LimitExceeded.into());
    }
    serialized.context("serialize transform JSON output")?;
    Ok(output.bytes)
}

fn replace_bounded(input: &[u8], from: &[u8], to: &[u8], limit: usize) -> Result<Vec<u8>> {
    ensure!(!from.is_empty(), "replace source must not be empty");
    let mut matches = 0usize;
    let mut cursor = 0usize;
    let finder = memchr::memmem::Finder::new(from);
    while let Some(offset) = finder.find(&input[cursor..]) {
        matches = matches
            .checked_add(1)
            .context("replacement count overflow")?;
        cursor = cursor
            .checked_add(offset)
            .and_then(|position| position.checked_add(from.len()))
            .context("replacement position overflow")?;
    }
    let removed = matches
        .checked_mul(from.len())
        .context("replacement size overflow")?;
    let added = matches
        .checked_mul(to.len())
        .context("replacement size overflow")?;
    let size = input
        .len()
        .checked_sub(removed)
        .and_then(|size| size.checked_add(added))
        .context("replacement size overflow")?;
    if size > limit {
        return Err(LimitExceeded.into());
    }

    let mut output = Vec::with_capacity(size);
    let mut start = 0usize;
    while let Some(offset) = finder.find(&input[start..]) {
        let position = start + offset;
        output.extend_from_slice(&input[start..position]);
        output.extend_from_slice(to);
        start = position + from.len();
    }
    output.extend_from_slice(&input[start..]);
    debug_assert_eq!(output.len(), size);
    Ok(output)
}

fn parse_xml_path(path: &str) -> Result<Vec<String>> {
    ensure!(path.starts_with('/'), "XML path must be absolute");
    ensure!(!path.ends_with('/'), "XML path must not end with '/'");
    let parts: Vec<String> = path[1..].split('/').map(str::to_owned).collect();
    ensure!(
        !parts.is_empty() && parts.len() <= 64,
        "XML path must contain 1..64 names"
    );
    for part in &parts {
        ensure!(
            valid_qualified_name(part),
            "invalid qualified XML name: {part}"
        );
    }
    Ok(parts)
}

fn valid_qualified_name(name: &str) -> bool {
    let mut pieces = name.split(':');
    let Some(first) = pieces.next() else {
        return false;
    };
    if !valid_xml_name_piece(first) {
        return false;
    }
    match pieces.next() {
        None => true,
        Some(second) => valid_xml_name_piece(second) && pieces.next().is_none(),
    }
}

fn valid_xml_name_piece(piece: &str) -> bool {
    let mut bytes = piece.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

enum XmlAction<'a> {
    SetText(&'a str),
    Remove,
}

fn transform_xml(
    input: &[u8],
    target: &[String],
    action: XmlAction<'_>,
    limit: usize,
) -> Result<Vec<u8>> {
    let xml = std::str::from_utf8(input).context("XML transform input is not UTF-8")?;
    ensure!(
        xml.chars().all(valid_xml_character),
        "XML transform input contains an invalid XML character"
    );
    let mut reader = Reader::from_reader(input);
    reader.config_mut().check_end_names = true;
    let output = LimitedOutput::new(limit, input.len());
    let mut writer = Writer::new(output);
    let mut buffer = Vec::new();
    let mut path = Vec::<String>::new();
    let mut skipped_at = None::<usize>;
    let mut saw_root = false;
    let mut root_closed = false;
    let mut saw_document_content = false;

    macro_rules! write_event {
        ($event:expr) => {{
            let result = writer.write_event($event);
            if result.is_err() && writer.get_ref().exceeded {
                return Err(LimitExceeded.into());
            }
            result.context("serialize transform XML output")?;
        }};
    }

    loop {
        let event = reader
            .read_event_into(&mut buffer)
            .context("parse transform XML input")?;
        match event {
            Event::Start(start) => {
                saw_document_content = true;
                validate_xml_attributes(&start)?;
                if path.is_empty() {
                    ensure!(
                        !saw_root && !root_closed,
                        "XML input has multiple document elements"
                    );
                    saw_root = true;
                }
                path.push(xml_event_name(start.name().as_ref())?);
                ensure!(path.len() <= 64, "XML nesting exceeds 64 elements");
                let matched = skipped_at.is_none() && path == target;
                if matched {
                    match action {
                        XmlAction::SetText(value) => {
                            write_event!(Event::Start(start.to_owned()));
                            write_event!(Event::Text(BytesText::new(value)));
                        }
                        XmlAction::Remove => {}
                    }
                    skipped_at = Some(path.len());
                } else if skipped_at.is_none() {
                    write_event!(Event::Start(start.to_owned()));
                }
            }
            Event::Empty(start) => {
                saw_document_content = true;
                validate_xml_attributes(&start)?;
                if path.is_empty() {
                    ensure!(
                        !saw_root && !root_closed,
                        "XML input has multiple document elements"
                    );
                    saw_root = true;
                    root_closed = true;
                }
                path.push(xml_event_name(start.name().as_ref())?);
                ensure!(path.len() <= 64, "XML nesting exceeds 64 elements");
                let matched = skipped_at.is_none() && path == target;
                if skipped_at.is_none() {
                    if matched {
                        if let XmlAction::SetText(value) = action {
                            let name = path.last().expect("empty event has a name").clone();
                            write_event!(Event::Start(start.to_owned()));
                            write_event!(Event::Text(BytesText::new(value)));
                            write_event!(Event::End(BytesEnd::new(name)));
                        }
                    } else {
                        write_event!(Event::Empty(start.to_owned()));
                    }
                }
                path.pop();
            }
            Event::End(end) => {
                saw_document_content = true;
                ensure!(
                    !path.is_empty(),
                    "XML input has an unmatched closing element"
                );
                if let Some(depth) = skipped_at {
                    if path.len() == depth {
                        if matches!(action, XmlAction::SetText(_)) {
                            write_event!(Event::End(end.to_owned()));
                        }
                        skipped_at = None;
                    }
                } else {
                    write_event!(Event::End(end.to_owned()));
                }
                path.pop();
                if path.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                saw_document_content = true;
                let raw: &[u8] = text.as_ref();
                validate_xml_entities(raw)?;
                if path.is_empty() {
                    ensure!(
                        raw.iter().all(u8::is_ascii_whitespace),
                        "XML text is not inside the document element"
                    );
                }
                if skipped_at.is_none() {
                    write_event!(Event::Text(text.into_owned()));
                }
            }
            Event::CData(data) => {
                saw_document_content = true;
                ensure!(
                    !path.is_empty(),
                    "XML CDATA is not inside the document element"
                );
                if skipped_at.is_none() {
                    write_event!(Event::CData(data.into_owned()));
                }
            }
            Event::GeneralRef(reference) => {
                saw_document_content = true;
                validate_xml_reference(reference.as_ref())?;
                ensure!(
                    !path.is_empty(),
                    "XML entity is not inside the document element"
                );
                if skipped_at.is_none() {
                    write_event!(Event::GeneralRef(reference.into_owned()));
                }
            }
            Event::DocType(_) => bail!("XML DTDs are not allowed"),
            Event::Decl(declaration) => {
                ensure!(
                    !saw_document_content && !saw_root && path.is_empty(),
                    "XML declaration must be the first document event"
                );
                saw_document_content = true;
                if let Some(encoding) = declaration.encoding() {
                    let encoding = encoding.context("invalid XML encoding declaration")?;
                    ensure!(
                        encoding.eq_ignore_ascii_case(b"utf-8")
                            || encoding.eq_ignore_ascii_case(b"utf8"),
                        "XML transform input must declare UTF-8 encoding"
                    );
                }
                if skipped_at.is_none() {
                    write_event!(Event::Decl(declaration.into_owned()));
                }
            }
            Event::PI(pi) => {
                saw_document_content = true;
                if skipped_at.is_none() {
                    write_event!(Event::PI(pi.into_owned()));
                }
            }
            Event::Comment(comment) => {
                saw_document_content = true;
                if skipped_at.is_none() {
                    write_event!(Event::Comment(comment.into_owned()));
                }
            }
            Event::Eof => break,
        }
        buffer.clear();
    }
    ensure!(path.is_empty(), "XML input ended inside an element");
    ensure!(saw_root, "XML input has no document element");
    Ok(writer.into_inner().bytes)
}

fn xml_event_name(name: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(name)
        .context("XML element name is not UTF-8")?
        .to_owned())
}

// Per-element attribute cap. quick-xml's `with_checks(true)` duplicate-name
// detection is O(n^2) in the attribute count; bounding the count keeps a single
// crafted element (which runs on a non-cancellable blocking thread holding a
// transform admission permit) from consuming that permit for a long time.
const MAX_XML_ATTRIBUTES: usize = 256;

fn validate_xml_attributes(start: &quick_xml::events::BytesStart<'_>) -> Result<()> {
    let mut count = 0usize;
    for attribute in start.attributes().with_checks(true) {
        count += 1;
        ensure!(
            count <= MAX_XML_ATTRIBUTES,
            "XML element exceeds {MAX_XML_ATTRIBUTES} attributes"
        );
        let attribute = attribute.context("invalid XML attribute")?;
        validate_xml_entities(attribute.value.as_ref())?;
    }
    Ok(())
}

fn validate_xml_entities(bytes: &[u8]) -> Result<()> {
    let mut cursor = 0usize;
    while let Some(offset) = bytes[cursor..].iter().position(|byte| *byte == b'&') {
        let start = cursor + offset + 1;
        let end = bytes[start..]
            .iter()
            .position(|byte| *byte == b';')
            .map(|offset| start + offset)
            .context("unterminated XML entity reference")?;
        validate_xml_reference(&bytes[start..end])?;
        cursor = end + 1;
    }
    Ok(())
}

fn validate_xml_reference(reference: &[u8]) -> Result<()> {
    let allowed = matches!(reference, b"amp" | b"lt" | b"gt" | b"apos" | b"quot")
        || valid_numeric_xml_reference(reference);
    ensure!(allowed, "custom XML entities are not allowed");
    Ok(())
}

fn valid_numeric_xml_reference(reference: &[u8]) -> bool {
    let digits = if let Some(rest) = reference.strip_prefix(b"#x") {
        if !rest.iter().all(u8::is_ascii_hexdigit) {
            return false;
        }
        (rest, 16)
    } else if let Some(rest) = reference.strip_prefix(b"#") {
        if !rest.iter().all(u8::is_ascii_digit) {
            return false;
        }
        (rest, 10)
    } else {
        return false;
    };
    if digits.0.is_empty() {
        return false;
    }
    let Ok(text) = std::str::from_utf8(digits.0) else {
        return false;
    };
    let Ok(codepoint) = u32::from_str_radix(text, digits.1) else {
        return false;
    };
    char::from_u32(codepoint).is_some_and(valid_xml_character)
}

fn valid_xml_character(character: char) -> bool {
    matches!(character as u32, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn transform(operations: Vec<Operation>) -> BodyTransform {
        BodyTransform {
            operations,
            max_output_bytes: MAX_LIMIT,
            ..BodyTransform::default()
        }
    }

    #[test]
    fn xml_attribute_count_is_bounded() {
        use quick_xml::events::BytesStart;
        // More than the cap on a single element is rejected before the O(n^2)
        // duplicate check can run away.
        let mut many = BytesStart::new("e");
        for i in 0..(MAX_XML_ATTRIBUTES + 50) {
            let name = format!("a{i}");
            many.push_attribute((name.as_str(), "v"));
        }
        assert!(validate_xml_attributes(&many).is_err());
        // A modest number is accepted.
        let mut few = BytesStart::new("e");
        for i in 0..10 {
            let name = format!("a{i}");
            few.push_attribute((name.as_str(), "v"));
        }
        assert!(validate_xml_attributes(&few).is_ok());
    }

    #[test]
    fn serde_defaults_and_unknown_fields_are_strict() {
        let value: BodyTransform = serde_json::from_str("{}").unwrap();
        assert_eq!(value, BodyTransform::default());
        assert!(serde_json::from_str::<BodyTransform>(r#"{"unknown":true}"#).is_err());
        assert!(
            serde_json::from_str::<BodyTransform>(
                r#"{"operations":[{"op":"replace","from":"a","to":"b","extra":1}]}"#
            )
            .is_err()
        );
        assert_eq!(
            serde_json::from_str::<BodyTransform>(r#"{"mode":"ndjson"}"#)
                .unwrap()
                .mode,
            TransformMode::Ndjson
        );
    }

    #[test]
    fn validation_rejects_unsafe_or_oversized_configuration() {
        let value = BodyTransform {
            operations: (0..33)
                .map(|_| Operation::Replace {
                    from: "a".into(),
                    to: "b".into(),
                })
                .collect(),
            ..Default::default()
        };
        assert!(value.validate().is_err());

        let mut value = BodyTransform::default();
        value
            .set_headers
            .insert("Content-Length".into(), "3".into());
        assert!(value.validate().is_err());

        let mut value = BodyTransform::default();
        value
            .set_headers
            .insert("x-ok".into(), "bad\r\nvalue".into());
        assert!(value.validate().is_err());

        let mut value = BodyTransform {
            lua: Some("return body".into()),
            ..Default::default()
        };
        assert!(value.validate().is_err());
        value.max_buffer_bytes = MAX_LUA_BYTES;
        value.max_output_bytes = MAX_LUA_BYTES;
        assert!(value.validate().is_ok());

        let value = transform(vec![Operation::Replace {
            from: "x".into(),
            to: "y".repeat(MAX_CONFIG_BYTES + 1),
        }]);
        assert!(value.validate().is_err());
    }

    #[test]
    fn validation_rejects_mixed_structural_families_and_bad_paths() {
        let value = transform(vec![
            Operation::JsonSet {
                pointer: "/x".into(),
                value: json!(1),
            },
            Operation::XmlSetText {
                path: "/root/x".into(),
                value: "1".into(),
            },
        ]);
        assert!(value.validate().is_err());
        assert!(
            transform(vec![Operation::JsonRemove { pointer: "".into() }])
                .validate()
                .is_err()
        );
        assert!(
            transform(vec![Operation::JsonSet {
                pointer: "/bad~2".into(),
                value: json!(1)
            }])
            .validate()
            .is_err()
        );
        assert!(
            transform(vec![Operation::XmlRemove {
                path: "/root".into()
            }])
            .validate()
            .is_err()
        );
        assert!(
            transform(vec![Operation::XmlSetText {
                path: "root/x".into(),
                value: "a".into()
            }])
            .validate()
            .is_err()
        );
    }

    #[test]
    fn literal_replace_is_nonrecursive_and_bounded() {
        let value = transform(vec![Operation::Replace {
            from: "a".into(),
            to: "aa".into(),
        }]);
        assert_eq!(value.apply_native(b"aba").unwrap(), b"aabaa");

        let mut bounded = value;
        bounded.max_output_bytes = 4;
        assert!(bounded.apply_native(b"aba").is_err());
        bounded.max_buffer_bytes = 2;
        let error = bounded.apply_native(b"aba").unwrap_err();
        assert!(error.downcast_ref::<LimitExceeded>().is_some());

        let mut shrinking = transform(vec![Operation::Replace {
            from: "long".into(),
            to: "x".into(),
        }]);
        shrinking.max_buffer_bytes = 16;
        shrinking.max_output_bytes = 2;
        assert_eq!(shrinking.apply_native(b"long").unwrap(), b"x");
    }

    #[test]
    fn json_set_supports_root_objects_arrays_and_escaped_tokens() {
        let value = transform(vec![
            Operation::JsonSet {
                pointer: "/new".into(),
                value: json!(2),
            },
            Operation::JsonSet {
                pointer: "/a~1b/~0key".into(),
                value: json!(3),
            },
            Operation::JsonSet {
                pointer: "/items/1".into(),
                value: json!(9),
            },
        ]);
        let output = value
            .apply_native(br#"{"a/b":{"~key":0},"items":[1,2]}"#)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            json!({
                "a/b": {"~key": 3}, "items": [1, 9], "new": 2
            })
        );

        let root = transform(vec![Operation::JsonSet {
            pointer: "".into(),
            value: json!([1]),
        }]);
        assert_eq!(root.apply_native(b"null").unwrap(), b"[1]");
    }

    #[test]
    fn json_remove_obeys_object_and_array_bounds() {
        let value = transform(vec![
            Operation::JsonRemove {
                pointer: "/object/a".into(),
            },
            Operation::JsonRemove {
                pointer: "/array/1".into(),
            },
        ]);
        let output = value
            .apply_native(br#"{"object":{"a":1,"b":2},"array":[0,1,2]}"#)
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output).unwrap(),
            json!({
                "object": {"b": 2}, "array": [0, 2]
            })
        );
        assert!(
            transform(vec![Operation::JsonSet {
                pointer: "/array/2".into(),
                value: json!(3)
            }])
            .apply_native(br#"{"array":[1]}"#)
            .is_err()
        );
        assert!(
            transform(vec![Operation::JsonRemove {
                pointer: "/missing".into()
            }])
            .apply_native(b"{}")
            .is_err()
        );
    }

    #[test]
    fn xml_set_text_replaces_contents_and_escapes_values() {
        let value = transform(vec![Operation::XmlSetText {
            path: "/root/item".into(),
            value: "<& text".into(),
        }]);
        let output = value
            .apply_native(
                br#"<?xml version="1.0"?><root><item id="1">old<child/></item><item/></root>"#,
            )
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            r#"<?xml version="1.0"?><root><item id="1">&lt;&amp; text</item><item>&lt;&amp; text</item></root>"#
        );
    }

    #[test]
    fn xml_remove_uses_exact_qualified_absolute_paths() {
        let value = transform(vec![Operation::XmlRemove {
            path: "/p:root/p:item".into(),
        }]);
        let output = value
            .apply_native(
                br#"<p:root xmlns:p="urn:x"><p:item><p:item/></p:item><item/><p:item/></p:root>"#,
            )
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&output).unwrap(),
            r#"<p:root xmlns:p="urn:x"><item/></p:root>"#
        );
    }

    #[test]
    fn xml_rejects_dtd_custom_entities_bad_nesting_and_depth() {
        let value = transform(vec![Operation::XmlSetText {
            path: "/root/x".into(),
            value: "ok".into(),
        }]);
        assert!(
            value
                .apply_native(b"<!DOCTYPE root><root><x/></root>")
                .is_err()
        );
        assert!(value.apply_native(b"<root><x>&custom;</x></root>").is_err());
        assert!(value.apply_native(b"<root><x></root>").is_err());
        assert!(value.apply_native(&[0xff]).is_err());
        assert!(value.apply_native(b"<root><x>\x01</x></root>").is_err());
        assert!(
            value
                .apply_native(br#"<?xml encoding="iso-8859-1"?><root><x/></root>"#)
                .is_err()
        );
        assert!(
            value
                .apply_native(br#"<!--before--><?xml version="1.0"?><root><x/></root>"#)
                .is_err()
        );

        let mut deep = String::new();
        for _ in 0..65 {
            deep.push_str("<x>");
        }
        for _ in 0..65 {
            deep.push_str("</x>");
        }
        assert!(value.apply_native(deep.as_bytes()).is_err());
    }

    #[test]
    fn structural_serialization_obeys_output_limit() {
        let mut json = transform(vec![Operation::JsonSet {
            pointer: "/value".into(),
            value: json!("a long value"),
        }]);
        json.max_output_bytes = 8;
        let error = json.apply_native(b"{}").unwrap_err();
        assert!(error.downcast_ref::<LimitExceeded>().is_some());

        let mut xml = transform(vec![Operation::XmlSetText {
            path: "/root".into(),
            value: "a long value".into(),
        }]);
        xml.max_output_bytes = 8;
        let error = xml.apply_native(b"<root/>").unwrap_err();
        assert!(error.downcast_ref::<LimitExceeded>().is_some());
    }

    #[test]
    fn xml_accepts_standard_and_valid_numeric_references() {
        let value = transform(vec![Operation::XmlSetText {
            path: "/root/missing".into(),
            value: "unused".into(),
        }]);
        assert_eq!(
            value
                .apply_native(b"<root>&amp;&#9;&#x1F642;</root>")
                .unwrap(),
            b"<root>&amp;&#9;&#x1F642;</root>"
        );
        assert!(value.apply_native(b"<root>&#0;</root>").is_err());
    }

    #[test]
    fn xml_set_text_rejects_characters_xml_cannot_represent() {
        let value = transform(vec![Operation::XmlSetText {
            path: "/root/item".into(),
            value: "bad\u{1}".into(),
        }]);
        assert!(value.validate().is_err());
    }
}
