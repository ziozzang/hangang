//! Bounded, explicit parameter deny profiles. All inspected bytes remain private.
use anyhow::{Result, ensure};
use http_body_util::{BodyExt, Full};
use hyper::body::Body as _;
use hyper::{Request, header};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
fn body_limit() -> usize {
    65536
}
fn deadline() -> u64 {
    2000
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Match {
    #[default]
    Exact,
    Prefix,
    SegmentPrefix,
    PathPrefix,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    pub name: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default, rename = "match")]
    pub matcher: Match,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default)]
    pub negate: bool,
    #[serde(default)]
    pub json_field: Option<String>,
    #[serde(default)]
    pub default_value: Option<String>,
    #[serde(default)]
    pub strip_pattern: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub path: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    #[serde(default)]
    pub include_subpaths: bool,
    #[serde(default)]
    pub methods: Vec<String>,
    pub params: Vec<Condition>,
    #[serde(default = "body_limit")]
    pub max_body_bytes: usize,
    #[serde(default = "deadline")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub multipart_spool: Option<crate::request_block_spool::Config>,
}
#[derive(Debug)]
pub struct Compiled {
    rule: Rule,
    patterns: Vec<Option<regex::Regex>>,
    directory: Option<Arc<crate::request_block_spool::Directory>>,
}
fn name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn path_value(value: &str) -> Result<String, u16> {
    if value.contains(['%', '?', '#']) {
        return Err(400);
    }
    let input = if value.starts_with('/') {
        value.to_owned()
    } else {
        format!("/{value}")
    };
    crate::resource_policy::canonical_path(&input).map_err(|_| 400u16)
}
pub fn validate(rules: &[Rule]) -> Result<()> {
    prepare(rules).map(|_| ())
}
pub fn prepare(rules: &[Rule]) -> Result<Vec<Compiled>> {
    ensure!(rules.len() <= 128, "request blocks allows at most128 rules");
    crate::path_blocks::validate(
        &rules
            .iter()
            .map(|r| crate::path_blocks::Rule {
                path: r.path.clone(),
                hosts: r.hosts.clone(),
            })
            .collect::<Vec<_>>(),
    )?;
    let mut text = 0;
    let mut output = Vec::new();
    for rule in rules {
        ensure!(
            (1..=16).contains(&rule.params.len()),
            "request blocks requires1..16 conditions"
        );
        ensure!(
            (1..=16 * 1024 * 1024).contains(&rule.max_body_bytes)
                && (1..=5000).contains(&rule.timeout_ms),
            "invalid request inspection limits"
        );
        ensure!(
            rule.methods.len() <= 8,
            "too many request inspection methods"
        );
        let mut methods = HashSet::new();
        for method in &rule.methods {
            ensure!(
                [
                    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"
                ]
                .contains(&method.as_str())
                    && methods.insert(method),
                "invalid or duplicate inspection method"
            );
            text += method.len();
        }
        let directory = if let Some(spool) = &rule.multipart_spool {
            spool.validate()?;
            text += spool.directory.len();
            Some(crate::request_block_spool::Directory::open(
                &spool.directory,
            )?)
        } else {
            None
        };
        text += rule.path.len() + rule.hosts.iter().map(String::len).sum::<usize>();
        let mut names = HashSet::new();
        let mut patterns = Vec::new();
        for condition in &rule.params {
            ensure!(
                name_valid(&condition.name) && names.insert(&condition.name),
                "invalid or duplicate parameter name"
            );
            text += condition.name.len();
            if let Some(default) = &condition.default_value {
                ensure!(
                    default.len() <= 4096
                        && !condition.values.is_empty()
                        && condition.json_field.is_none(),
                    "default parameter comparison requires scalar value matcher"
                );
                text += default.len();
            }
            if let Some(field) = &condition.json_field {
                ensure!(name_valid(field), "invalid nested JSON field");
                text += field.len();
            }
            ensure!(
                condition.values.len() <= 128,
                "too many parameter match values"
            );
            let mut values = HashSet::new();
            for value in &condition.values {
                ensure!(
                    value.len() <= 4096 && values.insert(value),
                    "invalid or duplicate parameter match value"
                );
                text += value.len();
                if condition.matcher == Match::PathPrefix {
                    ensure!(
                        path_value(value).is_ok(),
                        "path parameter matcher needs canonical path values"
                    );
                }
            }
            let pattern = if let Some(raw) = &condition.strip_pattern {
                ensure!(raw.len() <= 256, "parameter strip pattern too large");
                text += raw.len();
                Some(
                    regex::RegexBuilder::new(raw)
                        .size_limit(65536)
                        .dfa_size_limit(262144)
                        .build()?,
                )
            } else {
                None
            };
            patterns.push(pattern);
        }
        ensure!(
            !output
                .iter()
                .any(|previous: &Compiled| previous.rule == *rule),
            "duplicate request block rule"
        );
        output.push(Compiled {
            rule: rule.clone(),
            patterns,
            directory,
        });
    }
    ensure!(text <= 32768, "request block policy exceeds32KiB");
    Ok(output)
}
type Params = HashMap<String, String>;
fn canonical_name(name: &str, protected: &HashSet<&str>) -> Result<String, u16> {
    if name.len() > 256 || name.chars().any(|c| c.is_control()) {
        return Err(400);
    }
    let canonical = name
        .trim_start_matches(' ')
        .split('[')
        .next()
        .unwrap()
        .replace([' ', '.'], "_");
    if matches!(
        canonical.to_ascii_lowercase().as_str(),
        "_method" | "_http_method" | "http_method_override" | "x-http-method-override"
    ) {
        return Err(400);
    }
    let malformed_array = name.find('[').is_some_and(|i| !name[i..].contains(']'));
    if malformed_array {
        let fallback = name.trim_start_matches(' ').replace([' ', '.', '['], "_");
        if protected.contains(fallback.as_str())
            || matches!(
                fallback.to_ascii_lowercase().as_str(),
                "_method" | "_http_method" | "http_method_override" | "x-http-method-override"
            )
        {
            return Err(400);
        }
    }
    if protected.contains(canonical.as_str()) && (!name_valid(name) || canonical != name) {
        return Err(400);
    }
    Ok(canonical)
}
fn insert(
    params: &mut Params,
    name: String,
    value: String,
    protected: &HashSet<&str>,
) -> Result<(), u16> {
    let canonical = canonical_name(&name, protected)?;
    if value.chars().any(|c| c == '\0') {
        return Err(400);
    }
    if protected.contains(canonical.as_str()) {
        if value.len() > 4096 {
            return Err(413);
        }
        if params.contains_key(&canonical) {
            return Err(400);
        }
        params.insert(canonical, value);
    }
    Ok(())
}
fn decode(raw: &[u8]) -> Result<String, u16> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut index = 0;
    while index < raw.len() {
        match raw[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if index + 2 >= raw.len() {
                    return Err(400);
                }
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                decoded.push(
                    hex(raw[index + 1]).ok_or(400u16)? * 16 + hex(raw[index + 2]).ok_or(400u16)?,
                );
                index += 2;
            }
            b => decoded.push(b),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| 400u16)
}
fn form(raw: &[u8], params: &mut Params, protected: &HashSet<&str>) -> Result<(), u16> {
    if raw.is_empty() {
        return Ok(());
    }
    if raw.contains(&b';') {
        return Err(400);
    }
    for (index, pair) in raw.split(|b| *b == b'&').enumerate() {
        if index >= 256 {
            return Err(413);
        }
        if pair.is_empty() {
            return Err(400);
        }
        let separator = pair.iter().position(|b| *b == b'=');
        let (name, value) = match separator {
            Some(i) => (&pair[..i], &pair[i + 1..]),
            None => (pair, &[][..]),
        };
        insert(params, decode(name)?, decode(value)?, protected)?;
    }
    Ok(())
}
fn compare(
    condition: &Condition,
    pattern: Option<&regex::Regex>,
    value: &str,
) -> Result<bool, u16> {
    if condition.values.is_empty() {
        return Ok(true);
    }
    let stripped = pattern.map(|p| p.replace_all(value, "").into_owned());
    let value = stripped.as_deref().unwrap_or(value);
    let path = if condition.matcher == Match::PathPrefix {
        Some(path_value(value)?)
    } else {
        None
    };
    let value = path.as_deref().unwrap_or(value);
    let value = if condition.case_insensitive {
        value.to_ascii_lowercase()
    } else {
        value.to_owned()
    };
    Ok(condition.values.iter().any(|expected| {
        let expected = if condition.matcher == Match::PathPrefix {
            path_value(expected).expect("compiled path matcher")
        } else {
            expected.clone()
        };
        let expected = if condition.case_insensitive {
            expected.to_ascii_lowercase()
        } else {
            expected.clone()
        };
        match condition.matcher {
            Match::Exact => value == expected,
            Match::Prefix => value.starts_with(&expected),
            Match::SegmentPrefix | Match::PathPrefix => {
                let expected = expected.trim_end_matches('/');
                value == expected
                    || value
                        .strip_prefix(expected)
                        .is_some_and(|tail| tail.starts_with('/'))
            }
        }
    }))
}
fn validate_controls(params: &Params, nested: &HashSet<&str>) -> Result<(), u16> {
    for (name, value) in params {
        if !nested.contains(name.as_str()) && value.chars().any(char::is_control) {
            return Err(400);
        }
    }
    Ok(())
}
fn validate_parameters(compiled: &[&Compiled], params: &Params) -> Result<(), u16> {
    for runtime in compiled {
        for condition in &runtime.rule.params {
            if let Some(value) = params.get(&condition.name) {
                if let Some(field) = &condition.json_field {
                    for extracted in nested_values(value, field, Some(&condition.name))? {
                        if extracted.chars().any(char::is_control) {
                            return Err(400);
                        }
                    }
                } else if value.chars().any(char::is_control) {
                    return Err(400);
                }
            }
        }
    }
    Ok(())
}
fn blocked(compiled: &[&Compiled], params: &Params, complete: bool) -> Result<bool, u16> {
    validate_parameters(compiled, params)?;
    for runtime in compiled {
        let mut all = true;
        for (condition, pattern) in runtime.rule.params.iter().zip(&runtime.patterns) {
            let Some(value) = params.get(&condition.name).or({
                if complete {
                    condition.default_value.as_ref()
                } else {
                    None
                }
            }) else {
                if condition.negate && complete {
                    continue;
                }
                all = false;
                break;
            };
            let extracted = if let Some(field) = &condition.json_field {
                nested_values(value, field, Some(&condition.name))?
            } else {
                vec![value.clone()]
            };
            let mut any = false;
            let mut outside = false;
            for value in &extracted {
                if compare(condition, pattern.as_ref(), value)? {
                    any = true
                } else {
                    outside = true
                }
            }
            let matches = if condition.negate {
                extracted.is_empty() || outside
            } else {
                any
            };
            if !matches {
                all = false;
                break;
            }
        }
        if all {
            return Ok(true);
        }
    }
    Ok(false)
}
fn quoted(raw: &str) -> Result<String, u16> {
    let raw = raw.trim();
    if raw.starts_with('"') {
        if !raw.ends_with('"') || raw.len() < 2 {
            return Err(400);
        }
        let inner = &raw[1..raw.len() - 1];
        if inner.contains(['"', '\\', '\r', '\n']) {
            return Err(400);
        }
        Ok(inner.to_owned())
    } else {
        if raw
            .bytes()
            .any(|b| b <= 32 || b >= 127 || b == b'"' || b == b'\\')
        {
            return Err(400);
        }
        Ok(raw.to_owned())
    }
}
fn multipart(
    raw: &[u8],
    boundary: &str,
    params: &mut Params,
    protected: &HashSet<&str>,
) -> Result<(), u16> {
    let mut parser = crate::request_block_multipart::Parser::new(boundary, 65536)?;
    parser.feed(raw)?;
    for field in parser.finish()? {
        let name = canonical_name(&field.name, protected)?;
        if field.file {
            if protected.contains(name.as_str()) {
                return Err(400);
            }
        } else {
            insert(params, field.name, field.value, protected)?;
        }
    }
    Ok(())
}
struct JsonSeed<'a> {
    nodes: &'a std::cell::Cell<usize>,
    depth: usize,
}
impl<'de> serde::de::DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = serde_json::Value;
    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Self::Value, D::Error> {
        if self.depth > 16 || self.nodes.get() >= 1024 {
            return Err(serde::de::Error::custom("JSON inspection limit"));
        }
        self.nodes.set(self.nodes.get() + 1);
        struct Visitor<'a>(JsonSeed<'a>);
        impl<'de> serde::de::Visitor<'de> for Visitor<'_> {
            type Value = serde_json::Value;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(serde_json::Value::Number)
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(v.into())
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(serde_json::Value::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                self.visit_unit()
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(v) = seq.next_element_seed(JsonSeed {
                    nodes: self.0.nodes,
                    depth: self.0.depth + 1,
                })? {
                    values.push(v)
                }
                Ok(serde_json::Value::Array(values))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) || key.chars().any(char::is_control) {
                        return Err(serde::de::Error::custom("ambiguous JSON key"));
                    }
                    let value = map.next_value_seed(JsonSeed {
                        nodes: self.0.nodes,
                        depth: self.0.depth + 1,
                    })?;
                    values.insert(key, value);
                }
                Ok(serde_json::Value::Object(values))
            }
        }
        deserializer.deserialize_any(Visitor(self))
    }
}
fn parse_json(
    raw: &[u8],
    nodes: &std::cell::Cell<usize>,
    depth: usize,
) -> Result<serde_json::Value, u16> {
    use serde::de::DeserializeSeed;
    let mut parser = serde_json::Deserializer::from_slice(raw);
    let value = JsonSeed { nodes, depth }
        .deserialize(&mut parser)
        .map_err(|_| 400u16)?;
    parser.end().map_err(|_| 400u16)?;
    Ok(value)
}
fn scalar(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(v) => Some(v.clone()),
        serde_json::Value::Number(v) => Some(v.to_string()),
        serde_json::Value::Bool(v) => Some(v.to_string()),
        serde_json::Value::Null => Some(String::new()),
        _ => None,
    }
}
fn nested_values(raw: &str, field: &str, container: Option<&str>) -> Result<Vec<String>, u16> {
    if raw.len() > 4096 {
        return Err(413);
    }
    let nodes = std::cell::Cell::new(0);
    let root = parse_json(raw.as_bytes(), &nodes, 0)?;
    fn candidate(
        raw: &str,
        nodes: &std::cell::Cell<usize>,
        depth: usize,
        strict: bool,
    ) -> Result<Option<serde_json::Value>, u16> {
        use serde::de::DeserializeSeed;
        let before = nodes.get();
        let mut parser = serde_json::Deserializer::from_str(raw);
        let parsed = JsonSeed { nodes, depth }.deserialize(&mut parser);
        match parsed {
            Ok(value) => {
                parser.end().map_err(|_| 400u16)?;
                Ok(Some(value))
            }
            Err(error) if !strict && (error.is_syntax() || error.is_eof()) => {
                nodes.set(before);
                Ok(None)
            }
            Err(_) => Err(400),
        }
    }
    struct Walk<'a> {
        field: &'a str,
        container: Option<&'a str>,
        nodes: &'a std::cell::Cell<usize>,
        decoded: usize,
        values: Vec<String>,
    }
    impl Walk<'_> {
        fn visit(
            &mut self,
            value: &serde_json::Value,
            key: Option<&str>,
            depth: usize,
        ) -> Result<(), u16> {
            if depth > 16 {
                return Err(400);
            }
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        let mut protected = HashSet::from([self.field]);
                        if let Some(container) = self.container {
                            protected.insert(container);
                        }
                        canonical_name(key, &protected)?;
                        if key == self.field {
                            self.values.push(scalar(value).ok_or(400u16)?);
                        }
                        self.visit(value, Some(key), depth + 1)?;
                    }
                }
                serde_json::Value::Array(values) => {
                    for value in values {
                        self.visit(value, key, depth + 1)?;
                    }
                }
                serde_json::Value::String(raw) => {
                    let strict = self.container.is_some() && key == self.container;
                    if (strict || raw.trim_start().starts_with(['{', '[']))
                        && let Some(inner) = candidate(raw, self.nodes, depth + 1, strict)?
                    {
                        self.decoded += raw.len();
                        if self.decoded > 16384 {
                            return Err(413);
                        }
                        self.visit(&inner, None, depth + 1)?;
                    }
                }
                _ => {}
            }
            Ok(())
        }
    }
    let mut walk = Walk {
        field,
        container,
        nodes: &nodes,
        decoded: raw.len(),
        values: Vec::new(),
    };
    walk.visit(&root, container, 0)?;
    let values = walk.values;
    Ok(values)
}
fn json(
    raw: &[u8],
    params: &mut Params,
    protected: &HashSet<&str>,
    nested: &HashSet<&str>,
) -> Result<(), u16> {
    let value = parse_json(raw, &std::cell::Cell::new(0), 0)?;
    let map = value.as_object().ok_or(400u16)?;
    for (name, value) in map {
        let canonical = canonical_name(name, protected)?;
        if protected.contains(canonical.as_str()) {
            let value = if nested.contains(canonical.as_str()) {
                if let serde_json::Value::String(value) = value {
                    value.clone()
                } else {
                    serde_json::to_string(value).map_err(|_| 400u16)?
                }
            } else {
                scalar(value).ok_or(400u16)?
            };
            insert(params, name.clone(), value, protected)?;
        }
    }
    Ok(())
}
fn multipart_boundary(raw: &str) -> Result<String, u16> {
    let mut boundary = None;
    let mut seen = HashSet::new();
    for attr in raw.split(';').skip(1) {
        let (name, value) = attr.trim().split_once('=').ok_or(400u16)?;
        let name = name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err(400);
        }
        match name.as_str() {
            "boundary" => boundary = Some(quoted(value)?),
            "charset" => {
                if !quoted(value)?.eq_ignore_ascii_case("utf-8") {
                    return Err(415);
                }
            }
            _ => return Err(415),
        }
    }
    boundary.ok_or(400)
}
async fn collect_body(mut body: crate::proxy::Body, limit: usize) -> Result<bytes::Bytes, u16> {
    let mut buffered = Vec::with_capacity(limit.min(8192));
    let mut frames = 0usize;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| 400u16)?;
        if let Ok(data) = frame.into_data() {
            if data.len() > limit - buffered.len() {
                return Err(413);
            }
            buffered.extend_from_slice(&data);
        }
        frames += 1;
        if frames.is_multiple_of(64) {
            tokio::task::yield_now().await;
        }
    }
    Ok(bytes::Bytes::from(buffered))
}
struct InspectedBytes {
    bytes: bytes::Bytes,
    _permit: Arc<tokio::sync::OwnedSemaphorePermit>,
}
impl AsRef<[u8]> for InspectedBytes {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
#[derive(Clone)]
struct SpoolCache {
    file: crate::request_block_spool::WeakStaged,
    params: Arc<Params>,
    content_type: String,
}
#[derive(Clone)]
struct ScopeProof {
    indices: Vec<usize>,
    uri: hyper::Uri,
    host: Option<hyper::header::HeaderValue>,
    forwarded: Option<String>,
    policies: Vec<Rule>,
    method: String,
    permit: std::sync::Weak<tokio::sync::OwnedSemaphorePermit>,
    spool: Option<SpoolCache>,
}
/// A body transform owns a new representation even if its streaming reader
/// still retains the original spool. Keep the ingress scope, but inspect the
/// transformed bytes instead of resurrecting the original cached file.
pub(crate) fn invalidate_body_cache<B>(request: &mut Request<B>) {
    if let Some(proof) = request.extensions_mut().get_mut::<ScopeProof>() {
        proof.spool = None;
    }
}

/// Immutable ingress scope; trusted rewrites cannot move a staged body outside its policy.
#[derive(Clone)]
pub(crate) struct PolicyFence(ScopeProof);
pub(crate) fn policy_fence<B>(request: &Request<B>) -> Option<PolicyFence> {
    request
        .extensions()
        .get::<ScopeProof>()
        .cloned()
        .map(PolicyFence)
}
impl PolicyFence {
    pub(crate) fn current(&self, rules: &[Compiled]) -> bool {
        let proof = &self.0;
        let mut request = Request::new(());
        *request.uri_mut() = proof.uri.clone();
        if let Some(host) = &proof.host {
            request.headers_mut().insert(header::HOST, host.clone());
        }
        let mut remaining = proof.policies.clone();
        for compiled in rules {
            let selector = crate::path_blocks::Rule {
                path: compiled.rule.path.clone(),
                hosts: compiled.rule.hosts.clone(),
            };
            match crate::path_blocks::selector_matches(
                &selector,
                &request,
                proof.forwarded.as_deref(),
                compiled.rule.include_subpaths,
            ) {
                Ok(false) => continue,
                Ok(true) => {
                    let Some(index) = remaining.iter().position(|old| old == &compiled.rule) else {
                        return false;
                    };
                    remaining.swap_remove(index);
                }
                Err(_) => return false,
            }
        }
        remaining.is_empty()
    }
}
pub(crate) async fn check(
    rules: &[Compiled],
    mut request: Request<crate::proxy::Body>,
    forwarded: Option<&str>,
    permits: &Arc<tokio::sync::Semaphore>,
    spool_pool: &Arc<crate::request_block_spool::Pool>,
) -> Result<Request<crate::proxy::Body>, u16> {
    let mut proof = if let Some(proof) = request.extensions().get::<ScopeProof>() {
        proof.clone()
    } else {
        let mut indices = Vec::new();
        for (index, compiled) in rules.iter().enumerate() {
            let selector = crate::path_blocks::Rule {
                path: compiled.rule.path.clone(),
                hosts: compiled.rule.hosts.clone(),
            };
            if crate::path_blocks::selector_matches(
                &selector,
                &request,
                forwarded,
                compiled.rule.include_subpaths,
            )? {
                indices.push(index)
            }
        }
        ScopeProof {
            uri: request.uri().clone(),
            host: request.headers().get(header::HOST).cloned(),
            forwarded: forwarded.map(str::to_owned),
            policies: indices.iter().map(|&i| rules[i].rule.clone()).collect(),
            indices,
            method: request.method().as_str().to_owned(),
            permit: std::sync::Weak::new(),
            spool: None,
        }
    };
    request.extensions_mut().insert(proof.clone());
    let scoped = proof
        .indices
        .iter()
        .map(|&i| rules.get(i).ok_or(503u16))
        .collect::<Result<Vec<_>, u16>>()?;
    if scoped.is_empty() {
        return Ok(request);
    }
    for name in [
        "x-http-method-override",
        "x-method-override",
        "x-http-method",
    ] {
        if request.headers().contains_key(name) {
            return Err(400);
        }
    }
    if !request.body().is_end_stream() {
        for value in request.headers().get_all(header::CONNECTION).iter() {
            let value = value.to_str().map_err(|_| 400u16)?;
            if value.split(',').any(|name| {
                name.trim().eq_ignore_ascii_case("content-type")
                    || name.trim().eq_ignore_ascii_case("content-encoding")
            }) {
                return Err(400);
            }
        }
    }
    let started = std::time::Instant::now();

    let protected: HashSet<&str> = scoped
        .iter()
        .flat_map(|r| {
            r.rule
                .params
                .iter()
                .flat_map(|p| std::iter::once(p.name.as_str()).chain(p.json_field.as_deref()))
        })
        .collect();
    let nested: HashSet<&str> = scoped
        .iter()
        .flat_map(|r| {
            r.rule
                .params
                .iter()
                .filter(|p| p.json_field.is_some())
                .map(|p| p.name.as_str())
        })
        .collect();
    let mut params = Params::new();
    let query = request.uri().query().unwrap_or("");
    if query.len() > 16384 {
        return Err(413);
    }
    form(query.as_bytes(), &mut params, &protected)?;
    let selected: Vec<_> = scoped
        .iter()
        .copied()
        .filter(|r| {
            r.rule.methods.is_empty()
                || r.rule
                    .methods
                    .iter()
                    .any(|m| m.eq_ignore_ascii_case(&proof.method))
        })
        .collect();
    validate_controls(&params, &nested)?;
    if blocked(&selected, &params, false)? {
        return Err(403);
    }
    if request.body().is_end_stream() {
        if blocked(&selected, &params, true)? {
            return Err(403);
        }
        return Ok(request);
    }
    if let Some(cache) = &proof.spool {
        let current = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        if current != Some(cache.content_type.as_str())
            || request
                .headers()
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(403);
        }
        if let Some(file) = cache.file.upgrade() {
            for (name, value) in cache.params.iter() {
                insert(&mut params, name.clone(), value.clone(), &protected)?;
            }
            validate_controls(&params, &nested)?;
            if blocked(&selected, &params, true)? {
                return Err(403);
            }
            let (parts, _body) = request.into_parts();
            return Ok(Request::from_parts(parts, file.body()));
        }
    }
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let memory_limit = scoped.iter().map(|r| r.rule.max_body_bytes).min().unwrap();
    let multipart_media = content_type.as_deref().is_some_and(|v| {
        v.split(';')
            .next()
            .unwrap()
            .trim()
            .eq_ignore_ascii_case("multipart/form-data")
    });
    if multipart_media
        && declared.is_none_or(|size| size > memory_limit as u64)
        && scoped.iter().all(|r| r.rule.multipart_spool.is_some())
    {
        if request
            .headers()
            .get_all(header::CONTENT_TYPE)
            .iter()
            .count()
            != 1
            || request
                .headers()
                .get_all(header::CONTENT_ENCODING)
                .iter()
                .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
        {
            return Err(415);
        }
        let raw_type = content_type.unwrap();
        let boundary = multipart_boundary(&raw_type)?;
        let mut config = scoped[0].rule.multipart_spool.clone().unwrap();
        for runtime in &scoped {
            let limits = runtime.rule.multipart_spool.as_ref().unwrap();
            if limits.directory != config.directory {
                return Err(503);
            }
            config.max_body_bytes = config.max_body_bytes.min(limits.max_body_bytes);
            config.timeout_ms = config.timeout_ms.min(limits.timeout_ms);
            config.idle_timeout_ms = config.idle_timeout_ms.min(limits.idle_timeout_ms);
            config.max_field_bytes = config.max_field_bytes.min(limits.max_field_bytes);
        }
        let directory = scoped[0].directory.clone().ok_or(503u16)?;
        let (mut parts, body) = request.into_parts();
        let (file, fields) = crate::request_block_spool::collect(
            body,
            &boundary,
            &config,
            directory,
            spool_pool.clone(),
            declared,
        )
        .await?;
        let mut body_params = Params::new();
        for field in fields {
            let name = canonical_name(&field.name, &protected)?;
            if field.file {
                if protected.contains(name.as_str()) {
                    return Err(400);
                }
            } else {
                insert(&mut body_params, field.name, field.value, &protected)?;
            }
        }
        for (name, value) in &body_params {
            insert(&mut params, name.clone(), value.clone(), &protected)?;
        }
        validate_controls(&params, &nested)?;
        if blocked(&selected, &params, true)? {
            return Err(403);
        }
        proof.spool = Some(SpoolCache {
            file: file.downgrade(),
            params: Arc::new(body_params),
            content_type: raw_type,
        });
        parts.extensions.insert(proof);
        return Ok(Request::from_parts(parts, file.body()));
    }
    let permit = if let Some(permit) = proof.permit.upgrade() {
        permit
    } else {
        Arc::new(permits.clone().try_acquire_owned().map_err(|_| 503u16)?)
    };
    let limit = scoped.iter().map(|r| r.rule.max_body_bytes).min().unwrap();
    let timeout = scoped.iter().map(|r| r.rule.timeout_ms).min().unwrap();
    if request
        .headers()
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .any(|v| !v.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(415);
    }
    let mut types = request.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = types
        .next()
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    if types.next().is_some() {
        return Err(400);
    }
    let (mut parts, body) = request.into_parts();
    let remaining = Duration::from_millis(timeout)
        .checked_sub(started.elapsed())
        .ok_or(408u16)?;
    let bytes = tokio::time::timeout(remaining, collect_body(body, limit))
        .await
        .map_err(|_| 408u16)??;
    if !bytes.is_empty() {
        let content_type = content_type.ok_or(415u16)?;
        let mut fields = content_type.split(';');
        let media = fields.next().unwrap().trim().to_ascii_lowercase();
        let mut boundary = None;
        let mut attrs = HashSet::new();
        for attr in fields {
            let (name, value) = attr.trim().split_once('=').ok_or(400u16)?;
            let name = name.to_ascii_lowercase();
            if !attrs.insert(name.clone()) {
                return Err(400);
            }
            match name.as_str() {
                "boundary" => boundary = Some(quoted(value)?),
                "charset" => {
                    if !quoted(value)?.eq_ignore_ascii_case("utf-8") {
                        return Err(415);
                    }
                }
                _ => return Err(415),
            }
        }
        match media.as_str() {
            "application/x-www-form-urlencoded" => form(&bytes, &mut params, &protected)?,
            "multipart/form-data" => {
                multipart(&bytes, &boundary.ok_or(400u16)?, &mut params, &protected)?
            }
            "application/json" => json(&bytes, &mut params, &protected, &nested)?,
            _ => return Err(415),
        }
    }
    validate_controls(&params, &nested)?;
    if started.elapsed() >= Duration::from_millis(timeout) {
        return Err(408);
    }
    let denied = blocked(&selected, &params, true)?;
    if started.elapsed() >= Duration::from_millis(timeout) {
        return Err(408);
    }
    if denied {
        return Err(403);
    }
    proof.permit = Arc::downgrade(&permit);
    parts.extensions.insert(proof);
    request = Request::from_parts(
        parts,
        Full::new(bytes::Bytes::from_owner(InspectedBytes {
            bytes,
            _permit: permit,
        }))
        .map_err(|e| match e {})
        .boxed_unsync(),
    );
    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rules(condition: serde_json::Value) -> Vec<Compiled> {
        prepare(&[serde_json::from_value(
            serde_json::json!({"path":"/control","hosts":["app.test"],"params":[condition]}),
        )
        .unwrap()])
        .unwrap()
    }
    #[test]
    fn php_aliases_duplicates_and_unrelated_names_have_distinct_boundaries() {
        let protected = HashSet::from(["action", "mode", "rest_route"]);
        for raw in [
            "%20action=x",
            "+action=x",
            "rest.route=x",
            "rest%5Broute=x",
            "action%00tail=x",
            "mode[user]=x",
            "action=x&action=y",
            "_method=DELETE",
        ] {
            assert!(
                form(raw.as_bytes(), &mut Params::new(), &protected).is_err(),
                "{raw}"
            );
        }
        let mut params = Params::new();
        form(
            b"billing[address]=a&billing[address]=b&mode=read",
            &mut params,
            &protected,
        )
        .unwrap();
        assert_eq!(params["mode"], "read");
        assert_eq!(params.len(), 1);
        assert!(
            form(b"mode=read", &mut params, &protected).is_err(),
            "cross-source duplicate ignored"
        );
    }
    #[test]
    fn matches_are_conjunctive_normalized_and_negation_defers_missing_body() {
        let rules = rules(
            serde_json::json!({"name":"mode","values":["read"],"negate":true,"strip_pattern":"[^a-z]"}),
        );
        let refs = rules.iter().collect::<Vec<_>>();
        assert!(!blocked(&refs, &Params::new(), false).unwrap());
        assert!(blocked(&refs, &Params::new(), true).unwrap());
        assert!(
            !blocked(
                &refs,
                &Params::from([("mode".into(), "r!e!ad".into())]),
                true
            )
            .unwrap()
        );
        assert!(
            blocked(
                &refs,
                &Params::from([("mode".into(), "write".into())]),
                true
            )
            .unwrap()
        );
        let rules = super::tests::rules(
            serde_json::json!({"name":"rest_route","values":["/wp/v2/users"],"match":"path_prefix"}),
        );
        let refs = rules.iter().collect::<Vec<_>>();
        for value in ["wp/v2/users", "/wp/v2/users/", "/wp/v2/users/1"] {
            assert!(
                blocked(
                    &refs,
                    &Params::from([("rest_route".into(), value.into())]),
                    true
                )
                .unwrap()
            );
        }
        assert!(
            !blocked(
                &refs,
                &Params::from([("rest_route".into(), "/wp/v2/users-other".into())]),
                true
            )
            .unwrap()
        );
        assert!(
            blocked(
                &refs,
                &Params::from([("rest_route".into(), "/%2fwp/v2/users".into())]),
                true
            )
            .is_err()
        );
    }
    #[test]
    fn scalar_missing_defaults_only_apply_after_full_inspection() {
        let rules = rules(
            serde_json::json!({"name":"mode","values":["","read"],"negate":true,"default_value":""}),
        );
        let refs = rules.iter().collect::<Vec<_>>();
        assert!(!blocked(&refs, &Params::new(), false).unwrap());
        assert!(!blocked(&refs, &Params::new(), true).unwrap());
        assert!(
            blocked(
                &refs,
                &Params::from([("mode".into(), "write".into())]),
                true
            )
            .unwrap()
        );
        let invalid: Rule = serde_json::from_value(
            serde_json::json!({"path":"/control","params":[{"name":"mode","default_value":""}]}),
        )
        .unwrap();
        assert!(prepare(&[invalid]).is_err());
    }
    #[test]
    fn nested_json_rejects_duplicates_and_decodes_bounded_nested_strings() {
        let rules = rules(
            serde_json::json!({"name":"compound","json_field":"api","values":["blocked.api"]}),
        );
        let refs = rules.iter().collect::<Vec<_>>();
        let nested=serde_json::json!([{"api":"allowed.api","params":{"compound":"[{\"api\":\"blocked.api\"}]"}}]).to_string();
        assert!(blocked(&refs, &Params::from([("compound".into(), nested)]), true).unwrap());
        for value in [
            "[{\"api\":\"blocked.api\",\"api\":\"allowed.api\"}]",
            "[{\" api\":\"blocked.api\"}]",
            "not-json",
        ] {
            assert!(
                blocked(
                    &refs,
                    &Params::from([("compound".into(), value.into())]),
                    true
                )
                .is_err()
            );
        }
        let too_many = serde_json::json!(vec![0; 1025]).to_string();
        assert!(nested_values(&too_many, "api", None).is_err());
    }
    #[test]
    fn bracketed_metadata_is_plain_text_but_named_nested_containers_stay_strict() {
        let rules =
            rules(serde_json::json!({"name":"batch","json_field":"api","values":["blocked.api"]}));
        let refs = rules.iter().collect::<Vec<_>>();
        let allowed=serde_json::json!([{"api":"allowed.api","params":{"label":"[draft].zip","name":"{example}.txt"}}]).to_string();
        assert!(!blocked(&refs, &Params::from([("batch".into(), allowed)]), true).unwrap());
        for inner in [
            "not-json",
            "/*comment*/[{\"api\":\"blocked.api\"}]",
            "{\"api\":\"blocked.api\",\"api\":\"allowed.api\"}",
        ] {
            let raw =
                serde_json::json!([{"api":"allowed.api","params":{"batch":inner}}]).to_string();
            assert!(blocked(&refs, &Params::from([("batch".into(), raw)]), true).is_err());
        }
    }

    #[test]
    fn multipart_controls_after_files_and_duplicate_sources_cannot_hide() {
        let bytes=b"--owned\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"file.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n\x00\xfffiledata\r\n--owned\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\nwrite\r\n--owned--\r\n";
        let protected = HashSet::from(["action"]);
        let mut params = Params::new();
        multipart(bytes, "owned", &mut params, &protected).unwrap();
        assert_eq!(params["action"], "write");
        assert!(multipart(bytes, "owned", &mut params, &protected).is_err());
    }
    #[tokio::test]
    async fn shared_capacity_and_body_caps_are_fail_closed() {
        let rules = rules(serde_json::json!({"name":"action","values":["write"]}));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = permits.clone().acquire_owned().await.unwrap();
        let empty = Request::builder()
            .uri("/control?action=read")
            .header("host", "app.test")
            .body(
                Full::new(bytes::Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        assert!(
            check(
                &rules,
                empty,
                None,
                &permits,
                &Arc::new(crate::request_block_spool::Pool::new())
            )
            .await
            .is_ok(),
            "empty asset consumed upload capacity"
        );
        let blocked_query = Request::builder()
            .uri("/control?action=write")
            .header("host", "app.test")
            .body(
                Full::new(bytes::Bytes::new())
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        assert_eq!(
            check(
                &rules,
                blocked_query,
                None,
                &permits,
                &Arc::new(crate::request_block_spool::Pool::new())
            )
            .await
            .unwrap_err(),
            403
        );
        let request = Request::builder()
            .uri("/control?action=read")
            .header("host", "app.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                Full::new(bytes::Bytes::from_static(b"ignored=value"))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        assert_eq!(
            check(
                &rules,
                request,
                None,
                &permits,
                &Arc::new(crate::request_block_spool::Pool::new())
            )
            .await
            .unwrap_err(),
            503
        );
        drop(permit);
        let request = Request::builder()
            .uri("/control")
            .header("host", "app.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                Full::new(bytes::Bytes::from(vec![b'x'; 65537]))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        assert_eq!(
            check(
                &rules,
                request,
                None,
                &permits,
                &Arc::new(crate::request_block_spool::Pool::new())
            )
            .await
            .unwrap_err(),
            413
        );
    }
    #[tokio::test]
    async fn inspected_memory_keeps_capacity_until_all_network_byte_references_drop() {
        let rules = rules(serde_json::json!({"name":"action","values":["write"]}));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let request = Request::builder()
            .uri("/control")
            .header("host", "app.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                Full::new(bytes::Bytes::from_static(b"action=read"))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let admitted = check(
            &rules,
            request,
            None,
            &permits,
            &Arc::new(crate::request_block_spool::Pool::new()),
        )
        .await
        .unwrap();
        let bytes = admitted.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(permits.available_permits(), 0);
        let writer_slice = bytes.slice(..1);
        drop(bytes);
        assert_eq!(permits.available_permits(), 0);
        drop(writer_slice);
        assert_eq!(permits.available_permits(), 1);
    }
    #[tokio::test]
    async fn fragmented_bodies_keep_one_bounded_buffer_and_preserve_bytes() {
        let body =
            http_body_util::StreamBody::new(futures_util::stream::iter((0..10000).map(|_| {
                Ok::<_, crate::proxy::BodyError>(hyper::body::Frame::data(
                    bytes::Bytes::from_static(b"x"),
                ))
            })))
            .boxed_unsync();
        assert_eq!(
            collect_body(body, 10000).await.unwrap(),
            bytes::Bytes::from(vec![b'x'; 10000])
        );
        let body =
            http_body_util::StreamBody::new(futures_util::stream::iter((0..10001).map(|_| {
                Ok::<_, crate::proxy::BodyError>(hyper::body::Frame::data(
                    bytes::Bytes::from_static(b"x"),
                ))
            })))
            .boxed_unsync();
        assert_eq!(collect_body(body, 10000).await.unwrap_err(), 413);
    }
    #[tokio::test]
    async fn final_inspection_reuses_capacity_and_keeps_original_scope_after_rewrites() {
        let rules = rules(serde_json::json!({"name":"action","values":["write"]}));
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let request = Request::builder()
            .uri("/control")
            .header("host", "app.test")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(
                Full::new(bytes::Bytes::from_static(b"action=read"))
                    .map_err(|e| match e {})
                    .boxed_unsync(),
            )
            .unwrap();
        let admitted = check(
            &rules,
            request,
            None,
            &permits,
            &Arc::new(crate::request_block_spool::Pool::new()),
        )
        .await
        .unwrap();
        assert_eq!(permits.available_permits(), 0);
        let fence = policy_fence(&admitted).unwrap();
        assert!(fence.current(&rules));
        let mut unrelated = rules.iter().map(|r| r.rule.clone()).collect::<Vec<_>>();
        let mut other = unrelated[0].clone();
        other.hosts = vec!["other.test".into()];
        other.max_body_bytes += 1;
        unrelated.push(other);
        assert!(fence.current(&prepare(&unrelated).unwrap()));
        unrelated[0].max_body_bytes += 1;
        assert!(!fence.current(&prepare(&unrelated).unwrap()));
        assert!(!fence.current(&[]));
        let mut admitted = check(
            &rules,
            admitted,
            None,
            &permits,
            &Arc::new(crate::request_block_spool::Pool::new()),
        )
        .await
        .unwrap();
        assert_eq!(
            permits.available_permits(),
            0,
            "recheck exhausted its own inspector slot"
        );
        admitted.headers_mut().insert(
            "host",
            hyper::header::HeaderValue::from_static("other.test"),
        );
        *admitted.uri_mut() = "/outside?action=write".parse().unwrap();
        assert!(
            fence.current(&rules),
            "trusted rewrites changed policy fence scope"
        );
        assert_eq!(
            check(
                &rules,
                admitted,
                None,
                &permits,
                &Arc::new(crate::request_block_spool::Pool::new())
            )
            .await
            .unwrap_err(),
            403
        );
        assert_eq!(permits.available_permits(), 1);
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn transformed_stream_rechecks_controls_and_preserves_new_bytes_while_old_spool_is_owned()
    {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let config: Rule = serde_json::from_value(serde_json::json!({
            "path":"/control", "hosts":["app.test"],
            "params":[{"name":"action", "values":["write"]}],
            "multipart_spool": {"directory":directory.path(), "max_body_bytes":1048576}
        }))
        .unwrap();
        let rules = prepare(&[config]).unwrap();
        let permits = Arc::new(tokio::sync::Semaphore::new(1));
        let pool = Arc::new(crate::request_block_spool::Pool::new());
        let message = |value: &str| {
            bytes::Bytes::from(format!(
                "--owned\r\nContent-Disposition: form-data; name=\"action\"\r\n\r\n{value}\r\n--owned--\r\n"
            ))
        };
        for value in ["write", "new-read"] {
            let initial = Request::builder()
                .uri("/control")
                .header("host", "app.test")
                .header("content-type", "multipart/form-data; boundary=owned")
                .body(
                    Full::new(message("read"))
                        .map_err(|e| match e {})
                        .boxed_unsync(),
                )
                .unwrap();
            let admitted = check(&rules, initial, None, &permits, &pool).await.unwrap();
            let (parts, original_body) = admitted.into_parts();
            let transformed_bytes = message(value);
            let expected = transformed_bytes.clone();
            let transformed_body =
                http_body_util::StreamBody::new(futures_util::stream::once(async move {
                    // A streaming transform retains the old representation until
                    // polled, so WeakStaged still upgrades at final inspection.
                    let _original_owner = original_body;
                    Ok::<_, crate::proxy::BodyError>(hyper::body::Frame::data(transformed_bytes))
                }))
                .boxed_unsync();
            let mut transformed = Request::from_parts(parts, transformed_body);
            invalidate_body_cache(&mut transformed);
            let result = check(&rules, transformed, None, &permits, &pool).await;
            if value == "write" {
                assert_eq!(
                    result.unwrap_err(),
                    403,
                    "stale controls hid the transformed command"
                );
            } else {
                assert_eq!(
                    result
                        .unwrap()
                        .into_body()
                        .collect()
                        .await
                        .unwrap()
                        .to_bytes(),
                    expected,
                    "inspection resurrected the original representation"
                );
            }
        }
    }
}
