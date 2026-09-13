//! Demand-driven, bounded body transformation. There is no background producer or queue.
use crate::{
    country_observation::Observation,
    policy::{PolicyPool, WorkerCapacityUnavailable},
    proxy::{Body, BodyError},
    transform::{BodyTransform, TransformMode},
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::body::Body as _;
use hyper::{
    body::Frame,
    header::{self, HeaderMap, HeaderName, HeaderValue},
};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

pub type Budget = Arc<OwnedSemaphorePermit>;

#[derive(Debug)]
pub enum TransformError {
    TooLarge,
    Timeout,
    Invalid,
    Policy,
    PolicyBusy,
}
impl TransformError {
    pub fn status(&self, request: bool) -> u16 {
        if !request {
            return match self {
                Self::Timeout => 504,
                Self::PolicyBusy => 503,
                _ => 502,
            };
        }
        match self {
            Self::TooLarge => 413,
            Self::Timeout => 408,
            Self::Invalid => 400,
            Self::Policy => 503,
            Self::PolicyBusy => 503,
        }
    }
}
impl std::fmt::Display for TransformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "body transformation {self:?}")
    }
}
impl std::error::Error for TransformError {}

pub fn identity_encoding(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CONTENT_ENCODING)
        .iter()
        .all(|v| v.as_bytes().eq_ignore_ascii_case(b"identity"))
}

pub fn no_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim().eq_ignore_ascii_case("no-transform"))
}

/// A changed representation cannot keep the original framing, validators or signatures.
pub fn rewrite_headers(headers: &mut HeaderMap, config: &BodyTransform) {
    for name in [
        "content-length",
        "content-encoding",
        "transfer-encoding",
        "trailer",
        "etag",
        "last-modified",
        "content-md5",
        "digest",
        "content-digest",
        "repr-digest",
        "signature",
        "signature-input",
        "accept-ranges",
        "content-range",
    ] {
        headers.remove(name);
    }
    for name in &config.remove_headers {
        headers.remove(name);
    }
    for (name, value) in &config.set_headers {
        // Config validation runs before installation. Still avoid panicking on direct callers.
        if let (Ok(name), Ok(value)) = (name.parse::<HeaderName>(), value.parse::<HeaderValue>()) {
            headers.insert(name, value);
        }
    }
}

pub async fn transform(
    body: Body,
    config: Arc<BodyTransform>,
    policy: Arc<PolicyPool>,
    phase: &'static str,
    budget: Budget,
    metrics: Arc<crate::metrics::Metrics>,
) -> Result<Body, TransformError> {
    transform_with_geoip(
        body,
        config,
        policy,
        phase,
        Observation::default(),
        budget,
        metrics,
    )
    .await
}

/// Carries one request-admission GeoIP observation through every body record.
/// The observation is copied into worker IPC; no body worker opens the MMDB.
pub async fn transform_with_geoip(
    body: Body,
    config: Arc<BodyTransform>,
    policy: Arc<PolicyPool>,
    phase: &'static str,
    geoip: Observation,
    budget: Budget,
    metrics: Arc<crate::metrics::Metrics>,
) -> Result<Body, TransformError> {
    match transform_inner(body, config, policy, phase, geoip, budget).await {
        Ok(body) => Ok(body
            .map_err(move |error| {
                metrics
                    .body_transform_errors
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if phase == "response" {
                    metrics
                        .errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                error
            })
            .boxed_unsync()),
        Err(error) => {
            metrics
                .body_transform_errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Err(error)
        }
    }
}

async fn transform_inner(
    body: Body,
    config: Arc<BodyTransform>,
    policy: Arc<PolicyPool>,
    phase: &'static str,
    geoip: Observation,
    budget: Budget,
) -> Result<Body, TransformError> {
    if config.mode == TransformMode::Buffered {
        if body.size_hint().lower() > config.max_buffer_bytes as u64 {
            return Err(TransformError::TooLarge);
        }
        let deadline = Duration::from_millis(config.timeout_ms);
        let operation = async {
            let bytes = Limited::new(body, config.max_buffer_bytes)
                .collect()
                .await
                .map_err(|error| {
                    if error.is::<http_body_util::LengthLimitError>() {
                        TransformError::TooLarge
                    } else {
                        TransformError::Invalid
                    }
                })?
                .to_bytes();
            let bytes = apply(bytes.to_vec(), config, policy, phase, geoip, budget.clone()).await?;
            Ok(hold(
                Full::new(Bytes::from(bytes))
                    .map_err(|never| match never {})
                    .boxed_unsync(),
                budget,
            ))
        };
        return tokio::time::timeout(deadline, operation)
            .await
            .map_err(|_| TransformError::Timeout)?;
    }
    let reader = Reader {
        body,
        chunk: Bytes::new(),
        eof: false,
        skip_lf: false,
    };
    let state = State {
        reader,
        config,
        policy,
        phase,
        geoip,
        budget,
        first: true,
    };
    let stream = futures_util::stream::try_unfold(state, |mut state| async move {
        let record =
            tokio::time::timeout(Duration::from_millis(state.config.timeout_ms), state.next())
                .await
                .map_err(|_| TransformError::Timeout)?;
        match record? {
            Some(bytes) => Ok(Some((Frame::data(Bytes::from(bytes)), state))),
            None => Ok(None),
        }
    });
    Ok(StreamBody::new(stream)
        .map_err(|error: TransformError| BodyError::from_error(error))
        .boxed_unsync())
}

async fn apply(
    input: Vec<u8>,
    config: Arc<BodyTransform>,
    policy: Arc<PolicyPool>,
    phase: &'static str,
    geoip: Observation,
    budget: Budget,
) -> Result<Vec<u8>, TransformError> {
    let cfg = config.clone();
    // Parsing and serialization do not run on the network reactor. The permit
    // remains owned by the job even if its caller is cancelled.
    let ndjson = config.mode == TransformMode::Ndjson;
    let mut output = if config.operations.is_empty() && !ndjson {
        if input.len() > config.max_buffer_bytes
            || (config.lua.is_none() && input.len() > config.max_output_bytes)
        {
            return Err(TransformError::TooLarge);
        }
        input
    } else {
        let job_budget = budget.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
            let _budget = job_budget;
            if ndjson {
                serde_json::from_slice::<serde::de::IgnoredAny>(&input)?;
            }
            let output = cfg.apply_validated_native(&input)?;
            if ndjson && cfg.lua.is_none() {
                serde_json::from_slice::<serde::de::IgnoredAny>(&output)?;
            }
            Ok(output)
        })
        .await
        .map_err(|_| TransformError::Invalid)?
        .map_err(|error| {
            if error
                .chain()
                .any(|cause| cause.is::<crate::transform::LimitExceeded>())
            {
                TransformError::TooLarge
            } else {
                TransformError::Invalid
            }
        })?
    };
    if let Some(script) = &config.lua {
        output = policy
            .transform(crate::policy::TransformInput {
                script: script.clone(),
                body: output,
                phase: phase.to_owned(),
                geoip,
            })
            .await
            .map_err(|error| {
                if error.is::<WorkerCapacityUnavailable>() {
                    TransformError::PolicyBusy
                } else {
                    TransformError::Policy
                }
            })?;
        if ndjson {
            output = tokio::task::spawn_blocking(move || {
                let _budget = budget;
                serde_json::from_slice::<serde::de::IgnoredAny>(&output)
                    .map_err(|_| TransformError::Invalid)?;
                Ok::<_, TransformError>(output)
            })
            .await
            .map_err(|_| TransformError::Invalid)??;
        }
    }
    if output.len() > config.max_output_bytes {
        return Err(TransformError::TooLarge);
    }
    Ok(output)
}

struct State {
    reader: Reader,
    config: Arc<BodyTransform>,
    policy: Arc<PolicyPool>,
    phase: &'static str,
    geoip: Observation,
    budget: Budget,
    first: bool,
}
impl State {
    async fn next(&mut self) -> Result<Option<Vec<u8>>, TransformError> {
        if self.config.mode == TransformMode::Sse {
            return self.sse().await;
        }
        let Some((record, terminated)) = self
            .reader
            .line(self.config.max_buffer_bytes, false)
            .await?
        else {
            return Ok(None);
        };
        let mut output = apply(
            record,
            self.config.clone(),
            self.policy.clone(),
            self.phase,
            self.geoip.clone(),
            self.budget.clone(),
        )
        .await?;
        if output.iter().any(|b| matches!(b, b'\r' | b'\n')) {
            return Err(TransformError::Invalid);
        }
        if terminated {
            output.push(b'\n');
        }
        Ok(Some(output))
    }
    async fn sse(&mut self) -> Result<Option<Vec<u8>>, TransformError> {
        let mut lines = Vec::new();
        let mut used = 0usize;
        loop {
            let Some((mut line, terminated)) = self
                .reader
                .line(self.config.max_buffer_bytes.saturating_sub(used), true)
                .await?
            else {
                return if lines.is_empty() {
                    Ok(None)
                } else {
                    Err(TransformError::Invalid)
                };
            };
            if self.first {
                self.first = false;
                if line.starts_with(&[0xef, 0xbb, 0xbf]) {
                    line.drain(..3);
                }
            }
            used = used
                .checked_add(line.len() + 1)
                .ok_or(TransformError::TooLarge)?;
            if used > self.config.max_buffer_bytes {
                return Err(TransformError::TooLarge);
            }
            if !terminated {
                return Err(TransformError::Invalid);
            }
            if line.is_empty() {
                break;
            }
            std::str::from_utf8(&line).map_err(|_| TransformError::Invalid)?;
            if lines.len() >= 1024 {
                return Err(TransformError::TooLarge);
            }
            lines.push(line);
        }
        let mut data = Vec::new();
        let mut data_count = 0;
        for line in &lines {
            if let Some(value) = sse_data(line) {
                if data_count > 0 {
                    data.push(b'\n');
                }
                data.extend_from_slice(value);
                data_count += 1;
            }
        }
        let transformed = if data_count > 0 {
            Some(
                apply(
                    data,
                    self.config.clone(),
                    self.policy.clone(),
                    self.phase,
                    self.geoip.clone(),
                    self.budget.clone(),
                )
                .await?,
            )
        } else {
            None
        };
        if let Some(data) = &transformed {
            std::str::from_utf8(data).map_err(|_| TransformError::Invalid)?;
            if data.contains(&b'\r') {
                return Err(TransformError::Invalid);
            }
        }
        let mut output = Vec::new();
        let mut emitted = false;
        for line in lines {
            if sse_data(&line).is_some() {
                if !emitted {
                    for piece in transformed
                        .as_ref()
                        .expect("data exists")
                        .split(|b| *b == b'\n')
                    {
                        append_bounded(&mut output, b"data: ", self.config.max_output_bytes)?;
                        append_bounded(&mut output, piece, self.config.max_output_bytes)?;
                        append_bounded(&mut output, b"\n", self.config.max_output_bytes)?;
                    }
                    emitted = true;
                }
            } else {
                append_bounded(&mut output, &line, self.config.max_output_bytes)?;
                append_bounded(&mut output, b"\n", self.config.max_output_bytes)?;
            }
        }
        append_bounded(&mut output, b"\n", self.config.max_output_bytes)?;
        Ok(Some(output))
    }
}
fn sse_data(line: &[u8]) -> Option<&[u8]> {
    if line == b"data" {
        Some(b"")
    } else {
        line.strip_prefix(b"data:")
            .map(|value| value.strip_prefix(b" ").unwrap_or(value))
    }
}
fn append_bounded(output: &mut Vec<u8>, bytes: &[u8], limit: usize) -> Result<(), TransformError> {
    if bytes.len() > limit.saturating_sub(output.len()) {
        return Err(TransformError::TooLarge);
    }
    output.extend_from_slice(bytes);
    Ok(())
}
struct Reader {
    body: Body,
    chunk: Bytes,
    eof: bool,
    skip_lf: bool,
}
impl Reader {
    async fn line(
        &mut self,
        limit: usize,
        sse: bool,
    ) -> Result<Option<(Vec<u8>, bool)>, TransformError> {
        let mut record = Vec::new();
        let append_limit = limit.saturating_add(usize::from(!sse));
        loop {
            if !self.chunk.is_empty() {
                if self.skip_lf {
                    self.skip_lf = false;
                    if self.chunk[0] == b'\n' {
                        self.chunk = self.chunk.slice(1..);
                        continue;
                    }
                }
                if let Some(index) = self
                    .chunk
                    .iter()
                    .position(|b| *b == b'\n' || (sse && *b == b'\r'))
                {
                    append_bounded(&mut record, &self.chunk[..index], append_limit)?;
                    self.skip_lf = sse && self.chunk[index] == b'\r';
                    self.chunk = self.chunk.slice(index + 1..);
                    if !sse && record.last() == Some(&b'\r') {
                        record.pop();
                    }
                    if record.len() > limit {
                        return Err(TransformError::TooLarge);
                    }
                    return Ok(Some((record, true)));
                }
                append_bounded(&mut record, &self.chunk, append_limit)?;
                if record.len() > limit && record.last() != Some(&b'\r') {
                    return Err(TransformError::TooLarge);
                }
                self.chunk = Bytes::new();
            }
            if self.eof {
                if record.len() > limit {
                    return Err(TransformError::TooLarge);
                }
                return Ok((!record.is_empty()).then_some((record, false)));
            }
            match self.body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(bytes) = frame.into_data() {
                        self.chunk = bytes;
                    } /* transformed trailers are deliberately dropped */
                }
                Some(Err(_)) => return Err(TransformError::Invalid),
                None => self.eof = true,
            }
        }
    }
}

struct HeldBody {
    body: Body,
    _budget: Budget,
}
fn hold(body: Body, budget: Budget) -> Body {
    HeldBody {
        body,
        _budget: budget,
    }
    .boxed_unsync()
}
impl hyper::body::Body for HeldBody {
    type Data = Bytes;
    type Error = BodyError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Bytes>, BodyError>>> {
        std::pin::Pin::new(&mut self.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}
