//! Bounded final entity preparation, before native request receipt issuance.
//! Neither the digest nor this buffer grants authentication or dispatch rights.
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, header};
use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    Limits,
    Capacity,
    Allocation,
    Length,
    TooLarge,
    Deadline,
    Body,
    Trailers,
    Target,
}

/// Compile once from the owning route; reuse across requests without string copies.
pub struct Scope {
    service: String,
    audience: String,
}
impl Scope {
    pub fn new(service: String, audience: String) -> Result<Arc<Self>, Refused> {
        if [&service, &audience].iter().any(|value| {
            value.is_empty()
                || value.len() > 128
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
        }) {
            return Err(Refused::Target);
        }
        Ok(Arc::new(Self { service, audience }))
    }
}

/// Immutable bound bytes; no Clone/serde or mutation before receipt issuance.
/// Admission is retained until the dispatch body is dropped or consumed.
pub struct Prepared {
    request: Request<Bytes>,
    scope: Arc<Scope>,
    digest: [u8; 32],
    admission: OwnedSemaphorePermit,
}
impl Prepared {
    pub fn request(&self) -> &Request<Bytes> {
        &self.request
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn service_scope(&self) -> crate::projection_receipt::ServiceScope<'_> {
        crate::projection_receipt::ServiceScope {
            service: &self.scope.service,
            audience: &self.scope.audience,
            request_sha256: self.digest,
        }
    }
    pub(crate) fn belongs_to(&self, scope: &Arc<Scope>) -> bool {
        Arc::ptr_eq(&self.scope, scope)
    }
    /// The caller must finish native authorization and final owner checks first.
    pub fn into_dispatch(self) -> Request<crate::proxy::Body> {
        let (mut parts, bytes) = self.request.into_parts();
        parts.headers.remove(header::TRANSFER_ENCODING);
        parts
            .headers
            .insert(header::CONTENT_LENGTH, bytes.len().into());
        Request::from_parts(
            parts,
            AdmittedBody {
                body: Full::new(bytes),
                admission: Some(self.admission),
            }
            .boxed_unsync(),
        )
    }
}
struct AdmittedBody {
    body: Full<Bytes>,
    admission: Option<OwnedSemaphorePermit>,
}
impl hyper::body::Body for AdmittedBody {
    type Data = Bytes;
    type Error = crate::proxy::BodyError;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::task::Poll;
        match std::pin::Pin::new(&mut self.body).poll_frame(cx) {
            Poll::Ready(None) => {
                self.admission.take();
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(never))) => match never {},
            Poll::Pending => Poll::Pending,
        }
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
}

fn reserve_entity(buffer: &mut Vec<u8>, additional: usize, limit: usize) -> Result<(), Refused> {
    let needed = buffer
        .len()
        .checked_add(additional)
        .ok_or(Refused::TooLarge)?;
    if needed > limit {
        return Err(Refused::TooLarge);
    }
    if needed > buffer.capacity() {
        let capacity = needed.next_power_of_two().min(limit);
        buffer
            .try_reserve_exact(capacity - buffer.len())
            .map_err(|_| Refused::Allocation)?;
    }
    Ok(())
}

/// The owner supplies global admission and a per-request budget. This phase
/// reads the complete transformed entity before any upstream effects. Inputs
/// with trailers require a separate binding contract and refuse here.
pub async fn prepare(
    request: Request<crate::proxy::Body>,
    service: &str,
    audience: &str,
    admission: Arc<Semaphore>,
    maximum_bytes: usize,
    deadline: Duration,
) -> Result<Prepared, Refused> {
    prepare_scoped(
        request,
        Scope::new(service.into(), audience.into())?,
        admission,
        maximum_bytes,
        deadline,
    )
    .await
}

/// Hot path for an already compiled immutable route scope.
pub async fn prepare_scoped(
    request: Request<crate::proxy::Body>,
    scope: Arc<Scope>,
    admission: Arc<Semaphore>,
    maximum_bytes: usize,
    deadline: Duration,
) -> Result<Prepared, Refused> {
    use hyper::body::Body as _;
    if maximum_bytes == 0
        || maximum_bytes > 16 * 1024 * 1024
        || deadline.is_zero()
        || deadline > Duration::from_secs(5)
    {
        return Err(Refused::Limits);
    }
    if request.headers().contains_key(header::TRAILER) {
        return Err(Refused::Trailers);
    }
    let mut lengths = request.headers().get_all(header::CONTENT_LENGTH).iter();
    let declared = if let Some(value) = lengths.next() {
        let text = value.to_str().map_err(|_| Refused::Length)?;
        if lengths.next().is_some() || text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Refused::Length);
        }
        let length = text.parse::<usize>().map_err(|_| Refused::Length)?;
        if length > maximum_bytes {
            return Err(Refused::TooLarge);
        }
        Some(length)
    } else {
        None
    };
    if request.body().size_hint().lower() > maximum_bytes as u64 {
        return Err(Refused::TooLarge);
    }
    let permit = admission
        .try_acquire_owned()
        .map_err(|_| Refused::Capacity)?;
    let (parts, body) = request.into_parts();
    let bytes = tokio::time::timeout(deadline, async {
        let mut body = Limited::new(body, maximum_bytes);
        let mut first = Bytes::new();
        let mut merged: Option<Vec<u8>> = None;
        let mut frames = 0;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|error| {
                if error.is::<http_body_util::LengthLimitError>() {
                    Refused::TooLarge
                } else {
                    Refused::Body
                }
            })?;
            if frame.is_trailers() {
                return Err(Refused::Trailers);
            }
            let data = frame.into_data().map_err(|_| Refused::Body)?;
            if !data.is_empty() {
                if let Some(bytes) = &mut merged {
                    reserve_entity(bytes, data.len(), maximum_bytes)?;
                    bytes.extend_from_slice(&data);
                } else if first.is_empty() {
                    first = data;
                } else {
                    // Retain single-frame allocations; grow fragmented entities
                    // geometrically without reserving the whole configured cap.
                    let mut bytes = Vec::new();
                    reserve_entity(
                        &mut bytes,
                        first
                            .len()
                            .checked_add(data.len())
                            .ok_or(Refused::TooLarge)?,
                        maximum_bytes,
                    )?;
                    bytes.extend_from_slice(&first);
                    bytes.extend_from_slice(&data);
                    first = Bytes::new();
                    merged = Some(bytes);
                }
            }
            frames += 1;
            if frames == 64 {
                frames = 0;
                // An always-ready stream of empty frames must not starve the
                // deadline or cancellation by never returning Pending.
                tokio::task::yield_now().await;
            }
        }
        Ok(merged.map_or(first, Bytes::from))
    })
    .await
    .map_err(|_| Refused::Deadline)??;
    if declared.is_some_and(|length| length != bytes.len()) {
        return Err(Refused::Length);
    }
    let request = Request::from_parts(parts, bytes);
    let digest =
        crate::projection_binding::digest_upstream(&scope.service, &scope.audience, &request)
            .map_err(|_| Refused::Target)?;
    Ok(Prepared {
        request,
        scope,
        digest,
        admission: permit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::body::Frame;
    use std::collections::VecDeque;
    struct Frames {
        frames: VecDeque<Result<Frame<Bytes>, crate::proxy::BodyError>>,
        pending: bool,
        polls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl hyper::body::Body for Frames {
        type Data = Bytes;
        type Error = crate::proxy::BodyError;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            self.polls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if self.pending {
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(self.frames.pop_front())
            }
        }
    }
    fn input(
        frames: Vec<Result<Frame<Bytes>, crate::proxy::BodyError>>,
        pending: bool,
    ) -> (
        Request<crate::proxy::Body>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let polls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let body = Frames {
            frames: frames.into(),
            pending,
            polls: polls.clone(),
        }
        .boxed_unsync();
        (
            Request::builder()
                .method("POST")
                .uri("https://orders.example.test/api/orders?x=%2F")
                .body(body)
                .unwrap(),
            polls,
        )
    }
    async fn buffered(
        request: Request<crate::proxy::Body>,
        admission: Arc<Semaphore>,
        cap: usize,
    ) -> Result<Prepared, Refused> {
        prepare(
            request,
            "orders",
            "orders-api",
            admission,
            cap,
            Duration::from_millis(10),
        )
        .await
    }
    #[tokio::test]
    async fn unknown_length_frames_bind_and_forward_identical_bytes_with_retained_admission() {
        let admission = Arc::new(Semaphore::new(1));
        let (mut request, _) = input(
            vec![
                Ok(Frame::data(Bytes::from_static(b"transformed "))),
                Ok(Frame::data(Bytes::from_static(b"entity"))),
            ],
            false,
        );
        request
            .headers_mut()
            .insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        let prepared = buffered(request, admission.clone(), 18).await.unwrap();
        assert_eq!(prepared.request().body(), b"transformed entity".as_slice());
        assert_eq!(
            prepared.digest(),
            crate::projection_binding::digest_upstream("orders", "orders-api", prepared.request())
                .unwrap()
        );
        assert_eq!(admission.available_permits(), 0);
        let outgoing = prepared.into_dispatch();
        assert_eq!(admission.available_permits(), 0);
        assert_eq!(outgoing.headers()[header::CONTENT_LENGTH], "18");
        assert!(!outgoing.headers().contains_key(header::TRANSFER_ENCODING));
        assert_eq!(
            outgoing.into_body().collect().await.unwrap().to_bytes(),
            "transformed entity"
        );
        assert_eq!(admission.available_permits(), 1);
    }
    #[tokio::test]
    async fn oversized_declared_and_unknown_entities_refuse_and_release_capacity() {
        let admission = Arc::new(Semaphore::new(1));
        let (mut request, polls) = input(vec![], true);
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "9".parse().unwrap());
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::TooLarge)
        ));
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
        let (request, _) = input(
            vec![
                Ok(Frame::data(Bytes::from_static(b"1234"))),
                Ok(Frame::data(Bytes::from_static(b"56789"))),
            ],
            false,
        );
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::TooLarge)
        ));
        assert_eq!(admission.available_permits(), 1);
    }
    #[tokio::test]
    async fn trailers_length_mismatch_body_errors_and_stalls_refuse_without_leaking_capacity() {
        let admission = Arc::new(Semaphore::new(1));
        let (request, _) = input(vec![Ok(Frame::trailers(hyper::HeaderMap::new()))], false);
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Trailers)
        ));
        let (mut request, _) = input(vec![Ok(Frame::data(Bytes::from_static(b"x")))], false);
        request
            .headers_mut()
            .insert(header::CONTENT_LENGTH, "2".parse().unwrap());
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Length)
        ));
        let (request, _) = input(
            vec![Err(crate::proxy::BodyError::from_error(
                std::io::Error::other("owned error"),
            ))],
            false,
        );
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Body)
        ));
        let (request, _) = input(vec![], true);
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Deadline)
        ));
        assert_eq!(admission.available_permits(), 1);
    }
    #[tokio::test]
    async fn exhausted_capacity_and_invalid_limits_refuse_before_reading() {
        let admission = Arc::new(Semaphore::new(0));
        let (request, polls) = input(vec![], true);
        assert!(matches!(
            buffered(request, admission, 8).await,
            Err(Refused::Capacity)
        ));
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
        let (request, polls) = input(vec![], true);
        assert!(matches!(
            buffered(request, Arc::new(Semaphore::new(1)), 0).await,
            Err(Refused::Limits)
        ));
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
    #[tokio::test]
    async fn continuous_empty_frames_cannot_starve_deadline_or_retain_admission() {
        struct EmptyForever;
        impl hyper::body::Body for EmptyForever {
            type Data = Bytes;
            type Error = crate::proxy::BodyError;
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
                std::task::Poll::Ready(Some(Ok(Frame::data(Bytes::new()))))
            }
        }
        let admission = Arc::new(Semaphore::new(1));
        let request = Request::builder()
            .uri("https://orders.example.test/orders")
            .body(EmptyForever.boxed_unsync())
            .unwrap();
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Deadline)
        ));
        assert_eq!(admission.available_permits(), 1);
    }
    #[tokio::test]
    async fn owner_cancellation_releases_pending_entity_and_admission() {
        let admission = Arc::new(Semaphore::new(1));
        let (request, polls) = input(vec![], true);
        let task = tokio::spawn(prepare(
            request,
            "orders",
            "orders-api",
            admission.clone(),
            8,
            Duration::from_secs(5),
        ));
        tokio::time::timeout(Duration::from_secs(1), async {
            while polls.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(admission.available_permits(), 0);
        task.abort();
        assert!(task.await.is_err_and(|error| error.is_cancelled()));
        assert_eq!(admission.available_permits(), 1);
    }
    #[tokio::test]
    async fn one_frame_entity_retains_original_allocation() {
        let bytes = Bytes::from(vec![1, 2, 3, 4]);
        let pointer = bytes.as_ptr();
        let (request, _) = input(vec![Ok(Frame::data(bytes))], false);
        let prepared = buffered(request, Arc::new(Semaphore::new(1)), 8)
            .await
            .unwrap();
        assert_eq!(prepared.request().body().as_ptr(), pointer);
    }
    #[tokio::test]
    async fn malformed_framing_and_targets_cannot_prepare_bound_requests() {
        let admission = Arc::new(Semaphore::new(1));
        for values in [vec!["+1"], vec!["1", "1"], vec![""], vec!["1, 1"]] {
            let (mut request, polls) = input(vec![], true);
            for value in values {
                request
                    .headers_mut()
                    .append(header::CONTENT_LENGTH, value.parse().unwrap());
            }
            assert!(matches!(
                buffered(request, admission.clone(), 8).await,
                Err(Refused::Length)
            ));
            assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
        }
        let (mut request, polls) = input(vec![], true);
        request
            .headers_mut()
            .insert(header::TRAILER, "authorization".parse().unwrap());
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Trailers)
        ));
        assert_eq!(polls.load(std::sync::atomic::Ordering::Relaxed), 0);
        let (mut request, _) = input(vec![], false);
        *request.uri_mut() = "ftp://orders.example.test/orders".parse().unwrap();
        assert!(matches!(
            buffered(request, admission.clone(), 8).await,
            Err(Refused::Target)
        ));
        assert_eq!(admission.available_permits(), 1);
    }
    #[test]
    fn fragment_reservation_stays_small_and_bounded_with_logarithmic_growth() {
        let mut buffer = Vec::new();
        reserve_entity(&mut buffer, 13, 16 * 1024 * 1024).unwrap();
        assert_eq!(buffer.capacity(), 16);
        for limit in [1, 3, 7, 31, 1025, 4096] {
            let mut buffer = Vec::new();
            let mut changes = 0;
            for index in 0..limit {
                let before = buffer.capacity();
                reserve_entity(&mut buffer, 1, limit).unwrap();
                changes += usize::from(buffer.capacity() != before);
                buffer.push((index % 251) as u8);
                assert!(buffer.capacity() <= limit);
            }
            assert!(changes <= (usize::BITS - limit.leading_zeros()) as usize + 1);
            assert!(
                buffer
                    .iter()
                    .enumerate()
                    .all(|(index, value)| *value == (index % 251) as u8)
            );
            let before = buffer.capacity();
            assert_eq!(
                reserve_entity(&mut buffer, 1, limit),
                Err(Refused::TooLarge)
            );
            assert_eq!(buffer.capacity(), before);
            assert_eq!(
                reserve_entity(&mut buffer, usize::MAX, limit),
                Err(Refused::TooLarge)
            );
        }
    }
    #[tokio::test]
    async fn compiled_scope_identity_and_receipt_fields_survive_preparation() {
        let scope = Scope::new("orders".into(), "orders-api".into()).unwrap();
        let replacement = Scope::new("orders".into(), "orders-api".into()).unwrap();
        let (request, _) = input(vec![Ok(Frame::data(Bytes::from_static(b"entity")))], false);
        let prepared = prepare_scoped(
            request,
            scope.clone(),
            Arc::new(Semaphore::new(1)),
            8,
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(prepared.belongs_to(&scope));
        assert!(!prepared.belongs_to(&replacement));
        let native = prepared.service_scope();
        assert_eq!(native.service, "orders");
        assert_eq!(native.audience, "orders-api");
        assert_eq!(native.request_sha256, prepared.digest());
        for invalid in ["".into(), "*".into(), "한강".into(), "x".repeat(129)] {
            assert!(Scope::new(invalid.clone(), "orders-api".into()).is_err());
            assert!(Scope::new("orders".into(), invalid).is_err());
        }
    }
}
