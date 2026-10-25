//! Shared resource admission and framing for uncompressed unary gRPC only.
//! Put component authentication outside this adapter and generated services with
//! their existing protobuf size limits inside it. No caller policy lives here.
use hyper::body::{Body as HttpBody, Bytes, Frame};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::Semaphore;
use tonic::{
    Status,
    body::Body,
    codegen::{Service, StdError, http},
};

/// Clones and independently wrapped services share the supplied admission owner.
/// A slot covers the complete service future, including decoding and handler
/// waits. Streaming RPCs and compressed gRPC messages are intentionally excluded.
#[derive(Clone)]
pub struct UnaryIngress<S> {
    inner: S,
    slots: Arc<Semaphore>,
    max_payload: u32,
}
impl<S> UnaryIngress<S> {
    /// Reuse the same semaphore across every service and connection in a resource
    /// class. Do not acquire that semaphore again in the handler. Keep component
    /// metadata authorization outside this adapter and Prost decode limits inside.
    ///
    /// The bound counts actual DATA bytes (payload plus the five-byte prefix).
    /// Limits above u32::MAX clamp to the maximum gRPC wire message length.
    /// Tonic unary services consume through EOF/trailers before handler dispatch;
    /// arbitrary services that do not consume their body cannot validate framing.
    /// A slot ends when the service future finishes, before response body draining.
    pub fn new(inner: S, slots: Arc<Semaphore>, max_payload: usize) -> Self {
        Self {
            inner,
            slots,
            max_payload: u32::try_from(max_payload).unwrap_or(u32::MAX),
        }
    }
}
impl<S: tonic::server::NamedService> tonic::server::NamedService for UnaryIngress<S> {
    const NAME: &'static str = S::NAME;
}
impl<S, B> Service<http::Request<B>> for UnaryIngress<S>
where
    S: Service<http::Request<Body>, Response = http::Response<Body>>,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    B: HttpBody<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<StdError>,
{
    type Response = http::Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Capacity is fail-fast in call(), never a permit waiting queue.
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, request: http::Request<B>) -> Self::Future {
        let Ok(permit) = self.slots.clone().try_acquire_owned() else {
            return Box::pin(async {
                Ok(Status::resource_exhausted("unary ingress capacity").into_http())
            });
        };
        let request = request.map(|body| Body::new(UnaryBody::new(body, self.max_payload)));
        let future = self.inner.call(request);
        Box::pin(async move {
            let _permit = permit;
            future.await
        })
    }
}

struct UnaryBody<B> {
    inner: B,
    max_payload: u32,
    total: u64,
    prefix: [u8; 5],
    prefix_len: usize,
    payload_left: Option<u32>,
    trailers_seen: bool,
    terminal: bool,
}
impl<B> UnaryBody<B> {
    fn new(inner: B, max_payload: u32) -> Self {
        Self {
            inner,
            max_payload,
            total: 0,
            prefix: [0; 5],
            prefix_len: 0,
            payload_left: None,
            trailers_seen: false,
            terminal: false,
        }
    }
    fn complete(&self) -> bool {
        self.payload_left == Some(0)
    }
    fn data(&mut self, mut bytes: &[u8]) -> Result<(), Status> {
        if self.trailers_seen {
            return Err(Status::invalid_argument("DATA after unary trailers"));
        }
        self.total = self
            .total
            .checked_add(bytes.len() as u64)
            .filter(|total| *total <= u64::from(self.max_payload) + 5)
            .ok_or_else(|| Status::resource_exhausted("unary DATA limit"))?;
        while !bytes.is_empty() {
            if self.prefix_len < 5 {
                let take = (5 - self.prefix_len).min(bytes.len());
                self.prefix[self.prefix_len..self.prefix_len + take]
                    .copy_from_slice(&bytes[..take]);
                self.prefix_len += take;
                bytes = &bytes[take..];
                if self.prefix_len == 5 {
                    if self.prefix[0] > 1 {
                        return Err(Status::invalid_argument("invalid gRPC compression flag"));
                    }
                    if self.prefix[0] == 1 {
                        return Err(Status::unimplemented("uncompressed unary message required"));
                    }
                    let length = u32::from_be_bytes(self.prefix[1..5].try_into().unwrap());
                    if length > self.max_payload {
                        return Err(Status::out_of_range("unary payload limit"));
                    }
                    self.payload_left = Some(length);
                }
            } else {
                let left = self.payload_left.as_mut().unwrap();
                if *left == 0 {
                    return Err(Status::invalid_argument("more than one unary message"));
                }
                let take = bytes.len().min(*left as usize);
                *left -= take as u32;
                bytes = &bytes[take..];
            }
        }
        Ok(())
    }
}
impl<B> HttpBody for UnaryBody<B>
where
    B: HttpBody<Data = Bytes> + Unpin,
    B::Error: Into<StdError>,
{
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if self.terminal {
            return Poll::Ready(None);
        }
        let next = match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(next) => next,
        };
        let result = match next {
            None => {
                self.terminal = true;
                return Poll::Ready(if self.complete() {
                    None
                } else {
                    Some(Err(Status::invalid_argument("truncated unary message")))
                });
            }
            Some(Err(error)) => Err(Status::from_error(error.into())),
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    self.data(data).map(|()| frame)
                } else if frame.is_trailers() {
                    if !self.complete() || self.trailers_seen {
                        Err(Status::invalid_argument("invalid unary trailers"))
                    } else {
                        self.trailers_seen = true;
                        Ok(frame)
                    }
                } else {
                    Err(Status::invalid_argument("unsupported unary body frame"))
                }
            }
        };
        if result.is_err() {
            self.terminal = true;
        }
        Poll::Ready(Some(result))
    }
    fn is_end_stream(&self) -> bool {
        // Do not let an empty/truncated inner body bypass our final EOF check.
        self.terminal
    }
}

#[cfg(test)]
mod tests;
