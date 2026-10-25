use super::*;
use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Input {
    frames: VecDeque<Result<Frame<Bytes>, Status>>,
    polls: Arc<AtomicUsize>,
    pending: bool,
}
impl HttpBody for Input {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            Poll::Pending
        } else {
            Poll::Ready(self.frames.pop_front())
        }
    }
}
fn input(chunks: Vec<Vec<u8>>) -> Input {
    Input {
        frames: chunks
            .into_iter()
            .map(|v| Ok(Frame::data(Bytes::from(v))))
            .collect(),
        polls: Arc::new(AtomicUsize::new(0)),
        pending: false,
    }
}
fn wire(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
#[derive(Default)]
struct Seen {
    calls: AtomicUsize,
    data: AtomicUsize,
    headers: Mutex<http::HeaderMap>,
    trailers: Mutex<http::HeaderMap>,
}
#[derive(Clone)]
struct Consumer {
    seen: Arc<Seen>,
    fail: bool,
}
impl Service<http::Request<Body>> for Consumer {
    type Response = http::Response<Body>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        self.seen.calls.fetch_add(1, Ordering::SeqCst);
        *self.seen.headers.lock().unwrap() = request.headers().clone();
        let seen = self.seen.clone();
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                return Err(std::io::Error::other("controlled service failure"));
            }
            let mut body = request.into_body();
            while let Some(next) =
                std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await
            {
                let frame = match next {
                    Ok(frame) => frame,
                    Err(error) => return Ok(error.into_http()),
                };
                if let Some(data) = frame.data_ref() {
                    seen.data.fetch_add(data.len(), Ordering::SeqCst);
                }
                if let Some(trailers) = frame.trailers_ref() {
                    *seen.trailers.lock().unwrap() = trailers.clone();
                }
            }
            Ok(Status::new(tonic::Code::Ok, "").into_http())
        })
    }
}
fn setup(cap: u32) -> (UnaryIngress<Consumer>, Arc<Semaphore>, Arc<Seen>) {
    let slots = Arc::new(Semaphore::new(1));
    let seen = Arc::new(Seen::default());
    (
        UnaryIngress::new(
            Consumer {
                seen: seen.clone(),
                fail: false,
            },
            slots.clone(),
            cap as usize,
        ),
        slots,
        seen,
    )
}
async fn code(service: &mut UnaryIngress<Consumer>, body: Input) -> tonic::Code {
    let response = service.call(http::Request::new(body)).await.unwrap();
    let value: i32 = response.headers()["grpc-status"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    tonic::Code::from_i32(value)
}
#[tokio::test]
async fn every_prefix_and_payload_fragmentation_accepts_the_exact_cap() {
    let bytes = wire(b"abcd");
    for first in 0..=5 {
        for second in first..=bytes.len() {
            let (mut service, slots, seen) = setup(4);
            let body = input(vec![
                bytes[..first].to_vec(),
                bytes[first..second].to_vec(),
                bytes[second..].to_vec(),
            ]);
            assert_eq!(code(&mut service, body).await, tonic::Code::Ok);
            assert_eq!(seen.data.load(Ordering::SeqCst), bytes.len());
            assert_eq!(slots.available_permits(), 1);
        }
    }
    let (mut service, slots, _) = setup(0);
    assert_eq!(
        code(&mut service, input(vec![wire(b"")])).await,
        tonic::Code::Ok
    );
    assert_eq!(slots.available_permits(), 1);
}
#[tokio::test]
async fn data_cap_and_one_message_grammar_reject_excess_before_forwarding_it() {
    let cases = [
        (4, vec![wire(b"abcde")], tonic::Code::ResourceExhausted),
        (4, vec![vec![0, 0, 0, 0, 5]], tonic::Code::OutOfRange),
        (
            100,
            vec![[wire(b"a"), wire(b"b")].concat()],
            tonic::Code::InvalidArgument,
        ),
        (
            100,
            vec![wire(b"a"), wire(b"b")],
            tonic::Code::InvalidArgument,
        ),
        (100, vec![vec![1, 0, 0, 0, 0]], tonic::Code::Unimplemented),
        (
            100,
            vec![vec![255, 0, 0, 0, 0]],
            tonic::Code::InvalidArgument,
        ),
    ];
    for (cap, chunks, expected) in cases {
        let (mut service, slots, seen) = setup(cap);
        assert_eq!(code(&mut service, input(chunks)).await, expected);
        assert!(
            seen.data.load(Ordering::SeqCst) <= 6,
            "rejected second frame reached consumer"
        );
        assert_eq!(slots.available_permits(), 1);
    }
}
#[tokio::test]
async fn empty_truncated_body_and_early_trailers_fail_without_slot_leaks() {
    let bytes = wire(b"abcd");
    for length in 0..bytes.len() {
        let (mut service, slots, _) = setup(4);
        assert_eq!(
            code(&mut service, input(vec![bytes[..length].to_vec()])).await,
            tonic::Code::InvalidArgument
        );
        assert_eq!(slots.available_permits(), 1);
    }
    let (mut service, slots, _) = setup(4);
    let mut body = input(vec![bytes[..6].to_vec()]);
    body.frames
        .push_back(Ok(Frame::trailers(http::HeaderMap::new())));
    assert_eq!(code(&mut service, body).await, tonic::Code::InvalidArgument);
    assert_eq!(slots.available_permits(), 1);
}
#[tokio::test]
async fn shared_admission_is_immediate_and_cancellation_releases_before_or_after_poll() {
    for poll_first in [false, true] {
        let (mut first, slots, seen) = setup(4);
        let mut other_service = UnaryIngress::new(
            Consumer {
                seen: seen.clone(),
                fail: false,
            },
            slots.clone(),
            4,
        );
        let mut body = input(vec![]);
        body.pending = true;
        let mut pending = first.call(http::Request::new(body));
        if poll_first {
            std::future::poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(slots.available_permits(), 0);
        let refused = input(vec![wire(b"x")]);
        let polls = refused.polls.clone();
        assert_eq!(
            code(&mut other_service, refused).await,
            tonic::Code::ResourceExhausted
        );
        assert_eq!(polls.load(Ordering::SeqCst), 0);
        assert_eq!(seen.calls.load(Ordering::SeqCst), 1);
        drop(pending);
        assert_eq!(slots.available_permits(), 1);
        assert_eq!(
            code(&mut other_service, input(vec![wire(b"x")])).await,
            tonic::Code::Ok
        );
        assert_eq!(slots.available_permits(), 1);
    }
}
#[tokio::test]
async fn body_and_service_errors_release_admission() {
    let (mut service, slots, _) = setup(4);
    let mut body = input(vec![]);
    body.frames
        .push_back(Err(Status::cancelled("controlled body reset")));
    assert_eq!(code(&mut service, body).await, tonic::Code::Cancelled);
    assert_eq!(slots.available_permits(), 1);
    service.inner.fail = true;
    assert!(
        service
            .call(http::Request::new(input(vec![wire(b"x")])))
            .await
            .is_err()
    );
    assert_eq!(slots.available_permits(), 1);
}
#[tokio::test]
async fn headers_and_trailers_are_preserved_and_content_length_is_not_trusted() {
    let (mut service, slots, seen) = setup(4);
    let mut body = input(vec![wire(b"abcd")]);
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-owned-trailer", "retained".parse().unwrap());
    body.frames.push_back(Ok(Frame::trailers(trailers.clone())));
    let mut request = http::Request::new(body);
    request
        .headers_mut()
        .insert("content-length", "1".parse().unwrap());
    request
        .headers_mut()
        .insert("authorization", "Bearer owned".parse().unwrap());
    let response = service.call(request).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "0");
    assert_eq!(
        seen.headers.lock().unwrap()["authorization"],
        "Bearer owned"
    );
    assert_eq!(*seen.trailers.lock().unwrap(), trailers);
    assert_eq!(slots.available_permits(), 1);
    let mut request = http::Request::new(input(vec![wire(b"abcde")]));
    request
        .headers_mut()
        .insert("content-length", "1".parse().unwrap());
    let response = service.call(request).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "8");
    assert_eq!(slots.available_permits(), 1);
}

// Exercise Tonic's actual unary decoding path, including Prost and the trailer
// read after the first decoded message, rather than only our body consumer.
#[derive(Clone, PartialEq, prost::Message)]
struct Message {
    #[prost(string, tag = "1")]
    value: String,
}
#[derive(Clone)]
struct CodecService {
    entered: Arc<AtomicUsize>,
    wait: bool,
}
impl tonic::server::UnaryService<Message> for CodecService {
    type Response = Message;
    type Future = Pin<Box<dyn Future<Output = Result<tonic::Response<Message>, Status>> + Send>>;
    fn call(&mut self, request: tonic::Request<Message>) -> Self::Future {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let wait = self.wait;
        Box::pin(async move {
            if wait {
                std::future::pending::<()>().await;
            }
            Ok(tonic::Response::new(request.into_inner()))
        })
    }
}
impl Service<http::Request<Body>> for CodecService {
    type Response = http::Response<Body>;
    type Error = std::convert::Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let handler = self.clone();
        Box::pin(async move {
            let codec = tonic_prost::ProstCodec::<Message, Message>::default();
            let mut grpc = tonic::server::Grpc::new(codec).max_decoding_message_size(32);
            Ok(grpc.unary(handler, request).await)
        })
    }
}
#[tokio::test]
async fn tonic_prost_rejects_second_message_and_preserves_decode_errors() {
    use prost::Message as _;
    let entered = Arc::new(AtomicUsize::new(0));
    let mut service = UnaryIngress::new(
        CodecService {
            entered: entered.clone(),
            wait: false,
        },
        Arc::new(Semaphore::new(1)),
        32,
    );
    let payload = Message { value: "ok".into() }.encode_to_vec();
    for chunks in [
        vec![[wire(&payload), wire(&payload)].concat()],
        vec![wire(&payload), wire(&payload)],
    ] {
        let response = service
            .call(http::Request::new(input(chunks)))
            .await
            .unwrap();
        assert_eq!(response.headers()["grpc-status"], "3");
    }
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    // Invalid protobuf string length: framing is valid and Prost owns the error.
    let response = service
        .call(http::Request::new(input(vec![wire(&[10, 5, 1])])))
        .await
        .unwrap();
    assert_eq!(response.headers()["grpc-status"], "13");
    assert!(
        response.headers()["grpc-message"]
            .to_str()
            .unwrap()
            .contains("decode")
    );
    assert_eq!(entered.load(Ordering::SeqCst), 0);
    let response = service
        .call(http::Request::new(input(vec![wire(&payload)])))
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(entered.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn decoded_handler_wait_retains_shared_slot_until_cancelled() {
    use prost::Message as _;
    let slots = Arc::new(Semaphore::new(1));
    let entered = Arc::new(AtomicUsize::new(0));
    let handler = CodecService {
        entered: entered.clone(),
        wait: true,
    };
    let mut first = UnaryIngress::new(handler.clone(), slots.clone(), 32);
    let mut second = UnaryIngress::new(handler, slots.clone(), 32);
    let payload = Message { value: "ok".into() }.encode_to_vec();
    let mut waiting = first.call(http::Request::new(input(vec![wire(&payload)])));
    std::future::poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_eq!(entered.load(Ordering::SeqCst), 1);
    assert_eq!(slots.available_permits(), 0);
    let refused = input(vec![wire(&payload)]);
    let polls = refused.polls.clone();
    let response = second.call(http::Request::new(refused)).await.unwrap();
    assert_eq!(response.headers()["grpc-status"], "8");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    drop(waiting);
    assert_eq!(slots.available_permits(), 1);
}
