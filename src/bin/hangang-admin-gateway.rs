//! Small, bounded HTTP relay for a Hangang administration Unix socket.
//! Authorization remains entirely in the native Admin router. The relay has
//! no Docker socket or application configuration access.
use anyhow::{Result, ensure};
use bytes::Bytes;
use clap::Parser;
use hangang::idle::IdleIo;
use http_body_util::{BodyExt, Limited};
use hyper::{
    Request, Response, StatusCode,
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1 as client_http1,
    header::{self, HeaderMap},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{
    convert::Infallible,
    io::Write,
    net::SocketAddr,
    path::{Component, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::{TcpListener, UnixStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
};

#[derive(Parser)]
#[command(about = "Bounded TCP relay to Hangang's private admin Unix socket")]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long)]
    admin_socket: PathBuf,
    /// Required when exposing the plaintext relay outside loopback.
    #[arg(long)]
    allow_insecure_public: bool,
    #[arg(long, default_value_t = 128)]
    max_connections: usize,
    #[arg(long, default_value_t = 128)]
    max_requests: usize,
    #[arg(long, default_value_t = 2 * 1024 * 1024)]
    max_body_bytes: u64,
    #[arg(long, default_value_t = 16 * 1024)]
    header_bytes: usize,
    #[arg(long, default_value_t = 60)]
    idle_seconds: u64,
}

struct State {
    socket: PathBuf,
    requests: Arc<Semaphore>,
    max_body_bytes: u64,
}

enum Payload {
    Text(Option<Bytes>),
    Upstream(Incoming),
}

struct RelayBody {
    payload: Payload,
    // Keep both slots while a streamed response (including SSE) is live.
    _request: Option<OwnedSemaphorePermit>,
    _driver: Option<DriverGuard>,
}

struct DriverGuard(JoinHandle<()>);

impl Drop for DriverGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl RelayBody {
    fn text(body: &'static str) -> Self {
        Self {
            payload: Payload::Text(Some(Bytes::from_static(body.as_bytes()))),
            _request: None,
            _driver: None,
        }
    }
}

impl Body for RelayBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match &mut this.payload {
            Payload::Text(body) => Poll::Ready(body.take().map(|bytes| Ok(Frame::data(bytes)))),
            Payload::Upstream(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.payload {
            Payload::Text(body) => body.is_none(),
            Payload::Upstream(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.payload {
            Payload::Text(body) => {
                let mut hint = SizeHint::new();
                hint.set_exact(body.as_ref().map_or(0, Bytes::len) as u64);
                hint
            }
            Payload::Upstream(body) => body.size_hint(),
        }
    }
}

fn plain(status: StatusCode, body: &'static str) -> Response<RelayBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(RelayBody::text(body))
        .expect("static relay response")
}

fn exactly_one(
    headers: &HeaderMap,
    name: impl hyper::header::AsHeaderName,
) -> Option<&hyper::header::HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
}

fn valid_request(request: &Request<Incoming>, max_body_bytes: u64) -> Result<(), StatusCode> {
    let uri = request.uri();
    if request.method() == hyper::Method::CONNECT
        || uri.scheme().is_some()
        || uri.authority().is_some()
        || !uri.path().starts_with('/')
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let headers = request.headers();
    let Some(host) = exactly_one(headers, header::HOST) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    if host.is_empty() || host.as_bytes().iter().any(u8::is_ascii_whitespace) {
        return Err(StatusCode::BAD_REQUEST);
    }
    for name in [header::AUTHORIZATION, header::ORIGIN] {
        if headers.get_all(name).iter().nth(1).is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if headers.contains_key(header::TRANSFER_ENCODING)
        || headers.contains_key(header::UPGRADE)
        || headers.contains_key(header::TE)
        || headers.contains_key(header::TRAILER)
        || headers.contains_key(header::EXPECT)
        || headers.contains_key("proxy-connection")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some(connection) = headers.get(header::CONNECTION) {
        let Ok(value) = connection.to_str() else {
            return Err(StatusCode::BAD_REQUEST);
        };
        if value.split(',').any(|part| {
            let token = part.trim();
            token.is_empty()
                || (!token.eq_ignore_ascii_case("close")
                    && !token.eq_ignore_ascii_case("keep-alive"))
        }) {
            return Err(StatusCode::BAD_REQUEST);
        }
        if headers.get_all(header::CONNECTION).iter().nth(1).is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    if headers.contains_key(header::CONTENT_LENGTH) {
        let Some(value) = exactly_one(headers, header::CONTENT_LENGTH) else {
            return Err(StatusCode::BAD_REQUEST);
        };
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > 19 || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(StatusCode::BAD_REQUEST);
        }
        let length = value
            .to_str()
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .ok_or(StatusCode::BAD_REQUEST)?;
        if length > max_body_bytes {
            return Err(StatusCode::PAYLOAD_TOO_LARGE);
        }
    }
    Ok(())
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    for name in [
        header::CONNECTION,
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
    ] {
        headers.remove(name);
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

async fn forward(mut request: Request<Incoming>, state: Arc<State>) -> Response<RelayBody> {
    let permit = match state.requests.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return plain(StatusCode::SERVICE_UNAVAILABLE, "management relay busy\n"),
    };
    if let Err(status) = valid_request(&request, state.max_body_bytes) {
        return plain(status, "invalid management request\n");
    }
    if let Some(response) = hangang::ui::serve(&request) {
        // The management image serves its own fixed assets. The bounded copy is
        // complete before releasing the request slot; slow readers remain
        // bounded by the connection limit but cannot consume the API budget.
        let (parts, body) = response.into_parts();
        let bytes = match Limited::new(body, 1024 * 1024).collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => {
                return plain(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "management UI unavailable\n",
                );
            }
        };
        return Response::from_parts(
            parts,
            RelayBody {
                payload: Payload::Text((!bytes.is_empty()).then_some(bytes)),
                _request: None,
                _driver: None,
            },
        );
    }
    // Keep the incoming Host and Origin exactly as sent by the client. Hyper
    // re-frames the body on the Unix hop, avoiding ambiguous wire framing.
    strip_hop_headers(request.headers_mut());
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let stream =
            tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(&state.socket))
                .await??;
        let (mut sender, connection) = tokio::time::timeout(
            Duration::from_secs(2),
            client_http1::handshake(TokioIo::new(stream)),
        )
        .await??;
        let driver = DriverGuard(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender.send_request(request).await?;
        Ok::<_, anyhow::Error>((response, driver))
    })
    .await;
    let (mut response, driver) = match result {
        Ok(Ok(value)) => value,
        _ => return plain(StatusCode::BAD_GATEWAY, "management backend unavailable\n"),
    };
    strip_hop_headers(response.headers_mut());
    response.map(|body| RelayBody {
        payload: Payload::Upstream(body),
        _request: Some(permit),
        _driver: Some(driver),
    })
}

fn validate(args: &Args) -> Result<()> {
    ensure!(
        args.listen.ip().is_loopback() || args.allow_insecure_public,
        "non-loopback plaintext management requires --allow-insecure-public"
    );
    ensure!(
        args.admin_socket.is_absolute()
            && args.admin_socket.as_os_str().len() <= 1024
            && !args
                .admin_socket
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
        "--admin-socket must be an absolute normalized path"
    );
    ensure!(
        (1..=4096).contains(&args.max_connections),
        "max-connections must be 1..4096"
    );
    ensure!(
        (1..=4096).contains(&args.max_requests),
        "max-requests must be 1..4096"
    );
    ensure!(
        (1..=16 * 1024 * 1024).contains(&args.max_body_bytes),
        "max-body-bytes must be 1..16777216"
    );
    ensure!(
        (8192..=65536).contains(&args.header_bytes),
        "header-bytes must be 8192..65536"
    );
    ensure!(
        (5..=3600).contains(&args.idle_seconds),
        "idle-seconds must be 5..3600"
    );
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    validate(&args)?;
    let listener = TcpListener::bind(args.listen).await?;
    // The address is useful for supervisors and lets an owned :0 fixture
    // confirm readiness from this process instead of probing a released port.
    {
        let mut output = std::io::stdout().lock();
        let _ = writeln!(
            output,
            "HANGANG_ADMIN_GATEWAY_LISTEN {}",
            listener.local_addr()?
        );
        let _ = output.flush();
    }
    let connections = Arc::new(Semaphore::new(args.max_connections));
    let state = Arc::new(State {
        socket: args.admin_socket,
        requests: Arc::new(Semaphore::new(args.max_requests)),
        max_body_bytes: args.max_body_bytes,
    });
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let state = state.clone();
        let idle = Duration::from_secs(args.idle_seconds);
        let header_bytes = args.header_bytes;
        tokio::spawn(async move {
            let (stream, watch) = IdleIo::new(stream, idle);
            let service = service_fn(move |request| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(forward(request, state).await) }
            });
            let mut builder = server_http1::Builder::new();
            builder.timer(TokioTimer::new());
            builder.header_read_timeout(Duration::from_secs(10));
            builder.max_buf_size(header_bytes);
            let connection = builder.serve_connection(TokioIo::new(stream), service);
            tokio::pin!(connection);
            tokio::select! {
                _ = &mut connection => {},
                _ = watch.expired() => {},
            }
            drop(permit);
        });
    }
}
