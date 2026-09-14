//! Named public HTTP and HTTPS listeners.
use crate::{
    config::Snapshot,
    metrics::{ConnectionLease, Metrics},
    proxy::Proxy,
    public_listener_config::Listener,
};
use arc_swap::ArcSwap;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use ipnet::IpNet;
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

/// Constructed only at the listener after verifying the active configuration
/// and, for HTTPS, completing the TLS handshake.
#[derive(Clone)]
pub struct Evidence(Arc<VerifiedListener>);
struct VerifiedListener {
    listener: Listener,
    tls_slot: Option<Arc<ArcSwap<rustls::ServerConfig>>>,
    generation: Arc<()>,
}
impl Evidence {
    pub fn listener_id(&self) -> &str {
        &self.0.listener.id
    }
    pub fn listen(&self) -> SocketAddr {
        self.0.listener.listen
    }
    pub fn trusted_proxy_cidrs(&self) -> &[IpNet] {
        &self.0.listener.trusted_proxy_cidrs
    }
    pub fn current(&self, snapshot: &Snapshot) -> bool {
        snapshot
            .config
            .public_http
            .iter()
            .any(|listener| listener.enabled && listener == &self.0.listener)
            && snapshot
                .public_http_generations
                .get(&self.0.listener.id)
                .is_some_and(|generation| Arc::ptr_eq(generation, &self.0.generation))
            && match &self.0.tls_slot {
                Some(slot) => snapshot
                    .public_http_tls
                    .get(&self.0.listener.id)
                    .is_some_and(|current| Arc::ptr_eq(current, slot)),
                None => {
                    !snapshot.public_http_tls.contains_key(&self.0.listener.id)
                        && self.0.listener.certificates.is_empty()
                }
            }
    }
}

// Keep the evidence and global connection lease attached to upgraded WebSocket
// streams. A configuration withdrawal closes idle and active streams promptly.
struct RevocableIo<T> {
    inner: T,
    active: Arc<ArcSwap<Snapshot>>,
    evidence: Evidence,
    tick: Pin<Box<tokio::time::Sleep>>,
    revoked: bool,
    _lease: Arc<ConnectionLease>,
}
impl<T> RevocableIo<T> {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        use std::future::Future;
        if !self.revoked && self.tick.as_mut().poll(cx).is_ready() {
            if !self.evidence.current(&self.active.load()) {
                self.revoked = true;
            } else {
                self.tick
                    .as_mut()
                    .reset(tokio::time::Instant::now() + Duration::from_millis(250));
                let _ = self.tick.as_mut().poll(cx);
            }
        }
        if self.revoked {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "public listener withdrawn",
            ))
        } else {
            Ok(())
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for RevocableIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for RevocableIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if let Err(error) = this.check(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Err(error) = this.check(cx) {
            return Poll::Ready(Err(error));
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn serve(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    active: Arc<ArcSwap<Snapshot>>,
    listener_id: String,
    proxy: Arc<Proxy>,
    header_bytes: usize,
    idle_timeout: Duration,
    cancel: CancellationToken,
    metrics: Arc<Metrics>,
    lease: Arc<ConnectionLease>,
) {
    use std::sync::atomic::Ordering;
    let reject = || {
        metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
    };
    let Ok(local) = stream.local_addr() else {
        reject();
        return;
    };
    let snapshot = active.load_full();
    let Some(listener) = snapshot
        .config
        .public_http
        .iter()
        .find(|listener| {
            listener.enabled
                && listener.id == listener_id
                && listener.listen.port() == local.port()
                && (listener.listen.ip().is_unspecified()
                    || listener.listen.ip().to_canonical() == local.ip().to_canonical())
        })
        .cloned()
    else {
        reject();
        return;
    };
    let tls_slot = if listener.certificates.is_empty() {
        None
    } else {
        let Some(slot) = snapshot.public_http_tls.get(&listener_id).cloned() else {
            reject();
            return;
        };
        Some(slot)
    };
    let Some(generation) = snapshot.public_http_generations.get(&listener_id).cloned() else {
        reject();
        return;
    };
    let evidence = Evidence(Arc::new(VerifiedListener {
        listener,
        tls_slot: tls_slot.clone(),
        generation,
    }));
    if !evidence.current(&active.load()) {
        reject();
        return;
    }
    drop(snapshot);
    let tls = tls_slot.is_some();
    if let Some(slot) = tls_slot {
        let Ok(handshake_permit) = crate::tcp::workload_handshake_admission().try_acquire_owned()
        else {
            reject();
            return;
        };
        let acceptor = tokio_rustls::TlsAcceptor::from(slot.load_full());
        let accepted = tokio::select! { biased; _ = cancel.cancelled() => return,
        result = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)) => result };
        let Ok(Ok(stream)) = accepted else {
            reject();
            return;
        };
        drop(handshake_permit);
        if !evidence.current(&active.load()) {
            reject();
            return;
        }
        serve_io(
            stream,
            peer,
            local,
            active,
            evidence,
            proxy,
            header_bytes,
            idle_timeout,
            cancel,
            lease,
            tls,
        )
        .await;
    } else {
        serve_io(
            stream,
            peer,
            local,
            active,
            evidence,
            proxy,
            header_bytes,
            idle_timeout,
            cancel,
            lease,
            tls,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_io<T: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    stream: T,
    peer: SocketAddr,
    local: SocketAddr,
    active: Arc<ArcSwap<Snapshot>>,
    evidence: Evidence,
    proxy: Arc<Proxy>,
    header_bytes: usize,
    idle_timeout: Duration,
    cancel: CancellationToken,
    lease: Arc<ConnectionLease>,
    tls: bool,
) {
    let io = RevocableIo {
        inner: stream,
        active,
        evidence: evidence.clone(),
        tick: Box::pin(tokio::time::sleep(Duration::ZERO)),
        revoked: false,
        _lease: lease.clone(),
    };
    let (io, idle) = crate::idle::IdleIo::new(io, idle_timeout);
    let service = service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
        request.extensions_mut().insert(evidence.clone());
        request.extensions_mut().insert(lease.clone());
        request.extensions_mut().insert(crate::tls::TransportInfo {
            tls,
            local_port: local.port(),
        });
        let proxy = proxy.clone();
        async move { proxy.handle(request, peer).await }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10))
        .max_buf_size(header_bytes);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(64)
        .max_header_list_size(header_bytes as u32)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));
    let connection = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    tokio::pin!(connection);
    tokio::select! { biased; _ = cancel.cancelled() => {}, _ = idle.expired(), if !idle_timeout.is_zero() => {}, _ = &mut connection => {} }
}
