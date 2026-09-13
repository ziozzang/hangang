//! Dedicated authenticated HTTP listeners. Public HTTPS/ACME is independent.
use crate::{
    config::Snapshot,
    metrics::{ConnectionLease, Metrics},
    proxy::Proxy,
    workload_tls::{Identity, Policy, Prepared},
};
use anyhow::{Result, ensure};
use arc_swap::ArcSwap;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listener {
    pub id: String,
    pub listen: SocketAddr,
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub tls: Policy,
}
fn enabled() -> bool {
    true
}
impl Listener {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.id.is_empty()
                && self.id.len() <= 128
                && self
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b)),
            "invalid workload HTTP listener id"
        );
        ensure!(
            self.listen.port() != 0,
            "workload HTTP listener port must be nonzero"
        );
        self.tls.validate()
    }
}

/// Only this module can construct evidence, after mandatory rustls verification.
#[derive(Clone)]
pub struct Evidence(Arc<VerifiedConnection>);
struct VerifiedConnection {
    listener_id: String,
    prepared: Arc<Prepared>,
    identity: Identity,
    deadline: tokio::time::Instant,
}
impl Evidence {
    pub fn listener_id(&self) -> &str {
        &self.0.listener_id
    }
    pub fn identity(&self) -> &Identity {
        &self.0.identity
    }
    pub fn current(&self, snapshot: &Snapshot) -> bool {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return false;
        };
        now.as_secs() < self.0.identity.expires_at
            && tokio::time::Instant::now() < self.0.deadline
            && snapshot
                .http_workload_tls
                .get(&self.0.listener_id)
                .is_some_and(|current| Arc::ptr_eq(current, &self.0.prepared))
    }
}

/// This wrapper moves with a Hyper upgrade, so expiry/withdrawal and connection
/// admission remain owned after the listener's HTTP future has completed.
struct RevocableIo<T> {
    inner: T,
    active: Arc<ArcSwap<Snapshot>>,
    evidence: Evidence,
    tick: Pin<Box<tokio::time::Sleep>>,
    revoked: bool,
    metrics: Arc<Metrics>,
    _lease: Arc<ConnectionLease>,
}
impl<T> RevocableIo<T> {
    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        use std::future::Future;
        if !self.revoked && self.tick.as_mut().poll(cx).is_ready() {
            if !self.evidence.current(&self.active.load()) {
                self.revoked = true;
                self.metrics
                    .http_mtls_lease_terminations
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                "workload listener identity withdrawn",
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
        metrics.http_mtls_rejections.fetch_add(1, Ordering::Relaxed);
        metrics.rejected_connections.fetch_add(1, Ordering::Relaxed);
    };
    let Ok(local) = stream.local_addr() else {
        reject();
        return;
    };
    let snapshot = active.load_full();
    let Some(listener) = snapshot.config.workload_http.iter().find(|listener| {
        listener.enabled
            && listener.id == listener_id
            && listener.listen.port() == local.port()
            && (listener.listen.ip().is_unspecified()
                || listener.listen.ip().to_canonical() == local.ip().to_canonical())
    }) else {
        reject();
        return;
    };
    let Some(prepared) = snapshot.http_workload_tls.get(&listener_id).cloned() else {
        reject();
        return;
    };
    let Ok(handshake_permit) = crate::tcp::workload_handshake_admission().try_acquire_owned()
    else {
        reject();
        return;
    };
    let acceptor = tokio_rustls::TlsAcceptor::from(prepared.server_config.clone());
    let accepted = tokio::select! { biased; _ = cancel.cancelled() => return,
    result = tokio::time::timeout(Duration::from_millis(listener.tls.handshake_timeout_ms), acceptor.accept(stream)) => result };
    let Ok(Ok(stream)) = accepted else {
        reject();
        return;
    };
    let identity = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| prepared.authorize_peer(chain).ok());
    drop(handshake_permit);
    let Some(identity) = identity else {
        reject();
        return;
    };
    let deadline = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|now| identity.expires_at.checked_sub(now.as_secs()))
        .and_then(|seconds| tokio::time::Instant::now().checked_add(Duration::from_secs(seconds)));
    let Some(deadline) = deadline else {
        reject();
        return;
    };
    let evidence = Evidence(Arc::new(VerifiedConnection {
        listener_id,
        prepared,
        identity,
        deadline,
    }));
    if !evidence.current(&active.load()) {
        reject();
        return;
    }
    drop(snapshot);
    let io = RevocableIo {
        inner: stream,
        active,
        evidence: evidence.clone(),
        tick: Box::pin(tokio::time::sleep(Duration::ZERO)),
        revoked: false,
        metrics: metrics.clone(),
        _lease: lease.clone(),
    };
    let (io, idle) = crate::idle::IdleIo::new(io, idle_timeout);
    let service = service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
        request.extensions_mut().insert(evidence.clone());
        request.extensions_mut().insert(lease.clone());
        request.extensions_mut().insert(crate::tls::TransportInfo {
            tls: true,
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
