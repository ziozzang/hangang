//! Close HTTP transports that make no byte-level progress within a fixed idle
//! budget. Protocol keep-alive does not leave silent sockets alive forever.
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;
pub struct IdleIo<T> {
    inner: T,
    clock: IdleWatch,
}
#[derive(Clone)]
pub struct IdleWatch {
    started: Instant,
    last: Arc<AtomicU64>,
    timeout: Duration,
}
impl<T> IdleIo<T> {
    pub fn new(inner: T, timeout: Duration) -> (Self, IdleWatch) {
        let clock = IdleWatch {
            started: Instant::now(),
            last: Arc::new(AtomicU64::new(0)),
            timeout,
        };
        (
            Self {
                inner,
                clock: clock.clone(),
            },
            clock,
        )
    }
}
impl IdleWatch {
    fn progress(&self) {
        self.last
            .store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    pub async fn expired(&self) {
        loop {
            let observed = self.last.load(Ordering::Relaxed);
            let deadline = self.started + Duration::from_millis(observed) + self.timeout;
            tokio::time::sleep_until(deadline).await;
            if self.last.load(Ordering::Relaxed) == observed {
                return;
            }
        }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for IdleIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if buf.filled().len() > before {
            self.clock.progress();
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for IdleIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if matches!(result,Poll::Ready(Ok(n)) if n>0) {
            self.clock.progress();
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, buffers);
        if matches!(result, Poll::Ready(Ok(n)) if n > 0) {
            self.clock.progress();
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn silent_connection_has_a_finite_lifetime() {
        let (_peer, stream) = tokio::io::duplex(32);
        let (_io, watch) = IdleIo::new(stream, Duration::from_millis(50));
        let before = Instant::now();
        tokio::time::timeout(Duration::from_secs(2), watch.expired())
            .await
            .unwrap();
        assert!(before.elapsed() >= Duration::from_millis(50));
    }
    #[tokio::test]
    async fn actual_io_progress_updates_activity() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut peer, stream) = tokio::io::duplex(32);
        let (mut io, watch) = IdleIo::new(stream, Duration::from_millis(100));
        tokio::time::sleep(Duration::from_millis(2)).await;
        peer.write_all(b"a").await.unwrap();
        let mut byte = [0];
        io.read_exact(&mut byte).await.unwrap();
        assert!(watch.last.load(Ordering::Relaxed) > 0);
        io.write_all(b"b").await.unwrap();
        peer.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, [b'b']);
    }
}
