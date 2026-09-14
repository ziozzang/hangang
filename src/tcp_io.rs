//! TCP telemetry counts writes accepted by each destination, not read-ahead.
//! TLS handshake and ciphertext overhead are outside this application-byte view.
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tcp_history::ByteCounters;

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Upstream,
    Downstream,
}

pub(crate) struct CountedIo<T> {
    inner: T,
    counters: Option<Arc<ByteCounters>>,
    direction: Direction,
}

impl<T> CountedIo<T> {
    pub(crate) fn new(inner: T, counters: Option<Arc<ByteCounters>>, direction: Direction) -> Self {
        Self {
            inner,
            counters,
            direction,
        }
    }
    fn wrote(&self, count: usize) {
        if let Some(counters) = &self.counters {
            match self.direction {
                Direction::Upstream => counters.add_upstream(count as u64),
                Direction::Downstream => counters.add_downstream(count as u64),
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for CountedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for CountedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(count)) = result {
            self.wrote(count);
        }
        result
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(count)) = result {
            self.wrote(count);
        }
        result
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp_history::History;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct PartialThenError(usize);
    impl AsyncWrite for PartialThenError {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.0 == 0 {
                return Poll::Ready(Err(io::Error::other("owned failure")));
            }
            let written = self.0.min(buf.len());
            self.0 -= written;
            Poll::Ready(Ok(written))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn current_bytes(history: &History, field: &str) -> String {
        serde_json::to_value(history.active(None, 1)).unwrap()["records"][0][field]
            .as_str()
            .unwrap()
            .to_owned()
    }

    #[tokio::test]
    async fn write_error_preserves_partial_delivery_without_counting_unwritten_tail() {
        let history = Arc::new(History::default());
        let guard = history.begin(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:5678".parse().unwrap(),
        );
        let mut io = CountedIo::new(PartialThenError(3), guard.bytes(), Direction::Upstream);
        assert!(io.write_all(b"123456789").await.is_err());
        assert_eq!(current_bytes(&history, "bytes_upstream"), "3");
        assert_eq!(current_bytes(&history, "bytes_downstream"), "0");
        drop(io);
        drop(guard);
        let recent = serde_json::to_value(history.recent(None, 1)).unwrap();
        assert_eq!(recent["records"][0]["bytes_upstream"], "3");
        assert_eq!(recent["records"][0]["outcome"], "interrupted");
    }

    #[tokio::test]
    async fn cancelled_write_keeps_progress_and_read_ahead_is_not_delivery() {
        let history = Arc::new(History::default());
        let guard = history.begin(
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:5678".parse().unwrap(),
        );
        let (writer, mut peer) = tokio::io::duplex(4);
        let mut io = CountedIo::new(writer, guard.bytes(), Direction::Downstream);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                io.write_all(b"123456789")
            )
            .await
            .is_err()
        );
        assert_eq!(current_bytes(&history, "bytes_downstream"), "4");
        peer.write_all(b"read").await.unwrap();
        let mut bytes = [0; 4];
        io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"read");
        assert_eq!(current_bytes(&history, "bytes_upstream"), "0");
        assert_eq!(current_bytes(&history, "bytes_downstream"), "4");
    }
}
