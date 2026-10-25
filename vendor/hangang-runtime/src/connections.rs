//! Domain-neutral TCP task ownership. Handlers retain TLS, framing and decisions.
use std::{future::Future, io, net::SocketAddr, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

/// Reject excess accepted sockets immediately; hold capacity for the entire handler.
/// Dropping this server aborts its owned handlers. Normal shutdown drains up to the
/// supplied bound, then aborts and joins unfinished handlers.
pub async fn serve_connections<H, F, S>(
    listener: TcpListener,
    capacity: NonZeroUsize,
    drain: Duration,
    handler: H,
    shutdown: S,
) -> io::Result<()>
where
    H: Fn(TcpStream, SocketAddr) -> F,
    F: Future<Output = ()> + Send + 'static,
    S: Future<Output = ()>,
{
    if capacity.get() > Semaphore::MAX_PERMITS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "connection capacity exceeds semaphore bound",
        ));
    }
    let slots = Arc::new(Semaphore::new(capacity.get()));
    let mut tasks = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! { biased;
            _=&mut shutdown=>break,
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (socket,peer)=accepted?;
                let Ok(permit)=slots.clone().try_acquire_owned() else {continue;};
                // A per-client socket failure must not kill the owning listener.
                if socket.set_nodelay(true).is_err(){continue;}
                let work=handler(socket,peer);
                tasks.spawn(async move {let _permit=permit;work.await;});
            }
        }
    }
    if timeout(drain, async { while tasks.join_next().await.is_some() {} })
        .await
        .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        sync::oneshot,
    };
    #[tokio::test]
    async fn capacity_is_held_until_disconnect_and_shutdown_releases_owned_tasks() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, shutdown) = oneshot::channel();
        let running = tokio::spawn(serve_connections(
            listener,
            NonZeroUsize::new(1).unwrap(),
            Duration::from_millis(20),
            |mut socket, peer| async move {
                assert!(peer.ip().is_loopback());
                assert!(socket.nodelay().unwrap());
                socket.write_all(b"A").await.unwrap();
                let _ = socket.read_u8().await;
            },
            async {
                let _ = shutdown.await;
            },
        ));
        let mut first = TcpStream::connect(address).await.unwrap();
        assert_eq!(first.read_u8().await.unwrap(), b'A');
        let mut refused = TcpStream::connect(address).await.unwrap();
        assert_eq!(
            timeout(Duration::from_secs(2), refused.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        drop(first);
        // Await actual completion rather than sleeping to guess capacity release.
        let mut replacement = timeout(Duration::from_secs(2), async {
            loop {
                let mut socket = TcpStream::connect(address).await.unwrap();
                if socket.read_u8().await.is_ok() {
                    break socket;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        running.await.unwrap().unwrap();
        assert_eq!(
            replacement.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
    #[tokio::test]
    async fn dropping_server_aborts_connections_without_detaching() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let running = tokio::spawn(serve_connections(
            listener,
            NonZeroUsize::new(1).unwrap(),
            Duration::from_secs(1),
            |mut socket, _| async move {
                socket.write_all(b"A").await.unwrap();
                std::future::pending::<()>().await;
            },
            std::future::pending(),
        ));
        let mut socket = TcpStream::connect(address).await.unwrap();
        assert_eq!(socket.read_u8().await.unwrap(), b'A');
        running.abort();
        assert!(running.await.unwrap_err().is_cancelled());
        assert_eq!(
            timeout(Duration::from_secs(2), socket.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
