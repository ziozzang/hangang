//! Narrow Docker-network adapters for a host-network data plane.
//! Egress accepts only a private Unix socket and has one fixed destination.
//! DNS is a bounded UDP/TCP forwarder; deploy it only on a private network.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use hangang::{admin_socket::BoundAdminSocket, idle::IdleIo};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

#[derive(Parser)]
struct Args {
    #[arg(long, requires = "egress_target")]
    egress_unix: Option<PathBuf>,
    #[arg(long, requires = "egress_unix")]
    egress_target: Option<String>,
    #[arg(long)]
    dns_listen: Option<SocketAddr>,
    #[arg(long, default_value = "127.0.0.11:53")]
    dns_upstream: SocketAddr,
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    #[arg(long, default_value_t = 86400)]
    idle_seconds: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.egress_unix.is_some() || args.dns_listen.is_some(),
        "enable at least one adapter"
    );
    ensure!(
        (1..=16384).contains(&args.max_connections),
        "invalid connection limit"
    );
    ensure!(
        (1..=86400).contains(&args.idle_seconds),
        "invalid idle timeout"
    );
    let mut tasks = JoinSet::new();
    if let Some(path) = args.egress_unix {
        let listener = BoundAdminSocket::bind(&path)?;
        let target = args.egress_target.context("missing fixed egress target")?;
        ensure!(
            !target.contains('/') && target.rsplit_once(':').is_some(),
            "invalid egress target"
        );
        tasks.spawn(egress(
            listener,
            target,
            args.max_connections,
            Duration::from_secs(args.idle_seconds),
        ));
    }
    if let Some(address) = args.dns_listen {
        ensure!(address.port() != 0, "DNS port must not be zero");
        let udp = Arc::new(UdpSocket::bind(address).await.context("bind DNS UDP")?);
        let tcp = TcpListener::bind(address).await.context("bind DNS TCP")?;
        // Separate admission budgets prevent long TCP sessions starving UDP.
        tasks.spawn(dns_udp(
            udp,
            args.dns_upstream,
            args.max_connections.min(512),
        ));
        tasks.spawn(dns_tcp(
            tcp,
            args.dns_upstream,
            args.max_connections.min(512),
        ));
    }
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = term.recv() => {},
        result = tasks.join_next() => { result.context("adapter exited")???; anyhow::bail!("adapter unexpectedly stopped"); }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn egress(
    listener: BoundAdminSocket,
    target: String,
    limit: usize,
    idle: Duration,
) -> Result<()> {
    let permits = Arc::new(Semaphore::new(limit));
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (client, _) = result.context("accept fixed egress")?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                let target = target.clone();
                sessions.spawn(async move {
                    let _permit = permit;
                    let Ok(Ok(mut upstream)) = timeout(Duration::from_secs(3), TcpStream::connect(target)).await else { return };
                    let (mut client, watch) = IdleIo::new(client, idle);
                    tokio::select! {
                        _ = copy_bidirectional(&mut client, &mut upstream) => {},
                        _ = watch.expired() => {},
                    }
                });
            },
            _ = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

async fn dns_udp(listener: Arc<UdpSocket>, upstream: SocketAddr, limit: usize) -> Result<()> {
    let permits = Arc::new(Semaphore::new(limit));
    let mut sessions = JoinSet::new();
    let mut packet = vec![0; 65535];
    loop {
        tokio::select! {
            result = listener.recv_from(&mut packet) => {
                let (size, peer) = result.context("read DNS UDP")?;
                if size < 12 || packet[2] & 0x80 != 0 { continue }
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                let query = packet[..size].to_vec();
                let listener = listener.clone();
                sessions.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(Duration::from_secs(3), async {
                        let socket = UdpSocket::bind(if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }).await?;
                        socket.connect(upstream).await?;
                        socket.send(&query).await?;
                        let mut response = vec![0; 65535];
                        let size = socket.recv(&mut response).await?;
                        if size >= 12 && response[..2] == query[..2] && response[2] & 0x80 != 0 {
                            listener.send_to(&response[..size], peer).await?;
                        }
                        Ok::<_, std::io::Error>(())
                    }).await;
                });
            },
            _ = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

async fn dns_tcp(listener: TcpListener, upstream: SocketAddr, limit: usize) -> Result<()> {
    let permits = Arc::new(Semaphore::new(limit));
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            result = listener.accept() => {
                let (mut client, _) = result.context("accept DNS TCP")?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue };
                sessions.spawn(async move {
                    let _permit = permit;
                    let _ = timeout(Duration::from_secs(10), async {
                        let mut remote = TcpStream::connect(upstream).await?;
                        copy_bidirectional(&mut client, &mut remote).await
                    }).await;
                });
            },
            _ = sessions.join_next(), if !sessions.is_empty() => {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::UnixStream,
    };

    #[tokio::test]
    async fn fixed_egress_preserves_bytes_and_half_close() {
        let directory = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("egress.sock");
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = BoundAdminSocket::bind(&path).unwrap();
        let task = tokio::spawn(egress(
            listener,
            upstream.local_addr().unwrap().to_string(),
            2,
            Duration::from_secs(1),
        ));
        let mut client = UnixStream::connect(&path).await.unwrap();
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        server.write_all(b"response after EOF").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(2), client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"response after EOF");
        task.abort();
        let _ = task.await;
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn udp_dns_forwards_only_matching_response() {
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(dns_udp(listener, remote.local_addr().unwrap(), 2));
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut query = [0; 12];
        query[..2].copy_from_slice(&[0x12, 0x34]);
        for matches in [true, false] {
            client.send_to(&query, address).await.unwrap();
            let mut packet = [0; 12];
            let (n, peer) = timeout(Duration::from_secs(1), remote.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&packet[..n], query);
            packet[2] |= 0x80;
            if !matches {
                packet[0] ^= 1;
            }
            remote.send_to(&packet, peer).await.unwrap();
            let received = timeout(Duration::from_millis(150), client.recv_from(&mut query)).await;
            assert_eq!(received.is_ok(), matches);
            query[2] = 0;
        }
        task.abort();
    }

    #[tokio::test]
    async fn dns_tcp_preserves_length_framing_and_large_reply() {
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(dns_tcp(listener, remote.local_addr().unwrap(), 2));
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(&[0, 12, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (mut server, _) = remote.accept().await.unwrap();
        let mut query = [0; 14];
        server.read_exact(&mut query).await.unwrap();
        assert_eq!(&query[..4], &[0, 12, 1, 2]);
        let response = vec![42; 4096];
        server.write_all(&response).await.unwrap();
        let mut received = vec![0; response.len()];
        timeout(Duration::from_secs(2), client.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, response);
        task.abort();
    }
}
