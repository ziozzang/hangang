//! Native bounded PPG1 client. Endpoint configuration is trusted; errors never grant access.
mod endpoint;
pub use endpoint::Endpoint;

use anyhow::{Context, Result, ensure};
use pumgye_protocol::{MAX_QUERY, Query, REPLY_SIZE, Reply};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use rustls_pki_types::pem::PemObject;
use std::{
    io::Read,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{Mutex, Semaphore},
    time::timeout,
};
use tokio_rustls::TlsConnector;
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
struct Connection {
    stream: Box<dyn Io>,
    created: Instant,
    last_used: Instant,
}
#[derive(Clone)]
pub struct Tls {
    config: Arc<ClientConfig>,
    name: ServerName<'static>,
}
impl Tls {
    pub fn from_files(server_name: &str, ca: &Path, cert: &Path, key: &Path) -> Result<Self> {
        fn bytes(path: &Path) -> Result<Vec<u8>> {
            let mut bytes = Vec::new();
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC);
            }
            let file = options.open(path)?;
            let meta = file.metadata()?;
            ensure!(meta.is_file(), "TLS material is not a regular file");
            ensure!(meta.len() <= 1024 * 1024, "TLS material exceeds bound");
            file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
            ensure!(bytes.len() <= 1024 * 1024, "TLS material exceeds bound");
            Ok(bytes)
        }
        let ca = bytes(ca)?;
        let cert = bytes(cert)?;
        let key = bytes(key)?;
        let mut roots = RootCertStore::empty();
        for cert in rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca.as_slice()) {
            roots.add(cert?)?;
        }
        ensure!(!roots.is_empty(), "server CA must not be empty");
        let certs = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cert.as_slice())
            .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()?;
        let key = rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key.as_slice())
            .context("invalid or missing client private key")?;
        let mut config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)?;
        config.alpn_protocols = vec![b"ppg1".to_vec()];
        config.enable_early_data = false;
        Ok(Self {
            config: Arc::new(config),
            name: ServerName::try_from(server_name.to_owned())?,
        })
    }
}
pub struct Client {
    address: Endpoint,
    tls: Option<Tls>,
    credential: String,
    capacity: Semaphore,
    pool: Mutex<Vec<Connection>>,
    deadline: Duration,
    revision: AtomicU64,
    sequence: AtomicU64,
}
impl Client {
    pub fn new(
        address: impl Into<Endpoint>,
        tls: Option<Tls>,
        credential: String,
        pool_size: usize,
        deadline: Duration,
        minimum_revision: u64,
    ) -> Result<Self> {
        let address = address.into();
        address.validate()?;
        ensure!(
            address.is_loopback() || tls.is_some(),
            "remote PPG1 clients require mTLS"
        );
        ensure!(
            (16..=4096).contains(&credential.len())
                && credential.bytes().all(|b| (0x21..=0x7e).contains(&b)),
            "invalid service credential"
        );
        ensure!(
            (1..=1024).contains(&pool_size)
                && (Duration::from_millis(1)..=Duration::from_secs(5)).contains(&deadline),
            "invalid pool or deadline"
        );
        ensure!(minimum_revision > 0, "minimum revision must be positive");
        Ok(Self {
            address,
            tls,
            credential,
            capacity: Semaphore::new(pool_size),
            pool: Mutex::new(Vec::with_capacity(pool_size)),
            deadline,
            revision: AtomicU64::new(minimum_revision),
            sequence: AtomicU64::new(1),
        })
    }
    pub fn require_revision(&self, revision: u64) {
        self.revision.fetch_max(revision, Ordering::AcqRel);
    }
    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Acquire)
    }
    fn request_id(&self) -> Result<u64> {
        self.sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
            .map_err(|_| anyhow::anyhow!("request sequence exhausted"))
    }
    async fn connection(&self) -> Result<Connection> {
        while let Some(conn) = self.pool.lock().await.pop() {
            if conn.created.elapsed() < Duration::from_secs(240)
                && conn.last_used.elapsed() < Duration::from_secs(20)
            {
                return Ok(conn);
            }
        }
        let socket = TcpStream::connect(self.address.as_str()).await?;
        socket.set_nodelay(true)?;
        let mut stream: Box<dyn Io> = if let Some(tls) = &self.tls {
            let stream = TlsConnector::from(tls.config.clone())
                .connect(tls.name.clone(), socket)
                .await?;
            ensure!(
                stream.get_ref().1.alpn_protocol() == Some(b"ppg1"),
                "native ALPN mismatch"
            );
            Box::new(stream)
        } else {
            Box::new(socket)
        };
        let mut hello = Vec::with_capacity(6 + self.credential.len());
        hello.extend_from_slice(pumgye_protocol::HELLO);
        hello.extend_from_slice(&(self.credential.len() as u16).to_be_bytes());
        hello.extend_from_slice(self.credential.as_bytes());
        stream.write_all(&hello).await?;
        let mut ack = [0; 4];
        stream.read_exact(&mut ack).await?;
        ensure!(&ack == pumgye_protocol::ACK, "native handshake rejected");
        Ok(Connection {
            stream,
            created: Instant::now(),
            last_used: Instant::now(),
        })
    }
    /// One fresh decision. Cancellation/errors discard the connection and its correlation state.
    pub async fn decide(&self, query: &Query<'_>) -> Result<Reply> {
        timeout(self.deadline, async {
            let _permit = self.capacity.acquire().await?;
            let mut connection = self.connection().await?;
            let mut query = *query;
            query.request_id = self.request_id()?;
            query.minimum_revision = query.minimum_revision.max(self.revision());
            let mut body = [0; MAX_QUERY];
            let len = query.encode(&mut body)?;
            let mut frame = [0; MAX_QUERY + 2];
            frame[..2].copy_from_slice(&(len as u16).to_be_bytes());
            frame[2..2 + len].copy_from_slice(&body[..len]);
            connection.stream.write_all(&frame[..2 + len]).await?;
            let mut bytes = [0; REPLY_SIZE];
            connection.stream.read_exact(&mut bytes).await?;
            let reply = Reply::decode(&bytes)?;
            self.validate(&query, reply)?;
            connection.last_used = Instant::now();
            self.pool.lock().await.push(connection);
            Ok(reply)
        })
        .await?
    }
    /// Up to 64 requests written together and answered in order; no unbounded pipeline.
    pub async fn decide_batch(&self, queries: &[Query<'_>]) -> Result<Vec<Reply>> {
        ensure!(
            !queries.is_empty() && queries.len() <= 64,
            "invalid native batch size"
        );
        timeout(self.deadline, async {
            let _permit = self.capacity.acquire().await?;
            let mut connection = self.connection().await?;
            let mut frame = [0; (MAX_QUERY + 2) * 64];
            let mut used = 0;
            let mut sent = Vec::with_capacity(queries.len());
            for query in queries {
                let mut query = *query;
                query.request_id = self.request_id()?;
                query.minimum_revision = query.minimum_revision.max(self.revision());
                let mut body = [0; MAX_QUERY];
                let len = query.encode(&mut body)?;
                frame[used..used + 2].copy_from_slice(&(len as u16).to_be_bytes());
                frame[used + 2..used + 2 + len].copy_from_slice(&body[..len]);
                used += 2 + len;
                sent.push(query);
            }
            connection.stream.write_all(&frame[..used]).await?;
            let mut bytes = [0; REPLY_SIZE * 64];
            connection
                .stream
                .read_exact(&mut bytes[..REPLY_SIZE * queries.len()])
                .await?;
            let mut replies = Vec::with_capacity(queries.len());
            for (query, bytes) in sent.iter().zip(bytes.chunks_exact(REPLY_SIZE)) {
                let reply = Reply::decode(bytes.try_into()?)?;
                self.validate(query, reply)?;
                replies.push(reply);
            }
            let floor = self.revision();
            ensure!(
                replies.iter().all(|r| r.revision >= floor),
                "mixed or stale authority revisions"
            );
            connection.last_used = Instant::now();
            self.pool.lock().await.push(connection);
            Ok(replies)
        })
        .await?
    }
    fn validate(&self, query: &Query<'_>, reply: Reply) -> Result<()> {
        ensure!(
            reply.request_id == query.request_id
                && reply.revision >= query.minimum_revision
                && reply.revision >= self.revision(),
            "mismatched or stale authority reply"
        );
        self.require_revision(reply.revision);
        ensure!(reply.decision.is_some(), "authority unavailable or stale");
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_plaintext_and_invalid_limits_are_rejected() {
        let token = "fixture-credential-only".to_string();
        for name in ["localhost:9085", "pumgye.world.svc:9085"] {
            assert!(
                Client::new(
                    name.parse::<Endpoint>().unwrap(),
                    None,
                    token.clone(),
                    64,
                    Duration::from_millis(100),
                    1
                )
                .is_err()
            );
        }
        assert!(
            Client::new(
                "192.0.2.1:9085".parse::<Endpoint>().unwrap(),
                None,
                token.clone(),
                64,
                Duration::from_millis(100),
                1
            )
            .is_err()
        );
        assert!(
            Client::new(
                "127.0.0.1:9085".parse::<Endpoint>().unwrap(),
                None,
                token.clone(),
                0,
                Duration::from_millis(100),
                1
            )
            .is_err()
        );
        assert!(
            Client::new(
                "127.0.0.1:9085".parse::<Endpoint>().unwrap(),
                None,
                token,
                64,
                Duration::from_millis(100),
                0
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn correlation_failure_discards_connection_and_recovers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for bad in [true, false] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut magic = [0; 4];
                socket.read_exact(&mut magic).await.unwrap();
                assert_eq!(&magic, pumgye_protocol::HELLO);
                let len = socket.read_u16().await.unwrap();
                let mut token = vec![0; len as usize];
                socket.read_exact(&mut token).await.unwrap();
                assert_eq!(token, b"fixture-credential-only");
                socket.write_all(pumgye_protocol::ACK).await.unwrap();
                let len = socket.read_u16().await.unwrap();
                let mut frame = vec![0; len as usize];
                socket.read_exact(&mut frame).await.unwrap();
                let q = Query::decode(&frame).unwrap();
                socket
                    .write_all(
                        &Reply {
                            request_id: q.request_id + u64::from(bad),
                            revision: 1,
                            decision: Some(pumgye_protocol::Decision::Allow),
                        }
                        .encode(),
                    )
                    .await
                    .unwrap();
            }
        });
        let client = Client::new(
            address,
            None,
            "fixture-credential-only".into(),
            1,
            Duration::from_secs(1),
            1,
        )
        .unwrap();
        let q = Query {
            request_id: 0,
            minimum_revision: 0,
            ip: "192.0.2.8".parse().unwrap(),
            aal: 1,
            guard: pumgye_protocol::GuardEvidence::EnforcedAllow,
            service_id: "orders",
            subject: "fixture",
            permission: "read",
            information_class: "public",
        };
        assert!(client.decide(&q).await.is_err());
        assert_eq!(client.revision(), 1);
        assert_eq!(
            client.decide(&q).await.unwrap().decision,
            Some(pumgye_protocol::Decision::Allow)
        );
        server.await.unwrap();
    }
}

#[cfg(test)]
mod pem_security_tests {
    use super::*;
    #[test]
    fn migrated_pem_accepts_matching_material_and_refuses_bad_or_large_input() {
        let directory = tempfile::tempdir().unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        std::fs::write(&cert, pair.cert.pem()).unwrap();
        std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
        let config = Tls::from_files("localhost", &cert, &cert, &key).unwrap();
        assert!(config.config.cert_compressors.is_empty());
        assert!(config.config.cert_decompressors.is_empty());
        std::fs::write(&key, b"no private key").unwrap();
        assert!(Tls::from_files("localhost", &cert, &cert, &key).is_err());
        std::fs::File::create(&cert)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        assert!(Tls::from_files("localhost", &cert, &cert, &key).is_err());
    }
}
