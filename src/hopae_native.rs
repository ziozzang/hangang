//! Provider-independent, authenticated, bounded native Hopae client.
mod grpc;
use crate::hopae_wire as wire;
use hyper::{HeaderMap, Response};
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::Instant,
};
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
struct Connection {
    socket: Box<dyn Io>,
    created: Instant,
    used: Instant,
}
pub struct Client {
    grpc: Option<grpc::Client>,
    address: pumgye_client::Endpoint,
    tls: Option<(
        tokio_rustls::TlsConnector,
        rustls::pki_types::ServerName<'static>,
    )>,
    key: hyper::header::HeaderValue,
    idle: Mutex<Vec<Connection>>,
    slots: Semaphore,
    next: AtomicU64,
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid Hopae native exchange")
}
async fn read<S: AsyncRead + Unpin + ?Sized>(socket: &mut S) -> io::Result<(u64, Vec<u8>)> {
    let mut h = [0; 16];
    socket.read_exact(&mut h).await?;
    let (id, n) = wire::parse_header(h)?;
    let mut data = vec![0; n];
    socket.read_exact(&mut data).await?;
    Ok((id, data))
}
async fn write<S: AsyncWrite + Unpin + ?Sized>(
    socket: &mut S,
    id: u64,
    data: &[u8],
) -> io::Result<()> {
    let mut bytes = Vec::with_capacity(16 + data.len());
    bytes.extend_from_slice(&wire::frame_header(id, data.len())?);
    bytes.extend_from_slice(data);
    socket.write_all(&bytes).await
}
impl Client {
    pub fn from_config(
        settings: &crate::config::HopaeNative,
        key: hyper::header::HeaderValue,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=256).contains(&settings.pool_size),
            "invalid native Hopae pool size"
        );
        anyhow::ensure!(
            settings.address.is_loopback() || settings.tls.is_some(),
            "remote native Hopae requires mTLS"
        );
        settings.address.validate()?;
        if settings.transport == crate::config::HopaeTransport::Grpc {
            let grpc = grpc::Client::new(settings, &key)?;
            let mut client = Self::new(settings.address.clone(), settings.pool_size, key);
            client.grpc = Some(grpc);
            return Ok(client);
        }
        let mut client = Self::new(settings.address.clone(), settings.pool_size, key);
        if let Some(tls) = &settings.tls {
            client.tls = Some(crate::tls::mutual_client(
                &tls.ca,
                &tls.certificate,
                &tls.key,
                &tls.server_name,
                b"hop1",
            )?);
        }
        Ok(client)
    }
    pub fn new(
        address: impl Into<pumgye_client::Endpoint>,
        pool_size: usize,
        key: hyper::header::HeaderValue,
    ) -> Self {
        Self {
            grpc: None,
            address: address.into(),
            tls: None,
            key,
            idle: Mutex::new(Vec::with_capacity(pool_size)),
            slots: Semaphore::new(pool_size),
            next: AtomicU64::new(1),
        }
    }
    /// Separate native receipt phase. Unsupported transports refuse without fallback.
    pub async fn issue_service_receipt(
        &self,
        headers: &HeaderMap,
        scope: &crate::projection_receipt::ServiceScope<'_>,
        pin: &crate::projection_receipt::IssuerPin,
    ) -> io::Result<crate::projection_receipt::CheckedServiceReceipt> {
        self.grpc
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "receipt requires gRPC"))?
            .issue_service_receipt(headers, scope, pin)
            .await
    }

    pub async fn verify(&self, headers: &HeaderMap) -> io::Result<Response<crate::proxy::Body>> {
        if let Some(client) = &self.grpc {
            return client.verify(headers).await;
        }
        let _permit = self.slots.try_acquire().map_err(|_| {
            io::Error::new(io::ErrorKind::WouldBlock, "Hopae native capacity reached")
        })?;
        let mut connection = self
            .idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .filter(|c| {
                c.used.elapsed() < Duration::from_secs(25)
                    && c.created.elapsed() < Duration::from_secs(240)
            });
        if connection.is_none() {
            if self.tls.is_none() && !self.address.is_loopback() {
                return Err(invalid());
            }
            let socket = TcpStream::connect(self.address.as_str()).await?;
            socket.set_nodelay(true)?;
            let mut socket: Box<dyn Io> = if let Some((connector, name)) = &self.tls {
                let stream = connector.connect(name.clone(), socket).await?;
                if stream.get_ref().1.alpn_protocol() != Some(b"hop1".as_slice()) {
                    return Err(invalid());
                }
                Box::new(stream)
            } else {
                Box::new(socket)
            };
            write(&mut socket, 0, self.key.as_bytes()).await?;
            let (id, ack) = read(&mut socket).await?;
            if id != 0 || ack != [1] {
                return Err(invalid());
            }
            connection = Some(Connection {
                socket,
                created: Instant::now(),
                used: Instant::now(),
            });
        }
        let mut connection = connection.unwrap();
        let headers = headers
            .iter()
            .filter(|(n, _)| n.as_str() != "x-hopae-gateway-key")
            .map(|(n, v)| (n.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect::<Vec<_>>();
        let payload = wire::encode_request(&headers)?;
        let id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| invalid())?;
        write(&mut connection.socket, id, &payload).await?;
        let (reply_id, payload) = read(&mut connection.socket).await?;
        if reply_id != id {
            return Err(invalid());
        }
        let reply = wire::decode_reply(&payload)?;
        connection.used = Instant::now();
        self.idle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(connection);
        response(reply)
    }
}

fn response(reply: wire::Reply) -> io::Result<Response<crate::proxy::Body>> {
    let mut response = Response::builder()
        .status(reply.status)
        .body(crate::proxy::full_body(bytes::Bytes::from(reply.body)))
        .map_err(|_| invalid())?;
    for (name, value) in reply.headers {
        response.headers_mut().append(
            hyper::header::HeaderName::from_bytes(name.as_bytes()).map_err(|_| invalid())?,
            hyper::header::HeaderValue::from_bytes(&value).map_err(|_| invalid())?,
        );
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    fn headers() -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("cookie", "a=1".parse().unwrap());
        h
    }
    #[test]
    fn grpc_requires_mtls_even_on_loopback() {
        let settings = crate::config::HopaeNative {
            transport: crate::config::HopaeTransport::Grpc,
            address: "127.0.0.1:8703".parse().unwrap(),
            pool_size: 1,
            tls: None,
        };
        assert!(
            Client::from_config(
                &settings,
                hyper::header::HeaderValue::from_static("fixture-gateway-key")
            )
            .is_err()
        );
    }
    #[tokio::test]
    async fn mtls_verifies_server_name_ca_and_reuses_authenticated_pool() {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
            KeyPair,
        };
        let temp = tempfile::tempdir().unwrap();
        let mut ca_params = CertificateParams::new(vec![]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
        let mut server_params = CertificateParams::new(vec!["hopae.example.test".into()]).unwrap();
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_key = KeyPair::generate().unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap();
        let mut client_params = CertificateParams::new(vec![]).unwrap();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_key = KeyPair::generate().unwrap();
        let client_cert = client_params.signed_by(&client_key, &ca).unwrap();
        std::fs::write(temp.path().join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(temp.path().join("client.pem"), client_cert.pem()).unwrap();
        std::fs::write(temp.path().join("client.key"), client_key.serialize_pem()).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            std::sync::Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
            )
            .unwrap();
        server.alpn_protocols = vec![b"hop1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let (socket, _) = listener.accept().await.unwrap();
                let Ok(mut socket) = acceptor.accept(socket).await else {
                    continue;
                };
                let (id, key) = read(&mut socket).await.unwrap();
                assert_eq!((id, key), (0, b"fixture-key".to_vec()));
                write(&mut socket, 0, &[1]).await.unwrap();
                for _ in 0..2 {
                    let (id, _) = read(&mut socket).await.unwrap();
                    let reply = wire::Reply {
                        status: 403,
                        headers: vec![],
                        body: vec![],
                    };
                    write(&mut socket, id, &wire::encode_reply(&reply).unwrap())
                        .await
                        .unwrap();
                }
                break;
            }
        });
        let mut settings = crate::config::HopaeNative {
            transport: crate::config::HopaeTransport::Native,
            address: format!("localhost:{}", address.port()).parse().unwrap(),
            pool_size: 1,
            tls: Some(crate::config::HopaeNativeTls {
                server_name: "wrong.example.test".into(),
                ca: temp.path().join("ca.pem"),
                certificate: temp.path().join("client.pem"),
                key: temp.path().join("client.key"),
            }),
        };
        let bad = Client::from_config(&settings, "fixture-key".parse().unwrap()).unwrap();
        assert!(bad.verify(&headers()).await.is_err());
        settings.tls.as_mut().unwrap().server_name = "hopae.example.test".into();
        let mut other = CertificateParams::new(vec![]).unwrap();
        other.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let other = CertifiedIssuer::self_signed(other, KeyPair::generate().unwrap()).unwrap();
        std::fs::write(temp.path().join("other-ca.pem"), other.pem()).unwrap();
        settings.tls.as_mut().unwrap().ca = temp.path().join("other-ca.pem");
        let untrusted = Client::from_config(&settings, "fixture-key".parse().unwrap()).unwrap();
        assert!(untrusted.verify(&headers()).await.is_err());
        settings.tls.as_mut().unwrap().ca = temp.path().join("ca.pem");
        let good = Client::from_config(&settings, "fixture-key".parse().unwrap()).unwrap();
        for _ in 0..2 {
            assert_eq!(good.verify(&headers()).await.unwrap().status(), 403);
        }
        task.await.unwrap();
    }
    #[tokio::test]
    async fn reuses_authenticated_connection_and_preserves_multiple_cookies() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (id, key) = read(&mut socket).await.unwrap();
            assert_eq!(id, 0);
            assert_eq!(key, b"fixture-key");
            write(&mut socket, 0, &[1]).await.unwrap();
            for _ in 0..2 {
                let (id, p) = read(&mut socket).await.unwrap();
                assert!(id > 0);
                assert!(
                    wire::decode_request(&p)
                        .unwrap()
                        .iter()
                        .any(|(n, v)| n == "cookie" && v == b"a=1")
                );
                let reply = wire::Reply {
                    status: 302,
                    headers: vec![
                        ("set-cookie".into(), b"a=2".to_vec()),
                        ("set-cookie".into(), b"b=3".to_vec()),
                    ],
                    body: b"redirect".to_vec(),
                };
                write(&mut socket, id, &wire::encode_reply(&reply).unwrap())
                    .await
                    .unwrap();
            }
        });
        let client = Client::new(address, 1, "fixture-key".parse().unwrap());
        for _ in 0..2 {
            let r = client.verify(&headers()).await.unwrap();
            assert_eq!(r.status(), 302);
            assert_eq!(r.headers().get_all("set-cookie").iter().count(), 2);
        }
        task.await.unwrap();
    }
    #[tokio::test]
    async fn canceled_exchange_discards_socket_and_saturation_does_not_queue() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (seen, waiting) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read(&mut socket).await.unwrap();
            write(&mut socket, 0, &[1]).await.unwrap();
            let _ = read(&mut socket).await.unwrap();
            seen.send(()).unwrap();
            let mut one = [0];
            assert_eq!(socket.read(&mut one).await.unwrap(), 0);
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read(&mut socket).await.unwrap();
            write(&mut socket, 0, &[1]).await.unwrap();
            let (id, _) = read(&mut socket).await.unwrap();
            let reply = wire::Reply {
                status: 403,
                headers: vec![],
                body: vec![],
            };
            write(&mut socket, id, &wire::encode_reply(&reply).unwrap())
                .await
                .unwrap();
        });
        let client = std::sync::Arc::new(Client::new(address, 1, "fixture-key".parse().unwrap()));
        let c = client.clone();
        let active = tokio::spawn(async move { c.verify(&headers()).await });
        waiting.await.unwrap();
        assert_eq!(
            client.verify(&headers()).await.err().unwrap().kind(),
            io::ErrorKind::WouldBlock
        );
        active.abort();
        let _ = active.await;
        assert_eq!(client.verify(&headers()).await.unwrap().status(), 403);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn mismatched_response_id_fails_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let _ = read(&mut s).await.unwrap();
            write(&mut s, 0, &[1]).await.unwrap();
            let (id, _) = read(&mut s).await.unwrap();
            write(
                &mut s,
                id + 1,
                &wire::encode_reply(&wire::Reply {
                    status: 200,
                    headers: vec![],
                    body: vec![],
                })
                .unwrap(),
            )
            .await
            .unwrap();
        });
        let c = Client::new(address, 1, "fixture-key".parse().unwrap());
        assert!(c.verify(&headers()).await.is_err());
        task.await.unwrap();
    }
}
