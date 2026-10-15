//! Read-only native route observations on a separately authenticated mTLS server.
use crate::native_route_owner::Registry;
use anyhow::{Result, ensure};
use hangang_route_grpc::v1::{
    RouteReply, RouteRequest,
    route_ownership_server::{RouteOwnership, RouteOwnershipServer},
};
use serde::Deserialize;
use std::{
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use subtle::ConstantTimeEq;
use tokio::net::TcpListener;
use tonic::{Request, Response, Status, transport::ServerTlsConfig};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub listen: SocketAddr,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub client_ca: PathBuf,
    pub token_env: String,
}
impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        ensure!(
            file.metadata()?.is_file(),
            "route owner configuration must be a file"
        );
        let mut bytes = Vec::new();
        file.take(16 * 1024 + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() <= 16 * 1024,
            "route owner configuration exceeds bound"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }
}
#[derive(Clone)]
struct Service {
    registry: Arc<Registry>,
    credential: Arc<str>,
    admission: Arc<tokio::sync::Semaphore>,
    available: Arc<AtomicBool>,
}
impl Service {
    fn authorized(&self, metadata: &tonic::metadata::MetadataMap) -> bool {
        let mut values = metadata.get_all("authorization").iter();
        let Some(value) = values
            .next()
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return false;
        };
        values.next().is_none()
            && value.len() == self.credential.len()
            && bool::from(value.as_bytes().ct_eq(self.credential.as_bytes()))
    }
}
#[tonic::async_trait]
impl RouteOwnership for Service {
    async fn observe(
        &self,
        request: Request<RouteRequest>,
    ) -> Result<Response<RouteReply>, Status> {
        if !self.authorized(request.metadata()) {
            return Err(Status::unauthenticated(
                "route decision credential required",
            ));
        }
        if !self.available.load(Ordering::Acquire) {
            return Err(Status::unavailable("route server retired"));
        }
        let _admission = self
            .admission
            .try_acquire()
            .map_err(|_| Status::resource_exhausted("route observation capacity"))?;
        let input = request.into_inner();
        if !(1..=9_007_199_254_740_991).contains(&input.request_id) {
            return Err(Status::invalid_argument("invalid request id"));
        }
        let reference = input
            .reference
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid reference"))?;
        let digest = input
            .request_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid request digest"))?;
        let destination = input
            .destination_sha256
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("invalid destination digest"))?;
        let reply = self
            .registry
            .observe(reference, digest, destination, input.request_id)
            .ok_or_else(|| Status::unavailable("route owner unavailable"))?;
        if !self.available.load(Ordering::Acquire) {
            return Err(Status::unavailable("route server retired"));
        }
        Ok(Response::new(reply))
    }
}
/// No Debug/Clone/serialization. Binding validates dedicated credentials and
/// mandatory client certificates; a caller cannot supply optional-auth TLS.
pub struct Server {
    listener: TcpListener,
    tls: ServerTlsConfig,
    service: Service,
}
impl Server {
    pub(crate) async fn bind(
        configuration: Configuration,
        registry: Arc<Registry>,
        forbidden_credentials: &[&str],
    ) -> Result<Self> {
        Self::bind_resolved(configuration, registry, forbidden_credentials, &|name| {
            std::env::var(name).ok()
        })
        .await
    }
    async fn bind_resolved(
        configuration: Configuration,
        registry: Arc<Registry>,
        forbidden_credentials: &[&str],
        resolve: &(dyn Fn(&str) -> Option<String> + Sync),
    ) -> Result<Self> {
        ensure!(
            !configuration.token_env.is_empty()
                && configuration.token_env.len() <= 128
                && configuration
                    .token_env
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid route credential reference"
        );
        let credential = resolve(&configuration.token_env)
            .ok_or_else(|| anyhow::anyhow!("route credential unavailable"))?;
        ensure!(
            (32..=256).contains(&credential.len())
                && credential.bytes().all(|byte| byte.is_ascii_graphic())
                && forbidden_credentials
                    .iter()
                    .all(|other| credential.as_bytes() != other.as_bytes()),
            "route credential must be distinct and bounded"
        );
        let tls = hangang_runtime::configuration(
            &configuration.certificate,
            &configuration.key,
            &configuration.client_ca,
        )?;
        // Validate the shared mandatory-mTLS builder before opening a socket.
        hangang_runtime::server(tls.clone())?;
        let listener = TcpListener::bind(configuration.listen).await?;
        Ok(Self {
            listener,
            tls,
            service: Service {
                registry,
                credential: credential.into(),
                admission: Arc::new(tokio::sync::Semaphore::new(4096)),
                available: Arc::new(AtomicBool::new(true)),
            },
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }
    pub async fn serve(
        self,
        shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ) -> Result<()> {
        struct Retire(Arc<AtomicBool>);
        impl Drop for Retire {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Release);
            }
        }
        // Fence any retained service tasks when this owner future is cancelled.
        let _retire = Retire(self.service.available.clone());
        hangang_runtime::server(self.tls)?
            .add_service(
                RouteOwnershipServer::new(self.service)
                    .max_decoding_message_size(512)
                    .max_encoding_message_size(1024),
            )
            .serve_with_incoming_shutdown(hangang_runtime::incoming(self.listener), shutdown)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangang_route_grpc::v1::route_ownership_client::RouteOwnershipClient;
    use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};
    const TOKEN: &str = "owned-route-decision-credential-00000001";
    fn resources(root: &Path) -> Configuration {
        Configuration {
            listen: "127.0.0.1:0".parse().unwrap(),
            certificate: root.join("server.pem"),
            key: root.join("server.key"),
            client_ca: root.join("ca.pem"),
            token_env: "OWNED_ROUTE_TOKEN".into(),
        }
    }
    fn tls(root: &Path) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .domain_name("route.example.test")
            .ca_certificate(Certificate::from_pem(
                std::fs::read(root.join("ca.pem")).unwrap(),
            ))
            .identity(Identity::from_pem(
                std::fs::read(root.join("client.pem")).unwrap(),
                std::fs::read(root.join("client.key")).unwrap(),
            ))
    }
    fn certificates(root: &Path) {
        use rcgen::{
            BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
            KeyPair,
        };
        let mut parameters = CertificateParams::new(vec![]).unwrap();
        parameters.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = CertifiedIssuer::self_signed(parameters, KeyPair::generate().unwrap()).unwrap();
        std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();
        for (name, usages, names) in [
            (
                "server",
                vec![ExtendedKeyUsagePurpose::ServerAuth],
                vec!["route.example.test".into()],
            ),
            ("client", vec![ExtendedKeyUsagePurpose::ClientAuth], vec![]),
        ] {
            let mut parameters = CertificateParams::new(names).unwrap();
            parameters.extended_key_usages = usages;
            let key = KeyPair::generate().unwrap();
            let certificate = parameters.signed_by(&key, &ca).unwrap();
            std::fs::write(root.join(format!("{name}.pem")), certificate.pem()).unwrap();
            std::fs::write(root.join(format!("{name}.key")), key.serialize_pem()).unwrap();
        }
    }
    fn authenticated(input: RouteRequest) -> Request<RouteRequest> {
        let mut request = Request::new(input);
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {TOKEN}").parse().unwrap());
        request.set_timeout(std::time::Duration::from_secs(1));
        request
    }
    #[tokio::test]
    async fn credentials_are_reference_only_distinct_and_checked_before_tls_or_bind() {
        let (registry, _, _, _) = crate::native_route_owner::tests::fixture(1).await;
        let root = tempfile::tempdir().unwrap();
        let missing = resources(root.path());
        assert!(
            Server::bind_resolved(missing, registry.clone(), &[], &|_| None)
                .await
                .is_err()
        );
        assert!(
            Server::bind_resolved(resources(root.path()), registry.clone(), &[TOKEN], &|_| {
                Some(TOKEN.into())
            })
            .await
            .is_err()
        );
        let mut invalid = resources(root.path());
        invalid.token_env = "BAD=REFERENCE".into();
        assert!(
            Server::bind_resolved(invalid, registry.clone(), &[], &|_| panic!(
                "must not resolve invalid references"
            ))
            .await
            .is_err()
        );
        for value in ["short".into(), " ".repeat(40), "x".repeat(257)] {
            assert!(
                Server::bind_resolved(resources(root.path()), registry.clone(), &[], &|_| Some(
                    value.clone()
                ))
                .await
                .is_err()
            );
        }
        let config = root.path().join("config.json");
        std::fs::write(&config, b"{\"token\":\"inline-not-supported\"}").unwrap();
        assert!(Configuration::load(&config).is_err());
        std::fs::write(&config, vec![b' '; 16 * 1024 + 1]).unwrap();
        assert!(Configuration::load(&config).is_err());
    }
    #[tokio::test]
    async fn admission_precedes_lookup_and_malformed_context() {
        let (registry, _, _, _) = crate::native_route_owner::tests::fixture(1).await;
        let service = Service {
            registry,
            credential: TOKEN.into(),
            admission: Arc::new(tokio::sync::Semaphore::new(0)),
            available: Arc::new(AtomicBool::new(true)),
        };
        assert_eq!(
            service
                .observe(Request::new(RouteRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            service
                .observe(authenticated(RouteRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::ResourceExhausted
        );
        service.available.store(false, Ordering::Release);
        assert_eq!(
            service
                .observe(authenticated(RouteRequest::default()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
    }
    #[tokio::test]
    async fn cancelling_the_server_fences_retained_authenticated_connections() {
        let (registry, snapshot, runtime, prepared) =
            crate::native_route_owner::tests::fixture(1).await;
        let root = tempfile::tempdir().unwrap();
        certificates(root.path());
        let server = Server::bind_resolved(resources(root.path()), registry.clone(), &[], &|_| {
            Some(TOKEN.into())
        })
        .await
        .unwrap();
        let available = server.service.available.clone();
        let address = format!("https://{}", server.local_addr().unwrap());
        let task = tokio::spawn(server.serve(std::future::pending()));
        let channel = Endpoint::from_shared(address)
            .unwrap()
            .tls_config(tls(root.path()))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = RouteOwnershipClient::new(channel);
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, "192.0.2.9".parse().unwrap())
            .unwrap();
        let input = capture.request(9);
        assert!(client.observe(authenticated(input.clone())).await.is_ok());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!available.load(Ordering::Acquire));
        assert!(client.observe(authenticated(input)).await.is_err());
    }
    #[tokio::test]
    async fn actual_mtls_observes_native_scope_and_refuses_credential_binding_and_owner_failures() {
        use std::time::Duration;
        let (registry, snapshot, runtime, prepared) =
            crate::native_route_owner::tests::fixture(8).await;
        let root = tempfile::tempdir().unwrap();
        certificates(root.path());
        let server = Server::bind_resolved(resources(root.path()), registry.clone(), &[], &|_| {
            Some(TOKEN.into())
        })
        .await
        .unwrap();
        let address = format!("https://{}", server.local_addr().unwrap());
        let (shutdown, ending) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve(async move {
            let _ = ending.await;
        }));
        let channel = Endpoint::from_shared(address.clone())
            .unwrap()
            .tls_config(tls(root.path()))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = RouteOwnershipClient::new(channel);
        let invalid = RouteRequest {
            request_id: 0,
            reference: vec![],
            request_sha256: vec![],
            destination_sha256: vec![],
        };
        assert_eq!(
            client.observe(invalid.clone()).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        let mut wrong_role = authenticated(invalid.clone());
        wrong_role.metadata_mut().insert(
            "authorization",
            "Bearer owned-administrator-not-a-route-caller"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            client.observe(wrong_role).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );
        assert_eq!(
            client
                .observe(authenticated(invalid.clone()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let mut duplicate = authenticated(invalid);
        duplicate
            .metadata_mut()
            .append("authorization", format!("Bearer {TOKEN}").parse().unwrap());
        assert_eq!(
            client.observe(duplicate).await.unwrap_err().code(),
            tonic::Code::Unauthenticated
        );

        // Missing client certificate and wrong server identity refuse before
        // any native lookup. Connection success alone is not handshake proof.
        let no_identity = ClientTlsConfig::new()
            .domain_name("route.example.test")
            .ca_certificate(Certificate::from_pem(
                std::fs::read(root.path().join("ca.pem")).unwrap(),
            ));
        if let Ok(channel) = Endpoint::from_shared(address.clone())
            .unwrap()
            .tls_config(no_identity)
            .unwrap()
            .connect()
            .await
        {
            assert!(
                RouteOwnershipClient::new(channel)
                    .observe(authenticated(RouteRequest::default()))
                    .await
                    .is_err()
            );
        }
        assert!(
            Endpoint::from_shared(address)
                .unwrap()
                .tls_config(tls(root.path()).domain_name("wrong.example.test"))
                .unwrap()
                .connect()
                .await
                .is_err()
        );

        let capture = registry
            .capture(&snapshot, &runtime, &prepared, "192.0.2.9".parse().unwrap())
            .unwrap();
        let input = capture.request(7);
        let reply = client
            .observe(authenticated(input.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!((reply.request_id, reply.configuration_revision), (7, 7));
        assert_eq!(
            (
                reply.route_id.as_str(),
                reply.service.as_str(),
                reply.audience.as_str(),
                reply.resource.as_str(),
                reply.action.as_str()
            ),
            ("orders", "orders", "orders-api", "db:orders", "select")
        );
        assert_eq!(reply.client_ip, vec![192, 0, 2, 9]);
        assert_eq!(reply.request_sha256, input.request_sha256);
        assert_eq!(reply.destination_sha256, input.destination_sha256);
        assert!((1..=1000).contains(&reply.remaining_ms));
        for field in 0..3 {
            let mut changed = input.clone();
            match field {
                0 => changed.reference[0] ^= 1,
                1 => changed.request_sha256[0] ^= 1,
                _ => changed.destination_sha256[0] ^= 1,
            }
            assert_eq!(
                client
                    .observe(authenticated(changed))
                    .await
                    .unwrap_err()
                    .code(),
                tonic::Code::Unavailable
            );
        }
        let mut oversized = input.clone();
        oversized.reference = vec![0; 1024];
        assert!(client.observe(authenticated(oversized)).await.is_err());
        drop(capture);
        assert_eq!(
            client
                .observe(authenticated(input))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        let capture = registry
            .capture(&snapshot, &runtime, &prepared, "192.0.2.9".parse().unwrap())
            .unwrap();
        let input = capture.request(8);
        registry.active_for_test().store(Arc::new(
            crate::config::Snapshot::new(snapshot.config.clone()).unwrap(),
        ));
        assert_eq!(
            client
                .observe(authenticated(input))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::Unavailable
        );
        drop(client);
        shutdown.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}
