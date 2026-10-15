// Authenticated fixture peers exercise Root public SDK and native transport boundaries.
// They do not replace actual Hop TokenReview/Pum policy/consuming-ledger full-chain tests.
use super::*;
use hopae_grpc::{receipt, receipt_binding as rb, v1 as h};
use pumgye_grpc::v1 as p;
use sha2::{Digest, Sha256};
use std::{
    sync::atomic::{AtomicU8, AtomicU64},
    time::Instant,
};
use tonic::{Request, Response, Status};
const TOKEN: &str = "owned-observed-native-caller-token-0001";
#[derive(Clone)]
struct Sources {
    class: AuthenticationClass,
    auth_calls: Arc<AtomicU64>,
    permit_calls: Arc<AtomicU64>,
    output_calls: Arc<AtomicU64>,
    wrong_endpoints: Arc<AtomicU64>,
    started: Instant,
    attack: Arc<AtomicU8>,
    auth_key: ed25519_dalek::SigningKey,
    permit_key: ed25519_dalek::SigningKey,
    next: Arc<AtomicU64>,
}
fn digest(c: &h::AuthenticationReceiptContext, p: Option<&p::PermitBinding>) -> [u8; 32] {
    let i = c.identity.as_ref().unwrap();
    let context = rb::Context {
        issuer_ref: &c.issuer_ref,
        key_epoch: c.key_epoch,
        identity_authority_epoch: &c.identity_authority_epoch,
        identity: rb::Identity {
            subject_ref: &i.subject_ref,
            kind: match i.kind {
                2 => hopae_grpc::PrincipalKind::Service,
                3 => hopae_grpc::PrincipalKind::Workload,
                _ => panic!("fixture kind"),
            },
            aal: i.aal.try_into().expect("fixture assurance fits signed u8"),
            revision: i.revision,
            credential_generation: i.credential_generation,
        },
        service: &c.service,
        audience: &c.audience,
        request_sha256: c.request_sha256.as_slice().try_into().unwrap(),
    };
    let permit = p.map(|p| rb::Permit {
        authentication_receipt_sha256: p
            .authentication_receipt_sha256
            .as_slice()
            .try_into()
            .unwrap(),
        decision_ref: &p.decision_ref,
        resource: &p.resource,
        action: &p.action,
        authority_epoch: &p.authority_epoch,
        catalog_revision: p.catalog_revision,
        policy_revision: p.policy_revision,
        network_revision: p.network_revision,
        route_revision: p.route_revision,
        plan_revision: p.plan_revision,
    });
    rb::digest(&context, permit.as_ref()).unwrap()
}
impl Sources {
    fn wire_kind(&self) -> u32 {
        match self.class {
            AuthenticationClass::Service => 2,
            AuthenticationClass::Workload => 3,
        }
    }
    fn endpoint(&self, class: AuthenticationClass) -> Result<(), Status> {
        if self.class != class {
            self.wrong_endpoints.fetch_add(1, Ordering::AcqRel);
            return Err(Status::permission_denied("wrong typed fixture endpoint"));
        }
        Ok(())
    }
    fn issue_auth(
        &self,
        q: h::ServiceReceiptRequest,
    ) -> Result<Response<h::ServiceReceiptObservedReply>, Status> {
        let id = q.verification.unwrap().request_id;
        self.auth_calls.fetch_add(1, Ordering::AcqRel);
        let mut c = h::AuthenticationReceiptContext {
            issuer_ref: "hop-owned".into(),
            key_epoch: 1,
            identity_authority_epoch: match self.class {
                AuthenticationClass::Service => hopae_grpc::service_epoch::encode_clock(
                    "profiles",
                    2,
                    3,
                    "11111111111111111111111111111111",
                )
                .unwrap(),
                AuthenticationClass::Workload => hopae_grpc::workload_epoch::encode(
                    "profiles",
                    2,
                    3,
                    "11111111111111111111111111111111",
                )
                .unwrap(),
            },
            identity: Some(h::ReceiptIdentity {
                subject_ref: format!("s_{:048x}", self.next.fetch_add(1, Ordering::Relaxed)),
                kind: if self.attack.load(Ordering::Acquire) == 13 {
                    if self.class == AuthenticationClass::Service {
                        3
                    } else {
                        2
                    }
                } else {
                    self.wire_kind()
                },
                aal: 0,
                revision: 2,
                credential_generation: 2,
            }),
            service: q.service,
            audience: q.audience,
            request_sha256: q.request_sha256,
        };
        let now = self.auth_now();
        let receipt = receipt::sign(
            &self.auth_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Authentication,
                issued_ms: now,
                expires_ms: now
                    + if self.attack.load(Ordering::Acquire) == 18 {
                        1
                    } else {
                        950
                    },
                binding: digest(&c, None),
                nonce: [1; 32],
            },
        )
        .unwrap()
        .to_vec();
        // Native signing deliberately cannot mint nonzero-AAL Service/Workload.
        // Exercise hostile wire context AFTER signing a valid fixture receipt,
        // rather than panicking in the detached server's binding helper.
        if self.attack.load(Ordering::Acquire) == 14 {
            c.identity.as_mut().unwrap().aal = 1;
        }
        let observation = self.auth_report(id, &receipt);
        Ok(Response::new(h::ServiceReceiptObservedReply {
            receipt: Some(h::ServiceReceiptReply {
                request_id: id,
                context: Some(c),
                receipt,
            }),
            observation: Some(observation),
        }))
    }
    fn issue_permit(
        &self,
        q: p::AuthenticatedResourceRequest,
    ) -> Result<Response<p::ObservedProjectionPermitReply>, Status> {
        self.permit_calls.fetch_add(1, Ordering::AcqRel);
        let mut c = q.context.unwrap();
        if c.identity.as_ref().unwrap().kind != self.wire_kind() {
            return Err(Status::permission_denied("fixture permission kind"));
        }
        if self.attack.load(Ordering::Acquire) == 17 {
            c.identity.as_mut().unwrap().kind = if self.wire_kind() == 2 { 3 } else { 2 };
        }
        c.issuer_ref = "pum-owned".into();
        let binding = p::PermitBinding {
            authentication_receipt_sha256: Sha256::digest(q.receipt).to_vec(),
            decision_ref: "decision-owned".into(),
            resource: q.resource,
            action: q.action,
            authority_epoch: format!("pobs1:{}:policy", "2".repeat(32)),
            catalog_revision: 5,
            policy_revision: 5,
            network_revision: 6,
            route_revision: 7,
            plan_revision: 8,
        };
        let now = self.permit_now();
        let receipt = receipt::sign(
            &self.permit_key,
            &receipt::Claims {
                purpose: receipt::Purpose::Permit,
                issued_ms: now,
                expires_ms: now + 800,
                binding: digest(&c, Some(&binding)),
                nonce: [2; 32],
            },
        )
        .unwrap()
        .to_vec();
        let mut observation = p::ObservedPermitTimeReply {
            request_id: q.request_id,
            receipt_sha256: Sha256::digest(&receipt).to_vec(),
            clock_domain: binding.authority_epoch.clone(),
            owner_now_ms: now,
            proof_remaining_ms: 800,
            remaining_ms: 700,
            policy_revision: 5,
            network_revision: 6,
            route_revision: 7,
            plan_revision: 8,
            cache_ttl_ms: 0,
        };
        match self.attack.load(Ordering::Acquire) {
            9 => observation.owner_now_ms += 1,
            10 => observation.remaining_ms = 1001,
            _ => {}
        }
        Ok(Response::new(p::ObservedProjectionPermitReply {
            permit: Some(p::ProjectionPermitReply {
                request_id: q.request_id,
                context: Some(c),
                binding: Some(binding),
                receipt,
                cache_ttl_ms: 0,
            }),
            observation: Some(observation),
        }))
    }
    fn project_output(
        &self,
        q: h::ProjectionRequest,
    ) -> Result<Response<h::ObservedProjectionReply>, Status> {
        use prost::Message;
        self.output_calls.fetch_add(1, Ordering::AcqRel);
        if q.permission_contract
            != match self.class {
                AuthenticationClass::Service => 2,
                AuthenticationClass::Workload => 3,
            }
            || self.attack.load(Ordering::Acquire) == 16
        {
            return Err(Status::invalid_argument("contract"));
        }
        let chain_sha256 = Sha256::digest(&q.permission_query).to_vec();
        let query = p::PermitValidationRequest::decode(q.permission_query.as_slice()).unwrap();
        assert_eq!(query.request_id, q.request_id);
        let c = query.request.unwrap().context.unwrap();
        if c.identity.as_ref().unwrap().kind != self.wire_kind() {
            return Err(Status::permission_denied("fixture output kind"));
        }
        let mut reply = h::ObservedProjectionReply {
            request_id: q.request_id,
            service: c.service,
            audience: c.audience,
            request_sha256: c.request_sha256,
            header_name: "authorization".into(),
            header_value: b"Bearer owned-origin".to_vec(),
            chain_sha256,
            output_clock_domain: format!("hproj1:{}", "3".repeat(32)),
            owner_now_ms: 9_000_000_000_000,
            remaining_ms: 400,
            profile_revision: 2,
            application_generation: 3,
            key_registry_revision: 4,
            plan_revision: 8,
            cache_ttl_ms: 0,
        };
        match self.attack.load(Ordering::Acquire) {
            1 => reply.chain_sha256[0] ^= 1,
            2 => reply.cache_ttl_ms = 1,
            3 => reply.remaining_ms = 0,
            4 => reply.key_registry_revision += 1,
            5 => reply.plan_revision += 1,
            6 => reply.header_name = "cookie".into(),
            7 => reply.request_sha256[0] ^= 1,
            11 => reply.remaining_ms = 1,
            12 => reply.header_value = b"Bearer invalid\rvalue".to_vec(),
            _ => {}
        }
        Ok(Response::new(reply))
    }
    fn auth_now(&self) -> u64 {
        10_000 + self.started.elapsed().as_millis() as u64
    }
    fn permit_now(&self) -> u64 {
        5_000_000_000_000 + self.started.elapsed().as_millis() as u64
    }
    fn authorize<T>(&self, r: &Request<T>) -> Result<(), Status> {
        if r.metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            != Some(&format!("Bearer {TOKEN}"))
        {
            return Err(Status::unauthenticated("native caller"));
        }
        Ok(())
    }
    fn auth_report(&self, id: u64, receipt: &[u8]) -> h::ServiceReceiptTimeReply {
        let expiry = u64::from_be_bytes(receipt[10..18].try_into().unwrap());
        let now = self.auth_now();
        h::ServiceReceiptTimeReply {
            request_id: id,
            owner_now_ms: now,
            remaining_ms: expiry.saturating_sub(now).min(1000) as u32,
            receipt_sha256: Sha256::digest(receipt).to_vec(),
            clock_domain: if self.attack.load(Ordering::Acquire) == 8 {
                "9".repeat(32)
            } else {
                "1".repeat(32)
            },
            profile_revision: 2,
            application_generation: 3,
            key_registry_revision: 4,
            cache_ttl_ms: 0,
        }
    }
}
#[tonic::async_trait]
impl h::authentication_receipts_server::AuthenticationReceipts for Sources {
    async fn issue_service(
        &self,
        _: Request<h::ServiceReceiptRequest>,
    ) -> Result<Response<h::ServiceReceiptReply>, Status> {
        Err(Status::unimplemented("strict forbidden"))
    }
    async fn validate_service(
        &self,
        _: Request<h::ServiceReceiptValidationRequest>,
    ) -> Result<Response<h::ServiceReceiptValidationReply>, Status> {
        Err(Status::unimplemented("strict forbidden"))
    }
    async fn issue_service_observed(
        &self,
        r: Request<h::ServiceReceiptRequest>,
    ) -> Result<Response<h::ServiceReceiptObservedReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Service)?;
        self.issue_auth(r.into_inner())
    }

    async fn observe_service_time(
        &self,
        r: Request<h::ServiceReceiptValidationRequest>,
    ) -> Result<Response<h::ServiceReceiptTimeReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Service)?;
        let q = r.into_inner();
        Ok(Response::new(self.auth_report(q.request_id, &q.receipt)))
    }
}
#[tonic::async_trait]
impl p::observed_projection_permits_server::ObservedProjectionPermits for Sources {
    async fn issue(
        &self,
        r: Request<p::AuthenticatedResourceRequest>,
    ) -> Result<Response<p::ObservedProjectionPermitReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Service)?;
        self.issue_permit(r.into_inner())
    }

    async fn observe(
        &self,
        _: Request<p::PermitValidationRequest>,
    ) -> Result<Response<p::ObservedPermitTimeReply>, Status> {
        Err(Status::unimplemented("fixture root issues only"))
    }
}
#[tonic::async_trait]
impl h::observed_credential_projection_server::ObservedCredentialProjection for Sources {
    async fn project(
        &self,
        r: Request<h::ProjectionRequest>,
    ) -> Result<Response<h::ObservedProjectionReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Service)?;
        self.project_output(r.into_inner())
    }
}

#[tonic::async_trait]
impl h::workload_authentication_receipts_server::WorkloadAuthenticationReceipts for Sources {
    async fn issue_observed(
        &self,
        r: Request<h::WorkloadReceiptRequest>,
    ) -> Result<Response<h::WorkloadReceiptObservedReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Workload)?;
        let q = r.into_inner();
        let response = self
            .issue_auth(h::ServiceReceiptRequest {
                verification: q.verification,
                service: q.service,
                audience: q.audience,
                request_sha256: q.request_sha256,
            })?
            .into_inner();
        let proof = response.receipt.unwrap();
        let report = response.observation.unwrap();
        Ok(Response::new(h::WorkloadReceiptObservedReply {
            receipt: Some(h::WorkloadReceiptReply {
                request_id: proof.request_id,
                context: proof.context,
                receipt: proof.receipt,
            }),
            observation: Some(workload_report(report)),
        }))
    }
    async fn observe_time(
        &self,
        r: Request<h::WorkloadReceiptObservationRequest>,
    ) -> Result<Response<h::WorkloadReceiptTimeReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Workload)?;
        let q = r.into_inner();
        Ok(Response::new(workload_report(
            self.auth_report(q.request_id, &q.receipt),
        )))
    }
}
fn workload_report(r: h::ServiceReceiptTimeReply) -> h::WorkloadReceiptTimeReply {
    h::WorkloadReceiptTimeReply {
        request_id: r.request_id,
        owner_now_ms: r.owner_now_ms,
        remaining_ms: r.remaining_ms,
        receipt_sha256: r.receipt_sha256,
        clock_domain: r.clock_domain,
        profile_revision: r.profile_revision,
        application_generation: r.application_generation,
        key_registry_revision: r.key_registry_revision,
        cache_ttl_ms: r.cache_ttl_ms,
    }
}
#[tonic::async_trait]
impl p::workload_observed_projection_permits_server::WorkloadObservedProjectionPermits for Sources {
    async fn issue(
        &self,
        r: Request<p::AuthenticatedResourceRequest>,
    ) -> Result<Response<p::ObservedProjectionPermitReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Workload)?;
        self.issue_permit(r.into_inner())
    }
    async fn observe(
        &self,
        _: Request<p::PermitValidationRequest>,
    ) -> Result<Response<p::ObservedPermitTimeReply>, Status> {
        Err(Status::unimplemented("fixture root issues only"))
    }
}
#[tonic::async_trait]
impl h::workload_observed_credential_projection_server::WorkloadObservedCredentialProjection
    for Sources
{
    async fn project(
        &self,
        r: Request<h::ProjectionRequest>,
    ) -> Result<Response<h::ObservedProjectionReply>, Status> {
        self.authorize(&r)?;
        self.endpoint(AuthenticationClass::Workload)?;
        self.project_output(r.into_inner())
    }
}

fn certificates(root: &std::path::Path) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair,
    };
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(p, KeyPair::generate().unwrap()).unwrap();
    let mut p = CertificateParams::new(vec!["native.example.test".into()]).unwrap();
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = p.signed_by(&key, &ca).unwrap();
    let mut p = CertificateParams::new(vec![]).unwrap();
    p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client = p.signed_by(&client_key, &ca).unwrap();
    std::fs::write(root.join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(root.join("client.pem"), client.pem()).unwrap();
    std::fs::write(root.join("client.key"), client_key.serialize_pem()).unwrap();
    (
        ca.pem().into_bytes(),
        cert.pem().into_bytes(),
        key.serialize_pem().into_bytes(),
    )
}
#[tokio::test]
async fn native_dispatch_uses_independent_sources_and_refuses_output_attacks_before_backend_effects()
 {
    typed_dispatch_fixture(AuthenticationClass::Service).await;
}
#[tokio::test]
async fn workload_dispatch_public_sdk_dedicated_endpoints_and_backend_nondispatch() {
    typed_dispatch_fixture(AuthenticationClass::Workload).await;
}
async fn typed_dispatch_fixture(class: AuthenticationClass) {
    use base64::Engine;
    use http_body_util::BodyExt;
    let root = tempfile::tempdir().unwrap();
    let (ca, cert, key) = certificates(root.path());
    let source = Sources {
        class,
        auth_calls: Arc::new(AtomicU64::new(0)),
        permit_calls: Arc::new(AtomicU64::new(0)),
        output_calls: Arc::new(AtomicU64::new(0)),
        wrong_endpoints: Arc::new(AtomicU64::new(0)),
        started: Instant::now(),
        attack: Arc::new(AtomicU8::new(0)),
        auth_key: ed25519_dalek::SigningKey::from_bytes(&[9; 32]),
        permit_key: ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
        next: Arc::new(AtomicU64::new(1)),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let incoming = futures_util::stream::unfold(listener, |listener| async move {
        Some((listener.accept().await.map(|(socket, _)| socket), listener))
    });
    let server = tonic::transport::Server::builder()
        .tls_config(
            tonic::transport::ServerTlsConfig::new()
                .identity(tonic::transport::Identity::from_pem(cert, key))
                .client_ca_root(tonic::transport::Certificate::from_pem(ca)),
        )
        .unwrap()
        .add_service(
            h::authentication_receipts_server::AuthenticationReceiptsServer::new(source.clone()),
        )
        .add_service(
            h::observed_credential_projection_server::ObservedCredentialProjectionServer::new(
                source.clone(),
            ),
        )
        .add_service(
            p::observed_projection_permits_server::ObservedProjectionPermitsServer::new(
                source.clone(),
            ),
        );
    let server = server
        .add_service(h::workload_authentication_receipts_server::WorkloadAuthenticationReceiptsServer::new(source.clone()))
        .add_service(p::workload_observed_projection_permits_server::WorkloadObservedProjectionPermitsServer::new(source.clone()))
        .add_service(h::workload_observed_credential_projection_server::WorkloadObservedCredentialProjectionServer::new(source.clone()));
    let serving = tokio::spawn(server.serve_with_incoming(incoming));
    let hop_settings = crate::config::HopaeNative {
        transport: crate::config::HopaeTransport::Grpc,
        address: address.to_string().parse().unwrap(),
        pool_size: 8,
        tls: Some(crate::config::HopaeNativeTls {
            server_name: "native.example.test".into(),
            ca: root.path().join("ca.pem"),
            certificate: root.path().join("client.pem"),
            key: root.path().join("client.key"),
        }),
    };
    let hopae =
        crate::hopae_native::Client::from_config(&hop_settings, TOKEN.parse().unwrap()).unwrap();
    let authority_config = crate::pumgye::AuthorityConfig {
        transport: crate::pumgye::DecisionTransport::Grpc,
        decision_address: address.to_string().parse().unwrap(),
        management_address: address.to_string().parse().unwrap(),
        decision_token_env: match class {
            AuthenticationClass::Service => "OWNED_OBSERVED_SERVICE_DISPATCH_TOKEN",
            AuthenticationClass::Workload => "OWNED_OBSERVED_WORKLOAD_DISPATCH_TOKEN",
        }
        .into(),
        admin_token_env: "OWNED_OBSERVED_DISPATCH_ADMIN_UNSET".into(),
        tls: Some(crate::pumgye::AuthorityTls {
            server_name: "native.example.test".into(),
            ca: root.path().join("ca.pem"),
            certificate: root.path().join("client.pem"),
            key: root.path().join("client.key"),
        }),
        pool_size: 8,
        timeout_ms: 1000,
        minimum_revision: 1,
    };
    // Unique fixture environment reference; never reads an operating credential.
    unsafe {
        std::env::set_var(&authority_config.decision_token_env, TOKEN);
    }
    let authority = crate::pumgye::AuthorityRuntime::prepare(&authority_config).unwrap();
    let configuration = crate::native_resource::Configuration {
        audience: "orders-api".into(),
        issuer_ref: "hop-owned".into(),
        key_epoch: 1,
        public_key: base64::engine::general_purpose::STANDARD
            .encode(source.auth_key.verifying_key().to_bytes()),
        permission_permit: Some(crate::projection_permit::Configuration {
            issuer_ref: "pum-owned".into(),
            key_epoch: 1,
            public_key: base64::engine::general_purpose::STANDARD
                .encode(source.permit_key.verifying_key().to_bytes()),
        }),
        project_credentials: true,
        observed: Some(Configuration {
            authentication_class: class,
            identity_authority: "profiles".into(),
            minimum_profile_revision: 1,
            minimum_application_generation: 1,
            minimum_key_registry_revision: 1,
            source_error_ppm: 100,
            receiver_error_ppm: 100,
            maximum_final_header_bytes: 32768,
        }),
        maximum_body_bytes: 1024,
        body_timeout_ms: 1000,
    };
    let binding = configuration
        .compile(crate::pumgye::ResourceGate {
            service_id: "orders".into(),
            resource: "db:orders".into(),
            actions: [("POST".into(), "write".into())].into(),
        })
        .unwrap();
    let owner = Owner::compile(
        configuration.observed.clone().unwrap(),
        "hop-owned".into(),
        1,
        source.auth_key.verifying_key().to_bytes(),
        "orders".into(),
        "orders-api".into(),
    )
    .unwrap();
    let first = owner.client(&hopae).unwrap();
    let second = owner.client(&hopae).unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    let other_transport =
        crate::hopae_native::Client::from_config(&hop_settings, TOKEN.parse().unwrap()).unwrap();
    assert!(owner.client(&other_transport).is_err());
    let route = p::NativeRouteReference {
        reference: vec![7; 32],
        destination_sha256: vec![8; 32],
    };
    let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let effects = Arc::new(AtomicU64::new(0));
    let backend_effects = effects.clone();
    let backend_task = tokio::spawn(async move {
        loop {
            let (socket, _) = backend.accept().await.unwrap();
            let effects = backend_effects.clone();
            tokio::spawn(async move {
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(socket),
                        hyper::service::service_fn(
                            move |r: hyper::Request<hyper::body::Incoming>| {
                                let effects = effects.clone();
                                async move {
                                    assert_eq!(r.headers()["authorization"], "Bearer owned-origin");
                                    assert_eq!(
                                        r.into_body().collect().await.unwrap().to_bytes(),
                                        "materialized once"
                                    );
                                    effects.fetch_add(1, Ordering::AcqRel);
                                    Ok::<_, std::convert::Infallible>(hyper::Response::new(
                                        http_body_util::Full::new(bytes::Bytes::from_static(b"ok")),
                                    ))
                                }
                            },
                        ),
                    )
                    .await
                    .unwrap();
            });
        }
    });
    let endpoint = format!("http://{backend_address}");
    let transport_config: crate::config::Config = serde_json::from_value(
        serde_json::json!({"http":[{"id":"typed-native-fixture","backends":[endpoint.clone()]}]}),
    )
    .unwrap();
    let transport_runtime = crate::config::Snapshot::new(transport_config).unwrap().http[0].clone();
    let pools = crate::http_outbound::Pools::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
        4,
    );
    {
        let attack = 0;
        source.attack.store(attack, Ordering::Release);
        let request = hyper::Request::post(format!("http://{backend_address}/orders?x=1"))
            .header("authorization", "Bearer application-secret")
            .body(crate::proxy::full_body(bytes::Bytes::from_static(
                b"materialized once",
            )))
            .unwrap();
        let prepared = binding
            .prepare(request, Arc::new(tokio::sync::Semaphore::new(2)))
            .await
            .unwrap();
        let result = binding
            .observe_with_route(
                &prepared,
                &hyper::HeaderMap::new(),
                &hopae,
                &authority,
                "127.0.0.1".parse().unwrap(),
                Some(&route),
            )
            .await;
        let observation = Arc::new(result.unwrap());
        assert!(observation.local_fences_hold(&authority));
        let replacement_authority =
            crate::pumgye::AuthorityRuntime::prepare(&authority_config).unwrap();
        assert!(!observation.local_fences_hold(&replacement_authority));
        let mut excessive = hyper::HeaderMap::new();
        excessive.insert(
            "x-large",
            hyper::header::HeaderValue::from_str(&"x".repeat(32768)).unwrap(),
        );
        assert!(observation.install_credential(&mut excessive).is_err());
        let mut outgoing = prepared.into_dispatch();
        outgoing.headers_mut().remove("authorization");
        outgoing.headers_mut().remove("x-hopae-subject");
        observation
            .install_credential(outgoing.headers_mut())
            .unwrap();
        assert!(observation.local_fences_hold(&authority));
        let gate_observation = observation.clone();
        let gate_authority = authority.clone();
        let gate: crate::http_outbound::DispatchGate =
            Arc::new(move || gate_observation.local_fences_hold(&gate_authority));
        let client = pools
            .gated_client(
                &transport_runtime,
                &endpoint,
                &endpoint,
                0,
                None,
                None,
                gate,
            )
            .unwrap();
        assert_eq!(client.request(outgoing).await.unwrap().status(), 200);
        binding.retire();
        assert!(!observation.local_fences_hold(&authority));
    }
    assert_eq!(effects.load(Ordering::Acquire), 1);
    let binding = configuration
        .compile(crate::pumgye::ResourceGate {
            service_id: "orders".into(),
            resource: "db:orders".into(),
            actions: [("POST".into(), "write".into())].into(),
        })
        .unwrap();
    for attack in (1..=14).chain([16, 17, 18]) {
        source.attack.store(attack, Ordering::Release);
        let prepared = binding
            .prepare(
                hyper::Request::post(format!("http://{backend_address}/orders"))
                    .body(crate::proxy::full_body(bytes::Bytes::from_static(
                        b"materialized once",
                    )))
                    .unwrap(),
                Arc::new(tokio::sync::Semaphore::new(1)),
            )
            .await
            .unwrap();
        assert!(
            binding
                .observe_with_route(
                    &prepared,
                    &hyper::HeaderMap::new(),
                    &hopae,
                    &authority,
                    "127.0.0.1".parse().unwrap(),
                    Some(&route)
                )
                .await
                .is_err(),
            "attack {attack} accepted"
        );
    }
    assert_eq!(effects.load(Ordering::Acquire), 1);
    assert!(source.auth_calls.load(Ordering::Acquire) > 0);
    assert!(source.permit_calls.load(Ordering::Acquire) > 0);
    assert!(source.output_calls.load(Ordering::Acquire) > 0);
    assert_eq!(source.wrong_endpoints.load(Ordering::Acquire), 0);
    // Capture through public RPCs, install the checked secret, then let output
    // expire before the real raw-gated HTTP transport can emit any request.
    source.attack.store(0, Ordering::Release);
    let prepared = binding
        .prepare(
            hyper::Request::post(format!("http://{backend_address}/orders"))
                .body(crate::proxy::full_body(bytes::Bytes::from_static(
                    b"materialized once",
                )))
                .unwrap(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        )
        .await
        .unwrap();
    let observation = Arc::new(
        binding
            .observe_with_route(
                &prepared,
                &hyper::HeaderMap::new(),
                &hopae,
                &authority,
                "127.0.0.1".parse().unwrap(),
                Some(&route),
            )
            .await
            .unwrap(),
    );
    let mut outgoing = prepared.into_dispatch();
    observation
        .install_credential(outgoing.headers_mut())
        .unwrap();
    let gate_observation = observation.clone();
    let gate_authority = authority.clone();
    let client = pools
        .gated_client(
            &transport_runtime,
            &endpoint,
            &endpoint,
            0,
            None,
            None,
            Arc::new(move || gate_observation.local_fences_hold(&gate_authority)),
        )
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(450)).await;
    assert!(!observation.local_fences_hold(&authority));
    assert!(client.request(outgoing).await.is_err());
    assert_eq!(effects.load(Ordering::Acquire), 1);
    // Wrong native configured class selects the opposite PUBLIC endpoint and
    // fails closed; no private Authentication/Observation constructors are used.
    source.attack.store(0, Ordering::Release);
    let mut wrong = configuration.clone();
    wrong.observed.as_mut().unwrap().authentication_class = match class {
        AuthenticationClass::Service => AuthenticationClass::Workload,
        AuthenticationClass::Workload => AuthenticationClass::Service,
    };
    let wrong = wrong
        .compile(crate::pumgye::ResourceGate {
            service_id: "orders".into(),
            resource: "db:orders".into(),
            actions: [("POST".into(), "write".into())].into(),
        })
        .unwrap();
    let prepared = wrong
        .prepare(
            hyper::Request::post(format!("http://{backend_address}/orders"))
                .body(crate::proxy::full_body(bytes::Bytes::from_static(
                    b"materialized once",
                )))
                .unwrap(),
            Arc::new(tokio::sync::Semaphore::new(1)),
        )
        .await
        .unwrap();
    assert!(
        wrong
            .observe_with_route(
                &prepared,
                &hyper::HeaderMap::new(),
                &hopae,
                &authority,
                "127.0.0.1".parse().unwrap(),
                Some(&route)
            )
            .await
            .is_err()
    );
    assert_eq!(source.wrong_endpoints.load(Ordering::Acquire), 1);
    assert_eq!(effects.load(Ordering::Acquire), 1);
    backend_task.abort();
    serving.abort();
}

#[test]
fn route_authentication_class_is_explicit_and_preserves_legacy_service_json() {
    let legacy = serde_json::json!({
        "identity_authority":"profiles",
        "minimum_profile_revision":1,"minimum_application_generation":1,
        "minimum_key_registry_revision":1,"source_error_ppm":100,
        "receiver_error_ppm":100,"maximum_final_header_bytes":32768
    });
    let service: Configuration = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(service.authentication_class, AuthenticationClass::Service);
    assert_eq!(serde_json::to_value(&service).unwrap(), legacy);
    let mut explicit = legacy;
    explicit["authentication_class"] = "workload".into();
    let workload: Configuration = serde_json::from_value(explicit.clone()).unwrap();
    assert_eq!(workload.authentication_class, AuthenticationClass::Workload);
    assert_eq!(serde_json::to_value(&workload).unwrap(), explicit);
    explicit["authentication_class"] = "human".into();
    assert!(serde_json::from_value::<Configuration>(explicit.clone()).is_err());
    explicit["authentication_class"] = 3.into();
    assert!(serde_json::from_value::<Configuration>(explicit).is_err());
}
