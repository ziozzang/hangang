//! Bounded mandatory mTLS management server; authentication roles remain in handlers.
use anyhow::{Context, Result, ensure};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use rustls_pki_types::pem::PemObject;
use std::{future::Future, path::Path, sync::Arc, time::Duration};
use tokio::{net::TcpListener, time::timeout};
pub fn tls_config(cert: &Path, key: &Path, ca: &Path, alpn: &[&[u8]]) -> Result<Arc<ServerConfig>> {
    let cert_bytes = crate::read_tls_material(cert)?;
    let key_bytes = crate::read_tls_material(key)?;
    let ca_bytes = crate::read_tls_material(ca)?;
    let certs = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cert_bytes.as_slice())
        .collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>()?;
    let key = rustls_pki_types::PrivateKeyDer::from_pem_reader(&mut key_bytes.as_slice())
        .context("invalid or missing TLS private key")?;
    let mut roots = RootCertStore::empty();
    for cert in rustls_pki_types::CertificateDer::pem_reader_iter(&mut ca_bytes.as_slice()) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "client CA must not be empty");
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone()).build()?;
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

/// Server-injected proof of a successfully authenticated TLS client certificate.
#[derive(Clone, Debug)]
pub struct AuthenticatedTlsPeer;

pub async fn serve_https(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    router: axum::Router,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    crate::serve_connections(
        listener,
        std::num::NonZeroUsize::new(2048).unwrap(),
        Duration::from_secs(5),
        move |socket, peer| {
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            let router = router
                .clone()
                .layer(axum::Extension(axum::extract::ConnectInfo(peer)));
            async move {
                if let Ok(Ok(stream)) =
                    timeout(Duration::from_secs(3), acceptor.accept(socket)).await
                {
                    if stream
                        .get_ref()
                        .1
                        .peer_certificates()
                        .is_none_or(|certs| certs.is_empty())
                    {
                        return;
                    }
                    let router = router.layer(axum::Extension(AuthenticatedTlsPeer));
                    let mut builder = hyper::server::conn::http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(Duration::from_secs(5))
                        .max_headers(64)
                        .max_buf_size(32 * 1024);
                    let _ = timeout(
                        Duration::from_secs(300),
                        builder.serve_connection(
                            TokioIo::new(stream),
                            TowerToHyperService::new(router),
                        ),
                    )
                    .await;
                }
            }
        },
        shutdown,
    )
    .await?;
    Ok(())
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
        let config = tls_config(&cert, &key, &cert, &[b"h2"]).unwrap();
        assert!(config.cert_compressors.is_empty());
        assert!(config.cert_decompressors.is_empty());
        std::fs::write(&key, b"no private key").unwrap();
        assert!(tls_config(&cert, &key, &cert, &[b"h2"]).is_err());
        std::fs::File::create(&cert)
            .unwrap()
            .set_len(1024 * 1024 + 1)
            .unwrap();
        assert!(tls_config(&cert, &key, &cert, &[b"h2"]).is_err());
    }
}
