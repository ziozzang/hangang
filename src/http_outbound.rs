//! Route-isolated HTTP pools. Dial address, HTTP authority and TLS name are independent.
use crate::{config::HttpRuntime, proxy::Body, upstream::OutboundOptions};
use hyper::Uri;
use hyper_util::{
    client::legacy::Client,
    client::legacy::connect::{Connected, Connection},
    rt::{TokioExecutor, TokioIo},
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower_service::Service;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type HttpClient = Client<hyper_rustls::HttpsConnector<Dial>, Body>;
/// Hyper requires connection metadata in addition to Tokio I/O. The boxed
/// transport may be TCP or a Unix socket, so neither address type is assumed.
pub struct DialIo(crate::upstream::BoxIo);
impl Connection for DialIo {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}
impl AsyncRead for DialIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for DialIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
#[derive(Clone)]
pub struct Dial {
    target: String,
    options: OutboundOptions,
}
impl Service<Uri> for Dial {
    type Response = TokioIo<DialIo>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, _: Uri) -> Self::Future {
        let target = self.target.clone();
        let options = self.options.clone();
        Box::pin(async move {
            crate::upstream::connect(&target, &options)
                .await
                .map(|stream| TokioIo::new(DialIo(stream)))
                .map_err(|e| e.into_boxed_dyn_error())
        })
    }
}
struct Entry {
    runtime: Weak<HttpRuntime>,
    client: HttpClient,
}
pub struct Pools {
    base: rustls::ClientConfig,
    idle: usize,
    clients: Mutex<HashMap<(String, String), Entry>>,
}
impl Pools {
    pub fn new(base: rustls::ClientConfig, idle: usize) -> Self {
        Self {
            base,
            idle,
            clients: Mutex::new(HashMap::new()),
        }
    }
    pub fn client(
        &self,
        runtime: &Arc<HttpRuntime>,
        backend: &str,
        prepared: Option<&Arc<rustls::ClientConfig>>,
    ) -> anyhow::Result<HttpClient> {
        let key = (runtime.route.id.clone(), backend.to_owned());
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = clients.get(&key)
            && entry.runtime.ptr_eq(&Arc::downgrade(runtime))
        {
            return Ok(entry.client.clone());
        }
        let uri: Uri = backend.parse()?;
        let host = uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("missing upstream host"))?;
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });
        let target = format!("{host}:{port}");
        let options = &runtime.route.upstream;
        let mut tls = if let Some(settings) = &options.tls {
            if settings.ca_file.is_some() || settings.insecure_skip_verify {
                prepared
                    .ok_or_else(|| anyhow::anyhow!("missing upstream TLS configuration"))?
                    .as_ref()
                    .clone()
            } else {
                crate::upstream::build_client_config(&self.base, settings)?
            }
        } else {
            self.base.clone()
        };
        tls.alpn_protocols.clear();
        let name = options
            .tls
            .as_ref()
            .and_then(|tls| tls.server_name.as_deref())
            .unwrap_or(host)
            .trim_start_matches('[')
            .trim_end_matches(']');
        let name = rustls::pki_types::ServerName::try_from(name.to_owned())?;
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .with_server_name_resolver(hyper_rustls::FixedServerNameResolver::new(name))
            .enable_http1()
            .enable_http2()
            .wrap_connector(Dial {
                target,
                options: options.clone(),
            });
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(60))
            .pool_max_idle_per_host(if runtime.route.preserve_host {
                0
            } else {
                self.idle.clamp(1, 4096)
            })
            .build(connector);
        if clients.len() >= 1024 {
            clients.retain(|_, e| e.runtime.strong_count() > 0);
        }
        if clients.len() >= 1024 {
            clients.clear();
        }
        clients.insert(
            key,
            Entry {
                runtime: Arc::downgrade(runtime),
                client: client.clone(),
            },
        );
        Ok(client)
    }
}
