//! Route-isolated HTTP pools. Dial address, HTTP authority and TLS name are independent.
use crate::{
    config::HttpRuntime,
    discovery::{Discovery, Protocol, ResolvedTarget},
    proxy::Body,
    upstream::OutboundOptions,
};
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
    fence: Option<DockerFence>,
}
#[derive(Clone)]
struct DockerFence {
    discovery: Arc<Discovery>,
    configured: String,
    target: ResolvedTarget,
}
impl DockerFence {
    fn current(&self) -> bool {
        self.discovery
            .resolve_with_epoch(&self.configured, Protocol::Http)
            == Some(self.target.clone())
    }
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
        let fence = self.fence.clone();
        Box::pin(async move {
            if fence.as_ref().is_some_and(|fence| !fence.current()) {
                return Err(anyhow::anyhow!("stale Docker endpoint").into_boxed_dyn_error());
            }
            let stream = crate::upstream::connect(&target, &options)
                .await
                .map_err(|e| e.into_boxed_dyn_error())?;
            if fence.as_ref().is_some_and(|fence| !fence.current()) {
                return Err(anyhow::anyhow!("stale Docker endpoint").into_boxed_dyn_error());
            }
            Ok(TokioIo::new(DialIo(stream)))
        })
    }
}
struct Entry {
    runtime: Weak<HttpRuntime>,
    discovery: Option<Weak<Discovery>>,
    endpoint: String,
    epoch: u64,
    client: Arc<HttpClient>,
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
        self.client_for_target(runtime, backend, backend, 0, None, prepared)
    }

    /// Keep the logical Docker reference as the pool key, while binding the
    /// actual connection pool to the resolved endpoint identity. A container
    /// restart can retain its IP:port, so endpoint equality alone is not safe.
    pub fn client_for_epoch(
        &self,
        runtime: &Arc<HttpRuntime>,
        configured: &str,
        target: &ResolvedTarget,
        discovery: Option<Arc<Discovery>>,
        prepared: Option<&Arc<rustls::ClientConfig>>,
    ) -> anyhow::Result<HttpClient> {
        anyhow::ensure!(
            !configured.starts_with("docker://") || discovery.is_some(),
            "missing Docker discovery fence"
        );
        if let Some(discovery) = &discovery {
            anyhow::ensure!(
                discovery.resolve_with_epoch(configured, Protocol::Http) == Some(target.clone()),
                "stale Docker endpoint"
            );
        }
        self.client_for_target(
            runtime,
            configured,
            &target.endpoint,
            target.epoch,
            discovery,
            prepared,
        )
    }

    fn client_for_target(
        &self,
        runtime: &Arc<HttpRuntime>,
        configured: &str,
        endpoint: &str,
        epoch: u64,
        discovery: Option<Arc<Discovery>>,
        prepared: Option<&Arc<rustls::ClientConfig>>,
    ) -> anyhow::Result<HttpClient> {
        let key = (runtime.route.id.clone(), configured.to_owned());
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = clients.get(&key)
            && entry.runtime.ptr_eq(&Arc::downgrade(runtime))
            && entry.endpoint == endpoint
            && entry.epoch == epoch
            && match (&entry.discovery, &discovery) {
                (None, None) => true,
                (Some(old), Some(current)) => old.ptr_eq(&Arc::downgrade(current)),
                _ => false,
            }
        {
            return Ok(entry.client.as_ref().clone());
        }
        let uri: Uri = endpoint.parse()?;
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
                fence: discovery.as_ref().map(|discovery| DockerFence {
                    discovery: discovery.clone(),
                    configured: configured.to_owned(),
                    target: ResolvedTarget {
                        endpoint: endpoint.to_owned(),
                        epoch,
                    },
                }),
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
        // Replacing an epoch under an existing logical key does not increase
        // cardinality and should not evict unrelated live route pools.
        if clients.len() >= 1024 && !clients.contains_key(&key) {
            clients.clear();
        }
        clients.insert(
            key,
            Entry {
                runtime: Arc::downgrade(runtime),
                discovery: discovery.as_ref().map(Arc::downgrade),
                endpoint: endpoint.to_owned(),
                epoch,
                client: Arc::new(client.clone()),
            },
        );
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Snapshot};
    #[cfg(unix)]
    use crate::docker::DockerResolver;
    #[cfg(unix)]
    use bytes::Bytes;
    #[cfg(unix)]
    use http_body_util::{BodyExt, Full};
    #[cfg(unix)]
    use hyper::{Request, Response, server::conn::http1, service::service_fn};
    #[cfg(unix)]
    use std::{convert::Infallible, path::PathBuf};
    #[cfg(unix)]
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UnixListener},
        sync::oneshot,
    };
    #[cfg(unix)]
    use tokio_util::task::AbortOnDropHandle;

    fn runtime() -> Arc<HttpRuntime> {
        let config: Config = serde_json::from_str(
            r#"{"http":[{"id":"pool","backends":["http://127.0.0.1:8080"]}]}"#,
        )
        .unwrap();
        Snapshot::new(config).unwrap().http[0].clone()
    }

    fn pools() -> Pools {
        Pools::new(crate::tls::client_config(None).unwrap(), 8)
    }

    #[test]
    fn logical_pool_reuses_one_epoch_and_replaces_same_address_restart_without_growth() {
        let pools = pools();
        let runtime = runtime();
        let configured = "logical-docker-reference";
        let endpoint = "http://127.0.0.1:8080";
        let key = (runtime.route.id.clone(), configured.to_owned());
        let first = ResolvedTarget {
            endpoint: endpoint.into(),
            epoch: 1,
        };
        pools
            .client_for_epoch(&runtime, configured, &first, None, None)
            .unwrap();
        let old = pools
            .clients
            .lock()
            .unwrap()
            .get(&key)
            .unwrap()
            .client
            .clone();
        pools
            .client_for_epoch(&runtime, configured, &first, None, None)
            .unwrap();
        assert!(Arc::ptr_eq(
            &old,
            &pools.clients.lock().unwrap()[&key].client
        ));

        let restarted = ResolvedTarget {
            endpoint: endpoint.into(),
            epoch: 2,
        };
        pools
            .client_for_epoch(&runtime, configured, &restarted, None, None)
            .unwrap();
        assert!(!Arc::ptr_eq(
            &old,
            &pools.clients.lock().unwrap()[&key].client
        ));
        assert_eq!(pools.clients.lock().unwrap()[&key].endpoint, endpoint);
        assert_eq!(pools.clients.lock().unwrap()[&key].epoch, 2);
        // An owner of the previous client retains its established transport;
        // replacing the map entry does not forcibly close that client.
        assert_eq!(Arc::strong_count(&old), 1);

        for epoch in 3..=1002 {
            let next = ResolvedTarget {
                endpoint: endpoint.into(),
                epoch,
            };
            pools
                .client_for_epoch(&runtime, configured, &next, None, None)
                .unwrap();
        }
        assert_eq!(pools.clients.lock().unwrap().len(), 1);
        assert_eq!(pools.clients.lock().unwrap()[&key].epoch, 1002);
    }

    #[test]
    fn endpoint_and_discovery_identity_both_partition_cached_clients() {
        let pools = pools();
        let runtime = runtime();
        let configured = "http://127.0.0.1:8080";
        let first = ResolvedTarget {
            endpoint: configured.into(),
            epoch: 0,
        };
        let discovery_a = Arc::new(Discovery::new(None));
        let discovery_b = Arc::new(Discovery::new(None));
        let key = (runtime.route.id.clone(), configured.to_owned());
        pools
            .client_for_epoch(
                &runtime,
                configured,
                &first,
                Some(discovery_a.clone()),
                None,
            )
            .unwrap();
        let a = pools.clients.lock().unwrap()[&key].client.clone();
        pools
            .client_for_epoch(&runtime, configured, &first, Some(discovery_a), None)
            .unwrap();
        assert!(Arc::ptr_eq(&a, &pools.clients.lock().unwrap()[&key].client));
        pools
            .client_for_epoch(&runtime, configured, &first, Some(discovery_b), None)
            .unwrap();
        assert!(!Arc::ptr_eq(
            &a,
            &pools.clients.lock().unwrap()[&key].client
        ));

        let moved = ResolvedTarget {
            endpoint: "http://127.0.0.1:8081".into(),
            epoch: 1,
        };
        pools
            .client_for_epoch(&runtime, "another-key", &moved, None, None)
            .unwrap();
        let moved_key = (runtime.route.id.clone(), "another-key".to_owned());
        let before = pools.clients.lock().unwrap()[&moved_key].client.clone();
        let changed = ResolvedTarget {
            endpoint: "http://127.0.0.1:8082".into(),
            epoch: 1,
        };
        pools
            .client_for_epoch(&runtime, "another-key", &changed, None, None)
            .unwrap();
        assert!(!Arc::ptr_eq(
            &before,
            &pools.clients.lock().unwrap()[&moved_key].client
        ));
    }

    #[test]
    fn docker_client_requires_fence_and_rejects_stale_target_before_cache_lookup() {
        let pools = pools();
        let runtime = runtime();
        let configured = "docker://app/edge/80";
        let target = ResolvedTarget {
            endpoint: "http://127.0.0.1:8080".into(),
            epoch: 7,
        };
        assert!(
            pools
                .client_for_epoch(&runtime, configured, &target, None, None)
                .is_err()
        );
        let discovery = Arc::new(Discovery::new(None));
        assert!(
            pools
                .client_for_epoch(&runtime, configured, &target, Some(discovery), None)
                .is_err()
        );
        assert!(pools.clients.lock().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacing_epoch_does_not_interrupt_an_admitted_old_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let runtime = runtime();
        let pools = pools();
        let configured = "logical-docker-reference";
        let first = ResolvedTarget {
            endpoint: endpoint.clone(),
            epoch: 1,
        };
        let old = pools
            .client_for_epoch(&runtime, configured, &first, None, None)
            .unwrap();
        let (request_started_tx, request_started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();
        let origin = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = Vec::new();
            loop {
                let mut chunk = [0; 512];
                let size = stream.read(&mut chunk).await.unwrap();
                assert!(size > 0);
                buffer.extend_from_slice(&chunk[..size]);
                if buffer.windows(4).any(|part| part == b"\r\n\r\n") {
                    break;
                }
            }
            request_started_tx.send(()).unwrap();
            finish_rx.await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        let request = Request::builder()
            .uri(format!("{endpoint}/"))
            .body(
                Full::new(Bytes::new())
                    .map_err(crate::proxy::BodyError::from_error)
                    .boxed_unsync(),
            )
            .unwrap();
        let in_flight = tokio::spawn(async move { old.request(request).await });
        tokio::time::timeout(Duration::from_secs(2), request_started_rx)
            .await
            .unwrap()
            .unwrap();
        pools
            .client_for_epoch(
                &runtime,
                configured,
                &ResolvedTarget { endpoint, epoch: 2 },
                None,
                None,
            )
            .unwrap();
        finish_tx.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(2), in_flight)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        origin.await.unwrap();
    }

    #[cfg(unix)]
    struct FakeDocker {
        _directory: tempfile::TempDir,
        socket: PathBuf,
        started_at: Arc<Mutex<&'static str>>,
        _task: AbortOnDropHandle<()>,
    }

    #[cfg(unix)]
    impl FakeDocker {
        async fn start() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("docker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let started_at = Arc::new(Mutex::new("start-one"));
            let state = started_at.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let state = state.clone();
                    tokio::spawn(async move {
                        let service =
                            service_fn(move |_request: Request<hyper::body::Incoming>| {
                                let started_at = *state.lock().unwrap();
                                async move {
                                    let body = serde_json::json!({
                                        "Id": "container-one",
                                        "State": { "Running": true, "StartedAt": started_at },
                                        "NetworkSettings": { "Networks": { "edge": {
                                            "IPAddress": "127.0.0.1", "GlobalIPv6Address": ""
                                        } } }
                                    });
                                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(
                                        body.to_string(),
                                    ))))
                                }
                            });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self {
                _directory: directory,
                socket,
                started_at,
                _task: AbortOnDropHandle::new(task),
            }
        }

        fn restart_same_address(&self) {
            *self.started_at.lock().unwrap() = "start-two";
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn same_address_docker_restart_replaces_client_and_fences_pending_socks_dial() {
        let docker = FakeDocker::start().await;
        let reference = "docker://app/edge/8080";
        let config: Config = serde_json::from_str(&format!(
            r#"{{"http":[{{"id":"pool","backends":["{reference}"]}}]}}"#
        ))
        .unwrap();
        let runtime = Snapshot::new(config.clone()).unwrap().http[0].clone();
        let discovery = Arc::new(Discovery::new(Some(Arc::new(DockerResolver::new(
            docker.socket.clone(),
        )))));
        discovery.refresh(&config).await.unwrap();
        let first = discovery
            .resolve_with_epoch(reference, Protocol::Http)
            .unwrap();
        let pools = pools();
        pools
            .client_for_epoch(&runtime, reference, &first, Some(discovery.clone()), None)
            .unwrap();
        let key = (runtime.route.id.clone(), reference.to_owned());
        let old_client = pools.clients.lock().unwrap()[&key].client.clone();
        pools
            .client_for_epoch(&runtime, reference, &first, Some(discovery.clone()), None)
            .unwrap();
        assert!(Arc::ptr_eq(
            &old_client,
            &pools.clients.lock().unwrap()[&key].client
        ));

        // Hold a SOCKS5 CONNECT after it reaches the proxy. Discovery changes
        // while the underlying connect future is still pending; the post-dial
        // fence must reject the socket before Hyper can issue request bytes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let (connected_tx, connected_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut connect = [0; 10];
            stream.read_exact(&mut connect).await.unwrap();
            assert_eq!(&connect[..4], &[5, 1, 0, 1]);
            connected_tx.send(()).unwrap();
            release_rx.await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut unexpected = [0; 1];
            assert_eq!(
                stream.read(&mut unexpected).await.unwrap(),
                0,
                "stale request bytes reached proxy"
            );
        });
        let mut dial = Dial {
            target: "127.0.0.1:8080".into(),
            options: OutboundOptions {
                socks5: Some(crate::upstream::Socks5Config {
                    address: proxy_address.to_string(),
                    username_env: None,
                    password_env: None,
                }),
                ..OutboundOptions::default()
            },
            fence: Some(DockerFence {
                discovery: discovery.clone(),
                configured: reference.into(),
                target: first.clone(),
            }),
        };
        let dialing = tokio::spawn(async move {
            Service::call(&mut dial, Uri::from_static("http://example.test/")).await
        });
        tokio::time::timeout(Duration::from_secs(2), connected_rx)
            .await
            .unwrap()
            .unwrap();
        docker.restart_same_address();
        discovery.refresh(&config).await.unwrap();
        let restarted = discovery
            .resolve_with_epoch(reference, Protocol::Http)
            .unwrap();
        assert_eq!(restarted.endpoint, first.endpoint);
        assert_ne!(restarted.epoch, first.epoch);
        assert!(
            pools
                .client_for_epoch(&runtime, reference, &first, Some(discovery.clone()), None)
                .is_err()
        );
        pools
            .client_for_epoch(&runtime, reference, &restarted, Some(discovery), None)
            .unwrap();
        assert!(!Arc::ptr_eq(
            &old_client,
            &pools.clients.lock().unwrap()[&key].client
        ));
        release_tx.send(()).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), dialing)
            .await
            .unwrap()
            .unwrap();
        assert!(
            result.is_err(),
            "completed stale SOCKS connection must be fenced"
        );
        tokio::time::timeout(Duration::from_secs(2), proxy)
            .await
            .unwrap()
            .unwrap();
    }
}
