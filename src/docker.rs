use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, StatusCode, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::IpAddr, path::PathBuf, time::Duration};
use tokio::{net::UnixStream, time::timeout};
use tokio_util::task::AbortOnDropHandle;

const MAX_BODY: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Resolved {
    pub http_backend: String,
    pub tcp_backend: String,
    /// Internal process identity for discovery epoch comparison. Never expose
    /// Docker inspect identifiers in an API response.
    #[serde(skip)]
    pub(crate) identity: Option<String>,
}

pub struct DockerResolver {
    transport: Transport,
}

enum Transport {
    Unix(PathBuf),
    Https {
        base: reqwest::Url,
        client: reqwest::Client,
    },
}

impl DockerResolver {
    pub fn new(socket: PathBuf) -> Self {
        Self {
            transport: Transport::Unix(socket),
        }
    }

    /// Remote Docker access always verifies the daemon's certificate against
    /// the configured CA and authenticates with a client certificate.
    pub fn https(url: &str, ca_pem: &[u8], identity_pem: &[u8]) -> Result<Self> {
        let base = reqwest::Url::parse(url).context("parse Docker HTTPS URL")?;
        ensure!(
            base.scheme() == "https" && base.host_str().is_some(),
            "Docker remote URL must be HTTPS"
        );
        ensure!(
            base.username().is_empty()
                && base.password().is_none()
                && base.path() == "/"
                && base.query().is_none()
                && base.fragment().is_none(),
            "Docker remote URL must contain only an HTTPS origin"
        );
        let roots = rustls_pemfile::certs(&mut std::io::Cursor::new(ca_pem))
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("parse Docker CA certificates")?;
        ensure!(
            !roots.is_empty() && roots.len() <= 32,
            "Docker CA file must contain 1 to 32 certificates"
        );
        let identity =
            reqwest::Identity::from_pem(identity_pem).context("parse Docker client identity")?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            .tls_built_in_root_certs(false)
            .identity(identity)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0);
        for root in roots {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_der(&root).context("parse Docker CA certificate")?,
            );
        }
        let client = builder.build().context("build Docker HTTPS client")?;
        Ok(Self {
            transport: Transport::Https { base, client },
        })
    }

    pub async fn ping(&self) -> Result<()> {
        timeout(REQUEST_TIMEOUT, async {
            match &self.transport {
                Transport::Unix(socket) => {
                    let body = unix_request(socket, "/_ping").await?;
                    ensure!(
                        body.as_ref() == b"OK",
                        "Docker ping returned an unexpected response"
                    );
                }
                Transport::Https { base, client } => {
                    let body = https_request(base, client, "/_ping").await?;
                    ensure!(
                        body.as_ref() == b"OK",
                        "Docker ping returned an unexpected response"
                    );
                }
            }
            Ok(())
        })
        .await
        .context("Docker ping timed out")?
    }

    pub async fn resolve(&self, container: &str, network: &str, port: u16) -> Result<Resolved> {
        validate_container(container)?;
        ensure!(!network.is_empty(), "Docker network is required");
        ensure!(port > 0, "Docker container port must be nonzero");

        timeout(
            REQUEST_TIMEOUT,
            self.resolve_inner(container, network, port),
        )
        .await
        .context("Docker inspection timed out")?
    }

    async fn resolve_inner(&self, container: &str, network: &str, port: u16) -> Result<Resolved> {
        let path = format!("/containers/{}/json", percent_escape(container));
        let body = match &self.transport {
            Transport::Unix(socket) => unix_request(socket, &path).await?,
            Transport::Https { base, client } => https_request(base, client, &path).await?,
        };
        let inspect: InspectResponse =
            serde_json::from_slice(&body).context("parse Docker inspection response")?;
        ensure!(inspect.state.running, "Docker container is not running");
        let endpoint = inspect
            .network_settings
            .networks
            .get(network)
            .with_context(|| format!("Docker container is not attached to network {network}"))?;
        let address = if !endpoint.ip_address.is_empty() {
            &endpoint.ip_address
        } else if !endpoint.global_ipv6_address.is_empty() {
            &endpoint.global_ipv6_address
        } else {
            bail!("Docker network {network} has no IP address")
        };
        let ip: IpAddr = address
            .parse()
            .with_context(|| format!("invalid Docker network IP address {address}"))?;
        let tcp_backend = std::net::SocketAddr::new(ip, port).to_string();
        Ok(Resolved {
            http_backend: format!("http://{tcp_backend}"),
            tcp_backend,
            identity: inspect
                .id
                .as_deref()
                .filter(|id| !id.is_empty())
                .and_then(|id| {
                    inspect
                        .state
                        .started_at
                        .as_deref()
                        .filter(|started| !started.is_empty())
                        .map(|started| format!("{}:{id}{started}", id.len()))
                }),
        })
    }
}

async fn unix_request(socket: &PathBuf, path: &str) -> Result<Bytes> {
    let stream = UnixStream::connect(socket)
        .await
        .context("connect Docker socket")?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .context("start Docker HTTP connection")?;
    // Ensure cancellation of the enclosing three-second timeout cannot
    // leave a detached HTTP connection driver behind.
    let driver = AbortOnDropHandle::new(tokio::spawn(connection));

    let request = Request::get(path)
        .header(hyper::header::HOST, "docker")
        .header(hyper::header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())
        .context("build Docker inspection request")?;
    let response = sender
        .send_request(request)
        .await
        .context("send Docker inspection request")?;
    ensure!(
        response.status() == StatusCode::OK,
        "Docker inspection returned HTTP {}",
        response.status()
    );
    let body = Limited::new(response.into_body(), MAX_BODY)
        .collect()
        .await
        .map_err(|error| anyhow::anyhow!("read Docker inspection response: {error}"))?
        .to_bytes();
    drop(sender);
    drop(driver);

    Ok(body)
}

async fn https_request(base: &reqwest::Url, client: &reqwest::Client, path: &str) -> Result<Bytes> {
    use futures_util::StreamExt;
    let url = base.join(path).context("build Docker request URL")?;
    let response = client
        .get(url)
        .send()
        .await
        .context("send Docker HTTPS request")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "Docker request returned HTTP {}",
        response.status()
    );
    if let Some(length) = response.content_length() {
        ensure!(length <= MAX_BODY as u64, "Docker response too large");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read Docker HTTPS response")?;
        ensure!(
            chunk.len() <= MAX_BODY.saturating_sub(bytes.len()),
            "Docker response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(Bytes::from(bytes))
}

fn validate_container(container: &str) -> Result<()> {
    let bytes = container.as_bytes();
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= 128
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte)),
        "invalid Docker container name"
    );
    Ok(())
}

fn percent_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            escaped.push(char::from(byte));
        } else {
            use std::fmt::Write;
            write!(&mut escaped, "%{byte:02X}").expect("writing to a String cannot fail");
        }
    }
    escaped
}

#[derive(Deserialize)]
struct InspectResponse {
    #[serde(rename = "Id", default)]
    id: Option<String>,
    #[serde(rename = "State")]
    state: ContainerState,
    #[serde(rename = "NetworkSettings")]
    network_settings: NetworkSettings,
}

#[derive(Deserialize)]
struct ContainerState {
    #[serde(rename = "Running")]
    running: bool,
    #[serde(rename = "StartedAt", default)]
    started_at: Option<String>,
}

#[derive(Deserialize)]
struct NetworkSettings {
    #[serde(rename = "Networks")]
    networks: HashMap<String, NetworkEndpoint>,
}

#[derive(Deserialize)]
struct NetworkEndpoint {
    #[serde(rename = "IPAddress")]
    ip_address: String,
    #[serde(rename = "GlobalIPv6Address")]
    global_ipv6_address: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::{Response, server::conn::http1 as server_http1, service::service_fn};
    use std::{convert::Infallible, sync::Arc};
    use tempfile::TempDir;
    use tokio::{net::UnixListener, sync::oneshot};

    struct FakeDocker {
        _directory: TempDir,
        socket: PathBuf,
        path: oneshot::Receiver<String>,
        _task: AbortOnDropHandle<()>,
    }

    async fn fake_docker(status: StatusCode, body: Vec<u8>) -> FakeDocker {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("docker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (path_tx, path) = oneshot::channel();
        let path_tx = Arc::new(std::sync::Mutex::new(Some(path_tx)));
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let body = body.clone();
                let path_tx = path_tx.clone();
                async move {
                    if let Some(tx) = path_tx.lock().unwrap().take() {
                        let _ = tx.send(request.uri().path().to_owned());
                    }
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                }
            });
            let _ = server_http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
        FakeDocker {
            _directory: directory,
            socket,
            path,
            _task: AbortOnDropHandle::new(task),
        }
    }

    fn inspection(running: bool, network: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "State": {"Running": running},
            "NetworkSettings": {"Networks": {
                network: {"IPAddress": "172.20.0.7", "GlobalIPv6Address": ""}
            }}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn resolves_running_container_and_uses_exact_inspect_path() {
        let fake = fake_docker(StatusCode::OK, inspection(true, "edge")).await;
        let resolved = DockerResolver::new(fake.socket.clone())
            .resolve("api-1.example", "edge", 8080)
            .await
            .unwrap();
        assert_eq!(
            resolved,
            Resolved {
                http_backend: "http://172.20.0.7:8080".into(),
                tcp_backend: "172.20.0.7:8080".into(),
                identity: None,
            }
        );
        assert_eq!(fake.path.await.unwrap(), "/containers/api-1.example/json");
    }

    #[tokio::test]
    async fn process_replacement_at_same_address_changes_private_identity() {
        fn inspection(id: Option<&str>, started: Option<&str>) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "Id": id,
                "State": { "Running": true, "StartedAt": started },
                "NetworkSettings": { "Networks": {
                    "edge": { "IPAddress": "172.20.0.7", "GlobalIPv6Address": "" }
                } }
            }))
            .unwrap()
        }
        let first = fake_docker(
            StatusCode::OK,
            inspection(Some("container-a"), Some("2026-09-13T00:00:00Z")),
        )
        .await;
        let second = fake_docker(
            StatusCode::OK,
            inspection(Some("container-a"), Some("2026-09-13T00:01:00Z")),
        )
        .await;
        let third = fake_docker(
            StatusCode::OK,
            inspection(Some("container-b"), Some("2026-09-13T00:01:00Z")),
        )
        .await;
        let first = DockerResolver::new(first.socket.clone())
            .resolve("api", "edge", 8080)
            .await
            .unwrap();
        let restarted = DockerResolver::new(second.socket.clone())
            .resolve("api", "edge", 8080)
            .await
            .unwrap();
        let replaced = DockerResolver::new(third.socket.clone())
            .resolve("api", "edge", 8080)
            .await
            .unwrap();
        assert_eq!(first.tcp_backend, restarted.tcp_backend);
        assert_eq!(restarted.tcp_backend, replaced.tcp_backend);
        assert!(first.identity.is_some());
        assert_ne!(first.identity, restarted.identity);
        assert_ne!(restarted.identity, replaced.identity);
        let serialized = serde_json::to_value(&first).unwrap();
        assert!(serialized.get("identity").is_none());
        assert_eq!(serialized["tcp_backend"], "172.20.0.7:8080");
        let incomplete = fake_docker(StatusCode::OK, inspection(Some("container-a"), None)).await;
        let incomplete = DockerResolver::new(incomplete.socket.clone())
            .resolve("api", "edge", 8080)
            .await
            .unwrap();
        assert!(incomplete.identity.is_none());
    }

    #[tokio::test]
    async fn rejects_stopped_container_and_missing_network() {
        let stopped = fake_docker(StatusCode::OK, inspection(false, "edge")).await;
        let error = DockerResolver::new(stopped.socket.clone())
            .resolve("api", "edge", 80)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not running"));

        let missing = fake_docker(StatusCode::OK, inspection(true, "other")).await;
        let error = DockerResolver::new(missing.socket.clone())
            .resolve("api", "edge", 80)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not attached"));
    }

    #[tokio::test]
    async fn rejects_malformed_and_oversized_responses() {
        let malformed = fake_docker(StatusCode::OK, b"not json".to_vec()).await;
        let error = DockerResolver::new(malformed.socket.clone())
            .resolve("api", "edge", 80)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("parse Docker"));

        let oversized = fake_docker(StatusCode::OK, vec![b' '; MAX_BODY + 1]).await;
        let error = DockerResolver::new(oversized.socket.clone())
            .resolve("api", "edge", 80)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("read Docker"));
    }

    #[tokio::test]
    async fn validates_inputs_before_opening_socket() {
        let resolver = DockerResolver::new(PathBuf::from("/does/not/exist"));
        for container in ["", "bad/name", "-starts-wrong", &"a".repeat(129)] {
            assert!(resolver.resolve(container, "edge", 80).await.is_err());
        }
        assert!(resolver.resolve("api", "", 80).await.is_err());
        assert!(resolver.resolve("api", "edge", 0).await.is_err());
    }
}
