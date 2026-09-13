use anyhow::{Context, Result, bail, ensure};
use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{File, OpenOptions},
    io::{Cursor, Read},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CA_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(default, deny_unknown_fields)]
pub struct OutboundOptions {
    /// Address to dial instead of the route's logical upstream address.
    pub connect_address: Option<String>,
    /// Connect to this local Unix socket instead of dialing a TCP address.
    /// The logical backend still supplies HTTP authority and the TLS name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unix_socket: Option<PathBuf>,
    /// When non-empty, hostname resolution is restricted to these servers.
    pub dns_servers: Vec<SocketAddr>,
    pub socks5: Option<Socks5Config>,
    /// Enables TLS for a raw TCP upstream. HTTP routes still derive TLS from
    /// their URI scheme, but use these verifier and server-name settings.
    pub tls: Option<UpstreamTls>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct Socks5Config {
    pub address: String,
    pub username_env: Option<String>,
    pub password_env: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(default, deny_unknown_fields)]
pub struct UpstreamTls {
    pub server_name: Option<String>,
    pub insecure_skip_verify: bool,
    pub ca_file: Option<PathBuf>,
    pub max_fragment_size: Option<usize>,
}

impl OutboundOptions {
    pub fn validate(&self) -> Result<()> {
        if let Some(path) = &self.unix_socket {
            let encoded = path.as_os_str().as_encoded_bytes();
            ensure!(
                path.is_absolute(),
                "upstream unix_socket must be an absolute path"
            );
            ensure!(
                !encoded.is_empty() && encoded.len() <= 107 && !encoded.contains(&0),
                "upstream unix_socket path must contain 1 to 107 bytes without NUL"
            );
            ensure!(
                encoded
                    .split(|byte| *byte == b'/' || *byte == b'\\')
                    .all(|part| part != b"." && part != b".."),
                "upstream unix_socket path must be normalized"
            );
            ensure!(
                self.connect_address.is_none()
                    && self.socks5.is_none()
                    && self.dns_servers.is_empty(),
                "upstream unix_socket cannot be combined with connect_address, socks5, or dns_servers"
            );
        }
        ensure!(
            self.dns_servers.len() <= 4,
            "at most four upstream DNS servers may be configured"
        );
        ensure!(
            self.dns_servers.iter().all(|server| server.port() != 0),
            "upstream DNS server port must not be zero"
        );
        if let Some(address) = &self.connect_address {
            parse_authority(address).context("invalid upstream connect_address")?;
        }
        if let Some(socks) = &self.socks5 {
            parse_authority(&socks.address).context("invalid SOCKS5 address")?;
            ensure!(
                socks.username_env.is_some() == socks.password_env.is_some(),
                "SOCKS5 username_env and password_env must be configured together"
            );
            if let Some(name) = &socks.username_env {
                validate_credential_env_name(name, "username_env")?;
            }
            if let Some(name) = &socks.password_env {
                validate_credential_env_name(name, "password_env")?;
            }
        }
        if let Some(tls) = &self.tls {
            tls.validate()?;
        }
        Ok(())
    }
}

impl UpstreamTls {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !(self.insecure_skip_verify && self.ca_file.is_some()),
            "upstream TLS ca_file cannot be combined with insecure_skip_verify"
        );
        if let Some(server_name) = &self.server_name {
            ensure!(
                !server_name.is_empty(),
                "upstream TLS server_name must not be empty"
            );
            ServerName::try_from(server_name.clone())
                .context("invalid upstream TLS server_name")?;
        }
        if let Some(path) = &self.ca_file {
            let encoded = path.as_os_str().as_encoded_bytes();
            ensure!(
                path.is_absolute(),
                "upstream TLS ca_file must be an absolute path"
            );
            ensure!(
                encoded.len() <= 1024,
                "upstream TLS ca_file path exceeds 1024 bytes"
            );
            ensure!(
                encoded
                    .split(|byte| *byte == b'/' || *byte == b'\\')
                    .all(|part| part != b"." && part != b".."),
                "upstream TLS ca_file path must be normalized"
            );
        }
        if let Some(size) = self.max_fragment_size {
            ensure!(
                (128..=16_389).contains(&size),
                "upstream TLS max_fragment_size must be between 128 and 16389"
            );
        }
        Ok(())
    }
}

fn validate_credential_env_name(name: &str, field: &str) -> Result<()> {
    ensure!(
        name.starts_with("HANGANG_SOCKS5_")
            && name.len() <= 128
            && name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'),
        "SOCKS5 {field} must name a HANGANG_SOCKS5_ environment variable using only A-Z, 0-9, and _"
    );
    Ok(())
}

/// A boxed stream usable by both raw TCP forwarding and custom HTTP clients.
pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncIo for T {}
pub type BoxIo = Box<dyn AsyncIo>;

/// Establish a plain stream, using the configured Unix socket or SOCKS5 proxy
/// when present.
/// The deadline covers DNS for the address being dialled and the entire SOCKS
/// negotiation. A SOCKS failure is returned directly and never falls back to
/// a direct connection.
pub async fn connect(target: &str, options: &OutboundOptions) -> Result<BoxIo> {
    options.validate()?;
    timeout(CONNECT_TIMEOUT, connect_inner(target, options))
        .await
        .context("upstream connection timed out after 3 seconds")?
}

/// Establish a route stream and optionally perform its TLS handshake. The
/// caller supplies a client config built once with [`build_client_config`].
/// A single deadline covers every network operation.
pub async fn connect_with_tls(
    target: &str,
    options: &OutboundOptions,
    tls_config: Option<Arc<ClientConfig>>,
) -> Result<BoxIo> {
    options.validate()?;
    ensure!(
        options.tls.is_some() == tls_config.is_some(),
        "prepared upstream TLS config does not match route TLS options"
    );
    timeout(CONNECT_TIMEOUT, async {
        let stream = connect_inner(target, options).await?;
        let Some(config) = tls_config else {
            return Ok(stream);
        };
        let tls = options.tls.as_ref().expect("checked above");
        let logical = parse_authority(target).context("invalid upstream target")?;
        let name = tls.server_name.as_deref().unwrap_or(logical.host);
        let server_name =
            ServerName::try_from(name.to_owned()).context("invalid upstream TLS server name")?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(server_name, stream)
            .await
            .context("upstream TLS handshake failed")?;
        Ok(Box::new(stream) as BoxIo)
    })
    .await
    .context("upstream connection timed out after 3 seconds")?
}

async fn connect_inner(target: &str, options: &OutboundOptions) -> Result<BoxIo> {
    let logical = parse_authority(target).context("invalid upstream target")?;
    if let Some(path) = &options.unix_socket {
        #[cfg(unix)]
        return tokio::net::UnixStream::connect(path)
            .await
            .map(|stream| Box::new(stream) as BoxIo)
            .with_context(|| format!("connect upstream unix_socket {}", path.display()));
        #[cfg(not(unix))]
        bail!("upstream unix_socket requires a Unix platform");
    }
    let destination = match &options.connect_address {
        Some(address) => parse_authority(address).context("invalid upstream connect_address")?,
        None => logical,
    };

    let Some(proxy) = &options.socks5 else {
        return connect_authority(&destination, &options.dns_servers)
            .await
            .map(|stream| Box::new(stream) as BoxIo)
            .with_context(|| format!("connect upstream {}", destination.original));
    };

    let credentials = read_credentials(proxy)?;
    let proxy_address = parse_authority(&proxy.address).context("invalid SOCKS5 address")?;
    let mut stream = connect_authority(&proxy_address, &options.dns_servers)
        .await
        .context("connect SOCKS5 proxy")?;
    let resolved_destination;
    let (destination_host, destination_port) =
        if options.dns_servers.is_empty() || destination.host.parse::<IpAddr>().is_ok() {
            (destination.host, destination.port)
        } else {
            let addresses = crate::upstream_dns::resolve(destination.host, &options.dns_servers)
                .await
                .context("resolve SOCKS5 destination with configured DNS servers")?;
            resolved_destination = addresses[0].to_string();
            (resolved_destination.as_str(), destination.port)
        };
    socks5_handshake(
        &mut stream,
        destination_host,
        destination_port,
        credentials.as_ref(),
    )
    .await
    .context("SOCKS5 negotiation failed")?;
    Ok(Box::new(stream) as BoxIo)
}

async fn connect_authority(
    authority: &Authority<'_>,
    dns_servers: &[SocketAddr],
) -> Result<TcpStream> {
    if dns_servers.is_empty() || authority.host.parse::<IpAddr>().is_ok() {
        let stream = TcpStream::connect(authority.original).await?;
        stream.set_nodelay(true)?;
        return Ok(stream);
    }
    let addresses = crate::upstream_dns::resolve(authority.host, dns_servers)
        .await
        .context("resolve hostname with configured DNS servers")?;
    let mut last_error = None;
    for ip in addresses {
        match TcpStream::connect(SocketAddr::new(ip, authority.port)).await {
            Ok(stream) => {
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(error.into()),
        None => bail!("configured DNS servers returned no usable address"),
    }
}

struct Credentials {
    username: Vec<u8>,
    password: Vec<u8>,
}

fn read_credentials(config: &Socks5Config) -> Result<Option<Credentials>> {
    let (Some(username_env), Some(password_env)) = (&config.username_env, &config.password_env)
    else {
        return Ok(None);
    };
    let username = std::env::var_os(username_env)
        .context("SOCKS5 username environment variable is not set")?;
    let password = std::env::var_os(password_env)
        .context("SOCKS5 password environment variable is not set")?;
    let username = username.to_string_lossy().into_owned().into_bytes();
    let password = password.to_string_lossy().into_owned().into_bytes();
    ensure!(
        !username.is_empty() && username.len() <= u8::MAX as usize,
        "SOCKS5 username must contain 1 to 255 bytes"
    );
    ensure!(
        !password.is_empty() && password.len() <= u8::MAX as usize,
        "SOCKS5 password must contain 1 to 255 bytes"
    );
    Ok(Some(Credentials { username, password }))
}

async fn socks5_handshake<S>(
    stream: &mut S,
    destination_host: &str,
    destination_port: u16,
    credentials: Option<&Credentials>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let offered = if credentials.is_some() { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, offered]).await?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection).await?;
    ensure!(
        selection[0] == 0x05,
        "SOCKS5 proxy returned an invalid version"
    );
    ensure!(
        selection[1] != 0xff,
        "SOCKS5 proxy has no acceptable authentication method"
    );
    ensure!(
        selection[1] == offered,
        "SOCKS5 proxy selected an authentication method that was not offered"
    );

    if let Some(credentials) = credentials {
        let mut request =
            Vec::with_capacity(3 + credentials.username.len() + credentials.password.len());
        request.extend_from_slice(&[0x01, credentials.username.len() as u8]);
        request.extend_from_slice(&credentials.username);
        request.push(credentials.password.len() as u8);
        request.extend_from_slice(&credentials.password);
        stream.write_all(&request).await?;
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;
        ensure!(
            response[0] == 0x01,
            "SOCKS5 proxy returned an invalid authentication version"
        );
        ensure!(response[1] == 0x00, "SOCKS5 proxy rejected authentication");
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match destination_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
        Err(_) => {
            let host = destination_host.as_bytes();
            ensure!(
                host.len() <= u8::MAX as usize,
                "SOCKS5 destination name is too long"
            );
            request.extend_from_slice(&[0x03, host.len() as u8]);
            request.extend_from_slice(host);
        }
    }
    request.extend_from_slice(&destination_port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    ensure!(
        reply[0] == 0x05,
        "SOCKS5 proxy returned an invalid reply version"
    );
    ensure!(
        reply[2] == 0x00,
        "SOCKS5 proxy returned an invalid reserved byte"
    );
    if reply[1] != 0x00 {
        bail!(
            "SOCKS5 proxy refused CONNECT: {}",
            reply_description(reply[1])
        );
    }
    let address_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        _ => bail!("SOCKS5 proxy returned an invalid address type"),
    };
    let mut ignored = vec![0u8; address_len + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(())
}

fn reply_description(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

#[derive(Clone, Copy)]
struct Authority<'a> {
    original: &'a str,
    host: &'a str,
    port: u16,
}

fn parse_authority(value: &str) -> Result<Authority<'_>> {
    ensure!(!value.is_empty(), "address must not be empty");
    ensure!(
        value.trim() == value,
        "address must not contain surrounding whitespace"
    );
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest
            .split_once(']')
            .context("bracketed address is missing closing bracket")?;
        let port = suffix
            .strip_prefix(':')
            .context("address is missing a port")?;
        ensure!(
            host.parse::<std::net::Ipv6Addr>().is_ok(),
            "invalid IPv6 address"
        );
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .context("address is missing a port")?;
        ensure!(
            !host.contains(':'),
            "IPv6 addresses must be enclosed in brackets"
        );
        (host, port)
    };
    ensure!(!host.is_empty(), "address host must not be empty");
    validate_host(host)?;
    let port = port.parse::<u16>().context("invalid address port")?;
    ensure!(port != 0, "address port must not be zero");
    Ok(Authority {
        original: value,
        host,
        port,
    })
}

fn validate_host(host: &str) -> Result<()> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    ensure!(host.len() <= 253, "address host is too long");
    let host = host.strip_suffix('.').unwrap_or(host);
    ensure!(!host.is_empty(), "address host must not be empty");
    for label in host.split('.') {
        ensure!(
            !label.is_empty() && label.len() <= 63,
            "invalid address host label"
        );
        ensure!(
            label
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' }),
            "invalid character in address host"
        );
        ensure!(
            !label.starts_with('-') && !label.ends_with('-'),
            "address host label must not begin or end with '-'"
        );
    }
    Ok(())
}

/// Clone a process-wide base client configuration and apply route-specific
/// trust and TLS record settings. A custom CA augments the public WebPKI roots.
pub fn build_client_config(base: &ClientConfig, options: &UpstreamTls) -> Result<ClientConfig> {
    Ok(build_client_config_with_trust(base, options)?.0)
}

/// Build the client configuration and fingerprint the exact custom CA DER
/// certificates used by its verifier. The CA file is opened and parsed once;
/// a length prefix per certificate makes order and boundaries unambiguous.
/// No custom CA returns `None`, including an explicit insecure verifier.
pub fn build_client_config_with_trust(
    base: &ClientConfig,
    options: &UpstreamTls,
) -> Result<(ClientConfig, Option<[u8; 32]>)> {
    options.validate()?;
    let mut config = base.clone();
    config.max_fragment_size = options.max_fragment_size;
    let mut trust_fingerprint = None;
    if options.insecure_skip_verify {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(InsecureCertificateVerifier::new(provider)));
    } else if let Some(path) = &options.ca_file {
        let certs = read_ca_file(path)?;
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        for cert in &certs {
            let der = cert.as_ref();
            digest.update((der.len() as u64).to_be_bytes());
            digest.update(der);
        }
        let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        for cert in certs {
            roots
                .add(cert)
                .context("invalid certificate in upstream CA file")?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier =
            rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
                .build()
                .context("build upstream certificate verifier")?;
        config.dangerous().set_certificate_verifier(verifier);
        trust_fingerprint = Some(digest.finalize().into());
    }
    Ok((config, trust_fingerprint))
}

fn read_ca_file(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut file = open_ca_file(path)?;
    let metadata = file.metadata().context("inspect upstream CA file")?;
    ensure!(metadata.is_file(), "upstream CA path is not a regular file");
    ensure!(
        metadata.len() <= MAX_CA_BYTES,
        "upstream CA file exceeds 1 MiB"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("read upstream CA file")?;
    ensure!(
        bytes.len() as u64 <= MAX_CA_BYTES,
        "upstream CA file exceeds 1 MiB"
    );
    let certs = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<std::io::Result<Vec<_>>>()
        .context("parse upstream CA file")?;
    ensure!(
        !certs.is_empty(),
        "upstream CA file contains no certificates"
    );
    Ok(certs)
}

fn open_ca_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    options.open(path).context("open upstream CA file")
}

/// Disables chain, expiry, and name validation while retaining cryptographic
/// verification of the server's TLS 1.2/1.3 handshake signatures.
struct InsecureCertificateVerifier {
    algorithms: WebPkiSupportedAlgorithms,
}

impl InsecureCertificateVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            algorithms: provider.signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for InsecureCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InsecureCertificateVerifier")
    }
}

impl ServerCertVerifier for InsecureCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn outbound_tcp_socket_disables_nagle() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let stream = super::connect_authority(&super::parse_authority(&address).unwrap(), &[])
            .await
            .unwrap();
        assert!(stream.nodelay().unwrap());
    }

    use super::*;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    #[test]
    fn serde_defaults_and_rejects_unknown_fields() {
        let parsed: OutboundOptions = serde_json::from_value(json!({
            "socks5": {"address": "proxy.internal:1080", "username_env": null, "password_env": null},
            "tls": {"server_name": "origin.example", "max_fragment_size": 512}
        }))
        .unwrap();
        assert!(!parsed.tls.unwrap().insecure_skip_verify);
        assert!(
            serde_json::from_value::<OutboundOptions>(json!({"proxy": "localhost:9"})).is_err()
        );
        assert!(serde_json::from_value::<UpstreamTls>(json!({"unknown": true})).is_err());
    }

    #[test]
    fn validation_rejects_ambiguous_or_invalid_settings() {
        let one_credential = OutboundOptions {
            socks5: Some(Socks5Config {
                address: "127.0.0.1:1080".into(),
                username_env: Some("USER_ENV".into()),
                password_env: None,
            }),
            ..Default::default()
        };
        assert!(one_credential.validate().is_err());
        assert!(parse_authority("::1:443").is_err());
        assert!(parse_authority("host:0").is_err());
        assert!(parse_authority("user@host:443").is_err());
        assert!(parse_authority("host/path:443").is_err());
        assert!(
            OutboundOptions {
                dns_servers: vec!["127.0.0.1:1".parse().unwrap(); 5],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            OutboundOptions {
                socks5: Some(Socks5Config {
                    address: "127.0.0.1:1080".into(),
                    username_env: Some("DATABASE_PASSWORD".into()),
                    password_env: Some("HANGANG_SOCKS5_PASSWORD".into()),
                }),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            UpstreamTls {
                insecure_skip_verify: true,
                ca_file: Some("/ca.pem".into()),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            UpstreamTls {
                max_fragment_size: Some(127),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        assert!(
            UpstreamTls {
                max_fragment_size: Some(16_390),
                ..Default::default()
            }
            .validate()
            .is_err()
        );
        for conflicting in [
            OutboundOptions {
                unix_socket: Some("/run/hangang/egress.sock".into()),
                connect_address: Some("127.0.0.1:443".into()),
                ..Default::default()
            },
            OutboundOptions {
                unix_socket: Some("/run/hangang/egress.sock".into()),
                dns_servers: vec!["127.0.0.1:53".parse().unwrap()],
                ..Default::default()
            },
            OutboundOptions {
                unix_socket: Some("/run/hangang/egress.sock".into()),
                socks5: Some(Socks5Config {
                    address: "127.0.0.1:1080".into(),
                    username_env: None,
                    password_env: None,
                }),
                ..Default::default()
            },
            OutboundOptions {
                unix_socket: Some("relative.sock".into()),
                ..Default::default()
            },
            OutboundOptions {
                unix_socket: Some("/run/../egress.sock".into()),
                ..Default::default()
            },
            OutboundOptions {
                unix_socket: Some(format!("/{}", "a".repeat(107)).into()),
                ..Default::default()
            },
        ] {
            assert!(conflicting.validate().is_err(), "{conflicting:?}");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_carries_plain_payload_and_close_without_tcp_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("egress.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let options = OutboundOptions {
            unix_socket: Some(path),
            ..Default::default()
        };
        let mut stream = connect("unresolvable.invalid:443", &options).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        server.await.unwrap();
        assert_eq!(stream.read(&mut payload).await.unwrap(), 0);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_tls_uses_logical_name_or_explicit_override() {
        let pair = rcgen::generate_simple_self_signed(vec!["relay.example".into()]).unwrap();
        let server_config = crate::tls::server_config(
            pair.cert.pem().as_bytes(),
            pair.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("tls.sock");
        let ca_file = directory.path().join("ca.pem");
        std::fs::write(&ca_file, pair.cert.pem()).unwrap();
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(first).await;
            let (second, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(second).await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").await.unwrap();
        });
        let base = crate::tls::client_config(None).unwrap();
        let tls = UpstreamTls {
            ca_file: Some(ca_file),
            ..Default::default()
        };
        let config = Arc::new(build_client_config(&base, &tls).unwrap());
        let options = OutboundOptions {
            unix_socket: Some(path.clone()),
            tls: Some(tls.clone()),
            ..Default::default()
        };
        assert!(
            connect_with_tls("wrong.example:443", &options, Some(config.clone()))
                .await
                .is_err()
        );
        let options = OutboundOptions {
            unix_socket: Some(path),
            tls: Some(UpstreamTls {
                server_name: Some("relay.example".into()),
                ..tls
            }),
            ..Default::default()
        };
        let mut stream = connect_with_tls("wrong.example:443", &options, Some(config))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut payload = [0; 4];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"pong");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks_uses_remote_domain_address() {
        let (mut client, mut server) = duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 5 + 11 + 2];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..5], &[5, 1, 0, 3, 11]);
            assert_eq!(&request[5..16], b"example.com");
            assert_eq!(&request[16..], &443u16.to_be_bytes());
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
        });
        socks5_handshake(&mut client, "example.com", 443, None)
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks_username_password_authentication_is_exact() {
        let (mut client, mut server) = duplex(1024);
        let credentials = Credentials {
            username: b"alice".to_vec(),
            password: b"correct horse".to_vec(),
        };
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = vec![0; 2 + 5 + 1 + 13];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x05alice\x0dcorrect horse");
            server.write_all(&[1, 0]).await.unwrap();
            let mut request = [0; 10];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, &[5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
            server
                .write_all(&[5, 0, 0, 3, 2, b'o', b'k', 0, 1])
                .await
                .unwrap();
        });
        socks5_handshake(&mut client, "127.0.0.1", 80, Some(&credentials))
            .await
            .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks_rejects_unoffered_auth_and_failed_auth_without_sending_connect() {
        for (selection, auth_reply, expected) in [
            (0x02, None, "not offered"),
            (0x02, Some([1, 1]), "rejected authentication"),
        ] {
            let (mut client, mut server) = duplex(128);
            let credentials = auth_reply.map(|_| Credentials {
                username: b"u".to_vec(),
                password: b"p".to_vec(),
            });
            let server_task = tokio::spawn(async move {
                let mut greeting = [0; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[5, selection]).await.unwrap();
                if let Some(reply) = auth_reply {
                    let mut auth = [0; 5];
                    server.read_exact(&mut auth).await.unwrap();
                    server.write_all(&reply).await.unwrap();
                }
            });
            let error = socks5_handshake(&mut client, "host", 80, credentials.as_ref())
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains(expected), "{error}");
            server_task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn socks_reports_connect_error_and_truncation() {
        for (reply, expected) in [
            (vec![5, 5, 0, 1], "connection refused"),
            (vec![5, 0, 0, 1, 127], "early eof"),
            (vec![4, 0, 0, 1], "invalid reply version"),
            (vec![5, 0, 1, 1], "invalid reserved byte"),
            (vec![5, 0, 0, 9], "invalid address type"),
        ] {
            let (mut client, mut server) = duplex(128);
            let task = tokio::spawn(async move {
                let mut greeting = [0; 3];
                server.read_exact(&mut greeting).await.unwrap();
                server.write_all(&[5, 0]).await.unwrap();
                let mut request = [0; 11];
                server.read_exact(&mut request).await.unwrap();
                server.write_all(&reply).await.unwrap();
            });
            let error = socks5_handshake(&mut client, "host", 80, None)
                .await
                .unwrap_err()
                .to_string()
                .to_ascii_lowercase();
            assert!(error.contains(expected), "{error}");
            task.await.unwrap();
        }
    }

    #[tokio::test]
    async fn connect_address_overrides_the_socket_destination() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let options = OutboundOptions {
            connect_address: Some(listener.local_addr().unwrap().to_string()),
            ..Default::default()
        };
        let (connected, accepted) = tokio::join!(
            connect("unresolvable.invalid:443", &options),
            listener.accept()
        );
        connected.unwrap();
        accepted.unwrap();
    }

    #[tokio::test]
    async fn socks_failure_never_falls_back_to_the_target() {
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_address = target.local_addr().unwrap();
        let proxy_address = proxy.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            stream.write_all(&[5, 5, 0, 1]).await.unwrap();
        });
        let options = OutboundOptions {
            socks5: Some(Socks5Config {
                address: proxy_address.to_string(),
                username_env: None,
                password_env: None,
            }),
            ..Default::default()
        };
        let error = connect(&target_address.to_string(), &options)
            .await
            .err()
            .expect("SOCKS5 failure")
            .to_string();
        assert!(error.contains("SOCKS5 negotiation failed"), "{error}");
        proxy_task.await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "a direct fallback unexpectedly reached the target"
        );
    }

    #[tokio::test]
    async fn configured_dns_resolves_both_socks_proxy_and_destination() {
        let dns = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_address = dns.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            let mut query = [0u8; 512];
            loop {
                let (length, peer) = dns.recv_from(&mut query).await.unwrap();
                let query = &query[..length];
                assert!(query.len() >= 17);
                let mut end = 12;
                while query[end] != 0 {
                    end += query[end] as usize + 1;
                    assert!(end < query.len());
                }
                let question_end = end + 5;
                let query_type = u16::from_be_bytes([query[end + 1], query[end + 2]]);
                let answer_count = u16::from(query_type == 1);
                let mut response = Vec::with_capacity(question_end + 16);
                response.extend_from_slice(&query[..2]);
                response.extend_from_slice(&[0x81, 0x80]);
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&answer_count.to_be_bytes());
                response.extend_from_slice(&[0, 0, 0, 0]);
                response.extend_from_slice(&query[12..question_end]);
                if answer_count == 1 {
                    response.extend_from_slice(&[
                        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
                        127, 0, 0, 1,
                    ]);
                }
                dns.send_to(&response, peer).await.unwrap();
            }
        });

        let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy.local_addr().unwrap().port();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 0x20, 0xfb]);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
        });
        let options = OutboundOptions {
            dns_servers: vec![dns_address],
            socks5: Some(Socks5Config {
                address: format!("proxy-transport.test:{proxy_port}"),
                username_env: None,
                password_env: None,
            }),
            ..Default::default()
        };
        connect("origin-transport.test:8443", &options)
            .await
            .unwrap();
        proxy_task.await.unwrap();
        dns_task.abort();
        let _ = dns_task.await;
    }

    #[test]
    fn client_config_applies_fragment_size_and_checks_ca_files() {
        let base = crate::tls::client_config(None).unwrap();
        let configured = build_client_config(
            &base,
            &UpstreamTls {
                max_fragment_size: Some(512),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(configured.max_fragment_size, Some(512));
        assert_eq!(base.max_fragment_size, None);

        let directory = tempfile::tempdir().unwrap();
        let options = UpstreamTls {
            ca_file: Some(directory.path().to_owned()),
            ..Default::default()
        };
        assert!(
            build_client_config(&base, &options)
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
        let empty = directory.path().join("empty.pem");
        std::fs::write(&empty, []).unwrap();
        let options = UpstreamTls {
            ca_file: Some(empty),
            ..Default::default()
        };
        assert!(
            build_client_config(&base, &options)
                .unwrap_err()
                .to_string()
                .contains("no certificates")
        );
    }

    #[test]
    fn custom_ca_fingerprint_tracks_exact_parsed_trust_without_a_second_read() {
        let base = crate::tls::client_config(None).unwrap();
        let first = rcgen::generate_simple_self_signed(vec!["first.example".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["second.example".into()]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("roots.pem");
        let options = UpstreamTls {
            ca_file: Some(path.clone()),
            ..Default::default()
        };

        std::fs::write(&path, first.cert.pem()).unwrap();
        let (_, initial) = build_client_config_with_trust(&base, &options).unwrap();
        let initial = initial.expect("custom trust must have a fingerprint");
        let (_, same) = build_client_config_with_trust(&base, &options).unwrap();
        assert_eq!(same, Some(initial));
        // The fingerprint describes parsed DER, not irrelevant PEM spacing.
        std::fs::write(&path, format!("\n{}\n", first.cert.pem())).unwrap();
        let (_, reformatted) = build_client_config_with_trust(&base, &options).unwrap();
        assert_eq!(reformatted, Some(initial));

        std::fs::write(&path, second.cert.pem()).unwrap();
        let (_, replaced) = build_client_config_with_trust(&base, &options).unwrap();
        assert_ne!(replaced, Some(initial));
        assert_eq!(
            build_client_config(&base, &options)
                .unwrap()
                .max_fragment_size,
            None,
            "the existing builder remains source-compatible"
        );

        std::fs::write(&path, "not a certificate").unwrap();
        assert!(build_client_config_with_trust(&base, &options).is_err());
        assert!(build_client_config(&base, &options).is_err());

        let (_, no_custom_ca) =
            build_client_config_with_trust(&base, &UpstreamTls::default()).unwrap();
        assert_eq!(no_custom_ca, None);
    }

    #[tokio::test]
    async fn insecure_tls_accepts_an_untrusted_chain_with_a_valid_signature() {
        let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = crate::tls::server_config(
            pair.cert.pem().as_bytes(),
            pair.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await.is_ok()
        });

        let tls = UpstreamTls {
            server_name: Some("localhost".into()),
            insecure_skip_verify: true,
            ..Default::default()
        };
        let base = crate::tls::client_config(None).unwrap();
        let config = Arc::new(build_client_config(&base, &tls).unwrap());
        let options = OutboundOptions {
            tls: Some(tls),
            ..Default::default()
        };
        let connected = connect_with_tls(&address.to_string(), &options, Some(config)).await;
        if let Err(error) = connected {
            panic!("TLS connection failed: {error:#}");
        }
        assert!(server_task.await.unwrap());
    }
}
