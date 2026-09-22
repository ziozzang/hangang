use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use rcgen::generate_simple_self_signed;
use semver::Version;
use sha2::Digest;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Good,
    Version,
    Url,
    Size,
    Signature,
    EvilRedirect,
}

struct Fixture {
    address: std::net::SocketAddr,
    certificate: reqwest::Certificate,
    mode: Arc<Mutex<Case>>,
    task: tokio::task::JoinHandle<()>,
}

impl Fixture {
    async fn start(artifact: Vec<u8>, signing_key: SigningKey) -> anyhow::Result<Self> {
        let pair = generate_simple_self_signed(vec![
            "api.github.com".into(),
            "github.com".into(),
            "release-assets.githubusercontent.com".into(),
        ])?;
        let mut tls = crate::tls::server_config(
            pair.cert.pem().as_bytes(),
            pair.signing_key.serialize_pem().as_bytes(),
        )?;
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let mode = Arc::new(Mutex::new(Case::Good));
        let server_mode = mode.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let mode = server_mode.clone();
                let artifact = artifact.clone();
                let signing_key = signing_key.clone();
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut request = vec![0; 16 * 1024];
                    let Ok(size) = stream.read(&mut request).await else {
                        return;
                    };
                    let request = String::from_utf8_lossy(&request[..size]);
                    let path = request.split_whitespace().nth(1).unwrap_or("/");
                    let host = request
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("host").then(|| value.trim())
                        })
                        .unwrap_or("");
                    let case = *mode.lock().await;
                    let target = "x86_64-unknown-linux-gnu";
                    let binary = format!("hangang-{target}");
                    let artifact_url = format!(
                        "https://github.com/ziozzang/hangang/releases/download/v9.0.0/{binary}"
                    );
                    let mut manifest_artifact_url = artifact_url.clone();
                    let mut manifest_version = "9.0.0";
                    let mut manifest_size = artifact.len() as u64;
                    if case == Case::Url {
                        manifest_artifact_url.push_str("-wrong");
                    }
                    if case == Case::Version {
                        manifest_version = "9.0.1";
                    }
                    if case == Case::Size {
                        manifest_size += 1;
                    }
                    let payload = super::ReleaseManifest {
                        version: Version::parse(manifest_version).unwrap(),
                        target: target.into(),
                        artifact_url: manifest_artifact_url,
                        sha256: format!("{:x}", sha2::Sha256::digest(&artifact)),
                        size: manifest_size,
                    };
                    let payload = serde_json::to_vec(&payload).unwrap();
                    let mut manifest =
                        super::sign_release_manifest(&payload, &signing_key).unwrap();
                    if case == Case::Signature {
                        let mut envelope: serde_json::Value =
                            serde_json::from_slice(&manifest).unwrap();
                        let mut signature = STANDARD
                            .decode(envelope["signature"].as_str().unwrap())
                            .unwrap();
                        signature[0] ^= 1;
                        envelope["signature"] = STANDARD.encode(signature).into();
                        manifest = serde_json::to_vec(&envelope).unwrap();
                    }
                    let response = if host == "api.github.com" {
                        let metadata = serde_json::json!({
                            "tag_name":"v9.0.0", "draft":false, "prerelease":false,
                            "assets":[
                                {"name":binary,"browser_download_url":artifact_url,"size":artifact.len()},
                                {"name":format!("{binary}.manifest.json"),"browser_download_url":format!("https://github.com/ziozzang/hangang/releases/download/v9.0.0/{binary}.manifest.json"),"size":manifest.len()}
                            ]
                        }).to_string();
                        http_response("200 OK", metadata.as_bytes())
                    } else if host == "github.com" {
                        let cdn_path = if path.ends_with(".manifest.json") {
                            "/cdn/manifest"
                        } else {
                            "/cdn/artifact"
                        };
                        let location =
                            format!("https://release-assets.githubusercontent.com{cdn_path}");
                        format!("HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").into_bytes()
                    } else if host == "release-assets.githubusercontent.com"
                        && path == "/cdn/manifest"
                    {
                        http_response("200 OK", &manifest)
                    } else if host == "release-assets.githubusercontent.com"
                        && path == "/cdn/artifact"
                    {
                        if case == Case::EvilRedirect {
                            b"HTTP/1.1 302 Found\r\nLocation: https://evil.example.invalid/artifact\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec()
                        } else {
                            http_response("200 OK", &artifact)
                        }
                    } else {
                        http_response("404 Not Found", b"missing")
                    };
                    let _ = stream.write_all(&response).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        Ok(Self {
            address,
            certificate: reqwest::Certificate::from_der(pair.cert.der())?,
            mode,
            task,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn http_response(status: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn manager(fixture: &Fixture, key: &SigningKey) -> anyhow::Result<super::UpdateManager> {
    let builder = super::update_client_builder(false, true)
        .no_proxy()
        .resolve("api.github.com", fixture.address)
        .resolve("github.com", fixture.address)
        .resolve("release-assets.githubusercontent.com", fixture.address)
        .add_root_certificate(fixture.certificate.clone());
    let client = builder.build()?;
    Ok(super::UpdateManager {
        trust_key: super::TrustKey::from_base64(&STANDARD.encode(key.verifying_key().to_bytes()))?,
        current_version: Version::parse("1.0.0")?,
        target: "x86_64-unknown-linux-gnu".into(),
        client,
        allow_loopback_http: false,
    })
}

#[tokio::test]
async fn github_release_update_is_end_to_end_bounded_and_bound_to_assets() -> anyhow::Result<()> {
    let key = SigningKey::from_bytes(&[41; 32]);
    let artifact = b"signed hangang candidate\n".to_vec();
    let fixture = Fixture::start(artifact.clone(), key.clone()).await?;
    let temporary = tempfile::tempdir()?;
    let updater = manager(&fixture, &key)?;
    let staged = updater.stage_github(temporary.path()).await?;
    assert_eq!(std::fs::read(staged.path())?, artifact);
    assert_eq!(staged.version(), &Version::parse("9.0.0")?);

    for (case, expected) in [
        (Case::Version, "version differs"),
        (Case::Url, "artifact URL differs"),
        (Case::Size, "artifact size differs"),
        (Case::Signature, "signature verification failed"),
        (
            Case::EvilRedirect,
            "cross-origin update redirect is forbidden",
        ),
    ] {
        *fixture.mode.lock().await = case;
        let error = manager(&fixture, &key)?
            .stage_github(temporary.path())
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains(expected), "{error:#}");
        assert_eq!(std::fs::read_dir(temporary.path())?.count(), 1);
    }

    let generic_client = super::update_client_builder(false, false)
        .no_proxy()
        .resolve("github.com", fixture.address)
        .add_root_certificate(fixture.certificate.clone())
        .build()?;
    let generic = super::UpdateManager {
        trust_key: super::TrustKey::from_base64(&STANDARD.encode(key.verifying_key().to_bytes()))?,
        current_version: Version::parse("1.0.0")?,
        target: "x86_64-unknown-linux-gnu".into(),
        client: generic_client,
        allow_loopback_http: false,
    };
    *fixture.mode.lock().await = Case::Good;
    let error = generic
        .stage(
            "https://github.com/ziozzang/hangang/releases/download/v9.0.0/hangang-x86_64-unknown-linux-gnu.manifest.json",
            temporary.path(),
        )
        .await
        .unwrap_err();
    assert!(
        format!("{error:#}").contains("cross-origin") || format!("{error:#}").contains("manifest")
    );
    Ok(())
}
