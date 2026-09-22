//! Public GitHub release discovery. Metadata is not an update trust root.
use anyhow::{Context, Result, ensure};
use reqwest::{Client, Url};
use semver::Version;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const REPOSITORY: &str = "ziozzang/hangang";
pub const API_URL: &str = "https://api.github.com/repos/ziozzang/hangang/releases/latest";
const MAX_METADATA: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub assets: Vec<Asset>,
}
#[derive(Debug, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}
#[derive(Debug)]
pub struct Selection {
    pub version: Version,
    pub manifest_url: String,
    pub artifact_url: String,
    pub artifact_size: u64,
}
#[derive(Debug, Serialize)]
pub struct Check {
    pub repository: &'static str,
    pub current_version: Version,
    pub latest_version: Version,
    pub update_available: bool,
    /// Asset presence only; signature verification occurs during staging.
    pub signed_assets_present: bool,
    pub release_url: String,
}

impl Release {
    pub fn version(&self) -> Result<Version> {
        ensure!(
            !self.draft && !self.prerelease,
            "release is not a published stable release"
        );
        ensure!(self.assets.len() <= 256, "too many release assets");
        let version = Version::parse(self.tag_name.strip_prefix('v').unwrap_or(&self.tag_name))
            .context("GitHub release tag is not a semantic version")?;
        ensure!(
            version.pre.is_empty() && version.build.is_empty(),
            "release tag must be a stable version without build metadata"
        );
        ensure!(
            self.tag_name == format!("v{version}"),
            "release tag must use canonical v-prefixed version"
        );
        Ok(version)
    }

    pub fn select(&self, target: &str) -> Result<Selection> {
        let version = self.version()?;
        ensure!(
            !target.is_empty()
                && target.len() <= 128
                && target
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "invalid release target"
        );
        let binary = format!("hangang-{target}");
        let manifest = format!("{binary}.manifest.json");
        let find = |name: &str, maximum: u64| -> Result<&Asset> {
            let matches: Vec<_> = self.assets.iter().filter(|a| a.name == name).collect();
            ensure!(
                matches.len() == 1,
                "release must contain exactly one {name} asset"
            );
            let asset = matches[0];
            ensure!(
                asset.size > 0 && asset.size <= maximum,
                "invalid size for release asset {name}"
            );
            let expected = format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{name}",
                self.tag_name
            );
            ensure!(
                asset.browser_download_url == expected,
                "release asset URL does not match repository, tag, and name"
            );
            Ok(asset)
        };
        let manifest = find(&manifest, crate::update::MAX_MANIFEST_BYTES)?;
        let artifact = find(&binary, crate::update::MAX_ARTIFACT_BYTES)?;
        Ok(Selection {
            version,
            manifest_url: manifest.browser_download_url.clone(),
            artifact_url: artifact.browser_download_url.clone(),
            artifact_size: artifact.size,
        })
    }

    pub fn check(&self, current: Version, target: &str) -> Result<Check> {
        let latest = self.version()?;
        Ok(Check {
            repository: REPOSITORY,
            update_available: latest > current,
            signed_assets_present: self.select(target).is_ok(),
            current_version: current,
            latest_version: latest,
            release_url: format!(
                "https://github.com/{REPOSITORY}/releases/tag/{}",
                self.tag_name
            ),
        })
    }
}

pub async fn latest() -> Result<Release> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("hangang/", env!("CARGO_PKG_VERSION")))
        .build()?;
    fetch(&client, API_URL).await
}

pub(crate) async fn fetch(client: &Client, endpoint: &str) -> Result<Release> {
    let response = client
        .get(endpoint)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("fetch GitHub release metadata")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "GitHub release lookup returned HTTP {}",
        response.status()
    );
    let bytes = crate::update::read_response_limited(response, MAX_METADATA, "4 MiB").await?;
    let release: Release =
        serde_json::from_slice(&bytes).context("invalid GitHub release metadata")?;
    release.version()?;
    Ok(release)
}

/// A narrowly scoped exception to the generic updater's same-origin policy.
/// Never applies to operator-provided manifest URLs or GitHub API requests.
pub(crate) fn asset_redirect_allowed(original: &Url, next: &Url) -> bool {
    let transport = |url: &Url| {
        url.scheme() == "https"
            && url.port().is_none_or(|p| p == 443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    };
    if !transport(original) || !transport(next) {
        return false;
    }
    let prefix = format!("/{REPOSITORY}/releases/download/");
    original.host_str() == Some("github.com")
        && original.path().starts_with(&prefix)
        && (next.host_str() == Some("release-assets.githubusercontent.com")
            || (next.host_str() == Some("github.com") && next.path().starts_with(&prefix)))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn release() -> Release {
        let binary = "hangang-x86_64-unknown-linux-gnu";
        Release {
            tag_name: "v9.0.0".into(),
            draft: false,
            prerelease: false,
            assets: [binary.to_string(), format!("{binary}.manifest.json")]
                .into_iter()
                .map(|name| Asset {
                    browser_download_url: format!(
                        "https://github.com/{REPOSITORY}/releases/download/v9.0.0/{name}"
                    ),
                    name,
                    size: 64,
                })
                .collect(),
        }
    }
    #[test]
    fn exact_assets_and_semver_are_required() {
        let mut r = release();
        assert!(r.select("x86_64-unknown-linux-gnu").is_ok());
        assert!(r.select("../../wrong").is_err());
        r.assets[0].browser_download_url = "https://other.example/binary".into();
        assert!(r.select("x86_64-unknown-linux-gnu").is_err());
        for tag in ["latest", "v9.0.0-rc.1", "v9.0.0+build", "9.0.0", "v09.0.0"] {
            let mut r = release();
            r.tag_name = tag.into();
            assert!(r.version().is_err());
        }
        let mut r = release();
        r.prerelease = true;
        assert!(r.version().is_err());
        let mut r = release();
        r.draft = true;
        assert!(r.version().is_err());
    }
    #[test]
    fn missing_duplicate_and_oversized_assets_fail_closed() {
        let mut r = release();
        r.assets.pop();
        assert!(r.select("x86_64-unknown-linux-gnu").is_err());
        let mut r = release();
        r.assets[0].size = crate::update::MAX_ARTIFACT_BYTES + 1;
        assert!(r.select("x86_64-unknown-linux-gnu").is_err());
        let mut r = release();
        r.assets.push(Asset {
            name: r.assets[0].name.clone(),
            browser_download_url: r.assets[0].browser_download_url.clone(),
            size: 64,
        });
        assert!(r.select("x86_64-unknown-linux-gnu").is_err());
        let check = release()
            .check(Version::new(10, 0, 0), "x86_64-unknown-linux-gnu")
            .unwrap();
        assert!(!check.update_available);
    }
    #[test]
    fn redirect_exception_is_specific_to_github_release_assets() {
        let from =
            Url::parse("https://github.com/ziozzang/hangang/releases/download/v9.0.0/binary")
                .unwrap();
        let good = Url::parse("https://release-assets.githubusercontent.com/github-production-release-asset/asset?token=test").unwrap();
        assert!(asset_redirect_allowed(&from, &good));
        for url in [
            "http://release-assets.githubusercontent.com/asset",
            "https://evil.release-assets.githubusercontent.com/asset",
            "https://github.com/other/repo/releases/download/v9.0.0/a",
            "https://user@release-assets.githubusercontent.com/a",
            "https://release-assets.githubusercontent.com:444/a",
            "https://127.0.0.1/a",
        ] {
            assert!(!asset_redirect_allowed(&from, &Url::parse(url).unwrap()));
        }
        assert!(!asset_redirect_allowed(
            &Url::parse("https://private.example/manifest").unwrap(),
            &good
        ));
    }
    #[tokio::test]
    async fn discovery_uses_bounded_json_and_rejects_http_errors() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            for reply in [
                "HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n",
                "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let _ = stream.read(&mut request).await.unwrap();
                stream.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        assert!(fetch(&client, &endpoint).await.is_err());
        assert!(fetch(&client, &endpoint).await.is_err());
        task.await.unwrap();
    }
}
