//! Operator-defined bodies for errors the gateway itself produces
//! (403, 404, 502, 503, 504), globally (`settings.error_pages`) or per HTTP
//! route (`error_pages`). Upstream responses are never rewritten.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use hyper::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    collections::HashMap,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};

/// Status codes whose gateway-generated body may be replaced.
pub const STATUSES: [u16; 5] = [403, 404, 502, 503, 504];
/// Largest accepted body, inline or from a file.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorPage {
    /// Response `Content-Type`, for example `text/html; charset=utf-8` or
    /// `application/json`.
    pub content_type: String,
    /// Inline body. Exactly one of `body` and `body_file` is required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Relative file name inside the operator's `--error-pages-dir`, read
    /// when the configuration is activated (not per request). Absolute
    /// paths, `..`, symbolic links leaving the directory, and anything but a
    /// regular file of at most 64 KiB are rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_file: Option<PathBuf>,
}

/// Status code (as a JSON object key) to page.
pub type ErrorPages = BTreeMap<u16, ErrorPage>;

pub fn validate(pages: &ErrorPages) -> Result<()> {
    for (status, page) in pages {
        ensure!(
            STATUSES.contains(status),
            "error_pages supports only statuses {STATUSES:?}, not {status}"
        );
        ensure!(
            page.content_type.len() <= 256
                && HeaderValue::from_str(&page.content_type).is_ok()
                && !page.content_type.trim().is_empty(),
            "error_pages.{status}.content_type must be a nonempty header value of at most 256 bytes"
        );
        match (&page.body, &page.body_file) {
            (Some(body), None) => ensure!(
                body.len() <= MAX_BODY_BYTES,
                "error_pages.{status}.body exceeds 64 KiB"
            ),
            (None, Some(path)) => check_relative(*status, path)?,
            _ => anyhow::bail!("error_pages.{status} needs exactly one of body or body_file"),
        }
    }
    Ok(())
}

static PAGES_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Set once at startup from `--error-pages-dir` (operator-controlled, never
/// from the shared configuration). The directory is canonicalized here.
pub fn set_pages_dir(directory: &Path) -> Result<()> {
    let canonical = std::fs::canonicalize(directory)
        .with_context(|| format!("--error-pages-dir {}", directory.display()))?;
    ensure!(canonical.is_dir(), "--error-pages-dir must be a directory");
    PAGES_DIR
        .set(canonical)
        .map_err(|_| anyhow::anyhow!("error pages directory already set"))
}

fn check_relative(status: u16, path: &Path) -> Result<()> {
    ensure!(
        !path.as_os_str().is_empty()
            && path
                .components()
                .all(|part| matches!(part, Component::Normal(_))),
        "error_pages.{status}.body_file must be a relative path inside --error-pages-dir without '..' or '.'"
    );
    Ok(())
}

/// Read `relative` inside `root` (already canonical), refusing escapes via
/// symbolic links, non-regular files and oversized files.
fn read_confined(status: u16, root: Option<&Path>, relative: &Path) -> Result<Vec<u8>> {
    check_relative(status, relative)?;
    let root = root.with_context(|| {
        format!("error_pages.{status}.body_file needs the gateway started with --error-pages-dir")
    })?;
    let context = || format!("error_pages.{status}.body_file");
    let resolved = std::fs::canonicalize(root.join(relative)).with_context(context)?;
    ensure!(
        resolved.starts_with(root) && resolved != root,
        "error_pages.{status}.body_file resolves outside --error-pages-dir"
    );
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Refuse a final symbolic link swapped in after canonicalization and
        // never block on a FIFO.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&resolved).with_context(context)?;
    let metadata = file.metadata().with_context(context)?;
    ensure!(
        metadata.is_file(),
        "error_pages.{status}.body_file must be a regular file"
    );
    ensure!(
        metadata.len() <= MAX_BODY_BYTES as u64,
        "error_pages.{status}.body_file exceeds 64 KiB"
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        // The opened file itself must still be inside the directory, closing
        // the race where a parent directory is swapped for a link.
        let opened = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .with_context(context)?;
        ensure!(
            opened.starts_with(root),
            "error_pages.{status}.body_file resolves outside --error-pages-dir"
        );
    }
    let mut bytes = Vec::new();
    file.take(MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(context)?;
    ensure!(
        bytes.len() <= MAX_BODY_BYTES,
        "error_pages.{status}.body_file exceeds 64 KiB"
    );
    Ok(bytes)
}

/// Pages with bodies loaded, ready to serve.
#[derive(Debug, Default)]
pub struct Prepared {
    pages: HashMap<u16, (HeaderValue, Bytes)>,
}

impl Prepared {
    pub fn page(&self, status: u16) -> Option<&(HeaderValue, Bytes)> {
        self.pages.get(&status)
    }
}

/// Validate and load every page. Files are read here, once per activation.
pub fn prepare(pages: &ErrorPages) -> Result<Option<Arc<Prepared>>> {
    prepare_in(pages, PAGES_DIR.get().map(PathBuf::as_path))
}

fn prepare_in(pages: &ErrorPages, root: Option<&Path>) -> Result<Option<Arc<Prepared>>> {
    validate(pages)?;
    if pages.is_empty() {
        return Ok(None);
    }
    let mut prepared = Prepared::default();
    for (status, page) in pages {
        let body = match (&page.body, &page.body_file) {
            (Some(body), _) => Bytes::from(body.clone()),
            (None, Some(path)) => Bytes::from(read_confined(*status, root, path)?),
            (None, None) => unreachable!("validated error page"),
        };
        let content_type = HeaderValue::from_str(&page.content_type)?;
        prepared.pages.insert(*status, (content_type, body));
    }
    Ok(Some(Arc::new(prepared)))
}

/// Marks a response body written by the gateway rather than an upstream.
#[derive(Clone, Copy, Debug)]
pub struct GatewayGenerated;

/// Set by routing once a route is selected, so its pages take precedence.
#[derive(Clone, Debug, Default)]
pub struct RouteSlot(pub Arc<std::sync::OnceLock<Arc<Prepared>>>);

#[cfg(test)]
mod tests {
    use super::*;

    fn page(body: &str) -> ErrorPage {
        ErrorPage {
            content_type: "application/json".into(),
            body: Some(body.into()),
            body_file: None,
        }
    }

    #[test]
    fn validation_bounds_statuses_bodies_and_sources() {
        let mut pages = ErrorPages::new();
        pages.insert(502, page("{}"));
        validate(&pages).unwrap();
        pages.insert(500, page("{}"));
        assert!(validate(&pages).is_err());
        pages.remove(&500);
        pages.insert(503, page(&"x".repeat(MAX_BODY_BYTES + 1)));
        assert!(validate(&pages).is_err());
        pages.insert(
            503,
            ErrorPage {
                content_type: "text/html".into(),
                body: Some("a".into()),
                body_file: Some("x.html".into()),
            },
        );
        assert!(validate(&pages).is_err());
        pages.insert(
            503,
            ErrorPage {
                content_type: "text/html".into(),
                body: None,
                body_file: Some("pages/503.html".into()),
            },
        );
        validate(&pages).unwrap();
        for bad in ["/etc/passwd", "../secret", "a/../../b", "./x", ""] {
            pages.get_mut(&503).unwrap().body_file = Some(bad.into());
            assert!(validate(&pages).is_err(), "{bad} accepted");
        }
        pages.insert(
            503,
            ErrorPage {
                content_type: "bad\nvalue".into(),
                body: Some("a".into()),
                body_file: None,
            },
        );
        assert!(validate(&pages).is_err());
    }

    fn file_page(path: impl Into<PathBuf>) -> ErrorPages {
        let mut pages = ErrorPages::new();
        pages.insert(
            503,
            ErrorPage {
                content_type: "text/html; charset=utf-8".into(),
                body: None,
                body_file: Some(path.into()),
            },
        );
        pages
    }

    fn rejects(pages: &ErrorPages, root: &Path, needle: &str) {
        let error = format!("{:#}", prepare_in(pages, Some(root)).unwrap_err());
        assert!(error.contains(needle), "{error}");
    }

    #[test]
    fn files_are_loaded_once_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        std::fs::write(root.join("503.html"), "<h1>later</h1>").unwrap();
        std::fs::write(root.join("big.html"), vec![b'x'; MAX_BODY_BYTES + 1]).unwrap();
        let mut pages = file_page("503.html");
        let prepared = prepare_in(&pages, Some(&root)).unwrap().unwrap();
        // Later edits do not change the activated page.
        std::fs::write(root.join("503.html"), "changed").unwrap();
        assert_eq!(prepared.page(503).unwrap().1, Bytes::from("<h1>later</h1>"));
        assert!(prepared.page(502).is_none());
        pages.get_mut(&503).unwrap().body_file = Some("big.html".into());
        rejects(&pages, &root, "exceeds 64 KiB");
        pages.get_mut(&503).unwrap().body_file = Some("missing".into());
        assert!(prepare_in(&pages, Some(&root)).is_err());
        assert!(
            prepare_in(&ErrorPages::new(), Some(&root))
                .unwrap()
                .is_none()
        );
        // Without an operator directory no file is ever read.
        pages.get_mut(&503).unwrap().body_file = Some("503.html".into());
        let error = format!("{:#}", prepare_in(&pages, None).unwrap_err());
        assert!(error.contains("--error-pages-dir"), "{error}");
    }

    #[test]
    fn body_file_cannot_escape_the_pages_directory() {
        let outside = tempfile::tempdir().unwrap();
        let secret = std::fs::canonicalize(outside.path())
            .unwrap()
            .join("key.pem");
        std::fs::write(&secret, "PRIVATE KEY").unwrap();
        let directory = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(directory.path()).unwrap();
        let pages_root = root.join("pages");
        std::fs::create_dir(&pages_root).unwrap();
        std::fs::write(root.join("sibling.html"), "sibling").unwrap();

        // Absolute paths and parent components.
        rejects(&file_page(&secret), &pages_root, "relative path");
        rejects(&file_page("../sibling.html"), &pages_root, "relative path");
        rejects(
            &file_page("sub/../../sibling.html"),
            &pages_root,
            "relative path",
        );
        // Symbolic links: a file link and a directory link pointing outside.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&secret, pages_root.join("link.html")).unwrap();
            rejects(&file_page("link.html"), &pages_root, "outside");
            std::os::unix::fs::symlink(outside.path(), pages_root.join("dir")).unwrap();
            rejects(&file_page("dir/key.pem"), &pages_root, "outside");
            // A link that stays inside is fine.
            std::fs::write(pages_root.join("real.html"), "ok").unwrap();
            std::os::unix::fs::symlink(pages_root.join("real.html"), pages_root.join("in.html"))
                .unwrap();
            let prepared = prepare_in(&file_page("in.html"), Some(&pages_root))
                .unwrap()
                .unwrap();
            assert_eq!(prepared.page(503).unwrap().1, Bytes::from("ok"));
        }
        // Directories and device files.
        std::fs::create_dir(pages_root.join("folder")).unwrap();
        rejects(&file_page("folder"), &pages_root, "regular file");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/dev/zero", pages_root.join("zero")).unwrap();
            rejects(&file_page("zero"), &pages_root, "outside");
        }
        #[cfg(target_os = "linux")]
        rejects(&file_page("zero"), Path::new("/dev"), "regular file");
    }

    #[test]
    fn json_keys_are_status_codes() {
        let pages: ErrorPages = serde_json::from_str(
            r#"{"502":{"content_type":"application/json","body":"{\"error\":\"bad_gateway\"}"}}"#,
        )
        .unwrap();
        assert!(pages.contains_key(&502));
    }
}
