//! Operator-defined bodies for errors the gateway itself produces
//! (403, 404, 502, 503, 504), globally (`settings.error_pages`) or per HTTP
//! route (`error_pages`). Upstream responses are never rewritten.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use hyper::header::HeaderValue;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, collections::HashMap, io::Read, path::PathBuf, sync::Arc};

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
    /// Absolute path of a file on the gateway node, read when the
    /// configuration is activated (not per request).
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
            (None, Some(path)) => ensure!(
                path.is_absolute(),
                "error_pages.{status}.body_file must be an absolute path"
            ),
            _ => anyhow::bail!("error_pages.{status} needs exactly one of body or body_file"),
        }
    }
    Ok(())
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
    validate(pages)?;
    if pages.is_empty() {
        return Ok(None);
    }
    let mut prepared = Prepared::default();
    for (status, page) in pages {
        let body = match (&page.body, &page.body_file) {
            (Some(body), _) => Bytes::from(body.clone()),
            (None, Some(path)) => {
                let mut bytes = Vec::new();
                std::fs::File::open(path)
                    .with_context(|| format!("error_pages.{status}.body_file"))?
                    .take(MAX_BODY_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .with_context(|| format!("error_pages.{status}.body_file"))?;
                ensure!(
                    bytes.len() <= MAX_BODY_BYTES,
                    "error_pages.{status}.body_file exceeds 64 KiB"
                );
                Bytes::from(bytes)
            }
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
                body_file: Some("/tmp/x".into()),
            },
        );
        assert!(validate(&pages).is_err());
        pages.insert(
            503,
            ErrorPage {
                content_type: "text/html".into(),
                body: None,
                body_file: Some("relative.html".into()),
            },
        );
        assert!(validate(&pages).is_err());
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

    #[test]
    fn files_are_loaded_once_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let small = directory.path().join("503.html");
        std::fs::write(&small, "<h1>later</h1>").unwrap();
        let large = directory.path().join("big.html");
        std::fs::write(&large, vec![b'x'; MAX_BODY_BYTES + 1]).unwrap();
        let mut pages = ErrorPages::new();
        pages.insert(
            503,
            ErrorPage {
                content_type: "text/html; charset=utf-8".into(),
                body: None,
                body_file: Some(small.clone()),
            },
        );
        let prepared = prepare(&pages).unwrap().unwrap();
        // Later edits do not change the activated page.
        std::fs::write(&small, "changed").unwrap();
        assert_eq!(prepared.page(503).unwrap().1, Bytes::from("<h1>later</h1>"));
        assert!(prepared.page(502).is_none());
        pages.get_mut(&503).unwrap().body_file = Some(large);
        assert!(prepare(&pages).is_err());
        pages.get_mut(&503).unwrap().body_file = Some(directory.path().join("missing"));
        assert!(prepare(&pages).is_err());
        assert!(prepare(&ErrorPages::new()).unwrap().is_none());
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
