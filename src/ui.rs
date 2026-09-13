//! Management assets embedded in the executable; account sessions persist in same-tab session storage.
use crate::proxy::Body;
use base64::Engine;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};

fn body(value: impl Into<bytes::Bytes>) -> Body {
    http_body_util::Full::new(value.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn serve<B>(request: &Request<B>) -> Option<Response<Body>> {
    let path = request.uri().path();
    if path != "/ui" && !path.starts_with("/ui/") {
        return None;
    }
    let mut style_nonce = None;
    let mut response = if request.method() != Method::GET && request.method() != Method::HEAD {
        Response::builder()
            .status(405)
            .header("allow", "GET, HEAD")
            .body(body("method not allowed"))
            .unwrap()
    } else if path == "/ui" {
        Response::builder()
            .status(308)
            .header("location", "/ui/")
            .body(body(""))
            .unwrap()
    } else if matches!(path, "/ui/" | "/ui/index.html") {
        // CodeMirror creates scoped style sheets. Authorize only this HTML
        // response's fresh nonce; scripts remain restricted to same-origin
        // assets, and no unsafe-inline/eval policy is introduced.
        let mut random = [0_u8; 32];
        if rustls::crypto::ring::default_provider()
            .secure_random
            .fill(&mut random)
            .is_err()
        {
            Response::builder()
                .status(503)
                .body(body("management UI unavailable"))
                .unwrap()
        } else {
            let nonce = base64::engine::general_purpose::STANDARD.encode(random);
            let html = include_str!("../web/index.html").replacen(
                "<head>",
                &format!("<head><meta name=\"csp-nonce\" content=\"{nonce}\">"),
                1,
            );
            let length = html.len();
            style_nonce = Some(nonce);
            Response::builder()
                .header("content-type", "text/html; charset=utf-8")
                .header("content-length", length)
                .body(body(if request.method() == Method::HEAD {
                    bytes::Bytes::new()
                } else {
                    bytes::Bytes::from(html)
                }))
                .unwrap()
        }
    } else {
        let asset: Option<(&str, &'static [u8])> = match path {
            "/ui/lua-editor.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/lua-editor.js"),
            )),
            "/ui/lua-editor.css" => Some((
                "text/css; charset=utf-8",
                include_bytes!("../web/lua-editor.css"),
            )),
            "/ui/app.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/app.js"),
            )),
            "/ui/console.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/console.js"),
            )),
            "/ui/i18n.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/i18n.js"),
            )),
            "/ui/locales/ko-static.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/locales/ko-static.js"),
            )),
            "/ui/locales/ko-app.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/locales/ko-app.js"),
            )),
            "/ui/locales/ko-console.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/locales/ko-console.js"),
            )),
            "/ui/operations.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/operations.js"),
            )),
            "/ui/locales/ko-operations.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/locales/ko-operations.js"),
            )),
            "/ui/docker.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/docker.js"),
            )),
            "/ui/locales/ko-docker.js" => Some((
                "text/javascript; charset=utf-8",
                include_bytes!("../web/locales/ko-docker.js"),
            )),
            "/ui/style.css" => Some((
                "text/css; charset=utf-8",
                include_bytes!("../web/style.css"),
            )),
            _ => None,
        };
        match asset {
            Some((kind, bytes)) => Response::builder()
                .header("content-type", kind)
                .header("content-length", bytes.len())
                .body(body(if request.method() == Method::HEAD {
                    bytes::Bytes::new()
                } else {
                    bytes::Bytes::from_static(bytes)
                }))
                .unwrap(),
            None => Response::builder()
                .status(404)
                .body(body("not found"))
                .unwrap(),
        }
    };
    let headers = response.headers_mut();
    let styles = style_nonce
        .map(|nonce| format!("'self' 'nonce-{nonce}'"))
        .unwrap_or_else(|| "'self'".to_owned());
    headers.insert("content-security-policy", format!("default-src 'none'; script-src 'self'; style-src {styles}; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'").parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("cache-control", "no-store".parse().unwrap());
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn html_style_nonces_are_fresh_and_match_the_document() {
        let mut observed = Vec::new();
        for path in ["/ui/", "/ui/index.html"] {
            let response = serve(&Request::builder().uri(path).body(()).unwrap()).unwrap();
            let policy = response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .to_owned();
            assert!(policy.contains("script-src 'self';"));
            assert!(!policy.contains("unsafe-inline"));
            assert!(!policy.contains("unsafe-eval"));
            let nonce = policy
                .split("'nonce-")
                .nth(1)
                .unwrap()
                .split('\'')
                .next()
                .unwrap()
                .to_owned();
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&nonce)
                    .unwrap()
                    .len(),
                32
            );
            let expected_len: usize = response.headers()["content-length"]
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(bytes.len(), expected_len);
            let html = std::str::from_utf8(&bytes).unwrap();
            assert!(html.contains(&format!("<meta name=\"csp-nonce\" content=\"{nonce}\">")));
            observed.push(nonce);
        }
        assert_ne!(observed[0], observed[1]);
        let script = serve(
            &Request::builder()
                .uri("/ui/lua-editor.js")
                .body(())
                .unwrap(),
        )
        .unwrap();
        assert!(
            !script.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("nonce-")
        );
    }

    #[test]
    fn embedded_assets_have_strict_headers_and_head_semantics() {
        for path in [
            "/ui/",
            "/ui/app.js",
            "/ui/lua-editor.js",
            "/ui/lua-editor.css",
            "/ui/style.css",
            "/ui/console.js",
            "/ui/i18n.js",
            "/ui/locales/ko-static.js",
            "/ui/locales/ko-app.js",
            "/ui/locales/ko-console.js",
            "/ui/operations.js",
            "/ui/locales/ko-operations.js",
            "/ui/docker.js",
            "/ui/locales/ko-docker.js",
        ] {
            let get = serve(&Request::builder().uri(path).body(()).unwrap()).unwrap();
            assert_eq!(get.status(), 200);
            assert_eq!(get.headers()["cache-control"], "no-store");
            assert_eq!(get.headers()["x-content-type-options"], "nosniff");
            assert!(
                get.headers()["content-security-policy"]
                    .to_str()
                    .unwrap()
                    .contains("frame-ancestors 'none'")
            );
            let head = serve(
                &Request::builder()
                    .method(Method::HEAD)
                    .uri(path)
                    .body(())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                head.headers()["content-length"],
                get.headers()["content-length"]
            );
            assert_eq!(hyper::body::Body::size_hint(head.body()).exact(), Some(0));
        }
        assert_eq!(
            serve(&Request::builder().uri("/ui").body(()).unwrap())
                .unwrap()
                .status(),
            308
        );
        assert_eq!(
            serve(
                &Request::builder()
                    .uri("/ui/../Cargo.toml")
                    .body(())
                    .unwrap()
            )
            .unwrap()
            .status(),
            404
        );
        assert_eq!(
            serve(
                &Request::builder()
                    .method(Method::POST)
                    .uri("/ui/")
                    .body(())
                    .unwrap()
            )
            .unwrap()
            .status(),
            405
        );
        assert!(serve(&Request::builder().uri("/v1/config").body(()).unwrap()).is_none());
    }
}
