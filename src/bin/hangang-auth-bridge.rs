//! Bounded compatibility bridge for the existing service-scoped SSO plugin.
//! The bridge receives Hangang's trusted external-auth context, performs the
//! legacy session check, and returns an explicit terminal response when the
//! plugin would answer locally with an empty HTTP 200.

use anyhow::{Context, Result, ensure};
use arc_swap::ArcSwapOption;
use base64::Engine;
use bytes::Bytes;
use clap::Parser;
use http_body_util::Full;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::server::conn::http1;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::{
    convert::Infallible,
    io::Read,
    net::{IpAddr, SocketAddr},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    listen: SocketAddr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    auth_check_url: String,
    cookie_name: String,
    set_cookie_path: String,
    login_try_url: String,
    login_done_url: String,
    login_ban_url: String,
    allow_list: Vec<String>,
    deny_list: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_ms: u64,
}

fn default_timeout() -> u64 {
    1000
}

struct Prepared {
    settings: Settings,
    allow: Vec<Regex>,
    deny: Vec<Regex>,
    client: reqwest::Client,
}

fn prepare(settings: Settings) -> Result<Prepared> {
    ensure!(
        (1..=5000).contains(&settings.timeout_ms),
        "auth bridge timeout must be 1..5000 ms"
    );
    ensure!(
        !settings.cookie_name.is_empty()
            && settings.cookie_name.len() <= 128
            && settings
                .cookie_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
        "auth bridge cookie name is invalid"
    );
    ensure!(
        settings.set_cookie_path.starts_with('/')
            && settings.set_cookie_path.len() <= 2048
            && !settings.set_cookie_path.contains('?'),
        "auth bridge cookie setup path is invalid"
    );
    let check_url = reqwest::Url::parse(&settings.auth_check_url)?;
    ensure!(
        matches!(check_url.scheme(), "http" | "https")
            && check_url.host_str().is_some()
            && check_url.username().is_empty()
            && check_url.password().is_none()
            && check_url.fragment().is_none(),
        "auth bridge session check URL is invalid"
    );
    for target in [
        &settings.login_try_url,
        &settings.login_done_url,
        &settings.login_ban_url,
    ] {
        let url = reqwest::Url::parse(target)?;
        ensure!(
            matches!(url.scheme(), "http" | "https")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && target.len() <= 2048
                && HeaderValue::from_str(target).is_ok(),
            "auth bridge redirect URL is invalid"
        );
    }
    ensure!(
        settings.allow_list.len() <= 64 && settings.deny_list.len() <= 64,
        "auth bridge path lists exceed 64 entries"
    );
    let compile = |source: &String| -> Result<Regex> {
        ensure!(source.len() <= 512, "auth bridge regex exceeds 512 bytes");
        RegexBuilder::new(source)
            .size_limit(64 * 1024)
            .dfa_size_limit(64 * 1024)
            .nest_limit(32)
            .build()
            .context("invalid auth bridge regex")
    };
    let allow = settings
        .allow_list
        .iter()
        .map(compile)
        .collect::<Result<_>>()?;
    let deny = settings
        .deny_list
        .iter()
        .map(compile)
        .collect::<Result<_>>()?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(settings.timeout_ms))
        .connect_timeout(Duration::from_millis(settings.timeout_ms))
        .redirect(reqwest::redirect::Policy::none())
        .pool_max_idle_per_host(16)
        .build()?;
    Ok(Prepared {
        settings,
        allow,
        deny,
        client,
    })
}

fn load(path: &PathBuf) -> Result<Prepared> {
    ensure!(
        path.is_absolute()
            && path.as_os_str().as_encoded_bytes().len() <= 4096
            && path
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "auth bridge config requires a bounded normalized absolute path"
    );
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file(),
        "auth bridge config requires a regular file"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "auth bridge config must be private"
    );
    ensure!(
        metadata.len() <= 1024 * 1024,
        "auth bridge config exceeds 1 MiB"
    );
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "auth bridge config exceeds 1 MiB"
    );
    prepare(serde_json::from_slice(&bytes).context("invalid auth bridge JSON")?)
}

fn sole<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    first.to_str().ok()
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut fields = headers.get_all(header::COOKIE).iter();
    let field = fields.next()?;
    if fields.next().is_some() || field.as_bytes().len() > 16 * 1024 {
        return None;
    }
    let mut found = None;
    for part in field.to_str().ok()?.split(';') {
        let (key, value) = part.trim().split_once('=')?;
        if key == name {
            if value.is_empty() || found.is_some() {
                return None;
            }
            found = Some(value.to_owned());
        }
    }
    found
}

/// NGINX matches `ngx.var.uri` on the decoded, normalized path, whereas
/// Hangang forwards the original URI in its authorization context. Decode
/// once and merge redundant slashes before applying the legacy path policy.
/// Invalid escapes fail closed instead of accidentally missing a deny rule.
fn normalized_path(uri: &str) -> Option<String> {
    let raw = uri.split('?').next()?;
    let bytes = raw.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = if bytes[index] == b'%' {
            let nibble = |digit: u8| match digit {
                b'0'..=b'9' => Some(digit - b'0'),
                b'a'..=b'f' => Some(digit - b'a' + 10),
                b'A'..=b'F' => Some(digit - b'A' + 10),
                _ => None,
            };
            let hi = nibble(*bytes.get(index + 1)?)?;
            let lo = nibble(*bytes.get(index + 2)?)?;
            index += 3;
            hi * 16 + lo
        } else {
            let byte = bytes[index];
            index += 1;
            byte
        };
        if byte < 0x20 || byte == 0x7f || byte == b'\\' {
            return None;
        }
        if byte != b'/' || output.last() != Some(&b'/') {
            output.push(byte);
        }
    }
    let path = String::from_utf8(output).ok()?;
    path.starts_with('/').then_some(path)
}

fn reply(code: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::new()))
        .expect("static auth bridge response")
}

fn redirect(destination: &str, cookie: Option<&str>) -> Response<Full<Bytes>> {
    let mut response = reply(StatusCode::FOUND);
    response.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(destination).expect("validated redirect destination"),
    );
    if let Some(cookie) = cookie {
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(cookie).expect("base64 cookie and validated name"),
        );
    }
    response
}

async fn authorize(
    prepared: &Prepared,
    request: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    if request.method() != Method::GET || request.uri().path() != "/authorize" {
        return reply(StatusCode::NOT_FOUND);
    }
    let Some(uri) = sole(request.headers(), "x-original-uri") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Some(ip) = sole(request.headers(), "x-original-client-ip") else {
        return reply(StatusCode::SERVICE_UNAVAILABLE);
    };
    if uri.len() > 2048 || ip.len() > 45 || ip.parse::<IpAddr>().is_err() || !uri.starts_with('/') {
        return reply(StatusCode::SERVICE_UNAVAILABLE);
    }
    let Some(path) = normalized_path(uri) else {
        return reply(StatusCode::SERVICE_UNAVAILABLE);
    };
    if path == prepared.settings.set_cookie_path {
        let parsed = match reqwest::Url::parse(&format!("http://bridge.invalid{uri}")) {
            Ok(parsed) => parsed,
            Err(_) => return reply(StatusCode::SERVICE_UNAVAILABLE),
        };
        if let Some((_, supplied)) = parsed
            .query_pairs()
            .find(|(key, _)| key.as_ref() == prepared.settings.cookie_name)
            && supplied.len() <= 4096
        {
            let encoded = base64::engine::general_purpose::STANDARD.encode(supplied.as_bytes());
            let set_cookie = format!(
                "{}={encoded}; Path=/; secure",
                prepared.settings.cookie_name
            );
            return redirect(&prepared.settings.login_done_url, Some(&set_cookie));
        }
    }
    let Some(session) = cookie(request.headers(), &prepared.settings.cookie_name) else {
        return redirect(&prepared.settings.login_try_url, None);
    };
    let result = prepared
        .client
        .post(&prepared.settings.auth_check_url)
        .json(&serde_json::json!({"SSOSESSIONS":session,"client_ip":ip}))
        .send()
        .await;
    let Ok(mut result) = result else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut bytes = Vec::new();
    loop {
        match result.chunk().await {
            Ok(Some(chunk)) if bytes.len().saturating_add(chunk.len()) <= 1024 => {
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            _ => return reply(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
    if bytes.is_empty() {
        return reply(StatusCode::INTERNAL_SERVER_ERROR);
    }
    let Some(score) = std::str::from_utf8(&bytes)
        .ok()
        .and_then(|text| text.trim().parse::<f64>().ok())
        .filter(|score| score.is_finite())
    else {
        return reply(StatusCode::INTERNAL_SERVER_ERROR);
    };
    if score == -1.0 {
        return redirect(&prepared.settings.login_ban_url, None);
    }
    if score == 0.0 {
        return redirect(&prepared.settings.login_try_url, None);
    }
    if score == 1.0 {
        if prepared.deny.iter().any(|pattern| pattern.is_match(&path)) {
            return reply(StatusCode::FORBIDDEN);
        }
        if !prepared.allow.iter().any(|pattern| pattern.is_match(&path)) {
            let mut response = reply(StatusCode::OK);
            response
                .headers_mut()
                .insert("x-hangang-auth-terminal", HeaderValue::from_static("1"));
            return response;
        }
    }
    if score >= 1.0 {
        return reply(StatusCode::NO_CONTENT);
    }
    reply(StatusCode::INTERNAL_SERVER_ERROR)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let initial = tokio::task::spawn_blocking({
        let path = args.config.clone();
        move || load(&path)
    })
    .await??;
    let active = Arc::new(ArcSwapOption::from(Some(Arc::new(initial))));
    tokio::spawn({
        let active = active.clone();
        let path = args.config.clone();
        async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            loop {
                tick.tick().await;
                let path = path.clone();
                let next = tokio::task::spawn_blocking(move || load(&path)).await;
                active.store(next.ok().and_then(Result::ok).map(Arc::new));
            }
        }
    });
    let listener = TcpListener::bind(args.listen).await?;
    let permits = Arc::new(tokio::sync::Semaphore::new(256));
    let connections = Arc::new(tokio::sync::Semaphore::new(512));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(connection_permit) = connections.clone().try_acquire_owned() else {
            // Slow or idle clients must not exhaust the bridge's task set.
            drop(stream);
            continue;
        };
        let active = active.clone();
        let permits = permits.clone();
        tokio::spawn(async move {
            let _connection_permit = connection_permit;
            let service = hyper::service::service_fn(move |request| {
                let current = active.load_full();
                let permits = permits.clone();
                async move {
                    let response = if let (Some(current), Ok(_permit)) =
                        (current, permits.try_acquire_owned())
                    {
                        authorize(&current, request).await
                    } else {
                        reply(StatusCode::SERVICE_UNAVAILABLE)
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            let _ = http1::Builder::new()
                .keep_alive(false)
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(5))
                .max_buf_size(64 * 1024)
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use hyper::body::Incoming;
    use hyper::service::service_fn;
    use std::sync::Mutex;

    #[test]
    fn compatibility_path_rules_are_substring_regexes_and_ordered() {
        let prepared = prepare(Settings {
            auth_check_url: "http://127.0.0.1:9/check".into(),
            cookie_name: "SSOSESSIONS".into(),
            set_cookie_path: "/set-cookie".into(),
            login_try_url: "https://login.example/try".into(),
            login_done_url: "http://login.example/done".into(),
            login_ban_url: "http://login.example/ban".into(),
            allow_list: vec!["/docs".into()],
            deny_list: vec!["/docs/admin".into()],
            timeout_ms: 100,
        })
        .unwrap();
        assert!(prepared.allow[0].is_match("/prefix/docs"));
        assert!(prepared.deny[0].is_match("/docs/admin"));
        assert_eq!(
            normalized_path("/docs%2F%61dmin?a=1").as_deref(),
            Some("/docs/admin")
        );
        assert_eq!(
            normalized_path("//docs///admin").as_deref(),
            Some("/docs/admin")
        );
        assert!(normalized_path("/docs/%zz").is_none());
        assert!(
            prepare(Settings {
                allow_list: vec!["(?=cat)".into()],
                ..prepared.settings
            })
            .is_err()
        );
    }

    #[tokio::test]
    async fn live_bridge_preserves_cookie_setup_session_post_and_terminal_200() {
        let checks = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));
        let session_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let session_addr = session_listener.local_addr().unwrap();
        let checker = tokio::spawn({
            let checks = checks.clone();
            async move {
                loop {
                    let (stream, _) = session_listener.accept().await.unwrap();
                    let checks = checks.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let checks = checks.clone();
                            async move {
                                assert_eq!(request.method(), Method::POST);
                                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                let document: serde_json::Value =
                                    serde_json::from_slice(&bytes).unwrap();
                                let score = match document["SSOSESSIONS"].as_str().unwrap() {
                                    "banned" => "-1",
                                    "expired" => "0",
                                    "regular" => "1",
                                    "admin" => "2",
                                    _ => "invalid",
                                };
                                checks.lock().unwrap().push(document);
                                Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(score))))
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        });
        let prepared = Arc::new(
            prepare(Settings {
                auth_check_url: format!("http://{session_addr}/check"),
                cookie_name: "SSOSESSIONS".into(),
                set_cookie_path: "/set-cookie".into(),
                login_try_url: "https://login.example/try".into(),
                login_done_url: "http://login.example/done".into(),
                login_ban_url: "http://login.example/ban".into(),
                allow_list: vec!["^/allowed".into()],
                deny_list: vec!["^/allowed/deny".into()],
                timeout_ms: 1000,
            })
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bridge = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let prepared = prepared.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        let prepared = prepared.clone();
                        async move { Ok::<_, Infallible>(authorize(&prepared, request).await) }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let call = |path: &'static str, cookie: Option<&'static str>| {
            let client = client.clone();
            async move {
                let mut request = client
                    .get(format!("http://{address}/authorize"))
                    .header("x-original-uri", path)
                    .header("x-original-client-ip", "203.0.113.7");
                if let Some(cookie) = cookie {
                    request = request.header("cookie", cookie);
                }
                request.send().await.unwrap()
            }
        };
        let missing = call("/allowed", None).await;
        assert_eq!(missing.status(), StatusCode::FOUND);
        assert_eq!(
            missing.headers()[header::LOCATION],
            "https://login.example/try"
        );
        let setup = call("/set-cookie?SSOSESSIONS=plain", None).await;
        assert_eq!(setup.status(), StatusCode::FOUND);
        assert_eq!(
            setup.headers()[header::LOCATION],
            "http://login.example/done"
        );
        assert_eq!(
            setup.headers()[header::SET_COOKIE],
            "SSOSESSIONS=cGxhaW4=; Path=/; secure"
        );
        let ban = call("/allowed", Some("SSOSESSIONS=banned")).await;
        assert_eq!(ban.headers()[header::LOCATION], "http://login.example/ban");
        let expired = call("/allowed", Some("SSOSESSIONS=expired")).await;
        assert_eq!(
            expired.headers()[header::LOCATION],
            "https://login.example/try"
        );
        let denied = call("/allowed/deny", Some("SSOSESSIONS=regular")).await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let terminal = call("/outside", Some("SSOSESSIONS=regular")).await;
        assert_eq!(terminal.status(), StatusCode::OK);
        assert_eq!(terminal.headers()["x-hangang-auth-terminal"], "1");
        let allowed = call("/allowed", Some("SSOSESSIONS=regular")).await;
        assert_eq!(allowed.status(), StatusCode::NO_CONTENT);
        let admin = call("/outside", Some("SSOSESSIONS=admin")).await;
        assert_eq!(admin.status(), StatusCode::NO_CONTENT);
        let checks = checks.lock().unwrap();
        assert_eq!(checks.len(), 6);
        assert!(
            checks
                .iter()
                .all(|check| check["client_ip"] == "203.0.113.7")
        );
        bridge.abort();
        checker.abort();
    }
}
