//! Explicit per-domain HTTP-01 delegation, independent of application origins.
use anyhow::{Result, ensure};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request, Response, header};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const PREFIX: &str = "/.well-known/acme-challenge/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub backend: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listener_ids: Vec<String>,
}

pub fn validate(config: &crate::config::Config) -> Result<()> {
    let mut bindings = HashSet::new();
    for route in &config.http {
        let Some(service) = &route.acme_http01 else {
            continue;
        };
        ensure!(
            service.backend.len() <= 2048,
            "ACME backend exceeds 2048 bytes"
        );
        if crate::discovery::parse_reference(&service.backend)?.is_none() {
            let url = reqwest::Url::parse(&service.backend)?;
            ensure!(
                url.scheme() == "http"
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.query().is_none()
                    && url.port() != Some(0)
                    && url.fragment().is_none()
                    && url.path() == "/",
                "ACME backend must be an HTTP root URL or canonical Docker reference"
            );
        }
        ensure!(
            route.host_regex.is_none(),
            "ACME delegation requires exact domain hosts"
        );
        let hosts: Vec<_> = route.host.iter().chain(route.hosts.iter()).collect();
        ensure!(
            !hosts.is_empty() && hosts.iter().all(|host| !crate::host_match::is_glob(host)),
            "ACME delegation requires exact domain hosts"
        );
        ensure!(
            route.deny_cidrs.is_empty()
                && route.country_policy.is_none()
                && route.resource_policy.is_none()
                && route.workload_auth.is_none(),
            "ACME delegation cannot bypass route IP/country/resource/workload policy; use gateway path controls"
        );
        ensure!(
            service.listener_ids.len() <= 64,
            "ACME listener list exceeds 64"
        );
        let coverage: Vec<_> = if route.listener_ids.is_empty() {
            vec!["default".to_owned()]
        } else {
            route.listener_ids.clone()
        };
        let listeners = if service.listener_ids.is_empty() {
            &coverage
        } else {
            &service.listener_ids
        };
        let mut seen = HashSet::new();
        for listener in listeners {
            ensure!(
                coverage.contains(listener) && seen.insert(listener),
                "ACME listener must be unique and inside owning route coverage"
            );
            ensure!(
                listener == "default" || config.public_http.iter().any(|l| &l.id == listener),
                "ACME delegation requires a public HTTP listener"
            );
            if route.enabled {
                for host in &hosts {
                    ensure!(
                        bindings.insert((
                            host.trim_end_matches('.').to_ascii_lowercase(),
                            listener.clone()
                        )),
                        "duplicate ACME domain/listener binding"
                    );
                }
            }
        }
    }
    Ok(())
}

pub(crate) struct Admission {
    connections: tokio::sync::Semaphore,
    dns: Arc<tokio::sync::Semaphore>,
    rate: Mutex<(Instant, u64)>,
}
impl Admission {
    pub(crate) fn new() -> Self {
        Self {
            connections: tokio::sync::Semaphore::new(64),
            dns: Arc::new(tokio::sync::Semaphore::new(4)),
            rate: Mutex::new((Instant::now(), 100_000_000_000)),
        }
    }
    async fn resolve<R>(
        &self,
        host: String,
        port: u16,
        resolver: R,
    ) -> std::result::Result<Vec<std::net::SocketAddr>, ()>
    where
        R: FnOnce(String, u16) -> std::io::Result<Vec<std::net::SocketAddr>> + Send + 'static,
    {
        let permit = self.dns.clone().try_acquire_owned().map_err(|_| ())?;
        tokio::task::spawn_blocking(move || {
            // Real resolver work can outlive a canceled async request. It owns
            // this separate bound until the native call actually finishes.
            let _permit = permit;
            let addresses = resolver(host, port).map_err(|_| ())?;
            if addresses.is_empty() || addresses.len() > 16 {
                return Err(());
            }
            Ok(addresses)
        })
        .await
        .map_err(|_| ())?
    }
    fn admit(&self) -> Option<tokio::sync::SemaphorePermit<'_>> {
        self.admit_at(Instant::now())
    }
    fn admit_at(&self, now: Instant) -> Option<tokio::sync::SemaphorePermit<'_>> {
        let permit = self.connections.try_acquire().ok()?;
        let mut state = self
            .rate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = now.max(state.0);
        state.1 = (u128::from(state.1)
            .saturating_add(
                now.saturating_duration_since(state.0)
                    .as_nanos()
                    .saturating_mul(100),
            )
            .min(100_000_000_000)) as u64;
        state.0 = now;
        if state.1 < 1_000_000_000 {
            return None;
        }
        state.1 -= 1_000_000_000;
        Some(permit)
    }
}

fn response(status: u16, body: Bytes) -> Response<crate::proxy::Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(
            Full::new(body)
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .expect("fixed ACME response")
}

pub(crate) fn shaped(path: &str) -> bool {
    // Recognize encoded namespace aliases only to reject them. Decode at
    // most the namespace length, never allocate from an unbounded token.
    let mut prefix = Vec::with_capacity(PREFIX.len());
    let bytes = path.as_bytes();
    let mut index = 0;
    while index < bytes.len() && prefix.len() < PREFIX.len() {
        let mut byte = bytes[index];
        index += 1;
        if byte == b'%' {
            let hex = |b: u8| (b as char).to_digit(16).map(|n| n as u8);
            let Some(high) = bytes.get(index).and_then(|b| hex(*b)) else {
                return false;
            };
            let Some(low) = bytes.get(index + 1).and_then(|b| hex(*b)) else {
                return false;
            };
            byte = (high << 4) | low;
            index += 2;
        }
        prefix.push(byte);
    }
    prefix == PREFIX.as_bytes()
        || (index == bytes.len() && prefix == PREFIX.trim_end_matches('/').as_bytes())
}

pub(crate) async fn serve<B: hyper::body::Body>(
    routes: &[Arc<crate::config::HttpRuntime>],
    request: &Request<B>,
    discovery: Option<Arc<crate::discovery::Discovery>>,
    admission: &Admission,
) -> Option<Response<crate::proxy::Body>> {
    if request
        .extensions()
        .get::<crate::workload_http::Evidence>()
        .is_some()
    {
        return None;
    }
    if !shaped(request.uri().path()) {
        return None;
    }
    let listener = request
        .extensions()
        .get::<crate::public_http::Evidence>()
        .map(|e| e.listener_id())
        .unwrap_or("default");
    let host = crate::resource_guard::request_host(request)?;
    let host = host.trim_end_matches('.');
    let owner = routes.iter().find(|runtime| {
        let route = &runtime.route;
        let Some(service) = &route.acme_http01 else {
            return false;
        };
        let coverage = if service.listener_ids.is_empty() {
            &route.listener_ids
        } else {
            &service.listener_ids
        };
        let listener_matches = if coverage.is_empty() {
            listener == "default"
        } else {
            coverage.iter().any(|id| id == listener)
        };
        route.enabled
            && listener_matches
            && route
                .host
                .iter()
                .chain(route.hosts.iter())
                .any(|name| name.trim_end_matches('.').eq_ignore_ascii_case(host))
    })?;
    let token = request.uri().path().strip_prefix(PREFIX).unwrap_or("");
    if request.method() != Method::GET {
        return Some(response(404, Bytes::from_static(b"not found")));
    }
    if request.uri().query().is_some()
        || !crate::acme::valid_token(token)
        || !request.body().is_end_stream()
        || request.headers().contains_key(header::UPGRADE)
        || request.headers().contains_key(header::TRAILER)
        || request.headers().contains_key(header::TRANSFER_ENCODING)
    {
        return Some(response(400, Bytes::from_static(b"bad request")));
    }
    let Some(_permit) = admission.admit() else {
        return Some(response(503, Bytes::from_static(b"unavailable")));
    };
    let service = owner
        .route
        .acme_http01
        .as_ref()
        .expect("selected ACME service");
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        let target = if service.backend.starts_with("docker://") {
            discovery
                .as_ref()
                .and_then(|d| {
                    d.resolve_with_epoch(&service.backend, crate::discovery::Protocol::Http)
                })
                .ok_or(())?
        } else {
            crate::discovery::ResolvedTarget {
                endpoint: service.backend.clone(),
                epoch: 0,
            }
        };
        let current = || {
            !service.backend.starts_with("docker://")
                || discovery.as_ref().is_some_and(|d| {
                    d.resolve_with_epoch(&service.backend, crate::discovery::Protocol::Http)
                        == Some(target.clone())
                })
        };
        if !current() {
            return Err(());
        }
        let dial_uri: hyper::Uri = target.endpoint.parse().map_err(|_| ())?;
        let dial_host = dial_uri.host().ok_or(())?;
        let dial_host = dial_host.trim_start_matches('[').trim_end_matches(']');
        let port = dial_uri.port_u16().unwrap_or(80);
        let addresses = if let Ok(ip) = dial_host.parse::<std::net::IpAddr>() {
            vec![std::net::SocketAddr::new(ip, port)]
        } else {
            admission
                .resolve(dial_host.to_owned(), port, |host, port| {
                    use std::net::ToSocketAddrs;
                    (host.as_str(), port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.take(17).collect())
                })
                .await?
        };
        let mut connected = None;
        for address in addresses {
            if let Ok(stream) = tokio::net::TcpStream::connect(address).await {
                connected = Some(stream);
                break;
            }
        }
        let stream = connected.ok_or(())?;
        if !current() {
            return Err(());
        }
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(8192)
            .handshake(TokioIo::new(stream))
            .await
            .map_err(|_| ())?;
        let _driver = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            let _ = connection.await;
        }));
        if !current() {
            return Err(());
        }
        let authority = request
            .headers()
            .get(header::HOST)
            .cloned()
            .or_else(|| {
                request
                    .uri()
                    .authority()
                    .and_then(|a| header::HeaderValue::from_str(a.as_str()).ok())
            })
            .ok_or(())?;
        let outgoing = Request::builder()
            .method(Method::GET)
            .uri(format!("{PREFIX}{token}"))
            .header(header::HOST, authority)
            .body(Full::new(Bytes::new()))
            .map_err(|_| ())?;
        let reply = sender.send_request(outgoing).await.map_err(|_| ())?;
        if !current() {
            return Err(());
        }
        if reply.status() == 404 {
            return Ok((404, Bytes::from_static(b"not found")));
        }
        if reply.status() != 200 {
            return Err(());
        }
        let collected = Limited::new(reply.into_body(), 4096)
            .collect()
            .await
            .map_err(|_| ())?;
        if collected.trailers().is_some() {
            return Err(());
        }
        let body = collected.to_bytes();
        if !current() {
            return Err(());
        }
        let expected = token.len() + 1 + 43;
        if body.len() != expected
            || &body[..token.len()] != token.as_bytes()
            || body[token.len()] != b'.'
            || !body[token.len() + 1..]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        {
            return Err(());
        }
        Ok((200, body))
    })
    .await;
    Some(match result {
        Ok(Ok((status, body))) => response(status, body),
        _ => response(503, Bytes::from_static(b"unavailable")),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(host: &str) -> crate::config::Config {
        serde_json::from_value(serde_json::json!({"revision":0,"http":[{
            "id":"domain","host":host,"backends":["http://127.0.0.1:9"],
            "acme_http01":{"backend":"http://127.0.0.1:8081"}
        }],"tcp":[]}))
        .unwrap()
    }

    #[test]
    fn service_validation_rejects_ambiguous_bindings_and_policy_bypasses() {
        let valid = config("domain.test");
        valid.validate().unwrap();
        for backend in [
            "https://issuer.test",
            "http://user:password@issuer.test",
            "http://issuer.test/path",
            "http://issuer.test/?q=x",
            "http://issuer.test:0",
            "docker://issuer/network/0",
        ] {
            let mut invalid = valid.clone();
            invalid.http[0].acme_http01.as_mut().unwrap().backend = backend.into();
            assert!(invalid.validate().is_err(), "{backend}");
        }
        assert!(config("*.domain.test").validate().is_err());
        let mut incompatible = valid.clone();
        incompatible.http[0]
            .deny_cidrs
            .push("192.0.2.0/24".parse().unwrap());
        assert!(incompatible.validate().is_err());
        let mut listeners = valid.clone();
        listeners.http[0].acme_http01.as_mut().unwrap().listener_ids = vec!["unknown".into()];
        assert!(listeners.validate().is_err());
        let mut duplicate = valid.clone();
        let mut other = duplicate.http[0].clone();
        other.id = "other".into();
        other.host = Some("DOMAIN.TEST.".into());
        duplicate.http.push(other);
        assert!(
            duplicate.validate().is_err(),
            "case/root-dot variants cannot create two ACME owners"
        );
    }

    #[test]
    fn shared_admission_bounds_concurrency_and_fast_unknown_token_rate() {
        let admission = Admission::new();
        let now = Instant::now();
        let held: Vec<_> = (0..64).map(|_| admission.admit_at(now).unwrap()).collect();
        assert!(
            admission.admit_at(now).is_none(),
            "65th simultaneous issuer request must fail closed"
        );
        drop(held);
        for _ in 0..36 {
            drop(admission.admit_at(now).unwrap());
        }
        assert!(
            admission.admit_at(now).is_none(),
            "fast replies cannot evade aggregate100-request burst"
        );
        assert!(
            admission.admit_at(now + Duration::from_secs(1)).is_some(),
            "budget must recover without config reload"
        );
    }
    #[tokio::test]
    async fn canceled_dns_requests_keep_native_worker_permits_until_resolution_finishes() {
        use std::sync::{
            Condvar,
            atomic::{AtomicUsize, Ordering},
        };
        struct Release(Arc<(Mutex<bool>, Condvar)>);
        impl Drop for Release {
            fn drop(&mut self) {
                *self.0.0.lock().unwrap() = true;
                self.0.1.notify_all();
            }
        }
        let admission = Arc::new(Admission::new());
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Release(gate.clone());
        let started = Arc::new(AtomicUsize::new(0));
        let mut requests = Vec::new();
        for _ in 0..4 {
            let admission = admission.clone();
            let gate = gate.clone();
            let started = started.clone();
            requests.push(tokio::spawn(async move {
                admission
                    .resolve("owned.invalid".into(), 80, move |_, _| {
                        started.fetch_add(1, Ordering::SeqCst);
                        let mut ready = gate.0.lock().unwrap();
                        while !*ready {
                            ready = gate.1.wait(ready).unwrap();
                        }
                        Ok(vec!["127.0.0.1:80".parse().unwrap()])
                    })
                    .await
            }));
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            while started.load(Ordering::SeqCst) != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for task in requests {
            task.abort();
            let _ = task.await;
        }
        assert_eq!(admission.dns.available_permits(), 0);
        assert!(
            admission
                .resolve("fifth.invalid".into(), 80, |_, _| panic!(
                    "fifth native DNS job started"
                ))
                .await
                .is_err()
        );
        drop(release);
        tokio::time::timeout(Duration::from_secs(5), async {
            while admission.dns.available_permits() != 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            admission
                .resolve("owned.invalid".into(), 80, |_, _| Ok(vec![
                    "127.0.0.1:80".parse().unwrap()
                ]))
                .await
                .is_ok()
        );
    }
}
