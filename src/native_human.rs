//! Fixed Human route metadata and actual-byte binding, never native identity.
use anyhow::{Result, ensure};
use hopae_grpc::{human_observed_client::HumanScope, request_binding_v2 as v2};
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
};

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
    pub app_id: String,
    pub header_policy_revision: u64,
    pub header_names: Vec<String>,
}
/// Compiled only from the actual route/configuration, never an incoming digest.
pub(crate) struct Scopes {
    by_origin: HashMap<[u8; 32], Arc<HumanScope>>,
    policy: v2::HeaderPolicy,
    reserved: Vec<hyper::header::HeaderName>,
}
impl Scopes {
    pub(crate) fn compile(
        config: &Configuration,
        route: &crate::config::HttpRoute,
        revision: u64,
        service: &str,
        audience: &str,
    ) -> Result<Arc<Self>> {
        ensure!(
            !route.backends.is_empty(),
            "Human route requires fixed pool origins"
        );
        let mut reserved: BTreeSet<String> = [
            "authorization",
            "cookie",
            "host",
            "x-hopae-subject",
            "x-hopae-gateway-key",
            "x-forwarded-user",
            "x-hopae-aal",
            "x-hopae-principal-kind",
            "x-hopae-service-id",
            "x-hopae-human-policy-subject",
            "x-hopae-human-policy-issuer",
            "x-hopae-contract",
            "x-hangang-route-id",
            "x-hangang-canonical-path",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        if let Some(auth) = &route.auth {
            reserved.extend(auth.request_headers.iter().cloned());
            reserved.extend(auth.response_headers.iter().cloned());
            reserved.extend(auth.static_request_headers.keys().cloned());
        }
        let reserved: Vec<String> = reserved.into_iter().collect();
        let policy = v2::HeaderPolicy::new(
            config.header_policy_revision,
            &config
                .header_names
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &reserved.iter().map(String::as_str).collect::<Vec<_>>(),
        )
        .map_err(|_| anyhow::anyhow!("invalid Human header policy"))?;
        let mut names = config.header_names.clone();
        names.sort_unstable();
        let mut by_origin = HashMap::new();
        for backend in &route.backends {
            // Logical discovery names cannot silently become a source-owned origin.
            let uri: hyper::Uri = backend.address().parse()?;
            let origin = crate::human_destination::Origin::parse(&uri)
                .map_err(|_| anyhow::anyhow!("Human pool origin unsupported"))?
                .digest();
            if by_origin.contains_key(&origin) {
                continue;
            }
            ensure!(by_origin.len() < 128, "too many Human pool origins");
            let scope = HumanScope {
                service: service.into(),
                audience: audience.into(),
                app_id: config.app_id.clone(),
                route_id: route.id.clone(),
                route_revision: revision,
                destination_sha256: origin,
                header_policy_revision: config.header_policy_revision,
                header_names: names.clone(),
                reserved_names: reserved.clone(),
            };
            scope
                .fingerprint()
                .map_err(|_| anyhow::anyhow!("invalid Human fixed scope"))?;
            by_origin.insert(origin, Arc::new(scope));
        }
        let reserved = reserved
            .iter()
            .map(|s| s.parse())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Arc::new(Self {
            by_origin,
            policy,
            reserved,
        }))
    }
    pub(crate) fn actual_origin(&self, uri: &hyper::Uri) -> Result<Arc<HumanScope>> {
        let digest = crate::human_destination::Origin::parse(uri)
            .map_err(|_| anyhow::anyhow!("Human selected origin refused"))?
            .digest();
        self.by_origin
            .get(&digest)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Human selected origin not configured"))
    }
    pub(crate) fn all(&self) -> Vec<HumanScope> {
        self.by_origin
            .values()
            .map(|s| s.as_ref().clone())
            .collect()
    }
    pub(crate) fn reserved(&self) -> &[hyper::header::HeaderName] {
        &self.reserved
    }
    pub(crate) fn digest(
        &self,
        scope: &Arc<HumanScope>,
        request: &hyper::Request<bytes::Bytes>,
    ) -> Result<[u8; 32]> {
        ensure!(
            self.by_origin
                .get(&scope.destination_sha256)
                .is_some_and(|s| Arc::ptr_eq(s, scope)),
            "Human preparation belongs to another route"
        );
        let headers = bound_headers(scope, request.headers())?;
        v2::digest(&self.policy, &actual(scope, request, &headers))
            .map_err(|_| anyhow::anyhow!("Human final request refused"))
    }
}
pub(crate) fn bound_headers<'a>(
    scope: &'a HumanScope,
    headers: &'a hyper::HeaderMap,
) -> Result<Vec<v2::BoundHeader<'a>>> {
    scope
        .header_names
        .iter()
        .map(|name| {
            let mut values = headers.get_all(name).iter();
            let value = values.next();
            ensure!(values.next().is_none(), "duplicate Human bound header");
            Ok(v2::BoundHeader {
                name,
                value: value.map(|v| v.as_bytes()),
            })
        })
        .collect()
}
pub(crate) fn actual<'a>(
    scope: &'a HumanScope,
    request: &'a hyper::Request<bytes::Bytes>,
    headers: &'a [v2::BoundHeader<'a>],
) -> v2::Request<'a> {
    v2::Request {
        service: &scope.service,
        audience: &scope.audience,
        route_id: &scope.route_id,
        route_revision: scope.route_revision,
        destination_sha256: &scope.destination_sha256,
        method: request.method().as_str(),
        target: request.uri().path_and_query().map_or("/", |v| v.as_str()),
        body: request.body(),
        bound_headers: headers,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn route() -> crate::config::HttpRoute {
        serde_json::from_value(serde_json::json!({"id":"owned-route","backends":["http://example.test:80/base","http://EXAMPLE.test/other","https://example.test/"]})).unwrap()
    }
    fn config() -> Configuration {
        Configuration {
            app_id: "app".into(),
            header_policy_revision: 13,
            header_names: vec!["x-tenant".into()],
        }
    }
    #[test]
    fn all_fixed_origins_and_final_actual_bytes_are_independent_of_forward_host() {
        let scopes = Scopes::compile(&config(), &route(), 11, "orders", "api").unwrap();
        assert_eq!(scopes.all().len(), 2);
        let selected = scopes
            .actual_origin(&"https://example.test/".parse().unwrap())
            .unwrap();
        assert!(
            scopes
                .actual_origin(&"https://other.test/".parse().unwrap())
                .is_err()
        );
        let mut request = hyper::Request::builder()
            .method("POST")
            .uri("https://forward.example/base/data?x=1")
            .header("x-tenant", "one")
            .body(bytes::Bytes::from_static(b"body"))
            .unwrap();
        let first = scopes.digest(&selected, &request).unwrap();
        *request.body_mut() = bytes::Bytes::from_static(b"Body");
        assert_ne!(first, scopes.digest(&selected, &request).unwrap());
        *request.body_mut() = bytes::Bytes::from_static(b"body");
        request
            .headers_mut()
            .insert("x-tenant", hyper::header::HeaderValue::from_static("two"));
        assert_ne!(first, scopes.digest(&selected, &request).unwrap());
        request
            .headers_mut()
            .append("x-tenant", hyper::header::HeaderValue::from_static("three"));
        assert!(scopes.digest(&selected, &request).is_err());
        // A foreign compiled owner cannot borrow an equivalent metadata object.
        let other = Scopes::compile(&config(), &route(), 11, "orders", "api").unwrap();
        assert!(other.digest(&selected, &request).is_err());
    }
    #[test]
    fn credential_identity_and_custom_caller_slots_cannot_be_bound() {
        for header in [
            "cookie",
            "host",
            "authorization",
            "x-forwarded-user",
            "x-hopae-subject",
            "x-owned-caller",
        ] {
            let mut route = route();
            if header == "x-owned-caller" {
                route.auth=Some(serde_json::from_value(serde_json::json!({"url":"http://auth.test/verify","static_request_headers":{"x-owned-caller":{"env":"OWNED_CALLER"}}})).unwrap());
            }
            let mut config = config();
            config.header_names = vec![header.into()];
            assert!(
                Scopes::compile(&config, &route, 11, "orders", "api").is_err(),
                "{header}"
            );
        }
    }
}

/// Local per-request routing/header integrity, not authentication or permission.
/// Header Host stays absent; Hyper derives it from the exact sealed URI.
pub(crate) struct Seal {
    hash: [u8; 32],
    length: usize,
}
impl Seal {
    pub(crate) fn new(request: &hyper::Request<bytes::Bytes>) -> Result<Self> {
        ensure!(
            !request.headers().contains_key("authorization")
                && !request.headers().contains_key("x-hopae-subject"),
            "Human input credential not stripped"
        );
        Ok(Self {
            hash: Self::digest(request)?,
            length: request.body().len(),
        })
    }
    pub(crate) fn check<B>(
        &self,
        request: &hyper::Request<B>,
        slot: &hyper::header::HeaderName,
    ) -> Result<()> {
        ensure!(
            matches!(slot.as_str(), "authorization" | "x-hopae-subject"),
            "Human projection slot refused"
        );
        ensure!(
            request.headers().get_all(slot).iter().count() == 1,
            "Human projected credential cardinality changed"
        );
        for name in ["authorization", "x-hopae-subject"] {
            ensure!(
                name == slot.as_str() || !request.headers().contains_key(name),
                "unexpected Human credential slot"
            );
        }
        let mut lengths = request
            .headers()
            .get_all(hyper::header::CONTENT_LENGTH)
            .iter();
        ensure!(
            lengths
                .next()
                .is_some_and(|v| v.as_bytes() == self.length.to_string().as_bytes())
                && lengths.next().is_none()
                && !request
                    .headers()
                    .contains_key(hyper::header::TRANSFER_ENCODING),
            "Human final framing changed"
        );
        ensure!(
            self.hash == Self::digest(request)?,
            "Human final routing headers changed"
        );
        Ok(())
    }
    fn digest<B>(request: &hyper::Request<B>) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};
        ensure!(
            !request.headers().contains_key("host") && !request.headers().contains_key("cookie"),
            "Human Host/cookie not isolated"
        );
        let mut hash = Sha256::new();
        hash.update(b"hangang-human-final-headers-v1\0");
        let mut field = |bytes: &[u8]| -> Result<()> {
            hash.update(u32::try_from(bytes.len())?.to_be_bytes());
            hash.update(bytes);
            Ok(())
        };
        field(request.method().as_str().as_bytes())?;
        field(request.uri().to_string().as_bytes())?;
        let mut names = request
            .headers()
            .keys()
            .filter(|name| {
                !matches!(
                    name.as_str(),
                    "authorization" | "x-hopae-subject" | "content-length" | "transfer-encoding"
                )
            })
            .collect::<Vec<_>>();
        names.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));
        field(&u32::try_from(names.len())?.to_be_bytes())?;
        for name in names {
            field(name.as_str().as_bytes())?;
            field(&u32::try_from(request.headers().get_all(name).iter().count())?.to_be_bytes())?;
            for value in request.headers().get_all(name) {
                field(value.as_bytes())?;
            }
        }
        Ok(hash.finalize().into())
    }
}

#[cfg(test)]
mod seal_tests {
    use super::Seal;
    use bytes::Bytes;
    use hyper::{
        Request,
        header::{HeaderName, HeaderValue},
    };

    fn make_request() -> Request<Bytes> {
        Request::builder()
            .method("POST")
            .uri("https://origin.test/effect?q=one")
            .header("x-forwarded-host", "frontend.test")
            .header("x-tenant", "one")
            .body(Bytes::from_static(b"actual body"))
            .unwrap()
    }
    fn dispatch() -> (Seal, Request<Bytes>, HeaderName) {
        let mut request = make_request();
        let seal = Seal::new(&request).unwrap();
        request
            .headers_mut()
            .insert("content-length", HeaderValue::from_static("11"));
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_static("Bearer projected"),
        );
        (seal, request, HeaderName::from_static("authorization"))
    }
    #[test]
    fn seal_accepts_only_declared_credential_and_exact_framing() {
        let (seal, mut request, slot) = dispatch();
        assert!(seal.check(&request, &slot).is_ok());
        request
            .headers_mut()
            .append("authorization", HeaderValue::from_static("second"));
        assert!(seal.check(&request, &slot).is_err());
        let (seal, request, _) = dispatch();
        assert!(
            seal.check(&request, &HeaderName::from_static("x-hopae-subject"))
                .is_err()
        );
        assert!(
            seal.check(&request, &HeaderName::from_static("x-custom"))
                .is_err()
        );
        for (name, value) in [
            ("content-length", "10"),
            ("content-length", "011"),
            ("transfer-encoding", "chunked"),
            ("cookie", "session=private"),
            ("host", "other.test"),
            ("x-hopae-subject", "second"),
            ("x-forwarded-host", "other.test"),
            ("x-tenant", "two"),
        ] {
            let (seal, mut request, slot) = dispatch();
            request.headers_mut().insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
            assert!(seal.check(&request, &slot).is_err(), "{name}");
        }
        let (seal, mut request, slot) = dispatch();
        request
            .headers_mut()
            .append("content-length", HeaderValue::from_static("11"));
        assert!(seal.check(&request, &slot).is_err());
    }
    #[test]
    fn seal_rejects_uri_method_and_header_cardinality_changes() {
        for uri in [
            "https://other.test/effect?q=one",
            "https://origin.test/other?q=one",
            "https://origin.test/effect?q=two",
        ] {
            let (seal, mut request, slot) = dispatch();
            *request.uri_mut() = uri.parse().unwrap();
            assert!(seal.check(&request, &slot).is_err());
        }
        let (seal, mut request, slot) = dispatch();
        *request.method_mut() = hyper::Method::DELETE;
        assert!(seal.check(&request, &slot).is_err());
        let (seal, mut request, slot) = dispatch();
        request
            .headers_mut()
            .append("x-tenant", HeaderValue::from_static("one"));
        assert!(seal.check(&request, &slot).is_err());
        for header in ["authorization", "cookie", "host", "x-hopae-subject"] {
            let mut request = make_request();
            request.headers_mut().insert(
                HeaderName::from_bytes(header.as_bytes()).unwrap(),
                HeaderValue::from_static("input"),
            );
            assert!(Seal::new(&request).is_err());
        }
    }
}
