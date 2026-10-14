//! Bind native service scope to the exact final origin-form request and entity.
//! This helper grants no authentication or permission and does not dispatch.
use bytes::Bytes;
pub use hopae_grpc::request_binding::InvalidRequest;
use hyper::http::Request;
use sha2::{Digest, Sha256};

/// Call after route rewriting and body transformation. Unknown streaming bodies
/// must not be replaced with empty bytes; RPC integration must bound buffering.
pub fn digest(
    service: &str,
    audience: &str,
    request: &Request<Bytes>,
) -> Result<[u8; 32], InvalidRequest> {
    if request.uri().scheme().is_some() || request.uri().authority().is_some() {
        return Err(InvalidRequest);
    }
    let target = request
        .uri()
        .path_and_query()
        .ok_or(InvalidRequest)?
        .as_str();
    bind(
        service,
        audience,
        request.method().as_str(),
        target,
        request.body(),
    )
}

/// Use the actual selected upstream URI after backend base-path composition.
/// The service/audience must be bound independently to the selected owner; the
/// canonical request contract binds path/query and entity, not the URI authority.
/// This accepts only a fully materialized final entity, never a streaming proxy.
pub fn digest_upstream(
    service: &str,
    audience: &str,
    request: &Request<Bytes>,
) -> Result<[u8; 32], InvalidRequest> {
    if !matches!(request.uri().scheme_str(), Some("http" | "https"))
        || request
            .uri()
            .authority()
            .is_none_or(|authority| authority.as_str().contains('@'))
    {
        return Err(InvalidRequest);
    }
    let target = request
        .uri()
        .path_and_query()
        .ok_or(InvalidRequest)?
        .as_str();
    bind(
        service,
        audience,
        request.method().as_str(),
        target,
        request.body(),
    )
}

fn bind(
    service: &str,
    audience: &str,
    method: &str,
    target: &str,
    entity: &Bytes,
) -> Result<[u8; 32], InvalidRequest> {
    let body = Sha256::digest(entity);
    hopae_grpc::request_binding::digest(&hopae_grpc::request_binding::Request {
        service,
        audience,
        method,
        target,
        body_sha256: &body.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn matches_owner_fixed_vector_and_binds_final_entity_and_target() {
        let mut request = Request::builder()
            .uri("/private?x=1")
            .body(Bytes::new())
            .unwrap();
        let original = digest("ab", "c", &request).unwrap();
        assert_eq!(
            original
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            "234488f459d8b3069a74d308d639fa9bfb402b12a9544a413c06c6136a8dab11"
        );
        request
            .headers_mut()
            .insert("x-hopae-service-id", "attacker".parse().unwrap());
        assert_eq!(digest("ab", "c", &request).unwrap(), original);
        *request.body_mut() = Bytes::from_static(b"transformed entity");
        assert_ne!(digest("ab", "c", &request).unwrap(), original);
        *request.body_mut() = Bytes::new();
        *request.uri_mut() = "/private?x=2".parse().unwrap();
        assert_ne!(digest("ab", "c", &request).unwrap(), original);
        *request.uri_mut() = "/private?x=1".parse().unwrap();
        assert_ne!(digest("a", "bc", &request).unwrap(), original);
    }
    #[test]
    fn refuses_ambiguous_dispatch_targets() {
        for uri in [
            "https://other.example.test/private",
            "other.example.test:443",
            "*",
            "/private%zz",
        ] {
            let request = Request::builder().uri(uri).body(Bytes::new()).unwrap();
            assert_eq!(digest("owned", "upstream", &request), Err(InvalidRequest));
        }
    }
}
