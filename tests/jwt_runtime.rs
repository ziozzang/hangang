use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use hangang::jwt_runtime::{AuthFailure, JwtAuth, Runtime};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

fn token(signing: &SigningKey, kid: &str, claims: &Value) -> String {
    let header = json!({"alg":"EdDSA", "kid":kid, "typ":"at+jwt"});
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string()),
    );
    let signature = signing.sign(message.as_bytes());
    format!("{message}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

fn runtime() -> (Runtime, SigningKey, Value) {
    let signing = SigningKey::from_bytes(&[71; 32]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let config: JwtAuth = serde_json::from_value(json!({
        "verification": {
            "issuer":"https://issuer.example.test/",
            "audiences":["api://hangang"],
            "profile":"rfc9068",
            "algorithms":["EdDSA"],
            "required_scopes":["records:read"]
        },
        "keys": {"source":"local", "jwks":{"keys":[{
            "kty":"OKP", "crv":"Ed25519", "kid":"signer", "alg":"EdDSA",
            "use":"sig", "x":URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes())
        }]}}
    }))
    .unwrap();
    let claims = json!({
        "iss":"https://issuer.example.test/", "aud":"api://hangang",
        "sub":"alice", "client_id":"client-1", "jti":"token-1",
        "iat":now.saturating_sub(1), "exp":now+120,
        "scope":"records:read profile"
    });
    (Runtime::new(config).unwrap(), signing, claims)
}

#[tokio::test]
async fn local_jwt_runtime_bounds_crypto_and_distinguishes_invalid_from_denied() {
    let (runtime, signing, claims) = runtime();
    let valid = token(&signing, "signer", &claims);
    let no_capacity = Arc::new(tokio::sync::Semaphore::new(0));
    assert_eq!(
        runtime.authenticate(&valid, no_capacity.clone()).await,
        Err(AuthFailure::Capacity)
    );
    assert_eq!(
        runtime.authenticate("not-a-jwt", no_capacity.clone()).await,
        Err(AuthFailure::Invalid)
    );
    let unknown = token(&signing, "unknown", &claims);
    assert_eq!(
        runtime.authenticate(&unknown, no_capacity).await,
        Err(AuthFailure::Invalid)
    );

    let admitted = Arc::new(tokio::sync::Semaphore::new(1));
    let verified = runtime
        .authenticate(&valid, admitted.clone())
        .await
        .unwrap();
    assert_eq!(verified.subject, "alice");
    assert_eq!(
        admitted.available_permits(),
        1,
        "completed cryptography releases capacity"
    );

    let mut no_scope = claims;
    no_scope["scope"] = json!("profile");
    assert_eq!(
        runtime
            .authenticate(&token(&signing, "signer", &no_scope), admitted)
            .await,
        Err(AuthFailure::Forbidden)
    );
}
