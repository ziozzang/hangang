//! Owned fixture only: verifies one authenticated session before and after revocation.
use anyhow::{Result, ensure};
use std::io::{BufRead, Write};
#[tokio::main]
async fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("owned fixture file required"))?;
    let document: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let settings: hangang::config::HopaeNative =
        serde_json::from_value(document["settings"].clone())?;
    let key = hyper::header::HeaderValue::from_str("grpc-test-key")?;
    let client = hangang::hopae_native::Client::from_config(&settings, key)?;
    let mut headers = hyper::HeaderMap::new();
    for entry in document["headers"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("headers required"))?
    {
        headers.append(
            hyper::header::HeaderName::from_bytes(entry[0].as_str().unwrap().as_bytes())?,
            hyper::header::HeaderValue::from_str(entry[1].as_str().unwrap())?,
        );
    }
    ensure!(
        client.verify(&headers).await?.status() == 200,
        "authenticated session allow"
    );
    let wrong = hangang::hopae_native::Client::from_config(
        &settings,
        hyper::header::HeaderValue::from_static("wrong-key"),
    )?;
    ensure!(
        wrong.verify(&headers).await.is_err(),
        "wrong gateway key rejected without fallback"
    );
    let mut wrong_settings = settings.clone();
    wrong_settings.tls.as_mut().unwrap().server_name = "wrong.example.test".into();
    let wrong = hangang::hopae_native::Client::from_config(
        &wrong_settings,
        hyper::header::HeaderValue::from_static("grpc-test-key"),
    )?;
    ensure!(
        wrong.verify(&headers).await.is_err(),
        "server identity mismatch"
    );
    println!("READY");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    ensure!(
        line.trim() == "revoke",
        "owned fixture revocation handshake"
    );
    ensure!(
        client.verify(&headers).await?.status() != 200,
        "same-channel session revocation"
    );
    println!(
        "PASS: Hangang/Hopae gRPC authenticated session, role/key refusal, server identity and same-channel revocation"
    );
    Ok(())
}
