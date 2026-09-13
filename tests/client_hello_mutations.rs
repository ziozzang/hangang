//! Deterministic malformed-input regression coverage for the network parser.
use hangang::client_hello::read_client_hello;
fn hello() -> Vec<u8> {
    let name = b"host.example.test";
    let mut sni = Vec::new();
    sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend_from_slice(&sni);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0; 32]);
    body.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut handshake = vec![1, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
#[tokio::test]
async fn truncation_and_mutated_lengths_do_not_panic_or_exceed_capture_budget() {
    let original = hello();
    assert_eq!(
        read_client_hello(&mut original.as_slice(), 4096)
            .await
            .unwrap()
            .server_name,
        "host.example.test"
    );
    for n in 0..original.len() {
        assert!(read_client_hello(&mut &original[..n], 4096).await.is_err());
    }
    for index in 0..original.len() {
        for byte in [0, 1, 0x7f, 0x80, 0xff] {
            let mut mutated = original.clone();
            mutated[index] = byte;
            if let Ok(result) = read_client_hello(&mut mutated.as_slice(), 4096).await {
                assert!(result.consumed.len() <= 4096);
                assert!(result.server_name.is_ascii());
                assert!(!result.server_name.is_empty());
            }
        }
    }
}
