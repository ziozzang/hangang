# Authenticated TCP with inbound mutual TLS

`TcpRoute.inbound_tls` terminates client TLS at Hangang and authorizes an exact workload URI before selecting or connecting to an upstream. The upstream receives the decrypted application byte stream. Configure upstream TLS separately if that hop also needs encryption. This feature does not add bytes or HTTP identity headers to an opaque protocol.

```json
{
  "tcp": [{
    "id": "workload-database",
    "listen": "0.0.0.0:9443",
    "backends": ["127.0.0.1:5432"],
    "inbound_tls": {
      "cert_file": "/etc/hangang/workload/server.pem",
      "key_file": "/etc/hangang/workload/server-key.pem",
      "client_ca_file": "/etc/hangang/workload/client-ca.pem",
      "client_crl_file": "/etc/hangang/workload/client.crl.pem",
      "allowed_uri_sans": ["spiffe://example.test/services/orders"],
      "handshake_timeout_ms": 5000
    }
  }]
}
```

The file paths must be normalized absolute paths and refer to material managed on the gateway host. The example contains no certificates or private keys and cannot start until those files exist. The editor accepts paths rather than private PEM text. Different clients can use different certificates with the same authorized workload identity; this is a service identity, not proof of an individual human actor.

## Authentication and authorization

The TLS handshake uses rustls's mandatory [WebPkiClientVerifier](https://docs.rs/rustls/latest/rustls/server/struct.WebPkiClientVerifier.html), explicit client CA roots, certificate validity and client-auth verification. System/web PKI roots are not implicitly trusted. Missing certificates, untrusted issuers, invalid signatures and expired certificates cannot reach the upstream. TLS session resumption, tickets and early data are disabled on this listener to avoid admitting a resumed session without a fresh certificate check.

After successful TLS authentication, the leaf must have exactly one URI subject alternative name, and that URI must match an entry in `allowed_uri_sans` exactly. DNS names, common names, client-provided HTTP headers and SNI are not workload identity evidence. A CA-valid but unlisted identity is denied. The accepted namespace is a strict SPIFFE URI form; see [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/). This is not a SPIRE agent, workload attestation implementation or complete X.509-SVID conformance claim.

The allowlist has 1–128 distinct URIs of at most 2,048 bytes. No wildcard or regex authorization is used. Trust-domain names are lowercase; credentials, ports, query/fragment, percent escapes, dot segments and ambiguous paths are rejected. Handshakes have a 1–10,000 ms timeout (default 5,000) and hold the existing global and route connection permits. A process-wide fail-fast gate also bounds concurrent workload handshakes to twice available CPUs (minimum 2, maximum 64), with no waiting queue. At most 64 distinct inbound policies may exist in one configuration. Material is bounded per file and prepared once per identical policy during a configuration publication, never read for every connection.

## Listener separation and changes

Inbound termination and `sni` passthrough cannot coexist on one route. A terminating listener cannot be shared with a passthrough or plaintext route. Existing ordinary TCP and passthrough routes retain their behavior when `inbound_tls` is absent/null.

An active mTLS listener cannot be replaced directly by an enabled unauthenticated route at the same address, even through a route rename. First publish its removal or disabled state in an earlier revision, then repurpose the socket. The UI exposes ordinary route activation separately from the authentication settings.

Configuration preparation validates the TCP route and mTLS policy shape. Enabled inbound mTLS bindings verify their local certificate, key, trust-root and CRL files after publication: metadata is polled every 500 ms and full contents are verified every 5 s, including changes at unchanged paths. A new binding remains unavailable until post-publication material verification succeeds. A changed or invalid client CA or CRL closes admission and existing authenticated streams for the affected binding; the old trust is not kept as a fallback. A verified replacement creates a fresh material generation. Disabled routes retain structural validation but do not read private material, so damaged or missing files cannot obstruct disabling a listener.

The watcher groups identical policies by transport role, so multiple bindings do not reopen and parse the same material independently during a sweep. These polling intervals are scheduling targets; filesystem latency, sweep size and scheduler load affect the observation delay. Material checks continue while an old process drains established workload connections after a supervised handoff. Local file refresh does not enforce fleet-wide revocation ordering or CRL rollback prevention.

`GET /v1/status` reports each **enabled** inbound mTLS route as `workload_materials[{kind:"tcp",id,ready}]`. `ready:false` means this instance currently refuses authenticated admission for that binding. The TCP route inventory displays that local runtime state; an absent response, unpublished draft, or revision mismatch is shown as unknown. Status carries no file paths or certificate contents and does not establish fleet-wide readiness or material distribution. Startup waits up to 10 s for configured workload bindings. A later local material failure does not necessarily turn global `/healthz` readiness off: other listeners can keep serving, so inspect the per-binding status or material gauges.

After a handshake and again after an outbound dial, the connection checks that its prepared generation is still active. Established authenticated connections check generation/identity validity every 250 ms and close when their route is removed, disabled, moved or its security material/policy is replaced. Application data is not reinterpreted under a new principal. This interval is a scheduling bound under a functioning runtime, not a real-time operating-system guarantee. Already forwarded bytes cannot be recalled. A backend change by itself follows existing member lifecycle rules.

## Revocation and observability

When `client_crl_file` is set, up to 16 CRLs are admitted. Preparation requires thisUpdate ≤ current time < nextUpdate; rustls rejects unknown revocation status, invalid CRL signatures and expired CRLs during the handshake. Supply the CRLs needed for the presented chain. If omitted, there is no CRL-based revocation check; certificate expiry and explicit configuration/policy withdrawal still apply. No OCSP or automatic CRL download occurs. Identity lease expiry is bounded by the presented certificate chain and configured CRL validity. A monotonic deadline also prevents a backward wall-clock change from extending the initially admitted lifetime.

`tcp_mtls_rejections_total` counts inbound handshake, workload authorization and admission-generation failures. `tcp_mtls_lease_terminations_total` counts lease-driven connection termination. Both are in status metrics and Prometheus. They do not constitute durable per-actor audit records; certificate/private-key material is not exposed by these counters.

This qualifies a gateway-authenticated TCP boundary. HTTP workload principal binding, distributed trust/revocation delivery, durable audit and proof that clients cannot reach the backend by another path remain separate Zero Trust requirements.

## 한국어 요약

TCP 리스너에서 mTLS를 종료하고, 검증된 인증서의 SPIFFE URI를 라우트별 허용 목록과 대조한 뒤에만 업스트림에 연결한다. 기존 SNI 패스스루와 구분하며, CA가 유효해도 허용되지 않은 주체는 거부한다. 설정·인증서·신뢰 루트·CRL 변경은 새 설정 발행 시 준비하고, 기존 인증 스트림은 세대 교체 또는 유효기간 만료를 감지하면 종료한다. 파일만 바꾸는 자동 감시, HTTP 주체 바인딩, 분산 폐기 및 영구 감사까지 완료된 것은 아니다.

## TCP transport and diagnostic workload

Accepted TCP sockets and shared outbound TCP connections enable `TCP_NODELAY` to avoid Nagle/delayed-ACK stalls on request/response protocols and short TLS records. The outbound setting also covers SOCKS proxy connections, HTTP custom transports and probes using the same connector; Unix sockets are unaffected. This can increase small-packet frequency, and applications should still buffer writes appropriately.

Run `cargo test --release --test tcp_mtls tcp_mtls_owned_echo_throughput -- --ignored --nocapture` for an owned loopback workload. Up to eight authenticated clients each send and verify 8 MiB through a plaintext echo backend. Timing includes their TLS handshakes and equal-sized replies; fixture generation/listener setup is excluded. The fixture also enables TCP_NODELAY. This is a diagnostic transfer measurement, not a maximum-connection test or a commercial-product comparison.
