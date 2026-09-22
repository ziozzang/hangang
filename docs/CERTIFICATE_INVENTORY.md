# Certificate inventory and issuer observation

`GET /v1/certificates?offset=0&limit=32` is an administrator-only, instance-local inventory. The default page is 32 configured file certificates and the maximum is 64. The response includes `listener_id`, `total`, the configuration `revision`, and `server_time_unix_ms` for expiry comparisons. Viewer accounts receive 403. The endpoint returns public leaf-certificate DNS SANs (at most 128), issuer, validity timestamps and SHA-256 fingerprint. It never returns PEM, private keys, ACME account data, raw issuer errors, or filesystem paths. Certificate and optional status reads run in a bounded blocking pool with a five-second response deadline.

Each entry has `configured_hosts`, `enabled`, `read_state`, `source`, `tls_binding`, and optional `renewal`. `read_state: ok` means the public leaf file was read and parsed; it does **not** prove that its private key matches, that its SANs cover the configured hosts, or that those exact bytes are currently served. The config-TLS watcher can retain a prior valid generation after rejecting new files. For the default scope, `tls_binding: configured` means this **instance** started with `--config-tls` and has a configuration TLS resolver. For a named public listener it means that listener is enabled and has its own TLS resolver. `unknown` covers a metadata-only instance, and `disabled` means the entry is retained but not loaded. A separate HTTP gateway's inventory or activation switch cannot control another HTTPS gateway's resolver. Manual CLI TLS and Kubernetes Secret TLS are outside this file-backed list; in-process ACME has its own sanitized status card.

`CertificateFiles.enabled` defaults to `true` and is omitted when true. Set it to `false` through the existing revision-checked configuration API to retain the entry without loading or watching its certificate/key files. Re-enabling requires valid files before the new configuration can publish. Disabling a certificate is a local routing change and can remove a hostname or default TLS fallback; the inventory does not issue replacement certificates automatically.
Inactive entries retain unique IDs and valid metadata but do not reserve SNI names or the default fallback slot; a replacement can be staged disabled while another enabled certificate serves the same hosts. Activation rechecks enabled-name and fallback conflicts atomically.

## Select a public listener

Omit `listener_id` or use `listener_id=default` to inspect the legacy CLI/global certificate set. Use `GET /v1/certificates?listener_id=edge&offset=0&limit=32` to inspect `public_http` listener `edge`. Each scope has its own pagination, certificate IDs and TLS binding. An unknown listener returns404; invalid or repeated query parameters return400. A named listener never inherits the default scope’s in-process ACME status. Standalone issuer observation still comes from each certificate’s explicit status-file registration.

The Certificates page provides a default/named-listener selector. Activation and file-path edits modify only the selected set, even when certificate IDs repeat across listeners. Switching scope clears the previous draft and pagination; responses from the previous scope cannot repaint the current inventory.

## Register a standalone issuer

The standalone `hangang-acme-issuer` writes an atomic private `issuer-status.json` in its output directory. To associate one configured certificate with that specific issuer, set the optional server-side `issuer_status_file` path explicitly:

```json
{
  "id": "example",
  "hosts": ["example.test", "www.example.test"],
  "cert_file": "/run/hangang/issuer/current/cert.pem",
  "key_file": "/run/hangang/issuer/current/key.pem",
  "issuer_status_file": "/run/hangang/issuer/issuer-status.json"
}
```

The inventory labels a parsed file `standalone_acme` only when that private, process-owned regular status file names the same host set and its recorded public leaf DER fingerprint and expiry match the file being read. A manifest for an initial pending issuance can report `renewing` with null certificate fields; this does not claim that a certificate exists. Missing, malformed or mismatched manifests leave the issuance source `configured_file` (unknown). No pathname or certificate issuer-name heuristic makes an ACME claim.

The status file reports `ready`, `renewing` or `retrying`, the challenge type, `checked_at_unix_ms`, an optional renewal-window threshold `renew_before_unix_ms`, and optional `retry_next_unix_ms`. The inventory marks a matching status `stale` when its heartbeat is over 120 seconds old or more than 30 seconds in the future. The renewal threshold marks when the issuer may begin a renewal attempt; it is not a guaranteed order or completion time. The issuer writes a ready status for an existing valid certificate on startup without placing a new CA order. This API observes issuance; it has no force-renew endpoint and does not expose DNS-provider credentials.

See [file certificate loading](../README.md), [ACME operation](ACME.md), and the [OpenAPI contract](openapi.json) for configuration and response schemas.
