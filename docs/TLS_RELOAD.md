# Certificate hot reload

[Documentation](README.md) · [한국어](ko/TLS_RELOAD.md)

Hangang replaces rotated certificates and keys without a restart. It polls the **contents** of the files: every `--tls-reload-seconds` (default 10; `0` disables polling) it reads each referenced file, bounded to 1 MiB, and compares a SHA-256 digest with the material in use. No inotify watches are used, so hosts with a small `fs.inotify.max_user_instances` budget are unaffected, and a file replaced by rename, symlink swap (Kubernetes Secret and cert-manager volumes) or in-place write is detected the same way.

## What is reloaded

| Material | Source | After a valid change |
| --- | --- | --- |
| `public-listener` | `--tls-cert` / `--tls-key` | New handshakes use the new certificate |
| `admin-listener` | `--admin-tls-cert` / `--admin-tls-key` | New handshakes use the new certificate |
| `upstream-client` | route `auth.native.tls` (Hopae) and `pumgye_authority.tls` (Pumgye), including the Pumgye authority compiled from `--kubernetes-protection-config` | The active configuration is re-prepared unchanged and every client built from these files is rebuilt |
| `guard-decision` | `--guard-decision-ca` / `--guard-decision-cert` / `--guard-decision-key` | The native TCP and gRPC decision clients are rebuilt |

Changes to the CA file of a client set are reloaded the same way: a client identity is validated and rebuilt as the trio of CA, certificate and key.

## Atomic replacement

The new rustls configuration replaces the old one with a single atomic pointer swap. Existing connections keep the configuration they were established with and are never interrupted: a listener connection finishes on the old certificate, and pooled upstream or guard connections retire through their normal idle and lifetime limits while new connections present the new identity. Requests in flight are not retried or cancelled.

## Validation and failure

Nothing is swapped until the new material is complete and consistent. A listener pair must parse and the key must match the certificate. A client set must additionally build a mutual-TLS client from its CA. If the new files fail validation, or cannot be read:

- the previous certificate and key stay in use;
- the failure is logged at `warn` (listeners) or `error` (client sets), once per distinct bad content;
- `hangang_tls_reload_rejected_total{material}` increments once per distinct bad content, and `hangang_tls_reload_failing{material}` is `1` until valid material, or the material already in use, is on disk again. Alert on `hangang_tls_reload_failing == 1`.

Writing the certificate and key as two separate in-place writes can be observed between the writes; that poll is rejected and the next one accepts the complete pair. Prefer an atomic rename or symlink swap.

## Observability

A successful reload is logged at `info` with the hexadecimal serial number of the new leaf certificate (`TLS listener certificate reloaded` or `TLS client material reloaded without restart`), and counted by `hangang_tls_reloads_total{material}`. The material label is one of the names in the table above.

## Not covered here

- Certificates from Kubernetes TLS Secrets (`--kubernetes-tls`), `--config-tls` certificate sets and ACME certificates have their own watchers and are swapped the same atomic way.
- A route's upstream server CA (`tls.ca_file`) is read when a configuration is prepared; reapply the configuration to refresh it (see [Outbound connection policies](UPSTREAM.md)).
- The Kubernetes API CA and service account token are re-read for every API request.
- The native route owner listener and console plugin clients are not polled; restart to rotate them.
