# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

## 0.2.1 — 2026-09-22

- Discover the latest stable GitHub release with `--check-update`; install signed
  GitHub release assets under the existing supervisor with `--update-github`.
  An explicitly provisioned Ed25519 trust key remains mandatory for installation.
- Bind signed manifest version, URL, target, size, and digest to the selected
  release. Permit only the GitHub release CDN redirect exception; preserve the
  generic updater's same-origin policy and readiness-gated rollback.
- Publish a raw update executable, signed manifest, verification public key,
  checksums, and the companion archive using `tools/prepare_release.py`.
- Add `--about` with the project URL and `Jioh Jung <jung@jioh.net>` to gateway
  and companion binaries; keep the gateway's `--version` format stable.
- Add initial JSON and deployment template READMEs with field explanations,
  startup, configuration changes, examples, and troubleshooting.
- Replace existing Korean summaries with full translations, and check translated
  heading structure, code examples, and table rows against their English sources.

## 0.2.0 — 2026-09-22

### Datagram routing

- Native UDP relay with IPv4/IPv6 listeners and backends, per-client flow
  affinity, round-robin selection, idle expiry, bounded queues, and aggregate
  session/payload-memory limits.
- Opaque QUIC passthrough, including HTTP/3 served by upstream QUIC endpoints.
  QUIC TLS termination and connection-ID-aware address migration are not provided.
- Revision-checked configuration, prebound candidate sockets, failed-change
  retention, activation controls, a dedicated English/Korean admin page, runtime
  status, and Prometheus metrics.
- UDP currently requires local-file configuration authority. Shared-store,
  Kubernetes-controller, and supervised UDP handoff are rejected explicitly.
  Changing a UDP route or replacing its process resets affected flows.

See [UDP routing](docs/UDP.md) for configuration, boundaries, and reproducible
UDP/HTTP/3 container verification.

### Direct server return

- A separate Linux `hangang-dsr` companion validates and manages explicitly
  configured IPv4 IPVS direct-routing TCP/UDP services through `ipvsadm`.
- Scoped apply/cleanup controls preserve unrelated IPVS services. Real servers
  require VIP, ARP, and routing configuration appropriate to the deployment.
- Container verification checks source-IP preservation, backend distribution,
  and direct-return traffic. This is a network-specific companion, not a native
  gateway DSR data plane or an automatic backend health controller.

See [DSR deployment](docs/DSR.md) for prerequisites, commands, and test scope.

### Enterprise-class lifecycle documentation

- Document live configuration publication, supervised HTTP/TCP listener handoff,
  existing-connection drain, signed binary update checks, and pre-readiness
  rollback as separate operational capabilities.
- State continuity limits explicitly: drain deadlines, intentional security
  revocation, container replacement, and no automatic rollback after readiness.
- Keep English reference documentation and Korean summaries aligned.

See [Updates and restarts](docs/UPDATES.md) for the supported deployment modes
and lifecycle tests. Release checksums identify downloadable artifacts; they do
not replace the operator-controlled signing keys and manifest required by the
signed updater.
