# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

## Unreleased

- Drop request trailers before policy and upstream forwarding so late HTTP/2
  fields cannot restore stripped authentication or forwarding headers.
- Fence retired Docker discovery completions and timeout cleanup against newer
  daemon generations; reject symlink replacement on SQLite cache reopening.

- Fence Docker connection writes against account/session revocation after body
  admission and writer-queue waits; recheck candidate-test authorization.
- Recheck cache freshness and invalidation after disk reads, and reject
  nonregular command-line TLS material without blocking on FIFO replacement.

- Separate viewer response and login password-work budgets from administrator
  recovery; limit account sessions without evicting another account's sessions.
- Retain cache-fill capacity through publication and yield while consuming
  empty or fragmented body frames so transform deadlines remain effective.
- Bound command-line TLS handshakes with the shared public-listener budget and
  back off after policy worker creation failures.
- Harden SSO cookies with HttpOnly and SameSite=Lax, reject ambiguous callbacks,
  and suppress credential-bearing callback referrers.
- Require rustls 0.23.45 or later to fix TLS handshake encryption-level
  validation (RUSTSEC-2026-0285).
- Canonicalize authentication route paths before selection, including legacy
  Basic/JWT/external authentication, and reject ambiguous authenticated paths.
- Reserve authentication identity output headers across public fallbacks and
  prevent other routes or Lua from forging those identities.
- Fence pending administrator logins across role and enabled-state changes;
  keep login admission available with unread HTTP/2 authentication responses.
- Normalize SSO bridge dot segments and reject authorization scores from
  unsuccessful session-check HTTP responses.
- Unify administration colors, surfaces, typography and light/dark themes;
  include three self-contained console design candidates.
- Add native Linux x86-64/ARM64 and macOS Intel/Apple Silicon qualification jobs and platform-specific release packaging.
- Support ordinary macOS gateway execution; explicitly reject Linux-only supervised replacement. macOS archives exclude IPVS DSR.
- Require an explicit macOS development opt-in for Lua without Linux syscall isolation; retain Linux sandbox behavior.
- Document laptop-to-server use, Windows/ARMv7 limitations, and unsigned CI artifact boundaries.
- Use physical temporary state paths on macOS and separate disk-cache ownership locks from SQLite locks.

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
