# Changelog

[Project overview](README.md) · [Documentation](docs/README.md)

## Unreleased

- Console operator assurance (Hopae ADR-0021): with `operator_policy` the console
  SSO verifies Hopae's Ed25519-signed operator assertion against pinned public
  keys (`assertion_public_keys`, current and next) on every request, requires the
  configured level and a passkey for sign-in and every change, and a factor used
  within `sensitive_max_age_seconds` for sensitive changes (publish, activate,
  factor reset, accounts, configuration), sending the operator to Hopae's step-up
  path otherwise; the header shows the operator's AAL and factor.
- Break-glass local administrator sign-in is audited and can be disabled with
  `--disable-local-login`.
- Console operator audit store: SSO sign-ins, step-ups, changes and break-glass
  records are kept in a bounded ring (`--operator-audit-db`, max records and
  retention days), read by administrators at `GET /v1/console/operator-audit`
  and shown as the "Console operators" source of the unified audit;
  `--audit-log` remains an optional JSON-lines sink.
- `hangang-console --upstream-ca` trusts a private CA for an HTTPS upstream
  (re-read when it changes), so the authority's admin listener can stay TLS-only.
- `hangang-console` accepts Kubernetes ConfigMap/Secret volume files for the SSO
  and console plugin registry configuration (one shared rule; the registry file
  must now be private, no longer merely not group/world-writable) (root-owned, `fsGroup` group, 0440/0400, the `..data`
  atomic-writer layout); world-readable files and other symlinks stay refused.

## 0.3.6 — 2026-10-15

- Add opt-in native credential projection through Hopae's authenticated mTLS RPC.
  Retain the original permission request, verify response scope/hash and signed
  plan revision, remove incoming credentials and install a sensitive origin header.
- Intersect independent live deadlines without extending previously accepted
  authority; reject scope/header injection and responses beyond signed expiry.
- Verify independent Pumgye permission receipts and require current permission,
  network, route and projection-plan ownership before final dispatch.
- Start the bounded native route observation service with `--route-owner-config`.
  Require mTLS and dedicated caller credentials, validate resources before binding,
  preserve its typed listener during supervised restart and own shutdown tasks.
- Bind random request-scoped route references to exact snapshot/scope identity,
  final absolute URI, method, prepared entity digest and client IP. Cancellation,
  expiry, replacement and capacity exhaustion refuse without backend effects.
- Qualify actual four-server credential delivery, durable withdrawal, wrong trust
  and caller refusal, configuration/class restoration and existing-mode compatibility.

## 0.3.5 — 2026-10-15

- Add opt-in final native resource dispatch: compose the selected backend URI,
  bound the complete transformed entity and obtain actual Hopae/Pumgye/Sumunjang
  mTLS gRPC observations before upstream effects.
- Reject wrong issuer/public pin/audience, oversized or ambiguous bodies, stale
  revisions and unavailable authorities without dispatching to the origin.
- Qualify exact signed static packages on the backed-up four-server Kubernetes
  fixture, including integrated browser administration and durable revocation.
- Publish and internally adopt the gateway and console while preserving existing
  configuration and rights. Operating receipt resources remain unconfigured;
  signed permits, credential projection and replay admission remain separate work.

## 0.3.4 — 2026-10-15

- Enforce native resource/action gates through the independent Pumgye authority,
  keeping classification, permission mapping and minimum assurance in its catalog.
- Bind resource decisions to the trusted native service scope and retain route,
  authority revision/freshness and response-stream revocation checks.
- Display and preserve the owner resource catalog in the integrated administrator
  console; publish with owner/configuration CAS and keep source-managed policies read-only.
- Add an opt-in request-bound Hopae service authentication receipt client with
  pinned signatures and revision fencing. Provider translation/permit dispatch is
  still pending; ordinary authentication remains unchanged.
- Qualify resource dispatch in actual static four-server mTLS gRPC and remote
  Kubernetes/browser fixtures; existing native/gRPC service chains also pass.
- Publish five independently verified signed Linux amd64 musl assets containing
  all eight static executables; adopt the gateway and standalone administrator
  console internally with private rollback backups and preserved configuration.

## 0.3.2 — 2026-10-14

- Preserve the original request Host, including its port, on Kubernetes Ingress
  rule routes and default backends. Service DNS remains the upstream destination.
- Add an HTTP regression for exact, wildcard and default-backend routes.
- Qualify the Ingress fix on Linux amd64 GNU/musl and a live k3d cluster.
- Document deployment, edge-to-Ingress bridging, multiple Service routing,
  request reflection, validation results and operational limits.
- This maintenance release is based on v0.3.1 plus the tested Ingress fix;
  ongoing main-branch identity changes are excluded.

## 0.3.1 — 2026-10-12

- Add trusted pinned Guard/Hopae console packages and a native console adapter over an existing administrator authority, including role/revocation checks, bounded requests and durable mutation audit.
- Add authenticated persistent Hopae verification pools with bounded binary framing, cancellation-safe connections, no HTTP fallback and shared native result handling.
- Keep provider/login/logout decisions in Hopae; native entry routes require no Lua.


## 0.3.0 — 2026-10-12

- Add native integration with the zero-trust decision backbone: Hangang resolves
  trusted client identity and asks hangang-guard for each request's admission.
- Support authenticated HTTP decisions and optional persistent, pooled binary TCP
  transport with fixed-size frames, bounded timeouts and connection cleanup.
- Keep decision caching disabled by default; allow an explicit 1–5 second cache.
- Export explicit honeypot/scanner evidence without request credentials or bodies.
- Preserve route authentication after a guard allow; return403 for explicit deny
  and503 for unavailable authority by default, with explicit fail-allow support.
- Separate backbone responsibilities: hopae manages users/principals; guard
  manages IP/network controls, risk scoring, GeoIP/ASN and dynamic decision rules.
- Add the optional public listener field `advertised_port` (1-65535) and the
  CLI flag `--advertised-port`. Behind a port forward that adds no forwarding
  headers, it replaces the local port as the default forwarded port, so
  `x-forwarded-port` and `x-original-url` sent to external authorization and
  upstreams carry the externally visible port (and omit a scheme-default
  port). A trusted proxy's explicit `X-Forwarded-Port` still wins; `0` is
  rejected.
- Add the HTTP route field `path_case` (`sensitive` | `insensitive`). Routes with
  `auth`, `basic_auth`, `jwt_auth` or `access_mode: protected` and a
  `path_prefix` now default to ASCII case-insensitive prefix matching so
  `/ADMIN/x` selects a protected `/admin` route; other routes stay byte-exact.
  The upstream still receives the original path. An explicit `sensitive` on a
  protected prefix route is warned about (log at activation and `--check`), and
  same-host routes whose prefixes differ only in case with different effective
  case handling and a shared listener are rejected (IP-literal hosts and
  segment_prefix operands are compared in normalized form); an earlier-selected
  unauthenticated route covering a protected prefix now produces a warning.
- Add `auth.static_request_headers` for fixed headers, literal or resolved
  from an environment variable at activation, on external-authorization calls;
  reserved and colliding names are rejected, client copies are never sent, and
  resolved values are never serialized or logged.
- Shared-store polls and file reloads that cannot resolve a static header
  variable now activate the revision with that route failing closed (503,
  readiness false, listed in `/v1/status` `authorization_unavailable`) instead
  of keeping an older revision live. `--check` and `POST /v1/config/validate`
  now resolve static header variables and report missing, empty or invalid
  ones by name.
- Add route-level `strip_request_cookies` (also accepted as
  `auth.strip_request_cookies`; the effective set is the union) to remove named
  cookies from the request sent upstream, with or without `auth`. Removal is
  the last header mutation before dispatch (after Lua, request transforms and
  identity reassertion; before retries and WebSocket upgrades), matching is
  exact and case-sensitive, quoted values are respected, and a Cookie header
  that could still carry a listed cookie is dropped entirely. The authorization
  call is unchanged. `cookie` is rejected as an authentication identity output
  header.
- Add configurable request parameter deny profiles for query, form, multipart
  and bounded JSON inputs, including nested JSON fields and normalization.
- Reject ambiguous protected parameter aliases and duplicates before origin
  work; retain bounded inspection capacity through forwarded body ownership.
- Add opt-in bounded anonymous disk inspection and byte-exact replay for
  large multipart uploads, with private directories, shared quotas and strict framing.
- Keep application-specific rules in separate configuration examples.

## 0.2.5 — 2026-10-06

- Add a dedicated Lua policies menu to find route/request/response scripts and
  open the existing scoped editor directly while preserving other route fields.

## 0.2.4 — 2026-10-06

- Add opt-in domain response security at final response delivery, covering
  redirects, cached responses and gateway errors; emit HSTS on verified HTTPS.
- Upgrade selected same-host HTTP redirects from HTTPS without changing
  external destinations or leaking internal listener ports.

## 0.2.3 — 2026-10-06

- Keep HTTP-01 issuer registration when ACME permission is disabled; allow
  registered challenges by default and keep registration details in advanced UI.
- Show observed backend reachability, HTTP response status, age and routing
  eligibility independently; never label an unobserved backend healthy.
- Fence backend observation updates against retired Docker endpoint generations.

## 0.2.2 — 2026-10-06

- Add opt-in per-URL browser Origin/Referer checks with verified same-origin
  handling, exact internal-origin allowlists, and bounded private denial logs.
- Plan isolated certificate groups while keeping base/www aliases and matching
  wildcards together; reject mixed-service issuer configurations before CA/DNS
  work, and require DNS-01 validation for wildcard groups.

- Manage HTTP-01 challenge delegation on the existing domain route, with bounded
  work and responses that omit issuer metadata and application credentials.

- Add an offline, policy-aware migration tool for consolidating legacy listener
  copies into one route; keep distinct URL policies and conflicting routes separate.

- Add exact-URL country/IP allowlists, simultaneous minute/day quotas,
  failure-triggered IP bans and administrator lookup/release controls.
- Support shared Redis/Valkey admission and ban state with atomic server-time
  counters, bounded operations, and generation fences for delayed responses.
- Add opt-in host/global IP-ban scope, bounded private security logs, and
  English/Korean security controls and documentation.
- Accept verified DBIP-Country-Lite MMDBs alongside existing country formats.
- Add bounded `settings.path_rate_limits` token buckets for URL namespaces,
  shared across clients/connections and retained on unrelated configuration
  updates; return429 with Retry-After and no-store before origin work.
- Add `settings.path_blocks` for bounded host-scoped path/directory denial
  before routing, authentication, cache, transforms and origin requests;
  reject encoded separators, double decoding and traversal aliases.
- Suppress `x-hangang-gateway` response headers and trailers by default,
  including legacy route and origin values; permit them only with explicit
  `settings.debug_gateway_header: true` for debugging.
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
