# Trusted console packages and Hopae native transport

[Documentation](README.md) · [한국어](ko/CONSOLE_PLUGINS.md)

The native console imports operator-installed packages as sidebar entries under
ZERO TRUST. Guard and Hopae own their management APIs and data; Hangang owns
console authentication. Packages are trusted same-origin JavaScript, not a sandbox.
Never install unreviewed code. No separate console account database is created.
Plugin views have labelled page headings and appear above the shared DB-IP
attribution footer, keeping its source link available beneath the active view.

## Load packages

Use `--admin-plugins /private/console-plugins.json` on Hangang, or run
`hangang-console --listen 127.0.0.1:19080 --upstream http://127.0.0.1:49000
--plugins /private/console-plugins.json` over an existing native admin authority.
The adapter serves the current native UI while delegating configuration/accounts
to that authority. Public plaintext requires explicit `--allow-insecure-public`;
protect it behind an authenticated TLS gateway and restrict direct network access.
Only a local relay may supply the adapter's generated client forwarding context.

Configuration (replace pins with the exact locally reviewed manifest digests):

```json
{
  "audit_database": "/private/console-audit.sqlite3",
  "plugins": [
    {"id":"guard","directory":"/opt/console/guard",
     "manifest_sha256":"<reviewed SHA-256>","backend":"http://127.0.0.1:19082",
     "token_env":"CONSOLE_GUARD_TOKEN"},
    {"id":"hopae","directory":"/opt/console/hopae",
     "manifest_sha256":"<reviewed SHA-256>","backend":"http://127.0.0.1:8702",
     "token_env":"CONSOLE_HOPAE_DELEGATION_KEY","delegate_actor":true,
     "delegation_cookie":"__Host-hopae"}
  ]
}
```

Run each component's `tools/build_console_plugin.py`; hash `manifest.json` and
pin it. Files must not be group/world writable. Manifests/assets are bounded,
hash-verified and copied into an immutable startup registry. Edits take effect
only after a validated reload/restart with a new pin. `--check` validates packages
without starting the console. Registry configuration and audit storage stay private.

Discovery `GET /v1/plugins` exposes names/entry points, never backend origins or
credentials. `GET /ui/plugins/<id>/<asset>` serves only pinned listed assets.
Only authenticated enabled administrators can call the explicit manifest route
allowlist at `/v1/plugins/<id>/<operation>`. Viewer access is rejected. Browser
credentials are not exposed to plugin mounts; the host API adds current authority.
Packages pause when hidden and dispose on logout, including late async responses.

Requests have independent public/login/ordinary/SSE admission, bounded bodies and
deadlines. Plugin calls have a separate cap and bounded JSON responses. Parent
identity is rechecked before dispatch and disclosure. Mutation intent/outcome,
actor and body digest are recorded in a private bounded SQLite audit; raw payloads
and secrets are excluded. Audit admission failure prevents dispatch. Ambiguous
outcomes are not retried automatically. Separate authorities cannot promise atomic
revocation of an operation already accepted by a backend.

Dispatched mutation replies retain `x-hangang-plugin-operation`, including a final
403 caused by parent authority withdrawal. That non-secret ID correlates only the
already admitted operation; it grants no audit access or authority to retry. The
403 discards the protected backend body and reports an uncertain outcome. The
private audit retains the actual backend result, which may already be committed.
Requests refused by the authority check before dispatch do not gain a new operation reference.

## Routes and route patterns

A manifest lists plain routes `{"path", "method", "mutation"}`: `path` is one
to several `/`-separated identifiers (lowercase letters, digits, `-`, each ≤ 32
bytes, ≤ 128 bytes in total), `method` is `GET`, `POST`, `PUT` or `DELETE`;
`GET` never mutates and `PUT`/`DELETE` always do. A package may declare up to
**64** plain routes (32 before contract v2): lookup is a linear comparison of
short strings and the manifest stays operator-reviewed and at most 64 KiB, so
the larger cap keeps review practical while letting owner APIs ship complete.

Contract v2 (`"api_version": 2`) adds bounded **route patterns** for owner APIs
keyed by an identifier:

```json
"route_patterns": [
  {"path": "zones/*", "method": "GET", "mutation": false},
  {"path": "zones/*", "method": "DELETE", "mutation": true, "max_depth": 1}
]
```

- `path` is a valid route name followed by `/*`; `max_depth` (1–4, default 1)
  is how many segments the `*` may span. `zones/*` matches `zones/corp`, not
  `zones`, `zones/a/b` (depth 1) or `zones/`.
- Each matched segment must be a valid identifier (as above): `..`, empty
  segments, percent-encoded characters (so no encoded `/` or `.`), upper case
  and over-long segments never match. The broker never decodes the path.
- Each pattern names exactly one method and its own mutation flag, validated
  like plain routes; a request with another method is `404`. Mutating patterns
  are journaled exactly like mutating routes, with the concrete path.
- Plain routes are matched first. A plain route below a pattern's prefix with
  the same method is refused at load (ambiguous), as are duplicate patterns.
- At most 16 patterns per package and at most 64 plain routes and patterns
  together. `api_version: 1` manifests may not declare patterns and keep their
  exact meaning; discovery lists `route_patterns` beside `routes`.

The broker forwards a matched request to exactly `<backend>/v1/<path>`. For
delegated packages the signed actor assertion binds that exact forwarded path,
the method and the SHA-256 of the body, so a backend verifying the assertion
cannot be steered to another resource (security review: path confusion — identifier-only segments, no decoding, no
normalization; method smuggling — one method per entry, `HEAD`/`OPTIONS`/other
methods unmatched; mutation-flag bypass — the flag comes from the matched
entry, and plain routes cannot be shadowed by a pattern).

## Mounted package locale lifecycle

The host owns the locale. A mount may subscribe with
`const unsubscribe = context.onLocaleChange?.(() => render(context.locale()));`.
The optional hook permits at most eight listeners per mount and returns an
unsubscribe function. Notifications also reach paused mounts; the host removes
listeners on abort/logout and fences callbacks from an older mount generation.
Event payloads are not locale authority. Older hosts without this hook remain
supported by packages that feature-detect it.

A locale callback updates presentation in place. It must preserve drafts, pending
mutations, selections and cached observation timestamps, and must not fetch data,
renew authority freshness or remount the package. Hopae and Guard update their
mounted labels and status composites through this contract. Browser regressions
exercise real package assets with mocked owner APIs; live four-service deployment
and reviewed package-pin adoption require separate qualification.

The real-package browser selection requires both package directories explicitly;
without them `plugin_locale.spec.js` reports skipped tests, not qualification.
Malformed/missing files and manifest asset hash mismatches fail the selection.
Use reviewed source checkouts (Hopae `b9b2a9a88de5c713c3f4acaf74de9d507db6fb39`,
Guard `d314d873a27d52d4a5fec981182f8118daeaf1f3`) and record their manifest pins:

```sh
HANGANG_TEST_HOPAE_PLUGIN=/reviewed/hopae/plugins/hopae \
HANGANG_TEST_SUMUNJANG_PLUGIN=/reviewed/sumunjang/plugins/guard \
npx playwright test --config web/playwright.config.js tests/plugin_locale.spec.js
```

Package versions are Hopae **0.1.6** and Guard **0.1.4**. Their manifest SHA-256
pins are `ec6385edf47321b7be9cfa8ef38c40be629383d1d931e22f1a4e22c090a515b8`
and `0d81330ffe804ffca3d98761c90f5868008bed359710b80d42c3166324d73310`, respectively.
These independently packaged assets do not change standalone runtime versions.

## Hopae management and login

The default native delegation mode preserves Hopae handle authentication, grant/role, assurance,
freshness, CSRF and transactional mutation fence. See Hopae's `HANGANG_NATIVE.md`.
An explicitly configured dedicated delegation key signs actor ID/name, timestamp,
nonce, method/path, body digest and handle/client-context evidence. It is not the
ordinary verification caller key. Native provider/session secrets remain in Hopae.
Browser mode requires both Hangang administrator authority and a valid Hopae
administrator handle/grant. A Hangang admin role alone never creates a Hopae grant.

Set Hopae's admin origin to the console origin when using browser mode. Route the
reserved `/_hopae/` entry namespace through forward-auth to Hopae, using
`forward_response:true`, `terminal_response:true`, request cookies/navigation
headers and static caller-key/contract headers. Login and logout use the native
`/_hopae/login` and `/_hopae/logout` handlers, without Lua. Logout retains Hopae's
confirmation/CSRF behavior. Strip Hopae cookies from application upstream requests.
Keep console API credentials and cookies out of unrelated application routes.

## Native verify pool

An existing route's external auth can add:

```json
"native": {"address":"127.0.0.1:8703","pool_size":32}
```

The auth URL must identify `/_hopae/verify`; configure a static
`x-hopae-gateway-key` and enable Hopae `listen.native_gateway` at that address.
HOP1 is a bounded authenticated persistent transport; remote connections require mTLS. No session decision
is cached, no provider is embedded, and native failures fail closed with no HTTP
fallback/replay. Both transports share the same forwarding and result handling.
Idle sockets retire before the server deadline; cancellation discards a socket.
Pool saturation rejects immediately, and unchanged prepared routes reuse pools.

Qualification includes codec bounds, duplicate cookies, wrong/replayed IDs,
key rejection, cancellation/reconnect/saturation, real session and entry-point
parity, native grant revocation, signed delegated actor audit and console lifecycle.
End-to-end identity throughput still requires deployment-specific load profiling;
Guard transport benchmarks are not evidence for Hopae session throughput.

The reserved Hopae entry route must outrank the broad console `/` route: use a higher `priority` or place it first at equal priority. Hangang uses priority then configuration order, not automatic longest-prefix ordering.

## Unified Hangang authority and SSO

For a console that follows Hangang login/roles, set the Hopae binding's
`delegation_authority` to `"hangang"` and remove `delegation_cookie`. In Hopae set
`admin.hangang_delegation.authority` to `"hangang"` with the same dedicated key.
This explicit mode accepts only signed Hangang administrator requests on the
existing narrow route allowlist. Assertions bind the authority mode and request,
are single-use, and expire within five seconds; the mutation transaction checks
the proof again. Standalone Hopae authentication and the default `native` mode
retain native grants, sessions, freshness and assurance checks. The embedded
package hides its separate login/logout links in unified mode. Hangang owns the
console authority; Hopae still owns provider credentials, identities and sessions.

Run the adapter with `--hopae-sso /private/console-sso.json` to add **Sign in with
SSO** beneath account sign-in. The configuration is a private regular file (0600):

```json
{
  "public_url": "https://console.example.test/",
  "native_address": "127.0.0.1:8703",
  "gateway_key_env": "CONSOLE_HOPAE_GATEWAY_KEY",
  "upstream_token_env": "CONSOLE_HANGANG_SYSTEM_TOKEN",
  "cookie": "__Host-hopae",
  "accounts": {"u_example": "operator"}
}
```

Account mappings use opaque Hopae user IDs, never unverified email/name claims.
Only existing enabled Hangang accounts can sign in, with their current Hangang
role; no account or privilege is automatically created. The private broker system
credential is never delivered to the browser. Hopae performs provider login at
`/_hopae/login`; its native cookie returns to `/ui/?sso=hopae`, where a same-origin
POST exchanges it for an opaque console bearer. The browser never receives an
upstream lease or provider token. Every SSO request verifies the bound Hopae
cookie, client IP/UA and current native session before acquiring a private
five-second upstream lease (reused for at most one second). Hangang rechecks its
local account/role. Logout revokes the opaque console session and current lease;
it does not globally log the user out of other Hopae applications. Adapter restart
invalidates opaque SSO sessions; sign in again using the retained Hopae session.
Configuration discovery reveals only the provider name and fixed entry URL.

Validation: native per-request revocation, same-origin exchange, explicit account
mapping, opaque-bearer isolation, local account disable/expiry, browser callback,
and Hangang-authority Hopae reads/mutations/replay/audit are covered by tests.

For remote HOP1, add `native.tls` with `server_name`, `ca`, `certificate` and
`key` (absolute PEM paths), and enable Hopae `listen.native_gateway_tls`.
Hangang dials only the fixed `native.address`, validates the explicit CA and
server identity, supplies its client certificate and requires ALPN `hop1`.
TLS errors never fall back to plaintext or HTTP. Connections retire after
240 seconds, before Hopae's 300-second server limit. TLS files are read only
when preparing a changed configuration; CA/key rotation requires publication
of changed `native.tls` settings (for example, new versioned PEM paths).

The optional console SSO configuration accepts `native_tls` with the same
`server_name`, `ca`, `certificate` and `key` fields. It uses the shared native
client and fixed `native_address`, preserving explicit Hopae-to-Hangang
account mappings and existing session/lease checks. Remote SSO peers require
mTLS; loopback plaintext remains available during migration.

## Operator assurance (passkey) and break-glass

With Hopae's `console_operators` policy (Hopae ADR-0021) the console can require
that operators signed in with a phishing-resistant factor. Add `operator_policy`
to the SSO configuration and give the console the same assertion key as Hopae's
`console_operators.assertion_key_env`:

```json
"operator_policy": {
  "assertion_key_env": "CONSOLE_OPERATOR_ASSERTION_KEY",
  "minimum_aal": 2,
  "require_factor": "webauthn",
  "accept_enrollment_grace": false,
  "sensitive_max_age_seconds": 300,
  "step_up_path": "/ui/step-up"
}
```

- Every SSO request (the exchange and each later request) needs Hopae's
  HMAC-signed operator assertion (`x-hopae-operator-assertion`). A missing,
  forged, expired or foreign assertion (another user or host) refuses the request.
- **Sign-in and reads** need the assertion's policy met (`satisfied`), at least
  `minimum_aal` (1 to 3) and, with `require_factor: webauthn`, a passkey. With
  `accept_enrollment_grace`, operators Hopae admits during its enrollment grace
  may sign in and read, never change anything.
- **Every change** needs the policy without grace. A **sensitive change** (path
  containing `/publish`, `/activate`, `/factors/reset`, `/bulk-disable`, or under
  `/v1/admin-users`, `/v1/users`, `/v1/config`, `/v1/plugins`,
  `/v1/audit/policy`; `sensitive_paths` replaces the list) also needs the factor
  used within `sensitive_max_age_seconds` (30 to 3600).
- A refusal answers `403` with `operator_step_up_required` or
  `operator_reauthentication_required` and a `step_up_url`. The console UI goes
  there: the gateway route of the console host (protected by Hopae, like
  `/_hopae/login`) runs Hopae's passkey step-up for `step_up_path`, then the
  console returns to the view (`/ui/?sso=hopae`, inside `/ui/` only) and signs in
  again with the rotated Hopae session. When Hopae itself asks for a step-up
  (`x-hopae-reason: step_up_required`) the console answers the same way.
- The header shows the operator's level and factor (`AAL2 · Passkey`), or
  **Break-glass (local)** for a local administrator session;
  `GET /v1/auth/sso/session` returns the same facts.

**Break-glass.** The local administrator sign-in (`/v1/auth/login`) stays as the
break-glass path. `--disable-local-login` (requires `--hopae-sso`) refuses it and
every local session. Audit records (JSON lines, `--audit-log <path>` 0600 or
stderr): `console.sso_login` (with the assurance or the refusal),
`console.step_up_required`, `console.change` (SSO changes with the level and
factor), `console.break_glass_login` (`attempt` or `disabled`) and
`console.break_glass_change`.

Validation: `tests/console_operator_aal_smoke.py` (real authority and console,
signed-assertion fixture) and Hopae's browser qualification
(`tools/browser-qual/run-operator.sh`: real Hopae, real Hangang authority and
console, Chrome with a virtual authenticator).

## Backend mTLS

A binding may include `tls` with `server_name`, `ca`, `certificate` and `key`.
All file paths must be absolute; TLS material is bounded. The backend must use
HTTPS and the server name must be DNS. For a Service DNS backend its host must
match that name. A literal IP backend is connected at the configured IP while
using the specified DNS name for TLS verification. Private CA roots replace
built-in roots for that binding. Each plugin has its own client identity/pool;
credentials and TLS paths are absent from browser discovery. There is no plaintext
fallback on TLS or role failure. Existing bindings without this object retain
their HTTPS or literal-loopback HTTP behavior.

Sumunjang `--management-tls` enables the corresponding native management server.
Owned process qualification proves pinned plugin policy reads and mutations over
mTLS; full browser/Kubernetes console adoption remains a separate gate.
