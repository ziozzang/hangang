# Trusted console packages and Hopae native transport

[Documentation](README.md) · [한국어](ko/CONSOLE_PLUGINS.md)

The native console imports operator-installed packages as sidebar entries under
ZERO TRUST. Guard and Hopae own their management APIs and data; Hangang owns
console authentication. Packages are trusted same-origin JavaScript, not a sandbox.
Never install unreviewed code. No separate console account database is created.

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
