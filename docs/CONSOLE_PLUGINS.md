# Trusted console packages and Hopae native transport

[한국어](ko/CONSOLE_PLUGINS.md)

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

Hopae preserves its existing native handle authentication, grant/role, assurance,
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
HOP1 is a bounded authenticated persistent loopback transport. No session decision
is cached, no provider is embedded, and native failures fail closed with no HTTP
fallback/replay. Both transports share the same forwarding and result handling.
Idle sockets retire before the server deadline; cancellation discards a socket.
Pool saturation rejects immediately, and unchanged prepared routes reuse pools.

Qualification includes codec bounds, duplicate cookies, wrong/replayed IDs,
key rejection, cancellation/reconnect/saturation, real session and entry-point
parity, native grant revocation, signed delegated actor audit and console lifecycle.
End-to-end identity throughput still requires deployment-specific load profiling;
Guard transport benchmarks are not evidence for Hopae session throughput.
