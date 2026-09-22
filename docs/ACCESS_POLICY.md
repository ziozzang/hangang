# Explicit HTTP access modes

[Documentation](README.md) · [한국어](ko/ACCESS_POLICY.md)

`HttpRoute.access_mode` records the operator's intended authentication boundary. The gateway validates it before publishing any route or full configuration, including disabled routes. Use resource policies and an authenticator for subject-level authorization.

| Value | Meaning | Validation |
|---|---|---|
| `legacy` (default, omitted on output) | Existing behavior: configured Basic/JWT/external authentication still runs; missing authentication remains permitted. | No new authenticator requirement. |
| `public` | Explicitly no gateway Basic/JWT/external authentication. IP, transport, Lua and application rules can still reject requests. | `basic_auth`, `jwt_auth` and `auth` must be absent/null. |
| `application` | Authentication is delegated to the upstream application. Hangang does not verify that application's login. | `basic_auth`, `jwt_auth` and `auth` must be absent/null. |
| `protected` | Gateway authentication is required. | At least one of `basic_auth`, `jwt_auth` or `auth` must be configured. JWT and Basic are mutually exclusive; all configured checks must succeed. Lua alone does not satisfy this requirement. |

Omitting the field preserves existing configurations and avoids silently imposing a new login requirement. The console distinguishes this unspecified declaration from an explicit protected mode; a legacy route may still have working authentication. Public/application labels describe ownership, not proof that every request succeeds.

For subject/method authorization and protection against alternate-route shadowing, see [Protected HTTP resources](RESOURCE_POLICY.md). The limitations below describe `access_mode` alone.

Native signed access-token configuration and its limits are documented in [JWT authentication](JWT_AUTH.md).

## Guarding accidental removal

For example, add `"access_mode": "protected"` to a working Basic-auth route. Removing only `basic_auth` now fails validation, unless another real authenticator remains. A failed API write leaves the active configuration and revision unchanged. The same check runs for a full configuration PUT and dynamic loading, not just the route editor. No UI-only security boundary is involved.

For an existing same-ID protected route, replacing the configuration with an omitted/default `legacy` mode is also rejected. This prevents an older editor dropping both the new field and the authenticator. The transition check uses the active prior snapshot; it is not a durable security authority across deleting/recreating a route or a fresh process loading an independently rewritten file.

An administrator can intentionally set explicit `public` or `application` and remove authentication together to change ownership. This feature is not central authorization, immutable security policy or dual approval. Route deletion, shadowing by a different route, unsafe path-normalization compatibility options and direct upstream access also require broader resource-policy/deployment controls.

The dedicated HTTP editor provides an Access mode selector and localized explanations; the Security view distinguishes declarations from observed configured controls. Existing route CRUD and full-config APIs carry the field, with the same revision/CAS requirements. [OpenAPI](openapi.json) includes the enum and compatibility contract; no extra endpoint is required for this field.

## Requests, cache and Lua

Existing Basic/JWT/external authentication remains on the request path. Protected routes are explicitly excluded from shared response caching. On the normal forwarding path, a protected `Cache-Control: only-if-cached` request runs authentication and Lua policy before returning 504 for an unsatisfiable cache-only request; an unauthenticated request receives its authentication denial/challenge instead. No upstream request is issued for that cache-only result. Trusted external-auth terminal/forwarded SSO responses may intentionally finish earlier, retaining existing behavior. Transport errors, parsing, route admission, IP denial and TLS redirection may still reject earlier; this mode is not a promise to authenticate malformed or rejected traffic.

General Lua application-header/body/supported backend-selection transformations remain available. Authenticator-owned identity fields cannot be overwritten by ordinary header mutation, including identity names whose value must remain absent. Merely configuring a Lua script does not prove a verified principal exists.

`protected` does not require transport TLS automatically, validate JWT/OIDC, authenticate inbound client certificates, evaluate device posture, enforce user-specific scopes, revoke established public streams, or create durable audit. Configure current transport/authenticator controls explicitly and qualify their topology. In particular, SNI passthrough cannot establish a gateway-verified client certificate without a terminating/authenticated identity hop.

## Upgrade compatibility

Older gateway binaries do not understand `access_mode` and may reject configurations containing it. Upgrade every intended reader before publishing explicit modes to shared configuration. A rollback to a pre-feature binary is not automatically compatible once such a document is stored; do not silently strip protection to make a rollback load. The active-snapshot transition guard also intentionally rejects older-editor replacements omitting a protected declaration. Coordinate reader versions before publishing new fields.

## Example

[examples/access-mode.json](../examples/access-mode.json) shows public, application-owned and protected routes with an external authenticator and ordinary Lua header mutation. Replace the reserved example identity endpoint and loopback backend with owned services before using it; the file does not install an IdP. TLS termination/trusted edge configuration is separate.

## Verification

The Rust suites cover default/explicit serialization, invalid modes, protected authenticator removal, dual authenticators, disabled routes, authoritative API rejection with unchanged state/revision, defensive cache eligibility, and protected cache-only/auth/Lua ordering. Browser tests exercise mode round trips, editor validation and security classification.

`python3 tests/access_mode_smoke.py` starts an owned loopback origin and actual gateway using `HANGANG_BIN` (defaults to `target/debug/hangang`). It checks legacy behavior, real protected Basic+Lua requests, credential hiding, cache-only authentication, and 100 operations across 12 concurrent clients (valid requests, denials and invalid policy edits), with 16 Lua worker slots. Ten rejected downgrades must preserve the active and persisted revision, and no unauthenticated request may reach the origin. This is concurrency correctness testing, **not a comparative performance benchmark**. The fixture uses temporary files and no production endpoints.
