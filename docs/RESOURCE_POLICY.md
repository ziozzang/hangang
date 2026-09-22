# Protected HTTP resources

[Documentation](README.md) · [한국어](ko/RESOURCE_POLICY.md)

An HTTP route may bind a gateway URL namespace to an authenticated principal and an exact method allowlist using `resource_policy`. This adds authorization to the existing `access_mode: protected` authentication boundary. The namespace is the route's host matcher plus `path_prefix` and `path_match`; it does not depend on route priority, header/JSON predicates, or whether the route is enabled.

```json
{
  "id": "records",
  "hosts": ["app.example", "www.app.example"],
  "path_prefix": "/records",
  "path_match": "segment_prefix",
  "access_mode": "protected",
  "backends": ["http://127.0.0.1:8080"],
  "auth": {
    "url": "http://127.0.0.1:9080/check",
    "response_headers": ["x-authenticated-subject"]
  },
  "resource_policy": {
    "resource_id": "records",
    "principal": {
      "source": "external",
      "subject_header": "x-authenticated-subject"
    },
    "allow": [
      {"subjects": ["reader"], "methods": ["GET", "HEAD"]},
      {"subjects": ["editor"], "methods": ["GET", "HEAD", "POST", "PATCH"]}
    ]
  }
}
```

[A complete configuration example](../examples/resource-policy.json) adds TLS enforcement and ordinary Lua application-header mutation.

The example requires a real authorization service at the configured address. It does not install an identity provider. Configure TLS and trusted proxies for the actual topology; this policy does not make a plaintext authentication hop confidential.

## Principal and action

`principal.source: basic` uses the username returned by the configured native Basic credential verifier. `external` uses exactly one nonempty subject header copied from the configured external authorization service's successful response. The header must be listed in `auth.response_headers`; a client request header is never principal evidence. Missing, repeated, comma-merged, malformed or oversized external subjects cannot authorize. `jwt` uses the signed `sub` from the configured [native JWT verifier](JWT_AUTH.md), with no subject-header field. `workload` uses the exact SPIFFE URI from the verified client certificate on a [dedicated workload mTLS listener](HTTP_WORKLOAD_MTLS.md); a request on an ordinary public listener cannot supply this evidence. JWT and Basic are mutually exclusive. Every configured authenticator must succeed; the declared source chooses whose subject is evaluated.

Subjects are case-sensitive exact strings, bounded to 255 UTF-8 bytes without surrounding whitespace or control characters, except verified workload SPIFFE URI subjects, which may be up to 2,048 ASCII bytes. `*` in a subject is a literal name. Methods are exact uppercase names (up to 32 ASCII letters/digits/hyphens), with an explicit `*` rule for all supported method names. GET does not implicitly grant HEAD. An empty `allow` array denies everyone. At most 32 rules, 32 subjects and 16 methods per rule, 512 combined subject/method items and 32 KiB of policy text are accepted. Resource IDs use 1–128 ASCII letters/digits or `. _ - :`; external header names have a 128-byte limit.

Authorization runs after authentication and before Lua, transformations, cache-only completion and upstream admission. General Lua flexibility remains available, but changing an application/identity header cannot change the principal or method already used for this decision. Protected routes remain ineligible for shared response caching. Authentication challenges and non-success SSO redirects may finish earlier. Terminal successful external-auth responses are incompatible with resource policies and rejected during validation, including released policies.

## Namespace and routing

Before route selection, the gateway checks every enforced resource namespace matching the request's host and canonical path. The selected route must carry that resource ID with enforcement enabled. A higher-priority public route, a header/JSON alternative, or a disabled protected route with a public fallback cannot bypass the guard. Overlapping namespaces with different resource IDs deny the request. Routes sharing an ID must declare identical policies and authenticators, preventing a weaker alternate route from borrowing an ID. Use `hosts` for aliases that should share a policy and upstream.

The existing exact, glob and compiled regex hostname matchers apply to both routing and guards. On a host with a protected namespace, disagreements between the request Host, absolute-form authority and effective trusted-proxy host are rejected. Hostnames compare case-insensitively; ports do not define a separate resource namespace. Trailing root-dot spellings of a protected host are rejected.

A strict, bounded path profile applies to the entire guarded host, including paths outside its protected prefix. Paths are limited to 2048 bytes, percent-decoded once to valid UTF-8 for guard and route matching. Encoded slashes, backslashes, percent signs (double decoding), query/fragment delimiters, semicolon path parameters, control characters, repeated slashes, and dot segments are rejected. This restriction applies even if the legacy `allow_dot_segments` compatibility setting is enabled. Configured resource path prefixes must already be canonical. The query is not part of the namespace or action rule. The forwarded request retains its original path encoding.

This is a gateway URL namespace contract, not discovery of all aliases to an upstream object. An administrator can expose the same backend through a different unprotected hostname/path or a configured rewrite/base path. Upstream-specific Unicode normalization (NFC/NFKC), filesystem aliases and direct backend access are not reconciled by this guard. Use the same interpretation throughout the deployment and enforce the backend's own object-level authorization. Ordinary valid UTF-8 path segments are supported; Unicode normalization equivalence is not asserted.

## Changes and explicit release

`enforce` defaults to true and is omitted from serialized output when true. Disabling a route preserves its guard. Replacing the active configuration cannot omit, delete, move or narrow an enforced namespace. A replacement must preserve its resource ID and existing host/path scope, even if the route ID changes. Exact/glob host aliases may be added, reordered or case-normalized without releasing existing protection. Path shapes and regex expressions must remain identical; containment between different glob/regex expressions is not guessed.

To deliberately release a namespace, first publish the existing policy with `enforce: false` at its existing scope. This immediately releases namespace and subject/action enforcement; the route still requires its declared authenticator. A later revision may remove the policy or route, or change ownership explicitly. All aliases using the same resource ID must be updated consistently. The dedicated English/Korean editor exposes the policy, rules and explicit release/removal steps; route CRUD and full configuration PUT share server validation and revision checks.

Transition protection compares with the active snapshot. It is not immutable central authority across a fresh process loading an independently rewritten file. For ordinary routes, a policy publication does not recall previously admitted requests or close established streams. A dedicated workload mTLS route has a separate route-generation lease: changing that route retires its existing response streams and upgraded tunnels; listener expiry or withdrawal can also close its connections. This is bounded by runtime scheduling and cannot recall bytes already delivered. [Native JWT verification](JWT_AUTH.md) and [dedicated workload mTLS](HTTP_WORKLOAD_MTLS.md) are implemented as separate, opt-in authentication slices; device posture, general revocation, durable decision audit and fleet capability enforcement remain outside this resource guard. All fleet readers must support the new field before publishing it to shared configuration; older binaries reject it rather than silently ignoring it.
