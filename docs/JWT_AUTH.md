# Native access-token authentication

[Documentation](README.md) · [한국어 요약](ko/JWT_AUTH.md)

`HttpRoute.jwt_auth` verifies signed OAuth access tokens against operator-selected public keys. It can use local JWKS or retrieve keys through a pinned HTTPS JWKS endpoint or OIDC discovery. The implemented token profile is [RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068); verification follows the issuer, audience, algorithm and token-type boundaries described in [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html). OIDC discovery here obtains verification keys. It does not implement a browser authorization-code flow, issue sessions or accept ID tokens as API credentials.

```json
{
  "id": "orders-api",
  "hosts": ["api.example.test", "www.api.example.test"],
  "path_prefix": "/orders",
  "path_match": "segment_prefix",
  "access_mode": "protected",
  "require_tls": true,
  "backends": ["http://127.0.0.1:8080"],
  "jwt_auth": {
    "verification": {
      "issuer": "https://identity.example.test/",
      "audiences": ["orders-api"],
      "profile": "rfc9068",
      "algorithms": ["RS256"],
      "leeway_seconds": 0,
      "max_lifetime_seconds": 3600,
      "scope_claim": "scope",
      "groups_claim": "groups",
      "required_scopes": ["orders:read"],
      "required_groups": []
    },
    "keys": {
      "source": "remote",
      "config": {
        "endpoint": {"kind": "oidc"},
        "cache_ttl_seconds": 300,
        "refresh_cooldown_seconds": 10,
        "timeout_ms": 3000
      }
    },
    "hide_credentials": true,
    "identity_header": "x-verified-subject"
  },
  "resource_policy": {
    "resource_id": "orders",
    "principal": {"source": "jwt"},
    "allow": [{"subjects": ["service-reader"], "methods": ["GET", "HEAD"]}]
  }
}
```

The example needs an owned issuer that actually emits this access-token profile, with a trusted certificate and a signing key published through discovery. It contains no token or signing secret. `jwt_auth` authenticates the selected route. Add [resource_policy](RESOURCE_POLICY.md) as shown to also guard its host/path namespace against alternate public routes. Domain aliases in `hosts` share the policy.

## Verification contract

Exactly one `Authorization: Bearer <compact-JWS>` field is accepted. Query parameters, cookies, proxy authorization and other headers are not alternate credential sources. Missing/malformed/duplicate authorization, invalid signature, unknown key, wrong issuer/audience/type and invalid claims produce 401 with a Bearer challenge. Valid tokens lacking required scopes/groups produce 403. Resource subject/method denial remains a separate 403 decision. Remote-key unavailability, expired key state or crypto admission exhaustion produce 503, never unauthenticated forwarding.

The protected JOSE header contains only `alg`, `kid` and `typ`. Token type accepts `at+jwt` and `application/at+jwt`, ASCII case-insensitively. Generic `JWT`, ID tokens, unsecured `none`, HMAC algorithms, token-supplied key URLs/keys, critical extensions, compression and detached/unencoded payloads are rejected. Header/claims/JWKS JSON member duplicates are rejected before maps can obscure them. The bearer is bounded to 16 KiB, decoded JOSE header to 2 KiB and decoded claims to 8 KiB, with canonical unpadded base64url encoding.

The algorithms are RS256, PS256, ES256 (P-256) and EdDSA (Ed25519), individually allowlisted. Each usable key binds one algorithm and one exact `kid`; a missing JWK `alg` is accepted only if exactly one configured algorithm is compatible with its key type. No RSA/HMAC algorithm conversion occurs. RSA moduli are 2048–4096 bits with exponent 65537. Cryptography uses `jsonwebtoken` with its RustCrypto provider, including public-key validation during preparation. No custom signature algorithm is implemented. Library verification still creates a crypto verifier from prepared key material per request; a shared Send/Sync verifier is not exposed by that library API.

Required claims are `iss`, `aud`, `sub`, `exp`, `iat`, `client_id` and `jti`. Issuer comparison is exact against the configured HTTPS issuer. At least one token audience must match a configured audience exactly. Numeric dates are unsigned integer seconds; expiration must be after issue time and within the configured maximum lifetime. `nbf` is checked when present. Leeway is explicit, defaults to zero and is at most 60 seconds. Expiration, issue time and not-before are rechecked after blocking crypto work, immediately before the authentication result is admitted. A `jti` is required but does not provide replay detection.

Scopes are a space-separated string; groups are a string array. Configured claim names select literal top-level members, not JSON paths. Required scopes and groups each use all-of matching. Values are exact and case-sensitive. Missing optional scope/group claims yield empty sets; malformed, duplicated or oversized attributes invalidate the token. Scope tokens use printable OAuth scope characters; groups may use bounded UTF-8 strings. Neither client headers nor Lua can supply these verified attributes.

Current bounds: at most 8 configured audiences, 16 token audiences, 32 scopes/groups per token or required list, 128 bytes per attribute and 255 bytes per subject/audience/client ID/JTI. Issuers are at most 512 bytes. Claim names are distinct bounded ASCII names excluding registered identity/time claims. At most 64 distinct JWT route policies are prepared per configuration; identical policies share one runtime across aliases and unchanged snapshots.

## Public-key sources and rotation

For local keys use `"keys":{"source":"local","jwks":{"keys":[...]}}`. Only public JWK material belongs in this document; private or symmetric key material is rejected. A local JWKS is validated before publication. It may contain bounded public keys for other algorithms or encryption purposes; only compatible configured verification keys are admitted. Duplicate `kid` values are rejected globally, and at least one usable signing key must remain. Selected signing keys are validated, including their declared usage. JWKS documents are bounded to 128 KiB and 32 total entries.

Remote source configuration uses `endpoint:{"kind":"oidc"}` or `endpoint:{"kind":"jwks","url":"https://keys.example.test/jwks"}`. Discovery is derived from the configured issuer. Its returned issuer must match exactly. In this implementation, a discovered JWKS URL must have the same HTTPS origin; explicitly pin a JWKS endpoint to trust a different origin. [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) defines issuer/metadata validation; the same-origin rule is an additional deployment restriction here.

The HTTP client verifies TLS, disables environment proxies and redirects, and does not send client Bearer credentials to the key endpoint. URLs cannot contain credentials, query or fragment components. Optional `ca_pem` adds a public PEM trust anchor for a private IdP; insecure TLS is not an option. One timeout of 1–5000 ms bounds discovery and JWKS retrieval together. Response bodies are bounded while streaming.

Remote configuration validation performs no network access. First use lazily initializes the key cache. A cold or expired cache fails closed when the issuer is unavailable; concurrent cold requests may receive 503 while one request fetches keys. Unknown key IDs can trigger only one bounded refresh, subject to a cooldown reserved before network I/O, including if the requesting client cancels. There is no unbounded waiting queue. While authenticated sessions exist, a bounded shared monitor refreshes the runtime key cache; it performs no idle fetches after sessions end.

After half the TTL, a request with a known key or the shared session monitor can refresh, subject to the configured cooldown. Concurrent requests continue using the still-fresh key. If refresh fails, the triggering request may also use that key only before its original deadline; unknown or expired keys receive no fallback. Choose a cooldown shorter than the TTL to allow this early refresh window.

Hard cache TTL is configured to 1–3600 seconds and measured from fetch start. Delayed responses cannot extend it. A final key-identity/deadline fence prevents a key selected before removal or expiry from admitting work after the cached key generation changes. Unchanged public JWKs retain their key identity on successful refresh; removed or changed keys invalidate it. Refresh errors never extend the previous deadline. Known cached keys remain authoritative only until that deadline, so issuer outages do not instantly invalidate a still-fresh cache. Key removal becomes effective when a successful refresh observes it, or at the hard deadline if refresh fails. A valid remote empty JWKS (or a structurally valid set with no eligible signing keys) explicitly withdraws the cached keys. Malformed documents remain refresh failures; they do not create a withdrawal generation. Local JWKS configuration still requires an eligible key. Restoring a previously withdrawn key creates a new identity and cannot revive old sessions.

Changing JWT policy, issuer, audiences, source or trust settings creates a new runtime generation; unrelated route updates retain the existing runtime/cache. Admitted JWT requests also retain the full selected route generation. An edit to that same route (including backend or matching fields), its disable/removal, token time invalidation, or signing-key withdrawal retires its uploads, response bodies, SSE and WebSocket tunnels. Unchanged routes preserve their leases, including other routes multiplexed on the same HTTP/2 connection.

The lease uses the verified token claims and selected key identity, not the raw bearer string. Time validity includes configured leeway, with both wall-clock checks and a monotonic expiry deadline. Synchronous per-frame checks perform no signature verification or network requests; a 250 ms timer also wakes idle bodies/tunnels. External authorization, Lua evaluation, body-transform buffering and origin-header waits also race against lease retirement; retirement before response headers returns 503 without treating it as an upstream failure or retrying another backend. These intervals depend on scheduler availability and are not instantaneous network-wide revocation guarantees. Already forwarded bytes cannot be recalled.

Remote key removal is observed through successful refresh or the cache hard deadline; a failed refresh never extends that deadline. Choose TTL and cooldown with enough margin for network latency and refresh. For example, a cooldown equal to TTL can prevent refresh before hard expiry and terminate otherwise valid sessions. The monitor shares work per runtime and does not create a fetch loop per stream. JWT and workload mTLS leases compose: expiry or withdrawal of either identity can end a stream. The configured token-ID denylist below adds operator-managed revocation; online introspection, immediate issuer-side logout and distributed revocation authority remain separate requirements.

## Operator-managed token revocation

`jwt_auth.verification.revocation` adds route-scoped admission conditions:

```json
{
  "issued_before": 1789257600,
  "token_ids": ["withdrawn-token-id"]
}
```

The gateway rejects a cryptographically valid token with 401 if its signed `jti` exactly matches a listed ID, or its signed `iat` is strictly before `issued_before`. Equality at the cutoff remains valid; configured time leeway never relaxes revocation. Omitted/null revocation keeps the existing behavior. Omitted/null cutoff and an empty list impose no additional condition. The cutoff is a UNIX-second integer from 0 through 253402300799; the list accepts at most 1,024 unique IDs, each 1–255 UTF-8 bytes without surrounding whitespace or control characters. Validation errors do not echo token IDs. Lookup uses a prepared hash set after signature and claim verification, with no new issuer request.

The English/Korean HTTP route editor exposes both fields. Publish through the existing revision-checked route or full-document configuration APIs. The durable configuration contains identifiers, never a required bearer credential; operators should enter only the `jti`, not a signed token. Shared-resource aliases require the same complete JWT verification policy so one alias cannot omit the revocation condition. Unrelated issuer/routes remain independent.

A successful local publication retires **all admitted streams on the edited route**, including tokens not on its denylist, because the full route policy generation changes. Clients holding other valid tokens can reconnect once the new verifier can acquire its signing keys. Like other JWT policy edits, a revocation edit creates a fresh runtime/cache; remote-key routes may need a new successful JWKS fetch, and fail closed if that fetch is unavailable. Unchanged unrelated routes preserve their streams. This conservative behavior also applies when entries are removed. Revocation entries do not expire or disappear automatically: retain them until the affected tokens can no longer be valid, including leeway. Explicitly removing an entry or lowering a cutoff can allow an unexpired token again, but cannot resume a stream already closed.

This is persistent configured policy, not an issuer introspection service or an automatically synchronized logout feed. A shared-store write is not proof that every data-plane reader has activated it; multi-node propagation, acknowledgements, authority fencing and durable actor audit retain their existing limitations. This feature does not claim selective connection indexing or a fleet-wide instantaneous revocation deadline.

## Request processing, observability and UI

JWT and native Basic cannot share a route because both consume Authorization. JWT may precede an additional external authorization check. The external service receives the original bearer only if explicitly included in its request headers; default `hide_credentials:true` removes the original bearer after that check and before Lua/upstream forwarding. All configured authentication checks must succeed. Resource-policy terminal-response restrictions continue to apply.

An optional identity header carries the verified subject. Client copies are removed before verification, external auth cannot claim the same header, and native transforms cannot modify it. Runtime identity reassertion and Lua mutation restrictions protect the established value. Ordinary Lua application transformations remain supported. JWT routes bypass shared response caching, including legacy-classified JWT routes, and cache-only requests still authenticate before an unsatisfiable 504.

Signature verification runs outside asynchronous I/O workers with a process-wide fail-fast semaphore sized to twice available CPUs (minimum 2, maximum 64). A blocking task retains its permit even if its requesting client disconnects. No unbounded crypto queue is created. Prometheus and status expose `jwt_auth_rejections_total`, `jwt_auth_unavailable_total` and `jwt_auth_capacity_rejections_total`. `jwt_lease_terminations_total` counts admitted request/body/tunnel guard terminations caused by token time, key, or route-generation invalidation; it is not a count of unique users or connections. These are operational counters, not durable security audit or per-user decision logs. Tokens and raw verification errors are not returned in failure responses.

The HTTP editor provides dedicated English/Korean JWT verification, key-source, claim, credential and identity controls, plus a JWT principal option in the resource policy. Existing route/full-document APIs and revision checks carry these fields. Upgrade every shared-configuration reader before publishing them; older binaries reject unknown fields. Rollback must preserve the authentication boundary rather than strip fields to make an older binary load.
