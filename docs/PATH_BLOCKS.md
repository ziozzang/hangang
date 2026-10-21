# URL security controls

[Documentation](README.md) · [한국어](ko/PATH_BLOCKS.md)

The administrator Settings menu provides URL blocks, country/IP allowlists, rate limits, failure-triggered IP bans and optional shared Redis. These are independent of ordinary route predicates and run before authentication services, cache, Lua and origins. Lists are empty by default; unconfigured URLs, including images, do not receive a rate limit. Publish through the full JSON editor or revision-checked configuration API. New requests use the published snapshot; already admitted responses are not retroactively cancelled.

## Configuration

```json
{
  "settings": {
    "path_blocks": [{"path": "/.git"}, {"path": "/.env"}],
    "path_allowlists": [{"path": "/office/login", "hosts": ["app.example"], "allow_cidrs": ["192.0.2.0/24"]}],
    "path_rate_limits": [{
      "path": "/login", "hosts": ["app.example"], "tps": 5, "burst": 10,
      "limits": [{"requests": 100, "window_seconds": 60}, {"requests": 1000, "window_seconds": 86400}]
    }],
    "path_failure_bans": [{
      "path": "/login", "hosts": ["app.example"], "failures": 5,
      "window_seconds": 300, "ban_seconds": 900, "statuses": [401, 403]
    }],
    "failure_ban_scope": "url"
  }
}
```

For country-only access, replace an allowlist rule with `{"path":"/login","hosts":["app.example"],"allow_countries":["KR"]}` and provision the existing [GeoIP source](GEOIP.md). If both `allow_cidrs` and `allow_countries` are present, both must pass. Overlapping rules also intersect. Unknown countries are denied403; unavailable or expired databases fail closed503. Country is IP metadata, not an authenticated identity. One copied database observation is shared with later route/Lua policies.

## Path and host matching

`path_blocks` matches a directory itself and slash-delimited descendants: `/private` and `/private/file` are blocked404, `/private-news` is separate. `/` blocks all application paths. Files such as `/.env.bak` need their own rule; there is no implicit suffix/regex matching.

All other URL controls match the exact normalized path by default; one optional trailing slash is treated as the same URL so common login aliases cannot bypass a budget or allowlist. `/login` does not include `/login/image.png`; opt into descendants with `include_subpaths: true`. Missing/empty `hosts` applies to all hosts/listeners. Host patterns use ordinary bounded hostname globs. Include every exposed alias, or omit hosts for a gateway-wide namespace. Trusted forwarded and absolute authorities also participate; client-supplied forwarding headers cannot choose a different IP.

**Fronting proxies must set X-Forwarded-Host.** A host-scoped rule (`path_blocks`, allowlists, CSRF, rate limits, failure bans) applies when any of these names matches: the `Host` header, the forwarded host, or an absolute request-URI authority. The forwarded host is the `Host` header for an ordinary client, and the single `X-Forwarded-Host` value (or, when the proxy sends no `X-Forwarded-*` field, the `host` of the selected RFC 7239 `Forwarded` element) only when the socket peer is in `trusted_proxy_cidrs`. Spoofing one name cannot remove a rule that another name still selects. But if a trusted proxy rewrites `Host` to an internal name and passes the client's own `X-Forwarded-Host` through, the client chooses the only public name Hangang sees and can step around host-scoped rules. Configure every trusted proxy to overwrite (not append to or pass through) `X-Forwarded-Host` with the host it actually served, or omit `hosts` for rules that must hold on every name. Route selection itself still uses `Host`.


Paths are case-sensitive canonical absolute paths, at most2048 bytes, without escapes/trailing slash except root. Queries do not affect matching. On scoped hosts, request escapes decode once; encoded separators, double encoding, traversal, repeated slashes, backslashes, semicolon parameters, invalid UTF-8 and controls are rejected400. Strict matching can reject application-specific encodings, so scope intentionally. Dedicated health probes bypass URL blocks/rate/allowlists, while explicit host/global IP bans apply before health responses. Separate administrator recovery remains outside these public HTTP controls. They do not install OS firewall rules or change raw TCP/UDP admission.

## Simultaneous rate limits

`tps` is an optional sustained token-bucket refill rate, with `burst` maximum immediate tokens (default1). `limits` adds up to8 fixed-window counters;60 seconds means minute,3600 hour,86400 day. At least TPS or a nonempty limits array is required. Every window must permit the request. TPS/burst/window requests accept1–1000000; window seconds accept1–86400.

Unless `per_client` is set, budgets are shared across clients, methods, connections and listeners for each rule. Tokens/counts are charged on admission and not refunded after cancellation, auth failure or origin errors. Rejection is opaque429 with `Retry-After: 1` and `Cache-Control: no-store`. Identical rules retain local state across unrelated configuration updates; edited rules/removal/restart reset local state. Within a local rule all windows are checked before charging; overlapping local rules may consume an earlier rule before a later one rejects. Shared Redis checks every selected rule/window atomically before charging.

`per_client: true` keeps a separate budget for each effective client IP instead, like nginx `limit_req` keyed by address, so one client cannot spend the budget of everyone else on the same URL. The client IP is the one used for IP policy: the socket peer, or the address resolved from `X-Forwarded-For`/`Forwarded` when the peer is in `trusted_proxy_cidrs`; IPv4-mapped IPv6 counts as its IPv4 address. Local mode keeps at most `max_clients` budgets per rule (1–1048576, default65536) and drops the least recently used client first; a dropped client starts again with a full budget. The sum of `max_clients` over all per-client rules may not exceed1048576, which bounds local state to roughly200 bytes per client plus 24 bytes per window. Redis mode keeps one expiring key per client and rule under the same namespace, with the same window and TPS meaning; its size is bounded by key expiry and Redis memory, not by `max_clients`. A per-client rule is a different rule from its shared form, so switching the flag resets that rule's budgets.

Local fixed windows start when a bucket is created/reset and use monotonic time. Redis windows align to server UTC/Unix-epoch boundaries, so daily quotas reset at UTC midnight. Fixed windows can permit bursts across their boundary; they are not sliding24-hour totals. TPS remains a smooth token bucket. Existing connection/TLS/body-work limits protect work before URL admission.

## Failure bans and management

Failures count only on configured URLs after failure-observation admission. The configured statuses can include gateway policy/rate denials, auth responses or origin responses; malformed selectors rejected before observation are not counted. Default401/403 excludes transient503. The window begins at the first counted response failure; successes do not erase a streak. Threshold establishes a fixed-duration ban. Already admitted responses cannot extend a ban or recreate it after natural expiry or administrator release. Cancellation is not a failure.

`failure_ban_scope` is `url` by default. `host` expands a triggered ban to every path for that rule's hosts; empty hosts means all hosts. `global` expands an IP ban learned on any configured URL to every public/workload HTTP host/path, including images and health. The verified client IP is used; configured trusted proxies can delegate it. Separate admin sockets/listeners remain available.

The administrator menu lists active bans, filters a canonical IPv4/IPv6 address and releases that IP after confirmation. APIs are `GET /v1/security/bans?ip=...` and `POST /v1/security/bans/release` with `{"ip":"192.0.2.10"}`. Queries return at most200 records and a truncated flag; filtered search reaches matching IPs beyond the unfiltered limit. Viewers cannot read or release bans. Release removes active configured-rule failure/ban records; accepted releases can finish after caller cancellation/logout, while revoked actors cannot admit new ones. Old observations are fenced from newly admitted generations.

Each rule tracks at most1024 client records, including pending observations. Active bans are not evicted to admit a new IP; unknown-IP capacity exhaustion fails closed503. Local cancellation releases reservations. Redis abandoned reservations expire after a bounded TTL; expired selected-failure callbacks fail closed503 instead of recreating records. Up to128 rules and16 hosts/rule are allowed, with32KiB aggregate selector/policy text per list; IP allowlists cap1024 CIDRs and country lists256 codes. Invalid settings leave the active document intact.

## Shared Redis and Valkey

```json
{
  "settings": {
    "security_redis": {
      "url_env": "HANGANG_SECURITY_REDIS_URL",
      "namespace": "hangang-security"
    }
  }
}
```

Provision that environment variable in every gateway with its Redis URL and credentials. The configuration and UI contain only its reference and namespace, never the URL/password. Default connections require verified `rediss://` TLS or loopback plaintext. An operator-approved private-network plaintext server requires explicit `allow_insecure_remote: true`; `#insecure` and Unix URLs are rejected. This backend uses public TLS roots; the config-store backend's custom CA option does not implicitly apply here.

All nodes must use the same Redis endpoint/database, namespace and canonical rules. Lua uses Redis TIME and atomic multi-rule counters; random record epochs prevent stale callbacks after release/recreation. Stable configuration hashes preserve Redis state across gateway restarts and unrelated publication. The key hash tag groups script keys; connection management targets a standalone Redis/Valkey or compatible proxy, not native Redis Cluster discovery.

Reserve the security namespace against eviction and other application writes. Use appropriate persistence/replication for restart retention: loss/eviction of Redis data loses budgets and bans. Operation deadlines are1 second, with64 concurrent commands. An outage fails selected admission closed503, without local fallback; nonselected URLs remain unaffected unless host/global ban scope explicitly requires shared checks. Administrator recovery is independent, but shared lookup/release needs the backend. The UI identifies local versus shared state. Without Redis, each node has its own budget and must not be treated as a fleet-wide ceiling.

### Redis outage behaviour

When the shared backend is stopped, unreachable or slower than its 1-second deadline, hangang does not fall back to local counters. The table shows what a public request receives; the unit test `stopped_backend_fails_every_shared_check_closed_without_local_fallback` in `src/security_redis.rs` checks it.

| Control | Requests the rule selects | Other requests |
|---|---|---|
| Rate limit (`path_rate_limits`) | `503` | pass, Redis is not contacted |
| Failure ban check, scope `url` | `503` | pass |
| Failure ban check, scope `host` | `503` for every path on the rule's hosts | pass on other hosts |
| Failure ban check, scope `global` | `503` for every public/workload HTTP request | none (all requests are selected) |
| Failure observation (response recording) | response replaced by `503` | not recorded |
| Admin ban list / release | API error `503` | not applicable |
| No rules configured | pass, Redis is not contacted | pass |

Mitigation: there is no local fallback by design, because a per-node fallback would silently multiply fleet-wide budgets and forget bans. Operate Redis with replication or a supervised restart, keep `global` scope only where a shared outage may block all traffic, and remove `security_redis` from the published settings to return to per-node local state if Redis cannot be restored quickly. URL blocks, IP/country allowlists and admin sockets do not use Redis and keep working.

## Private security logs

Structured private events include path/allowlist denial, rate rejection, selected failures, ban creation/rejection, backend failure and administrator release. They carry verified client IP and status; newly created bans include the configured path. Raw request URLs, query strings, bodies, passwords and tokens are not logged by this feature. Public responses remain opaque.

Request security events are capped at10 per second per process. Administrator release events have an independent10-per-second budget, so public attack traffic cannot consume their log allowance. Accepted releases log inside their owned worker even if the caller disconnects. Suppressed counts accompany a later emitted event, preventing repeated rejected requests from producing unlimited security logs. Existing traffic/access logging has separate policy and retention controls.

Log output runs on one dedicated worker with bounded queues (224 request events and32 reserved administrator events). Request processing never waits for a blocked log sink; queue overflow is counted as suppression.

## Browser origin restrictions

Configure `settings.path_csrf` on selected processing URLs to block browser
requests from untrusted origins before authentication, cache or origin work:

```json
{
  "path_csrf": [
    {
      "path": "/api/login",
      "hosts": ["app.local.example.net"],
      "allow_origins": ["https://console.local.example.net"],
      "allow_same_origin": true,
      "allow_missing_origin": false,
      "methods": ["POST", "PUT", "PATCH", "DELETE"]
    }
  ]
}
```

The default methods are POST, PUT, PATCH and DELETE. Other methods and URLs,
including ordinary image GETs, are unaffected unless explicitly selected. Include
GET when an application changes state through GET. Rules match exact normalized
paths, including the optional trailing-slash alias; descendants require
`include_subpaths: true`. Overlapping rules must all permit the request.

An allowed origin is an exact HTTP(S) scheme, host and effective port, with no
credentials, path, query, fragment or wildcard. Host case and default ports are
normalized. `allow_same_origin` defaults to true and uses the verified gateway
request scheme/authority; untrusted forwarded headers cannot alter it. A sibling
subdomain is a different origin even when the browser calls it same-site.

A missing Origin uses the origin portion of Referer. Missing both headers is
denied by default; explicitly enable `allow_missing_origin` only for a selected
endpoint that needs clients without browser metadata. Origin `null` is denied
and never falls back to Referer. Duplicate or malformed Origin/Referer values
return opaque400; disallowed or missing origins return opaque403. Decisions are
private sampled security events, without origin/referrer/query values. Configured
failure-ban rules can count those responses. Browser origin restrictions supplement
normal authentication; non-browser callers can supply their own Origin header.

Each rule supports at most16 host patterns,128 allowed origins and8 unique standard
methods (CONNECT is excluded). There are at most128 rules and32 KiB combined
selector/origin text. The admin status exposes only the configured rule count.
