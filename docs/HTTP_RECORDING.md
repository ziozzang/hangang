# Selective HTTP response-head recording

[Documentation](README.md) · [한국어 안내](README.ko.md)

`settings.http_recording` controls the HTTP history ring and, when enabled by `--access-log`, the `hangang::access` tracing event. It is part of the revisioned configuration document, so existing configuration publication, persistence and conflict handling apply. The administrator Settings view provides an English/Korean editor; the same document is available through `GET`/`PUT /v1/config`. The viewer-readable status/SSE settings summary omits these rules.

```json
{
  "settings": {
    "http_recording": {
      "default_action": "record",
      "rules": [
        {
          "id": "retain-errors",
          "action": "record",
          "match": {"status_ranges": [{"min": 400, "max": 599}]}
        },
        {
          "id": "omit-routine-polling",
          "action": "drop",
          "match": {"methods": ["GET"], "path_prefixes": ["/poll/"]}
        }
      ]
    }
  }
}
```

The first matching rule decides; unmatched events use `default_action`. Absent/null policy and an empty default policy record everything in the covered outputs. Fields within a rule use AND, values in a condition array use OR, and empty/omitted arrays are unrestricted. An empty `match` is an explicit catch-all. A `record` rule is useful before broader `drop` rules or with a default-drop policy.

Conditions cover case-sensitive HTTP `methods`, exact `route_ids`, optional `route_matched`, inclusive `status_ranges`, literal `path_prefixes`, `peer_cidrs` and `client_cidrs`. A prefix is not a route path-segment matcher: `/api` also matches `/apiX`. The path is the incoming URI path, before Lua or upstream path rewriting. There is no implicit URL decoding or query matching. `route_matched: false` cannot be combined with a nonempty route-ID list.

Policies are bounded to 64 rules, 64 values per condition array and 65,536 canonical JSON bytes. Rule IDs must be unique ASCII identifiers of 1–64 letters, digits, dots, underscores or hyphens. Route IDs and path prefixes are bounded; methods must be valid HTTP tokens and status ranges must lie within 100–599. Invalid policies are rejected before publication. Refer to the OpenAPI schemas for field bounds.

## Decision boundary and identity

After a response head is produced, the proxy captures the currently published recording policy and configuration revision once, then shares that decision between the two enabled outputs. A request waiting on upstream headers can therefore use a newer recording policy than its routing snapshot. Its observed route and client identity stay as selected during request handling; changing the recording policy does not reroute or reauthenticate it.

The actual canonical socket peer and effective client are separate condition inputs. Forwarding headers contribute to the effective client only after existing trusted-proxy processing. Rejections that occur before that processing use the socket peer as the effective client. A forged forwarding header from an untrusted peer cannot match a client rule as the claimed address.

Capacity rejections participate in both enabled outputs. The dedicated health-path shortcut remains excluded. A retained event describes response headers, not body delivery, SSE completion or WebSocket tunnel termination. Recording decisions do not change forwarding, authorization, response status, cache behavior or aggregate request metrics.

## History and tracing

Retained HTTP history rows carry `policy_revision`, the configuration revision used for the recording decision. `filtered_total` counts intentional history omissions for this process lifetime. It is independent of age/capacity eviction (`dropped_total`); a filtered event consumes neither a ring slot nor a history ID. Policy changes do not reset the counter or retrospectively delete earlier rows. SSE sends empty traffic batches too, allowing drop-only intervals and eviction counts to remain visible.

The CLI access trace now uses bounded query-free path and method metadata and omits the raw Host header. This intentionally changes the older access-log field set, which included query strings and Host. The policy does not suppress other diagnostic tracing. Applications must still avoid placing secrets in path segments. Neither output records payloads, cookies or authorization headers.

The ring remains bounded to 4,096 rows and 60 seconds; it is not durable or complete audit evidence. Counters and history reset on process restart. Browser displays reject unsafe JSON integer values rather than presenting rounded counts as exact. External log collection, rotation and durable delivery need separate configuration and qualification.

TCP active/recent history and durable account auditing have separate recording boundaries. This HTTP policy cannot remove account policy-change records, configuration recovery journals or SQL recovery evidence. [TCP recording](TCP_RECENT_RECORDING.md) and the [account audit policy](ACCOUNT_AUDIT_FILTERS.md) describe those separate scopes.
