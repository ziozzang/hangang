# Country admission

HTTP and TCP routes can use the optional `country_policy` with an operator-provided offline country database. See [the example](../examples/country-policy.json). Country is approximate address metadata, not identity, nationality or proof of a user's location. `Accept-Language` filtering is a separate [language policy](LANGUAGE_POLICY.md).

`geoip_database.file` names an absolute normalized UTF-8 path on **each node**. Provision a current GeoIP2-Country or GeoLite2-Country MMDB using its IPv6 database format, which also supports IPv4. Hangang does not download a licensed database or distribute its bytes through configuration. Publish file updates using an atomic rename. Configuration accepts a structurally valid source even when the file is unavailable; `--check` does not certify node readiness.

| Source setting | Default | Allowed range |
| --- | --- | --- |
| `max_file_bytes` | 33554432 | 1–67108864 |
| `max_age_days` | 14 | 1–90 |
| `reload_interval_seconds` | 30 | 1–3600 |

Requests perform no database file or network I/O. The process serializes full file reading and MMDB structural verification on a blocking worker; the file-size limit does not bound total verifier memory. An unchanged source reuses its live slot across configuration publications. A changed source starts pending and can open only after verification following publication. Invalid, unavailable or expired replacements clear admission availability. Cancellation drains the current verifier before the dispatcher starts another source.

Structural MMDB verification does not validate every country record. Lookup reads `country.iso_code`, without falling back to `registered_country`, and rejects malformed values. Expiry uses wall and monotonic clocks. A live slot remembers expired build times so clock rollback followed by reload cannot revive the same or older build. That in-memory floor does not survive replacing the source configuration or restarting the process.

`country_policy` has `allow`, `deny`, required `on_unknown` (`allow` or `deny`), and `enforce` (default `true`). Lists contain uppercase two-letter country codes, at least one and at most 256 combined. Duplicates within a list are rejected; a code may occur in both lists, with denial taking precedence. A nonempty allowlist requires `on_unknown: "deny"`. Disabled policies retain structural validation but skip country admission. Enforced policies require a source configuration.

| Lookup outcome | HTTP | TCP |
| --- | --- | --- |
| Known country denied by policy | 403 | Close before upstream connection |
| Unknown/private address | Explicit `on_unknown` decision | Explicit `on_unknown` decision |
| Missing, pending, invalid or stale DB; malformed record | 503 | Close before upstream connection |

HTTP uses the existing trusted-proxy effective client address; untrusted forwarding headers cannot select another country. TCP uses the accepted canonical socket peer and applies policy after SNI route selection. IPv4-mapped IPv6 canonicalizes to IPv4. IPv6 socket reachability still depends on listener and host/container network configuration.

Country filtering acts on the selected route, without falling through to a lower-priority route on denial. HTTP checks run before cache, Lua and upstream processing, but after workload authentication and required HTTPS redirects. Enforced HTTP country routes bypass response caching. Routes sharing a protected `resource_id` must use equal country policies; use the protected resource boundary when namespace shadowing must be prevented. Admission uses one database generation; later updates do not retroactively revoke admitted requests or established streams.

Administrator APIs are `GET /v1/geoip/status` and `GET /v1/geoip/lookup?ip=...`. Status is per instance, with readiness, path-free error and generation metadata. Lookup requires exactly one IPv4/IPv6 address and returns a canonical IP and country or `null`. Unavailable lookup returns 503. Responses are not cacheable and authorization is rechecked after reading. Consult the [OpenAPI document](openapi.json) for the full wire format.

The EN/KO console provides source and route-policy controls plus local status refresh and IP lookup. Changing a draft is separate from the displayed runtime observation; other nodes may differ.

## Request observations and Lua

With a configured source, selected HTTP and TCP routes capture country metadata after IP admission, even when no country policy is enforced. Passive lookup failure does not reject traffic. An enforced country policy still rejects unavailable lookups before Lua, cache or upstream processing.

`hangang.geoip()` is available in route Lua and request/response body transforms. It returns immutable fields `state`, `country`, `generation_sha256` and `error_code`. Missing values are Lua `nil`. A request captures one observation: every NDJSON/SSE transform record uses that same value, even if the database changes during the stream. The observation contains no database handle or filesystem path. See the [Lua and NDJSON example](../examples/geoip-observation.json).

| State | Meaning |
| --- | --- |
| `not_checked` | Processing stopped before country observation, or no observation was supplied |
| `not_configured` | No country source was configured |
| `known` | Uppercase two-letter country and generation digest are available |
| `unknown` | Lookup succeeded without a country; generation digest is available |
| `unavailable` | Lookup could not complete; a bounded error code explains why |

A script cannot mutate this userdata or override native admission. Country remains address metadata and must not be treated as authenticated identity.

## Live traffic and metrics

HTTP traffic-ring records include `geoip` with the observation above; the live EN/KO console displays country/state and supports filtering. These are HTTP response-head records, not packet capture. TCP connections have a separate bounded [active/recent history](TCP_CONNECTION_HISTORY.md). Existing ring capacity and retention limits apply. Batch timestamps cover every returned record even after a wall-clock rollback.

Prometheus exports `hangang_geoip_lookups_total{protocol,result}`, `hangang_geoip_country_requests_total{protocol,country}` and `hangang_geoip_admission_total{protocol,decision}`. Protocol is `http` or `tcp`. Country labels are bounded to 676 uppercase two-letter combinations plus `unknown`; IPs, route IDs and database digests never become labels. Unavailable lookups have no country count. Admission counters describe enforced native country decisions only; passive observations count lookups but not native decisions. Earlier authorization or IP rejection does not count as a country lookup.

Status and its event stream include `geoip_metrics` with HTTP/TCP totals and bounded country maps. Concurrent atomic reads are approximate rather than a transactional snapshot; totals need not match exactly during traffic. The console shows these counters and the leading countries.

Country lookup and language policies do not establish workload-level performance characteristics. TCP history is a separate feature with its own bounds.
