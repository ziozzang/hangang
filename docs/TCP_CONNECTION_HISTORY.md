# Live TCP connection history

[Documentation](README.md) · [한국어 안내](README.ko.md)

Hangang maintains bounded, process-local active and recent metadata for raw TCP connections. This is separate from the HTTP [response-head traffic ring](TRAFFIC_HISTORY.md). Workload HTTP listeners do not create duplicate raw TCP records. Accept syscall errors have no connection peer and remain aggregate errors; a raw connection whose socket setup fails records `io_error` when tracking capacity is available.

## Capacity and lifetime

The active inventory tracks at most 4096 connections. Additional connections retain their normal traffic admission behavior but are omitted from this inventory. `active_untracked` reports currently omitted connections and `omitted_total` counts omissions. Completion of an untracked connection does not create a recent row. The active inventory is therefore not a complete count of all connected clients; the existing connection metric also includes pre-forwarding admission stages.

Recent history retains at most 4096 completed tracked connections for at most 60 seconds. Capacity pressure may evict entries sooner. `dropped_total` and cursor gaps expose this loss. Neither inventory is durable or an audit archive. The tracking limits are fixed operational limits, separate from the server connection admission limit.

An active connection owns only a small guard into the bounded inventory. Stored metadata does not retain sockets, configuration snapshots, country databases, TLS generations, credentials, raw SNI, payloads, arbitrary errors or resolved upstream addresses. Route/member identifiers and country observations are bounded copies. Existing connections retain their selected route and admission country across configuration and database replacement.

## State, outcomes and bytes

Phases are `accepted`, `inspecting`, `authenticating`, `dialing` and `forwarding`. Being active does not imply an established upstream stream. Recent rows distinguish `eof`, `idle_timeout`, `shutdown`, `identity_revoked`, `interrupted`, and bounded admission/dial/I/O failure codes; see OpenAPI for the full enum. Cancellation or unwinding without a more specific outcome is `interrupted`, not a successful EOF.

`bytes_upstream` and `bytes_downstream` count bytes accepted by successful writes to each destination at the proxy's application I/O boundary. They preserve partial progress when a later write fails or a future is cancelled. Read-ahead bytes that were never written do not count. A buffered passthrough ClientHello counts exactly once when forwarded. TLS handshakes and ciphertext overhead are excluded; an accepted application write does not prove remote application receipt.

Elapsed and total durations use a monotonic clock. Wall-clock timestamps remain display metadata and cannot establish a globally ordered audit trail. Batch wall time covers its returned records after clock rollback.

## Administrator API and live console

- `GET /v1/connections/tcp/active?after=0&limit=128` pages active connections in accept-ID order.
- `GET /v1/connections/tcp/recent?after=0&limit=128` pages recent completions in completion-event order. Omitting `after` returns the newest retained page.
- `/v1/events` sends a bounded `tcp_connections` event each authorized administrator tick, containing `active` (first page) and `recent` (stream cursor). Empty snapshots clear finished connections and omitted-active counts.

Both APIs require administrator authority, recheck it after reading, and prohibit caching. Event streams recheck authority each tick; an administrator session demoted to viewer receives `auth_expired` and closes at the next check, so the console clears privileged rows. Frames already authorized and buffered cannot be recalled. Cursors must be canonical unsigned decimal u64 strings and limits are 1–128. Unknown or repeated query keys are rejected. Connection IDs, completion event IDs, byte counters and cumulative omission/eviction counters serialize as decimal strings so JavaScript does not lose precision. Active tracked/untracked counts and capacities are bounded numeric values.

Every batch has a random per-process `process_id`. Cursors cannot be reused across process replacement. A connection's accept ID and its completion event ID are distinct: old connections may close after newer ones. Recent cursors follow completion order so polling does not miss those late completions. Active pages are best-effort observations, not one frozen inventory across requests.

The English/Korean console provides separate active/recent tables, phase/outcome/country filtering, bounded paging, bytes/durations, and omission/gap/stale indicators. Pausing freezes presentation while retained recent rows still expire locally. Logout and authority loss clear the records. The HTTP and TCP history APIs expose sensitive operational metadata and are not available to viewers.
