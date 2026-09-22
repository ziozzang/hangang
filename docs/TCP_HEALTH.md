# TCP transport health

TCP routes may configure an optional `health` policy:

```json
{
  "id": "tcp-service",
  "listen": "127.0.0.1:18000",
  "backends": ["127.0.0.1:19001", "127.0.0.1:19002"],
  "health": {
    "interval_ms": 1000,
    "timeout_ms": 500,
    "healthy_successes": 2,
    "unhealthy_failures": 2,
    "initial_state": "checking"
  }
}
```

Without this policy, existing round-robin selection is unchanged. With a
policy, periodic transport probes decide which members may receive new
connections. Selection checks at most the configured backend count, skips
excluded members, and closes new downstream connections when all are excluded.
There is no retry after client bytes have been forwarded. Existing streams are
not terminated when a member becomes unhealthy or its route is disabled.

A successful probe completes the same outbound connection path as traffic:
configured DNS, connect-address or Unix-socket override, SOCKS5 negotiation and
optional upstream TLS handshake. The entire probe has one deadline. It sends
no application bytes. A successful TCP connection is **not** evidence that an
application protocol, database query, HTTP request or inner passthrough TLS
session works. SNI passthrough reads the client's ClientHello to select a route,
but does not forward those buffered bytes before health admission.

`initial_state` is `healthy` (default, omitted on serialization) or `checking`.
The latter requires `healthy_successes` consecutive successful probes before
initial admission. Failures reset successes; successes reset failures. Later
failure thresholds exclude a member, and the success threshold permits recovery.
An absent/null health policy is unmonitored, not proven healthy.

Bounds: interval 100–300,000 ms, timeout 100–60,000 ms and no greater than the
interval, and each threshold 1–100. Configurations may declare at most 1,024
actively probed HTTP and TCP backends combined. One TCP monitor replaces and
joins its old probe tasks before starting a new snapshot generation; it stops
with the TCP manager. HTTP and TCP monitor handoffs are independently scheduled.

## Reload and discovery

Legacy string routes retain health only with the same route ID, ordered backend
list, health policy, configured upstream transport, prepared custom CA trust,
and enabled state. Serving object routes also retain compatible health by exact
member ID and address across reorder and weight changes. A changed endpoint,
health policy, transport, CA trust, or enabled state starts fresh state;
unrelated updates preserve progress. Delayed results retain their original
state and cannot qualify a replacement snapshot. This is state mapping, not a
published per-member drain/maintenance lifecycle.

Docker resolution supplies a private monotonically changing endpoint epoch.
Identical refreshes retain the epoch; address changes, managed-daemon changes,
container identity/restart changes, and removal/reappearance replace it. A
checking member must qualify the new epoch. Stale callbacks cannot overwrite a
newer epoch. The selected epoch and health are checked again after the outbound
dial, immediately before sending any downstream bytes. This defines admission;
Docker lifecycle changes are not atomic with network I/O or established streams.

Inspect identity is derived from Docker `Id` and `State.StartedAt`, and is not
included in the public resolution response. If this metadata is missing, each
refresh receives a fresh epoch rather than assuming the process is unchanged.
Frequent identity-less refreshes can therefore prevent checking qualification.
Changes behind a static DNS hostname do not currently have equivalent endpoint
epochs. On the next snapshot preparation/publication, changed custom CA
certificate contents at the same path reset health using a fingerprint of the
exact trust loaded into the TLS verifier. A CA file edit alone does not trigger
snapshot publication; existing streams retain their admitted transport.

## UI, API and validation

The TCP route editor exposes all health fields in English and Korean, with
native/advanced-JSON synchronization. Operations reports `member_id` for named
members, `active_tcp`, probe observation, initial-check pending state and
recorded eligibility. TCP `active_requests` remains `null`, not zero. Named
members separately expose numeric `member_active_streams`: an instance-local
count of established streams by continuously present route ID/member ID. It
includes old-endpoint streams after endpoint, health or enablement changes,
excludes pending dials, and starts fresh after rename or removal and re-add.
A removed ID has no Operations row. This is not drain completion or a
retired-endpoint breakdown; see [TCP member activity](TCP_MEMBER_ACTIVITY.md).
These are instance-local observations, not a fleet-wide or application-health
claim. Only local-file-authority object members in `serving` state are allowed;
shared ConfigStore publication and `draining`/`maintenance` are rejected.
The existing route/config APIs validate the same schema; see `docs/openapi.json`.

`tests/tcp_health.rs` covers real listener admission, refused members, all-down
recovery, stream preservation, SNI buffering, connect-address overrides, TLS
handshake gating and delayed results. `tests/tcp_health_smoke.py` starts an owned
real gateway, checks concurrent pending connections and tagged echoes, and saves
a policy through the actual embedded browser UI. It is not a throughput benchmark.
