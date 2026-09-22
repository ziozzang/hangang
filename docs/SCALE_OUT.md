# Scale-out operation

[Documentation](README.md) · [한국어](ko/SCALE_OUT.md)

Several instances can serve the same routes behind an external load balancer when they share one
configuration store (`--database sqlite:…` on one host, PostgreSQL, or Redis). This page states what
the fleet guarantees, what stays local to each instance, and how to operate it. Wording below uses
"authority" for the shared store and "instance" for one server process.

## Consistency model

- **The authority arbitrates writes.** An API write validates and prepares resources locally, then
  performs a compare-and-swap (CAS) against the authority. The CAS succeeds only when the durable state
  is exactly `(epoch, expected revision)`. Concurrent stale writers receive 409.
- **Followers converge asynchronously.** Every instance polls the authority every 500 ms and activates
  a newer revision after preparing it locally. 500 ms is the poll interval, not a convergence bound:
  store latency and preparation time add to it, and intermediate revisions can be skipped. In-flight
  HTTP requests keep the snapshot they started with; established TCP sessions keep their route.
- **Authority epoch.** The first bootstrap of an empty store creates a random epoch that never changes
  on CAS. A store that is wiped and bootstrapped again, or restored from a backup taken under a
  different bootstrap, carries a different epoch. Instances that were attached to the old epoch withdraw
  readiness immediately with the reason `authority changed` and do not adopt the new history until they
  are restarted; writes from them are rejected by the CAS. Revision numbers alone are never trusted to
  identify a history.
- **Idempotent CAS.** A write whose acknowledgement was lost (connection drop after commit) is retried
  once on PostgreSQL; the store recognises its own committed document at `expected + 1` and reports
  success instead of a false conflict. After an unacknowledged attempt PostgreSQL reports success only
  for `(epoch, expected + 1, our document)` and **indeterminate** (HTTP 500 "Indeterminate Outcome")
  for every other durable state and for a failed re-read — `(epoch, expected)` and another document at
  `expected + 1` included, because a backup restored under the same epoch can bring those back after
  the write committed (the history within an epoch is not monotonic across restores). Redis never
  re-sends a command; a lost acknowledgement there is reported as indeterminate and the operator's
  retry is what the idempotent CAS makes safe. On an indeterminate outcome reload the current revision
  before deciding whether to retry.
- **Preconditions are judged on a fresh base.** An `If-Match` that is ahead of the instance's local
  revision (read from another instance a moment ago) triggers a reconciliation with the authority
  before the write is judged, so read-then-write through a load balancer does not fail spuriously; a
  conflict also reconciles the losing instance so its next read is current.

## Readiness policy

`GET /healthz` on the administration listener (and `--health-path` on the public listener) answers
200 only when the instance is ready. Readiness reflects *"this instance's snapshot is known to agree with the authority"*:

| Observation on a poll | Effect |
|---|---|
| Agreement (same revision and document) or successful activation of a newer revision | ready |
| Store unreachable / timed out / unreadable | **tolerated** for `--store-grace-seconds` (default 30) since the last confirmation, then unready. Serving continues on the last good snapshot either way. |
| Store empty (`missing`) | same grace window, then unready |
| Older revision than active (`rollback`), same revision with a different document (`divergence`), different epoch (`authority changed`) | unready immediately |
| Newer revision that this instance cannot prepare (missing certificate file, unbindable TCP address, …) | unready immediately; the writer's instance stays ready |
| Newer revision while activation is frozen for a handoff (`stale`) | unready immediately |
| Grace window ends while a poll is still pending (`stalled`) | unready at the deadline, independent of the poll |

The grace window keeps a brief store incident from withdrawing the whole fleet at once, and it removes
readiness flapping at poll granularity. Set `--store-grace-seconds 0` to withdraw on the first failed
poll (strict mode). After withdrawal, readiness returns on the first confirming poll.

`GET /v1/status` reports the reason: `store.ready`, `store.reason`, `store.last_confirmed_seconds_ago`,
`store.epoch`, `store.grace_seconds`, plus `instance.id` (random per process) and
`instance.config_digest` so that instances behind one address can be told apart.

## Operational rules

- **Provision host-local material before writing the configuration.** Certificate paths, upstream CA
  files, Lua scripts and Docker service references in the shared document are resolved on every
  instance. A write that references a file present only on the writing host succeeds there and makes
  every other instance unready. Distribute files first (identical bytes; the digest is exposed in
  status), then write. Certificate rotation by file replacement is likewise per host.
- **Intentional rollback of the store** (restore from backup): running instances stay unready until
  restarted, by design. Restart them after the restore.
- **Seeds must be identical.** When several instances start against an empty store they race to
  bootstrap; the winner's seed becomes the authority and the others adopt it. Use one seed file. A
  bootstrap whose insert was not acknowledged reports **indeterminate** unless the read that follows
  finds a document — an empty or unreadable store afterwards does not prove that the seed never became
  the authority; startup fails with that message and the operator should read the store before seeding
  again. Before
  seeding, every TCP listen address of the seed is bound together with the process's own listeners and
  released again, so a seed that collides with itself or with the public/admin/ACME ports is never
  persisted.
  `--no-bootstrap` refuses to seed an empty store and fails startup instead, which is recommended for
  established deployments so that an accidentally emptied store cannot be re-seeded by a restart.
- **Redis** must run with `maxmemory-policy noeviction` for the configuration key; an evicted key is
  reported as `missing` and withdraws the fleet after the grace window.
- **A shared SQLite file** coordinates instances on one host only. Equal paths on different hosts are
  different stores.
- **Rolling upgrades.** The configuration schema rejects unknown fields. Upgrade every instance's
  executable before using a configuration field introduced by the new version; rolling the executable
  back does not roll back the shared document.

## Shutdown and replacement

On `SIGTERM`/`SIGINT` an instance first withdraws readiness (health returns 503) while still accepting
connections for `--lame-duck-seconds` (default 0), then stops accepting and drains for
`--drain-seconds`. Set the lame-duck window to at least one load-balancer probe interval plus its
failure threshold so that no connection is routed to a closed listener. Kubernetes manifests in
`deploy/` set it together with the readiness probe. Under `--supervised` the supervisor drives the same
two phases for the serving generation (a `Withdraw` control, the lame-duck wait, then `Drain`) and its
kill deadline covers both, so the window is never truncated.

Under `--supervised`, the replacement generation inherits the listening sockets together with the
authority epoch its predecessor followed, starts unready, and opens its TCP accept gate only after it
has confirmed its snapshot against the authority (bounded wait, 10 s). Freezing writes for the handoff
does not withdraw readiness, but the frozen generation keeps checking agreement: if the authority moves
while it cannot activate, it withdraws with reason `stale` (the successor activates the new revision).
A generation retired after a successful handoff closes its accept loops at once and drains without
withdrawing readiness, so probes on connections it still owns keep answering for the healthy endpoint.

## What stays per instance

| State | Fleet behaviour |
|---|---|
| Passive backend health (failure quarantine) | Each instance observes failures independently. Quarantine and least-connections counters survive configuration updates that do not change a route's backends or balancing policy. |
| Least-connections | Local count of this instance's streams, not backend-wide load. |
| Route admission limits (`max_requests`, `max_connections`) | Per instance. A fleet of N admits N × limit. Enforce hard aggregate caps at the upstream. |
| Session affinity | None built in. Backends that need affinity must share session state. |
| Response cache | Storage is per instance. Purging is fleet-wide in shared-store mode: `POST /v1/cache/purge` raises `cache.generation` through a CAS and every instance drops its entries when it activates that revision (adoption happens at activation, never during a write that may still fail; the generation is monotonic and preserved through document rollbacks). In file mode purge is local. Response header rules from the current document apply to cache hits as well. |
| Metrics | Per instance; scrape each address. |
| Docker service discovery | Resolved against the local daemon. Identical references can resolve to different containers on different hosts. |

## ACME with several instances

HTTP-01 validation is routed by the load balancer to any instance. In shared-store mode challenge
tokens are published to the store before the challenge is marked ready (acknowledged, bounded
retries; an unpublishable token aborts that authorization rather than gambling on which instance the
CA reaches) and refreshed for as long as the order runs, so every instance can answer for an issuance
started elsewhere — which also means HTTP-01 issuance depends on the store while it is down; a local miss costs one bounded store lookup (2 s, at most 8 in flight, otherwise
404), so the unauthenticated challenge path cannot amplify traffic into the store. Issuance itself is
serialised by an account lock that is effective only on a shared filesystem; with separate state
volumes run ACME on one designated instance and distribute the bundle, or use DNS-01. Followers
re-read a replaced bundle file every 5 s. Until the first certificate exists, HTTPS handshakes fail
although configuration readiness may already be true; `acme.tls_available`, `acme.bundle_digest` and
`acme.phase` in status show it. See [ACME](ACME.md), section "Multiple instances".

## Kubernetes controller replicas

See [Kubernetes](KUBERNETES.md): hostname ownership is decided from API-server facts (oldest Ingress
wins), readiness expires when the API has been unreachable for `--kubernetes-stale-seconds`, status
addresses are merged rather than replaced, and relists are spaced and jittered per replica.
