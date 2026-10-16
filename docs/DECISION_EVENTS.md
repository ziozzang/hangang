# Decision events and the decision exporter

[Documentation](README.md) · [한국어](ko/DECISION_EVENTS.md)

Decision events are bounded, pseudonymous records of enforced access decisions
for protected HTTP requests. Each event ties together the network stage
(Sumunjang), the identity stage (Hopae or a gateway-local authenticator), the
authorization stage (Pumgye) and Hangang's own enforcement, with stable reason
codes and the revision of every authority consulted. They feed the management
console's decision log and request detail. This guide implements phase D1 of
ADR 0019 (`hangang.decision.v1`).

Decision events are **off by default**. Without `--decision-events-config`, no
emitter exists, nothing is captured or allocated, and the decision APIs report
the log as disabled.

Decision events are not an access log. They never contain headers, cookies,
bodies, query strings, raw request paths, credentials, receipts, permits,
provider tokens, e-mail addresses or display names.

## Prerequisites and configuration

Decision events need three things:

1. The independent exporter process, `hangang-decision-exporter`, with its
   local store.
2. A key file that holds the pseudonymization epoch keys. All Hangang replicas
   of one deployment read the same file so that pseudonyms correlate across
   nodes. Exactly one owner manages it.
3. A decision events configuration file passed to Hangang with
   `--decision-events-config` (environment `HANGANG_DECISION_EVENTS_CONFIG`).

Configuration fragment:

```json
{
  "profile": "standard",
  "instance": "gw-a",
  "exporter_socket": "/run/hangang/decision-ingest.sock",
  "query_socket": "/run/hangang/decision-query.sock",
  "key_file": "/var/lib/hangang/decision-keys.json",
  "manage_keys": true,
  "key_rotation_hours": 24,
  "key_retention_hours": 192,
  "allow_sample_percent": 1.0,
  "audit_all_classes": ["restricted"],
  "routes": {"admin-api": {"audit_all": true}, "static": {"allow_sample_percent": 0}},
  "deny_bucket": {"burst": 20, "refill_per_second": 1.0, "window_seconds": 60},
  "rings": {"deny_slots": 8192, "allow_slots": 4096},
  "batch": {"max_events": 512, "interval_ms": 250},
  "bucket_slots": 4096
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `profile` | required | `off`, `strict` or `standard` (see privacy profiles) |
| `instance` | empty | Emitter instance label, an identifier of at most 64 characters |
| `exporter_socket` | required unless `off` | Exporter ingest Unix socket |
| `query_socket` | none | Exporter query Unix socket used by the decision APIs |
| `key_file` | required unless `off` | Epoch key file (secret reference, mode 0600) |
| `manage_keys` | `false` | This node creates and destroys epoch keys; set on exactly one node |
| `key_rotation_hours` | `24` | Epoch length, 1 to 720 hours |
| `key_retention_hours` | `192` | A key is destroyed this long after its epoch ends; set it to the store retention plus one epoch |
| `allow_sample_percent` | `1.0` | Head sampling of allowed decisions, 0 to 100 |
| `audit_all_classes` | `["restricted"]` | Pumgye information classes whose routes keep every allowed decision |
| `routes` | none | Per-route `allow_sample_percent` or `audit_all` by route ID |
| `deny_bucket` | 20 / 1.0 / 60 | Per-(route, client prefix) token bucket for refusals and its summary window |
| `rings` | 8192 / 4096 | Slots per shard for refusals and for allowed decisions; `shards` defaults to the CPU count |
| `batch` | 512 / 250 | Drain batch size (at most 512) and interval in milliseconds |
| `bucket_slots` | `4096` | Fixed size of the token bucket table |

Start the exporter before or after Hangang; neither waits for the other:

```sh
hangang-decision-exporter \
  --ingest-socket /run/hangang/decision-ingest.sock \
  --query-socket /run/hangang/decision-query.sock \
  --store /var/lib/hangang/decisions.db \
  --max-store-mib 2048 --retention-hours 168
```

The exporter defaults are a 2 GiB store and 7 days of retention; the hard
maximum retention is 90 days. Both sockets are created with mode `0600` (use
`--socket-mode 660` for a shared group). The exporter holds no policy
credential and no pseudonymization key.

## Behavior

### What is recorded

An event is produced for a request that reached a protected route (external
authentication, JWT, Basic, workload mTLS, an enforced resource policy, a native
resource binding or `access_mode: protected`), or that the gateway refused for
an access reason (Sumunjang denial, IP ban, request block, URL allowlist, rate
limit, namespace refusal). Ordinary public traffic produces no event.

| Stage | Source | Recorded |
| --- | --- | --- |
| `network` | Sumunjang admission | verdict (`allow`, `deny`, `observe`, `unavailable`), mode, policy revision, transport, latency; pseudonymous IP and prefix references, country |
| `identity` | Hopae (`hop1` or HTTP authentication) or Hangang (JWT, Basic, workload certificate) | verdict, principal kind, AAL, factor, pseudonymous subject reference, latency |
| `authorization` | Pumgye remote or compiled policy | exact `pumgye_core::Decision` variant (plus `UnknownResource`, `UnknownAction`, `Unavailable`, `NotMapped`), information class, policy revision, transport, latency |
| `enforcement` | Hangang | `refused`, `challenged`, `forwarded` or `redirected`, fence, Hangang configuration revision, upstream status class |

The route block carries the route ID, listener, configured host, configured
path prefix as the path template, the method, and the Pumgye service, resource
and action. When Sumunjang is not configured the network stage carries only the
client references. Stages that were not reached are omitted; the deciding stage
and reason explain why. The `revisions` vector lists only the authorities that
were consulted.

Reason codes are namespaced (`sumunjang.*`, `hopae.*`, `pumgye.*`,
`hangang.*`) and registered with English and Korean messages in the
`hangang-decision-event` crate. Contract tests require every code that Hangang
emits and every Pumgye decision variant to be registered.

### Sampling and flood bounds

Head sampling is deterministic on the Hangang request ID.

| Class | Kept | Bound |
| --- | --- | --- |
| Deny, challenge, error, unavailable | 100% | Token bucket per (route, /24 IPv4 or /48 IPv6 prefix); refusals beyond it are counted and summarized as one `hangang.suppressed` event per window with the count and first/last time |
| Allow | `allow_sample_percent` (1%) | Per-route override; `audit_all` routes and routes whose Pumgye gate uses an `audit_all_classes` class keep 100% (`audit` class) |

Every kept event records its sampling class and rate, so the console labels
allow counts as estimates. Prometheus counters remain the authoritative request
counts.

### Request path, rings and drain

The request thread only writes fixed-size fields into a stack value. On
completion it applies sampling and the token bucket and moves the event into a
preallocated slot of a bounded ring with `try_push`. Each shard has separate
rings for refusals and for allowed decisions, so an allow flood cannot evict
refusals. A full ring increments a drop counter and returns immediately. The
request path performs no I/O, no allocation and no wait for decision events, with
the feature on or off (verified by a counting-allocator test).

A background drain task runs every `interval_ms`: it sweeps finished bucket
windows into summaries, pseudonymizes, seals and encodes each event (at most
2 KiB, validated against the schema) and writes length-delimited batches of up
to 512 events to the exporter socket with a 1 second connect and a 2 second write
timeout. Hangang has no disk spool and never retries: a batch that cannot be
written is dropped and counted (`exporter_unavailable`), and reconnection uses a
bounded backoff of up to 30 seconds.

### Privacy profiles and keys

| Profile | Events | Pseudonyms | Sealed values |
| --- | --- | --- | --- |
| `off` | none; the log is reported as disabled | — | — |
| `strict` | yes | yes | none; forward lookup only |
| `standard` | yes | yes | the opaque subject ID and client IP, sealed with the epoch key |

Pseudonyms are `HMAC-SHA-256` of a domain-separated value under the epoch key,
truncated to 80 bits and written as `ip~`, `pfx~`, `sub~` or `ses~` followed by
16 Crockford base32 characters. Sealed values use ChaCha20-Poly1305 bound to the
event ID and field. They stay in the local store and are never part of the
console projection; only their presence is shown.

Each epoch has its own random 256-bit key. The managing node creates the
current and next epoch keys ahead of time and destroys every key whose epoch
ended more than `key_retention_hours` ago, rewriting the key file atomically.
After destruction the epoch's pseudonyms can no longer be computed from a
subject or address and its sealed values can no longer be opened
(crypto-shredding). Other replicas reload the key file when it changes. An event
whose epoch key is missing is dropped and counted (`no_key`); it is never stored
unpseudonymized.

### Local store

The exporter validates every event, refuses events older than the retention or
more than 10 minutes in the future, and inserts them into SQLite (WAL mode) with
`event_id` uniqueness, so duplicate delivery is harmless. Events are kept in
hourly partitions; simulation and shadow events use a separate lane and are
excluded from traffic queries. The byte cap is checked after every batch and the
age cap every minute; both are enforced by dropping whole partitions, oldest
first, followed by incremental vacuum.

## Management API

All decision operations are administrator-only and `GET`-only on the management
listener. Viewer accounts receive `403`. With decision events off they answer
`200` with `"state": "disabled"`, which the console must show as disabled rather
than empty.

| Operation | Purpose |
| --- | --- |
| `GET /v1/observability/status` | Profile, ring capacity and queue, drop and export counters, key epoch state and store status |
| `GET /v1/observability/decisions` | Filtered, cursor-paginated decision log, newest first |
| `GET /v1/observability/decisions/facets` | Counts by outcome, stage, reason, route, service, class, country and ASN |
| `GET /v1/observability/decisions/timeseries` | Counts by outcome per time bucket |
| `GET /v1/observability/requests/{request_id}` | Every event for one request in time order |

Filters: `from` and `to` (Unix milliseconds; default the last 24 hours, at most
31 days), `limit` (1 to 200, default 50), `order` (`desc` or `asc`), `cursor`,
`kind` (`enforced` or `simulation`), `outcome`, `stage`, `reason`, `route`,
`service`, `resource`, `class`, `principal`, `asn`, `country`,
`pumgye_revision`, `bucket` (time series, 60 to 86400 seconds), and the
pseudonymous `subject_ref`, `ip_ref` and `prefix_ref`. Repeating a filter means
any of its values. Queries have a 3 second deadline.

Forward lookup: `subject`, `ip` and `prefix` accept the raw Hopae subject ID or
address. Hangang converts them into the pseudonyms of every retained key epoch
that overlaps the window and forwards only those; the raw value never reaches
the exporter and is not echoed. Destroyed epochs cannot be searched.

```sh
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9000/v1/observability/decisions?outcome=deny&subject=u_example&limit=50"
```

Each item is the JSON projection of `hangang.decision.v1`: `event_id`, `kind`,
`request_id`, `time`, `emitter`, `route`, `outcome` (with `message_key`),
`stages`, `revisions`, `sampling`, `privacy` and, for summaries, `suppressed`.
Sampled allowed decisions carry `estimate_weight`.

## Observability

`/metrics` adds, when decision events are enabled:

| Metric | Meaning |
| --- | --- |
| `hangang_decision_events_dropped_total{class,reason}` | Events lost: `ring_full` (per `deny` or `allow` ring), `exporter_unavailable`, `no_key`, `invalid` |
| `hangang_decision_events_captured_total` | Protected decisions seen |
| `hangang_decision_events_kept_total{class}` | Events placed in rings |
| `hangang_decision_events_sampled_out_total` | Allowed decisions not sampled |
| `hangang_decision_events_suppressed_total` | Refusals absorbed by the token bucket |
| `hangang_decision_events_summaries_total` | Suppressed summary events |
| `hangang_decision_events_exported_total` | Events written to the exporter |
| `hangang_decision_events_export_errors_total` | Exporter connect or write failures |
| `hangang_decision_events_queued` | Events waiting in rings |
| `hangang_decision_exporter_connected` | Exporter connection state |

The exporter serves `hangang_decision_exporter_*` counters, the store size and
the lag of the newest stored event at `/metrics` on its query socket. No metric
label contains a pseudonym, route or subject.

## Limitations and compatibility

This is phase D1. Not yet implemented:

- `POST /v1/observability/reveal`, audited unsealing and the
  `decisions:reveal` and `network:reveal-ip` permissions; access is
  administrator-only until scoped console permissions exist.
- Explain/simulation, impact analysis and operator trace sessions (phase D2).
- ClickHouse or Jangbu sinks and Kubernetes decisions (phase D3).
- mTLS transport to a remote exporter; D1 uses local Unix sockets.
- Sumunjang matched rule IDs and ASN, Hopae provider, session reference and
  state generation, Pumgye matched roles, required AAL and permit digest: the
  current wire contracts do not deliver them to Hangang, so these fields are
  empty.
- Request IDs are not yet shown on deny pages.

Per-request overhead measured by `tests/decision_overhead.rs` in an unoptimized
debug build is about 0.1 µs with decision events off and 0.3 to 1.5 µs with them
on; drain-side encoding is a background cost. The ADR 0019 budget (at most 2%
CPU and 5 µs p99 at 100k decisions per second) is a qualification target for
release builds and has not yet been measured.

## Verification and related guides

```sh
cargo test -p hangang-decision-event -p hangang-decision-exporter
cargo test -p hangang --lib decision::
cargo test -p hangang --test decision_events --test decision_admin --test decision_overhead -- --nocapture
```

- [Native hangang-guard admission](GUARD.md)
- [Pumgye authorization](PUMGYE.md)
- [Hopae gRPC gateway client](HOPAE_GRPC.md)
- [Administrator accounts](ADMIN_USERS.md)
