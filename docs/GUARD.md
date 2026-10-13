# Native hangang-guard integration

Hangang supports hangang-guard as an opt-in native request admission service.
By default each request sends an authenticated `POST /v1/decision` after Hangang
resolves the client IP using its trusted-proxy configuration, before route
security and authentication. Allow decisions still require all existing Hangang
checks. Deny decisions produce HTTP 403. Transport errors, timeouts and malformed
decisions return HTTP 503 by default; `--guard-failure-mode allow` explicitly changes this.
The existing unauthenticated health probe remains outside guard admission.
ACME requests reaching ordinary proxy admission are subject to guard decisions.

```sh
# Provide the collector credential through your service environment or secret manager.
hangang --config config.json --guard-url http://127.0.0.1:8090 \
  --guard-honeypot-path /deliberate-trap --guard-scanner-path /configured-scanner
```

The token is read from `HANGANG_GUARD_COLLECTOR_TOKEN`; change the variable name
with `--guard-token-env`. Never pass a token in command arguments or the URL.
Plain HTTP requires a literal loopback IP. Remote collectors require HTTPS.
Redirects are rejected, so credentials cannot follow them to another endpoint.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--guard-url` | absent | Enables native guard support with an origin URL |
| `--guard-source-id` | `hangang` | Collector ID, maximum 64 ASCII characters |
| `--guard-mode` | `query` | `query` for per-request decisions; `snapshot` for local admission |
| `--guard-timeout-ms` | `100` | Transport deadline, 1–5000 ms |
| `--guard-failure-mode` | `deny` | Query failures `deny` or `allow` |
| `--guard-cache-ms` | `0` | Optional query cache: zero disables; 1000–5000 ms enables |
| `--guard-honeypot-path` | empty | Repeatable exact path yielding a honeypot signal |
| `--guard-scanner-path` | empty | Repeatable exact path yielding a scanner signal |

Query requests carry only `{source_id, ip, kind?}`. No raw path, query, host,
headers, credentials or bodies are exported. A configured path supplies the typed
signal in its decision request; the service checks an existing block before
counting evidence to prevent guard rejections from reinforcing themselves.
Ordinary 403 responses do not automatically create evidence.

Caching is disabled by default. When explicitly enabled, up to 10,000 canonical
IP decisions are cached for the lesser of configured duration and response TTL,
measured from query start to avoid adding network delay to the server TTL.
The service bounds its TTL by block expiry. Signals always query the service.
A newly observed policy revision clears cached decisions; cached requests cannot
observe a new revision. Consequently a policy change may remain stale until the
short cache entry expires, at most five seconds. Use the default zero cache when
every request must obtain the current service decision.

`--guard-mode snapshot` explicitly opts into asynchronous event batches and
policy polling every two seconds. It uses an immutable local prefix index with
at most 33 IPv4 or 129 IPv6 lookups per allow/block set, normalizes mapped IPv6
clients, and gives guard allowlists precedence over guard blocks. Full snapshots
are validated before atomic publication (version, canonical unique networks,
100,000 entries per set, 4 MiB response, times and reason lengths). Failed polls
retain a valid cache; snapshot expiration fails open independently of query
failure mode. Individual expired blocks never enforce. Observe snapshots do not
block. Evidence uses a bounded queue of 4096 events and batches of at most 256;
queue overflow and failed deliveries increment counters reported through tracing.

Snapshot mode never performs transport in a request worker. Query mode awaits
one bounded remote request and therefore requires guard availability and capacity
appropriate for proxy traffic. Disabling `--guard-url` creates no guard tasks.

## Persistent binary decisions for local high-volume traffic

`--guard-decision-tcp 127.0.0.1:9081` opts ordinary query requests into the
hangang-guard binary decision listener (`--decision-listen` on the service).
It requires `--guard-url` for explicit evidence submissions, accepts only literal
loopback addresses, and requires query mode. The collector token must contain
16–4096 bytes. Evidence-bearing honeypot/scanner requests continue using the
HTTP decision endpoint so the service receives and evaluates the signal.

The native client maintains up to 64 authenticated persistent sockets, instead
of serializing all proxy requests through one connection. Each decision uses a
24-byte request and response. A correlation ID, reserved fields, protocol
version, action, mode and TTL are checked before returning the socket to the
pool. IPv4-mapped IPv6 addresses use the IPv4 wire form. Pool admission,
connection, handshake, write and read share `--guard-timeout-ms`. A timed-out or
malformed response discards the socket; failures follow the configured failure
policy without making an additional HTTP request. A socket closed by the server
also fails that request and is discarded, so a later request can reconnect.
Sockets idle for 25 seconds are retired before reuse, ahead of the service's
30-second idle deadline. Idle sockets are also closed on shutdown cancellation.

Caching remains disabled by default and the optional 1–5 second IP cache has the
same semantics on both decision transports. Persistent transport removes HTTP
and JSON overhead for ordinary requests; throughput depends on server capacity,
concurrency and workload and must be measured for the deployed topology.

GeoIP-dependent and dynamic JSON/Lua rules are evaluated by the service in query
mode, on both HTTP and binary decision transports. The service rejects snapshot
retrieval while dynamic rules are active because a prefix-only snapshot cannot
represent those decisions. Use the default query mode for these rules; an older
snapshot retains its normal expiration behavior and fails open after expiry.

## Remote native mTLS

With `--guard-decision-tcp`, configure `--guard-decision-server-name`,
`--guard-decision-ca`, `--guard-decision-cert` and `--guard-decision-key`
together. PEM paths must be absolute. Outside literal loopback these settings
are required; the native destination remains a fixed, nonzero unicast socket
address. Hangang validates the explicit CA and expected server name, presents
its client certificate, requires ALPN `hgd1` and disables TLS early data.
Collector-key authentication remains mandatory inside the encrypted connection.

The existing bounded pool and total decision timeout include TCP connection,
TLS handshake and request/reply. Idle connections retire after 25 seconds;
connections also retire after 240 seconds, before the server's 300-second
limit. Cancellation, malformed responses, TLS failure and timeout discard the
connection. Native failure never triggers HTTP or plaintext fallback.

The HTTP origin still handles signals/evidence and snapshot export; the native
CA configuration applies only to HGD1. Configure the HTTP origin for the same
authority through its existing authenticated HTTPS ingress or local broker.
These settings do not implement fleet discovery, persisted revision watermarks
or measured full-stack 100k QPS.
