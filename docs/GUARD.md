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
