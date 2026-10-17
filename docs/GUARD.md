# Native hangang-guard integration

[Documentation](README.md) · [한국어](ko/GUARD.md)

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

Native decision endpoints may use a bounded Service DNS name (`sumunjang.world.svc:9081`)
or literal IPv4/IPv6 address. Every DNS endpoint requires mTLS, including localhost.
New pooled connections resolve under the existing request deadline; TLS verifies
the separately configured server name and CA. No plaintext HTTP fallback is added
when native DNS or TLS fails. Keep an HTTPS origin for remote evidence exports.

## Optional gRPC query transport

Add `--guard-decision-grpc` to use `--guard-decision-tcp` as the Sumunjang gRPC
endpoint. `--guard-decision-server-name`, CA, certificate and key are mandatory,
including on loopback. This remains query mode, with the collector role only.
The listener must be the server's `--grpc-listen`, not its HGD1 port.

A reusable HTTP/2 channel admits at most 64 concurrent decisions, with bounded
metadata/message sizes and one configured timeout covering connection and RPC.
It rejects unspecified/unavailable responses, malformed modes/TTLs, mismatched
request IDs and revision rollback. Observe allow is not enforced admission.
Cancellation aborts an outstanding query. There is no additional HTTP/native
request on a gRPC failure; optional guard admission follows the configured failure
policy, while mandatory Pumgye evidence remains unavailable and fails closed.
Evidence-bearing honeypot/scanner calls still use the explicit HTTP signal endpoint.
Credential/channel rotation, actual Kubernetes rollout and complete gateway chain
qualification remain separate gates. Native HGD1 is still the default.

Owned client/server qualification:

```sh
cargo build --example guard_grpc_qualification
python /path/to/sumunjang/tools/grpc_smoke.py --binary /path/to/sumunjang --hangang-client target/debug/examples/guard_grpc_qualification
```

Admission and fresh authorization evidence share a monotonically increasing observed revision. An older reply cannot replace newer cached policy evidence, including when HTTP signals and gRPC/native queries are mixed.

### Query budget and cache lifetime

On Linux, positive decision TTLs age from the original local query start using
suspend-inclusive BOOTTIME, including connection/queue/RPC/body-read time. Cache
hits share that original capture and never start a new TTL. A clock read failure
or reversal permanently invalidates the capture; a later successful read cannot
restore it. One millisecond of source quantization is excluded. Cache entries
still use `min(configured_cache_ms, reply.ttl_ms)` (up to five seconds); native
request evidence additionally remains capped at one second and bound to the
exact client owner, canonical IP, and current revision. No foreign absolute
clock is compared. Other platforms retain the legacy Instant behavior; this does
not qualify them for the Linux observed contract.

The classic protocol's TTL is a bounded cache/reuse hint, not a remote revocation
lease or a guarantee covering all later proxy transport writes. TTL zero is a
valid point-in-time decision, including the final second of a timed rule. It
creates neither a cache entry nor reusable request evidence; disabling the local
cache does not change the authority's TTL. The public numeric authorization
result preserves this compatibility and must not be treated as retained proof.
A positive reply whose original budget has already elapsed after transport is
unavailable (subject to the configured admission failure mode; mandatory fresh
authorization remains unavailable). Existing legacy connection pooling and
point-in-time dispatch behavior are preserved. The explicit observed native
chain has separate local authority/output/transport fences; this cache change
does not claim that every legacy socket write is fenced by network evidence.
Canceling the native guard owner also retires its cached and retained captures;
query-mode admission cannot reuse the cache or issue fresh proof under that owner.
## Hopae risk context

Hangang can pass Sumunjang's network evidence for a request to Hopae, so
Hopae's risk rules can require a fresh factor or deny (Hopae ADR-0023, Hopae
`GATEWAY_CONTRACT.md` "Risk context").

```sh
hangang ... --guard-decision-grpc ... \
  --risk-context-key-env HANGANG_RISK_CONTEXT_KEY \
  --risk-elevated-reason sumunjang.allow.rule --risk-elevated-country RU \
  --risk-elevated-asn 64666 --risk-unlisted-elevated
```

and, on each route whose authorization service is Hopae, `"auth": {...,
"risk_context": true}`.

- **Evidence.** With `--risk-context-key-env`, the gRPC query asks
  Sumunjang's Network service for `include_evidence`. The evidence covers
  the reason code, the deciding stage, the ASN, the country, and what
  enforcement would decide. A Sumunjang without this additive field answers
  the original reply. When there is no evidence, the header is omitted and
  Hopae's `risk.missing` applies. That happens with an older Sumunjang, with
  the HTTP or HGD1 transports, when Sumunjang is unavailable, or when a
  decision has a zero TTL.
- **Level.** The mapping follows the contract table, with configurable
  thresholds:
  - `high`: enforcement would deny the request, which is only seen in observe
    mode, because an enforced denial is refused before Hopae.
  - `elevated`: a configured reason code (`--risk-elevated-reason`, matched
    against the decision's or the would-be enforcement's), country
    (`--risk-elevated-country`) or ASN (`--risk-elevated-asn`), or, with
    `--risk-unlisted-elevated`, a request allowed only by the policy default
    (in observe mode: the would-be enforcement's `sumunjang.allow.default`).
  - `low`: everything else.
- **Header.** `x-hopae-risk-context: v1.<P>.<T>`, exactly as the contract
  defines it:
  - `P` holds `iat`, `level`, `source`, `mode`, `reason`, `rev`, `asn` and
    `country`.
  - `T` is an HMAC-SHA256 over the claims and this verify call's
    `x-original-method`, `x-forwarded-for` and `x-original-url`.
  - The key comes from `--risk-context-key-env` (32 to 4,096 bytes, the same
    as Hopae's `risk.context_key_env`).

  It is sent only on the route's authorization call, over HTTP forward-auth
  or HOP1, and never upstream. A client-supplied header of that name is
  removed at the edge, and the name cannot be configured as a forwarded or
  static authorization header. The unit test
  `the_contract_test_vector_is_reproduced` reproduces Hopae's documented test
  vector byte for byte.
- **Rotation.**
  1. Set Hopae's `risk.context_key_next_env` to the new key.
  2. Restart Hangang with `--risk-context-key-env` naming the new key.
  3. Make the new key Hopae's current key and remove the old one.
- **Observability.**
  - `hangang_risk_context_sent_total{level}` and
    `hangang_risk_context_omitted_total` count what was sent.
  - The decision event's identity stage records `risk_level`
    ([decision events](DECISION_EVENTS.md)).
- **Validation.** `tests/risk_context_smoke.py` runs a real Sumunjang with
  evidence, a real Hopae with risk rules and Hangang. It checks that `low` is
  allowed, `elevated` is stepped up on `/admin`, and `high` is denied, and
  that client copies are stripped and never reach the upstream.

