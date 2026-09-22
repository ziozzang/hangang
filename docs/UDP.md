# UDP routing and QUIC passthrough

[Documentation](README.md) · [한국어 요약](ko/UDP.md)

Hangang relays UDP datagrams to a configured backend, keeping each client flow
on the same backend until its idle timeout or a route change. The same relay
can carry encrypted QUIC, including HTTP/3 served by a QUIC backend. Hangang does
not terminate QUIC or apply HTTP route, Lua, JWT, or body-transformation policy
to its encrypted contents.

## Configuration

Add a `udp` array to the local JSON configuration. This fragment listens on a
loopback UDP port and forwards to two literal backend addresses:

```json
{
  "udp": [{
    "id": "quic-edge",
    "enabled": true,
    "protocol": "quic",
    "listen": "127.0.0.1:8443",
    "backends": ["127.0.0.1:9443", "127.0.0.1:9444"],
    "idle_timeout_ms": 30000,
    "max_sessions": 1024,
    "max_datagram_bytes": 65507
  }]
}
```

Use `protocol: "udp"` for general datagrams. `quic` describes intended use and
requires a datagram allowance of at least 1,200 bytes; it does not inspect or
classify packets. The [complete UDP example](../examples/udp/config.json) can be
validated with `hangang --config examples/udp/config.json --check` before starting
its separately provisioned backends.

| Field | Default | Valid range or behavior |
| --- | --- | --- |
| `id` | Required | 1–64 ASCII letters, digits, dots, underscores, or dashes; unique across HTTP/TCP/UDP route IDs. |
| `enabled` | `true` | Disabled routes retain configuration but have no active UDP listener. |
| `listen` | Required | Literal IPv4 or bracketed IPv6 socket address with a nonzero port; wildcard binds are supported. |
| `backends` | Required | 1–64 distinct unicast literal socket addresses; no DNS lookup, multicast, broadcast, or unspecified destinations. |
| `protocol` | `udp` | `udp` or opaque `quic` passthrough. |
| `idle_timeout_ms` | `30000` | 100–86,400,000 ms without successfully forwarded application datagrams. |
| `max_sessions` | `1024` | 1–16,384; sum across configured routes must not exceed 16,384. |
| `max_datagram_bytes` | `65507` | 1–65,507 bytes; at least 1,200 for `quic`. Oversized packets are dropped rather than forwarded truncated. |

At most 64 UDP routes are allowed, within the overall 1,024-route configuration
limit. TCP and UDP may use the same numeric port because they are different
transports. Conflicting UDP binds fail candidate preparation. Backends must be
reachable from the gateway; configuring a route does not create a service.

## Flow affinity and resource limits

The flow key is the client IP and source port within one listener. New flows
select backends round-robin. Each gets a connected upstream UDP socket, which
accepts replies only from its selected endpoint. Different client flows do not
share an upstream socket. Backend applications see the gateway's source address;
use the separate [DSR companion](DSR.md) when the network is designed for direct
return and source-IP preservation.

UDP preserves datagram boundaries, including empty payloads, but does not add
reliability, ordering, retries, or backend health checks. A lost packet remains
lost; retransmission belongs to the application or QUIC endpoints. Backend
selection is pinned for the flow and is not retried against another destination.

Each session has a queue of at most eight outgoing packets. A process-wide
64 MiB budget bounds queued payload bytes and per-session receive buffers;
listener buffers, socket/kernel memory, task metadata, and configuration are
additional. Session and byte limits are independent, so a large datagram limit
can exhaust memory admission before `max_sessions`. Saturated admission or a
full queue drops datagrams. Configure firewall/source restrictions appropriate
to a UDP service; QUIC/backend authentication remains the backend's responsibility.

## Reload, activation, and shutdown

UDP participates in the gateway's revision-checked whole-configuration
preparation. New sockets are bound before publication; failed preparation leaves
the active configuration and listeners intact. An unrelated HTTP/configuration
edit preserves unchanged UDP flows.

Changing a UDP route retires its existing sessions, even if the listening address
is unchanged. Disabling or removing a route closes its listener and sessions.
Clients must reconnect after those changes; datagrams arriving during the
transition can be dropped, and already forwarded bytes cannot be recalled. Counters restart when a listener generation is replaced. Process
shutdown closes UDP sessions instead of applying TCP's connection-drain protocol.

This release supports UDP under **local-file configuration authority only**.
Shared stores, Kubernetes controller mode, and `--supervised` mode reject UDP
routes. UDP socket/session handoff is not implemented; the documented
[HTTP/TCP supervised continuity](UPDATES.md) must not be interpreted as UDP/QUIC
upgrade continuity. Read-only container replacement also resets UDP sessions.

## QUIC boundaries

QUIC endpoints handle TLS, certificates, connection IDs, congestion control,
loss recovery, and HTTP/3. Hangang passes encrypted datagrams unchanged. A stable
client IP/port keeps the selected backend even when QUIC changes connection IDs
or keys. Client address migration or NAT rebinding creates a new relay flow and
can select another backend; connection-ID-aware routing is not implemented.
Idle expiry likewise loses the existing upstream mapping. Choose the relay idle
budget with the endpoint's keepalive/idle policy in mind.

See [RFC 9000, simple load balancers](https://www.rfc-editor.org/rfc/rfc9000.html#section-5.2.3)
for the QUIC implications of routing by network addresses. The `quic` mode does
not provide SNI routing, HTTP/3 termination, QUIC-aware health checks, or DSR.

## Management and observability

The English/Korean **UDP / QUIC** console page creates, edits, deletes, and toggles
relays through `GET /v1/config` and revision-checked `PUT /v1/config`. Edits preserve
unrelated configuration and reject conflicting relay changes. There is no separate
UDP route CRUD endpoint; the [OpenAPI schema](openapi.json) defines `UdpRoute`.

`GET /v1/status` and status SSE events include `udp_routes` (all configured routes)
and `udp.routes` (active listeners only). Each active entry reports its ID,
protocol, address, active sessions, session limit, backend count, and datagram
counters. `datagrams_forwarded` and `responses_forwarded` count successful local
socket sends, not confirmed delivery. `dropped_datagrams` counts observed relay
rejections/failures; kernel drops are not fully observable through these counters.
These observations are not a durable log or a packet capture.

Prometheus `/metrics` exports `hangang_udp_sessions` and the counters
`hangang_udp_datagrams_received_total`, `hangang_udp_datagrams_forwarded_total`,
`hangang_udp_responses_forwarded_total`, `hangang_udp_dropped_datagrams_total`,
and `hangang_udp_sessions_created_total`, each labeled by `route`. They use the
same active-listener scope and reset when that listener generation changes.

For Docker, explicitly publish UDP ports, for example `"8443:8443/udp"`, and
listen on the container interface. The default [Compose template](DEPLOYMENT.md)
publishes only its documented TCP ports; adding a route in the console does not
change Docker port mappings.

## Verification

```sh
cargo test --locked --lib udp::tests
cargo test --locked --test udp_lifecycle
cargo build --locked --bin hangang
python3 tests/udp_smoke.py
make static
python3 tests/datagram_container.py
```

For OpenAPI contract checks, run `python3 tests/udp_schema.py` in a Python
environment with `jsonschema` installed.

The container fixture builds pinned aioquic test peers and creates an owned
internal Docker network with no published ports. It verifies UDP flow isolation,
balancing, boundaries, configuration rejection/activation, and real TLS-verified
HTTP/3 through encrypted QUIC passthrough. CID rotation is exercised without
changing the client tuple; this is not a migration test. Build dependencies need
network access, while protocol traffic stays inside the owned test network.
The runner requires a local Docker daemon, Python/pip, and OpenSSL, and removes
its containers and network on exit. It is a correctness test, not a throughput
ranking or an availability guarantee.
