# Outbound connection policies

[Documentation](README.md) · [한국어 안내](README.ko.md)

HTTP and TCP routes accept an optional `upstream` object. A route can match a host, path, header, JSON condition or incoming TLS SNI using the existing routing rules, then select its own outbound transport. These options do not affect other routes, external authorization calls, ACME, update downloads or management traffic. Existing connections keep their transport; newly published route settings apply to new work. Failed configuration validation leaves the active configuration intact.

## Independent identities

- `backends`: the logical destination and load-balancing candidates. For HTTP, the URL also supplies the default Host and TLS verification name.
- `upstream.connect_address`: the socket destination, `host:port` or `[IPv6]:port`. This overrides the chosen backend address without changing its logical identity. If set on a route with several backends, all candidates dial this same address.
- `upstream.unix_socket`: an absolute, normalized path (at most 107 encoded bytes) to a Unix stream socket mounted inside the gateway. All candidates dial this socket; their logical backend still supplies HTTP Host and the default TLS verification name. It cannot be combined with `connect_address`, `socks5`, or `dns_servers`. A failed socket connection has no direct-TCP fallback.
- `upstream_host` (HTTP only): explicitly sets HTTP Host and HTTP/2 `:authority`.
- `preserve_host` (HTTP only): preserves the incoming Host/authority. It conflicts with `upstream_host`.
- `upstream.tls.server_name`: TLS SNI and certificate verification name. Defaults to the logical backend name, not the connect override or HTTP Host. IP names use IP certificate verification without a DNS SNI extension.

For example, connect to `1.2.3.4:443`, send HTTP Host `foo.bar`, and authenticate the upstream as `foo.bar`:

```json
{
  "id": "pinned-origin",
  "host": "public.example",
  "backends": ["https://foo.bar"],
  "upstream_host": "foo.bar",
  "upstream": {
    "connect_address": "1.2.3.4:443",
    "tls": { "server_name": "foo.bar" }
  }
}
```

For a private CA, set `tls.ca_file` to an absolute PEM file path. Files must be regular files, at most 1 MiB; at most 16 routes may load CA files. They are read when preparing a configuration, so a configuration update also reloads the CA. Reapply the full configuration with PUT to refresh unchanged file references; a no-op file reload does not refresh them. A CA-only file edit is not watched automatically. TLS server certificate watching is a separate feature. The route CA verifier trusts the public roots plus the given private roots; it replaces any process-wide custom upstream CA verifier for that route.

For a fixed-target bridge egress relay, a route can retain its logical backend while dialing a private Unix socket:

```json
{
  "id": "via-local-relay",
  "host": "relay.example",
  "backends": ["https://origin.example"],
  "upstream": { "unix_socket": "/run/hangang/egress/origin.sock" }
}
```

The relay must connect only to its intended destination and authenticate the gateway by a private mount/permissions or a stronger channel identity. The socket path is not created by Hangang. Unix transport applies to HTTP and raw TCP route backends, including optional TLS wrapping with the logical name; external authorization requests use a separate client and are unaffected.

`tls.insecure_skip_verify: true` explicitly skips certificate chain and name verification on this route. Encryption and TLS handshake signature checks remain, but server identity is not authenticated. It is incompatible with `ca_file`. It does not disable TLS or relax public/admin listener TLS. Verification is on by default. HTTP routes with `tls` options must have HTTPS backends. For TCP, a non-null `tls` object enables an upstream TLS client; `{}` enables verified TLS with defaults.

## SOCKS5 and selected DNS

```json
{
  "id": "selected-egress",
  "path_prefix": "/via-proxy/",
  "backends": ["https://origin.example"],
  "upstream": {
    "socks5": {
      "address": "127.0.0.1:1080",
      "username_env": "HANGANG_SOCKS5_USER",
      "password_env": "HANGANG_SOCKS5_PASSWORD"
    },
    "dns_servers": ["192.0.2.53:53", "[2001:db8::53]:53"],
    "tls": { "server_name": "origin.example" }
  }
}
```

Omit both environment references for a no-authentication SOCKS5 proxy. Both names must start with `HANGANG_SOCKS5_` and contain only uppercase ASCII letters, digits and underscores (maximum 128 characters). Actual values are read for new connections, never serialized into config or debug output. Username/password authentication uses RFC 1929 and does not encrypt the proxy hop by itself. This implements SOCKS5 TCP CONNECT, not BIND or UDP ASSOCIATE. Proxy refusal, authentication failure or timeout never triggers a direct fallback.

| Configuration | Destination name resolution |
| --- | --- |
| No custom DNS, direct | System resolver |
| No custom DNS, SOCKS5 | Destination domain is sent to SOCKS5; proxy endpoint itself uses system DNS if needed |
| Custom DNS, direct | Only listed DNS servers |
| Custom DNS, SOCKS5 | Listed DNS servers resolve the target locally, then SOCKS5 receives an IP; they also resolve a named proxy endpoint |
| Literal IP or literal connect override | No destination DNS lookup |

DNS servers must be literal IP:port addresses, up to four. Queries use UDP with TCP support on the same configured endpoints; there is no system resolver, search suffix or hosts-file fallback. This is plain DNS, not DoH/DoT or DNSSEC validation. `localhost` names are rejected with explicit DNS to avoid the resolver's synthetic loopback answer; use a loopback IP explicitly. Standard reserved `.invalid` names produce a negative result.

The selected-DNS address cache is isolated by server list and canonical name, respects answer TTL (capped at 300 seconds), holds at most 2,048 entries with up to 16 addresses each, and allows at most 64 concurrent uncached lookups. Cache capacity exhaustion evicts cached entries; lookup capacity exhaustion fails the connection. DNS queries have a two-second outer deadline within the outbound connection budget. Existing HTTP pooled connections can outlive DNS TTL; TTL changes affect fresh connections, not already-established transports. Direct connections try resolved addresses within the shared deadline; SOCKS5 with selected DNS sends the first returned address.

## TLS fragmentation and ECH

`tls.max_fragment_size` optionally configures rustls record fragmentation, with accepted values 128–16,389. The limit includes the unencrypted record header for ClientHello, and applies to outgoing TLS records generally, not just the SNI extension. Small values add records and overhead. TCP may coalesce or split these records independently. This option is not a guarantee that a network filter will be bypassed.

For an SNI passthrough route, enabling `upstream.tls` creates TLS inside TLS: the original client's bytes travel inside a new outer TLS connection. The upstream must explicitly support that tunnel protocol. A normal HTTPS origin does not unwrap arbitrary nested TLS automatically. Terminating HTTPS in Hangang and originating HTTPS upstream uses a fresh handshake to the ordinary origin.

Encrypted ClientHello (ECH) is not implemented. TLS record fragmentation does not provide ECH or hide the destination name.

## Management and verification

The HTTP/TCP route editors expose outbound JSON; HTTP has separate Host override/preserve fields. The full configuration API, route CRUD and [OpenAPI](openapi.json) use the same schema. Idle pooling is disabled for `preserve_host` routes, preventing arbitrary incoming Host values from accumulating an unbounded number of idle authority pools. This costs additional connection/handshake work on those routes. Other HTTP pools are isolated by route generation and logical backend so verifier/proxy settings cannot leak between routes. Cache fingerprints include these fields, preventing cached responses from crossing a policy change. The HTTP dial/SOCKS stage has a three-second deadline, and the existing 15-second response-header deadline covers TLS and request processing. Raw TCP has one three-second deadline covering DNS, connection, SOCKS and TLS handshake.

[Example configuration](../examples/upstream/config.json) uses documentation addresses and must be adapted before use. Owned loopback tests exercise verified and insecure TLS, Host/SNI separation including HTTP/2, pool invalidation, SOCKS protocol errors, selected DNS and TLS-record fragmentation. No external production gateway is used for these tests.

Host globs, regexes and explicit matching priority can select these policies for particular traffic. See [matching semantics](MATCHING.md).
