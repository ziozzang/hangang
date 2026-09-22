# Configured TLS termination and SNI passthrough

[Documentation](README.md) · [한국어 안내](README.ko.md)

Hangang supports two distinct ways to use the TLS Server Name Indication (SNI).

## Terminate HTTPS with a configured certificate set

Start the public listener with `--config-tls` and manage the top-level `certificates` array through the configuration file or the authenticated, ETag-protected `PUT /v1/config` API. The same document is editable in the management console.

```json
{
  "certificates": [
    {
      "id": "site",
      "hosts": ["site.example.test", "*.site.example.test"],
      "cert_file": "/run/hangang/certs/site.pem",
      "key_file": "/run/hangang/certs/site.key"
    }
  ],
  "http": [{"id":"site","host":"site.example.test","backends":["http://127.0.0.1:8080"]}]
}
```

The certificate must cover every configured host and match its private key. Paths must be absolute and refer to regular files readable by Hangang. Configuration/API responses contain paths and domain names, never PEM material. Limit: 1,024 certificate entries, 128 hosts per entry, 1 MiB per file, 16 MiB of total certificate/key material. IDs and host assignments are unique; exact names take priority over one-label wildcards.

Certificate list updates are validated before snapshot publication. File identity, size, and change timestamps are polled every 500 ms; unchanged contents receive a full verification every 30 seconds. File reading and certificate parsing run outside the async worker threads. Valid changed material is published atomically; invalid or partially replaced pairs retain the last good resolver. Established TLS sessions continue with their original state. Removing a name rejects new handshakes for it unless another configured wildcard covers it. An empty set rejects handshakes; it never enables plaintext on that listener.

`--config-tls` is an explicit listener mode. Certificate entries alone do not turn a plaintext listener into HTTPS. It is mutually exclusive with `--tls-cert`/`--tls-key`, Kubernetes controller mode, and ACME-managed TLS. Existing ACME and Kubernetes certificate management remain separate modes; a combined manual/ACME certificate registry is not implemented by this change. All replicas consuming a shared configuration need the corresponding local files.

TLS termination permits HTTP routing, authorization, transformations, and eligible HTTP response caching. It supports the existing HTTP/1.1 and HTTP/2 listener behavior; HTTP/1.1 WebSocket upgrades and SSE streaming remain available. This does not add HTTP/2 Extended CONNECT WebSocket support.

## Route encrypted TLS without terminating it

Several TCP routes can share a listener if every route has `sni` settings:

```json
{
  "tcp": [
    {
      "id": "specific-app",
      "listen": "127.0.0.1:9443",
      "sni": {"hosts":["app.example.test"],"max_client_hello_bytes":65536,"hello_timeout_ms":3000},
      "backends": ["127.0.0.1:10443"]
    },
    {
      "id": "other-apps",
      "listen": "127.0.0.1:9443",
      "sni": {"hosts":["*.example.test"],"max_client_hello_bytes":65536,"hello_timeout_ms":3000},
      "backends": ["127.0.0.1:11443"]
    }
  ]
}
```

The gateway reads the initial ClientHello, chooses a route by priority and its exact/glob/regex hostname condition, forwards every consumed TLS record unchanged, and then copies bytes bidirectionally. TLS terminates at the selected backend, so Hangang does not need that backend's private key. Certificate verification is performed by the client against the backend certificate.

See [host patterns and priority](MATCHING.md) for `f??.bar.com`, `host_regexes`, precedence and resource limits. Routing patterns do not change certificate identity validation.

Missing or unknown SNI, malformed records, ambiguous duplicate extensions/names, byte-limit excess, more than 256 handshake records, and handshake-read timeout close the connection. There is no implicit fallback backend. An SNI listener does not also accept plaintext TCP routes. All routes sharing a listener must have identical hello limits because the route is unknown before parsing. Defaults are 65,536 bytes and 3,000 ms; allowed ranges are 1..1,048,576 bytes and 1..30,000 ms. The byte, record-count and time ceilings apply independently; parser buffers and connection metadata add memory overhead. A peer denied by every candidate route is rejected before ClientHello parsing and global admission. Otherwise global connection admission applies during inspection, followed by the selected route's admission and source-IP policy before upstream connection.

Fragmentation across network reads and TLS records is supported. An encrypted ClientHello inner hostname is not visible; only the clear outer name, when present, can be used. This is a TCP/TLS feature, not QUIC/HTTP/3 routing. No PROXY protocol header is inserted. The backend sees the gateway's network source address.

In passthrough mode HTTP headers, paths, WebSocket frames and SSE events are encrypted. Hangang cannot apply HTTP authorization, rewrite their contents, or cache their responses in that mode. A WebSocket/SSE connection can still travel through the TLS tunnel. Choose termination when those HTTP controls are needed.

Configuration changes affect new connections. Existing tunnels retain their selected backend and drain under the existing shutdown/restart policy. TCP listener ownership remains per address, including supervised descriptor handoff when multiple SNI routes share that address.

## Run an isolated example

```sh
cargo build --locked
python3 examples/sni/run.py
```

The runner uses temporary self-signed certificates, two owned TLS origins and ephemeral loopback gateway ports. It verifies domain-specific public TLS termination and two encrypted passthrough destinations. It needs the `openssl` executable and changes no existing service. Set `HANGANG_BINARY` to test a particular release artifact. See [the combined configuration](../examples/sni/hangang.json).
