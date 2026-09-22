# Per-route outbound transport

[Documentation](../../docs/README.md)

See [the configuration](config.json) and [the complete guide](../../docs/UPSTREAM.md). The addresses are documentation placeholders. The first route deliberately demonstrates opt-in certificate verification bypass; remove `insecure_skip_verify` for a trusted origin. The TCP example accepts plain local bytes and originates verified TLS to its backend.

Validate this example without contacting the configured upstreams:

```sh
cargo run -- --config examples/upstream/config.json --check
```

Run executable tests against owned local HTTP/2/TLS, SOCKS5 and DNS fixtures:

```sh
cargo test --locked --test upstream_http --test upstream_dns --test tcp_outbound
cargo test --locked --lib upstream::tests
```

Run an end-to-end demonstration with an owned HTTPS origin and SOCKS5 proxy (requires OpenSSL):

```sh
cargo build --locked
python3 examples/upstream/run.py
# Or select the static build:
HANGANG_BINARY=target/x86_64-unknown-linux-gnu/release/hangang python3 examples/upstream/run.py
```

The demonstration creates temporary certificates and configuration, asserts actual Host/SNI and SOCKS route selection, and cleans up its own processes and loopback servers.

For glob/regex/priority composition, use [matching.json](matching.json) with [matching semantics](../../docs/MATCHING.md):

```sh
target/debug/hangang --config examples/upstream/matching.json --check
```
