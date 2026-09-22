# Hangang

Hangang is a Rust reverse proxy for HTTP and TCP services. It combines live JSON configuration, an embedded English/Korean management console, TLS, and route-level traffic policies in one server. [한국어](README.ko.md) · [Documentation](docs/README.md)

HTTP routes match hosts, paths, headers, and optional JSON fields, then forward to HTTP or HTTPS backends. TCP routes forward bidirectional streams. Routes can use named listeners, backend health and balancing, access controls, response caching, body transforms, and isolated Lua policy workers. The console and management API expose configuration, status, and operational views. Optional ACME, Docker discovery, Kubernetes reconciliation, and shared configuration stores have their own setup requirements.

## Try it locally

You need Rust 1.96 and a C compiler. The checked-in example uses a local HTTP backend; start it separately:

```sh
python3 -m http.server 8081 --bind 127.0.0.1
```

In another terminal, build and run Hangang:

```sh
cargo build --locked
cp examples/hangang.json /tmp/hangang.json
export HANGANG_ADMIN_TOKEN="$(openssl rand -hex 32)"
./target/debug/hangang --check --config /tmp/hangang.json
./target/debug/hangang --config /tmp/hangang.json
```

The proxy listens on `127.0.0.1:8080` and the management console on `http://127.0.0.1:9000/ui/`. On first visit, create an administrator account using the generated setup token and a new password. Keep that token private; it remains a break-glass credential. For non-local deployment, supply it through a private secret source and protect the management listener with TLS or a private Unix socket. See [administrator accounts](docs/ADMIN_USERS.md) and the [single-node Compose example](docs/DEPLOYMENT.md).

The source configuration is JSON. Hangang watches a local file and keeps the last working configuration if a new version is invalid. Management API writes require the current revision. `--check` validates the file and Lua policies without starting listeners. The [example configuration](examples/hangang.json), [route matching guide](docs/MATCHING.md), and [OpenAPI specification](docs/openapi.json) cover the wire format.

## Build and verify

```sh
make check      # Rust formatting and Clippy
make test       # Rust tests and local integration scenarios
make test-web   # Embedded console and browser tests
```

Some integration targets need Docker or other local test dependencies; see the [development guide](docs/DEVELOPMENT.md). The project is licensed under [MIT](LICENSE).
