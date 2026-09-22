# Hangang

[Documentation](docs/README.md) · [Quick start](#quick-start) · [한국어](README.ko.md)

**An HTTP and TCP gateway with live configuration, isolated Lua policies, and a built-in management console.**

Hangang brings reverse proxying, load balancing, TLS certificate management, access policies, and traffic visibility into one Rust binary. Configure routes in the browser or through the API, inspect live traffic, and extend request handling with Lua—without deploying a separate console service. The console supports English and Korean; this README and the English guides are the reference documentation.

## Why Hangang

- **One place to operate HTTP and TCP.** Manage routes, listeners, backend members, certificates, and activation from the embedded console. The same server exposes a documented management API and OpenAPI specification. See [console coverage](docs/API_UI_COVERAGE.md).
- **Customize policy with a separate failure boundary.** Lua runs in replaceable child processes with memory, instruction, and wall-time limits. The built-in editor offers syntax highlighting and API completion. Worker saturation rejects the request rather than silently skipping its policy. See [architecture](docs/ARCHITECTURE.md) and [Lua editing](web/LUA_EDITOR.md).
- **Transform streaming traffic as well as ordinary bodies.** Apply native JSON/XML/text operations or Lua transforms. Whole-document processing uses bounded buffering; line, NDJSON, and SSE modes work on complete records. Ordinary bodies stream by default, and WebSocket upgrades become tunnels. See [transformations](docs/TRANSFORMS.md).
- **Change configuration while serving traffic.** File watching and revision-checked API updates prepare candidates before publication. Invalid candidates leave the working configuration in place. Under local-file configuration authority, named members support draining and maintenance; connection behavior follows the policy being changed. See [publication](docs/CONFIG_PUBLICATION.md) and [member lifecycle](docs/MEMBER_LIFECYCLE.md).
- **See what is happening without adding a dashboard service.** Live console views combine status, metrics, recent HTTP metadata, and active/recent TCP connections. Prometheus endpoints support external monitoring. Recording filters and bounded history control what the gateway retains. See [HTTP history](docs/TRAFFIC_HISTORY.md) and [TCP history](docs/TCP_CONNECTION_HISTORY.md).
- **Keep routing and security policy together.** Combine host glob/regex matching and priorities with JWT, workload mTLS, protected-resource rules, country/language filters, and per-route outbound DNS, SOCKS5, and TLS policy. See [routing](docs/MATCHING.md), [access control](docs/RESOURCE_POLICY.md), and [outbound connections](docs/UPSTREAM.md).

## Enterprise controls, integrated

**Our goal is to surpass the operational experience of commercial enterprise gateways by making advanced controls coherent, inspectable, and practical to run.** Hangang brings capabilities commonly expected from enterprise gateways into its MIT-licensed codebase. Today, its clearest advantage is their integration: routing, policy editing, traffic views, and management APIs share one application and configuration model.

| Operational requirement | Implemented in Hangang | Scope to understand |
| --- | --- | --- |
| Identity-aware access | JWT verification, HTTP/TCP workload mTLS, protected-resource rules, administrator/viewer accounts | Workload identity and local accounts are supported; this is not a centralized enterprise identity platform. [Access model](docs/RESOURCE_POLICY.md) |
| Auditable administration | Transactional local account audit, recording filters, configuration operation history, SQL commit receipts | Coverage is operation-specific; traffic history is separate from durable audit. [Account audit](docs/ACCOUNT_AUDIT.md), [configuration history](docs/CONFIG_OPERATIONS.md) |
| Controlled configuration changes | Revision checks, candidate preparation, durable operation tracking, SQL receipt lookup | A committed configuration does not prove that every instance has activated it. [Publication](docs/CONFIG_PUBLICATION.md), [SQL receipts](docs/SQL_COMMIT_RECEIPTS.md) |
| Service continuity | Backend health checks, serving/draining/maintenance states, supervised process replacement, signed updates | Named-member lifecycle controls require local-file authority and are rejected by shared stores; connection continuity depends on the policy change and deployment mode. [Lifecycle](docs/MEMBER_LIFECYCLE.md), [updates](docs/UPDATES.md) |
| Operational visibility | Live console views, Prometheus metrics, bounded connection/request history, authenticated remote observations | Remote observation is read-only; it is not fleet rollout control. [Fleet observations](docs/FLEET_OBSERVATIONS.md) |
| Policy customization | Bounded native transforms, isolated Lua workers, syntax highlighting and API completion | Lua and body limits are explicit; a rejected or interrupted stream cannot recall bytes already forwarded. [Transforms](docs/TRANSFORMS.md), [Lua capacity](docs/LUA_CAPACITY.md) |

These are implemented capabilities, not a claim of complete enterprise-product parity. The project aims to improve on commercial products where integration and operator control matter; universal performance, availability, and compliance claims require separate evidence.

## How it compares

Hangang is especially useful when you want **interactive gateway administration, HTTP/TCP traffic handling, and custom Lua policy in one deployable application**. The table compares operating models, not throughput or complete feature parity. Other products can cover overlapping use cases through their own modules, plugins, and editions.

| Product | Documented approach | Why choose Hangang for this use case? |
| --- | --- | --- |
| **Hangang** | One binary embeds HTTP/TCP routing, an English/Korean management console, revision-checked configuration, and isolated Lua workers. | A compact, self-hosted gateway stack with browser administration and policy customization built together. |
| **Caddy** | [Automatic HTTPS](https://caddyserver.com/docs/automatic-https) and a [JSON administration API](https://caddyserver.com/docs/api); extensions use its [module system](https://caddyserver.com/docs/modules). | Choose Hangang when the embedded route-management console, TCP administration, and Lua policy editor are central to your workflow. |
| **Kong Gateway** | [Services, Routes, Consumers, and plugins](https://developer.konghq.com/gateway/entities/) organize API policy; [Kong Manager](https://developer.konghq.com/gateway/kong-manager/) provides administration. | Choose Hangang when its native policies fit your requirements and you prefer a local-file starting point with process-isolated Lua and an embedded console. |
| **Traefik Proxy** | [Providers](https://doc.traefik.io/traefik/getting-started/configuration-overview/) discover dynamic configuration, including [Docker label-based routing](https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/). | Choose Hangang when direct route editing, custom Lua, and request/record transformations are more central than provider-driven configuration. |
| **HAProxy** | Its [Lua API](https://www.haproxy.com/documentation/haproxy-lua-api/getting-started/introduction/) extends a non-blocking load balancer and requires scripts to respect that execution model. | Choose Hangang when you want process-isolated Lua workers and an integrated policy editor alongside gateway management. |

Comparison sources reviewed on **2026-09-22**. Product editions and configuration affect availability. These are deployment tradeoffs, not a claim that Hangang is universally faster or replaces every enterprise capability. Hangang does not implement UDP/QUIC routing; administrator accounts remain instance-local, and fleet observation is read-only. Review [architecture](docs/ARCHITECTURE.md) and [scale-out semantics](docs/SCALE_OUT.md) before a migration.

## Quick start

This local example demonstrates a working proxy, a Lua rejection rule, and the management console. You need Git, Rust 1.96 or newer, a C compiler, Python 3, OpenSSL, and curl. Node.js is only needed when developing the console; its built assets are already included.

### 1. Build

```sh
git clone https://github.com/ziozzang/hangang.git
cd hangang
cargo build --locked
```

### 2. Start a demo backend

In a separate terminal, serve a temporary directory containing only the demo page:

```sh
HANGANG_DEMO_BACKEND="$(mktemp -d)"
printf 'Hello through Hangang!\n' > "$HANGANG_DEMO_BACKEND/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$HANGANG_DEMO_BACKEND"
```

### 3. Start Hangang

From the repository root in your first terminal:

```sh
umask 077
export HANGANG_DEMO_DIR="$(mktemp -d)"
cp examples/hangang.json "$HANGANG_DEMO_DIR/hangang.json"
openssl rand -hex 32 > "$HANGANG_DEMO_DIR/admin-token"
export HANGANG_ADMIN_TOKEN="$(cat "$HANGANG_DEMO_DIR/admin-token")"
./target/debug/hangang --check --config "$HANGANG_DEMO_DIR/hangang.json"
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json"
```

The example forwards `/` to the backend on port 8081. Its Lua rule rejects requests carrying `X-Block: yes`. The proxy binds to `127.0.0.1:8080`; management binds to `127.0.0.1:9000`. Both remain local to your machine.

### 4. Verify and open the console

In another terminal:

```sh
curl --fail http://127.0.0.1:8080/
# Hello through Hangang!

curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Block: yes' http://127.0.0.1:8080/
# 403
```

Open **http://127.0.0.1:9000/ui/**. Create the first administrator using the setup token saved in `$HANGANG_DEMO_DIR/admin-token`, a username, and a new password of at least 12 bytes. Read the token with a local editor; its directory is the value created in step 3, not a variable shared automatically with other terminals. Keep it private: it remains a break-glass administrator credential after account creation.

Open the HTTP route editor to inspect the Lua policy, then send more requests while watching the dashboard. `--check` validates configuration and Lua without starting listeners. To stop the demo, press `Ctrl+C` in the gateway and backend terminals. The temporary state remains available for inspection; restarting with the same config path preserves the local administrator database.

## What you can build next

| Need | Included capability | Guide |
| --- | --- | --- |
| Serve several domains and ports | Host patterns, priorities, canonical redirects, named HTTP/HTTPS listeners | [Matching](docs/MATCHING.md), [listeners](docs/PUBLIC_LISTENERS.md) |
| Automate certificate renewal | ACME HTTP-01 and DNS-01; Cloudflare or authenticated DNS webhook; ZeroSSL EAB | [ACME](docs/ACME.md) |
| Protect application services | JWT verification, workload mTLS, protected HTTP resources | [JWT](docs/JWT_AUTH.md), [mTLS](docs/HTTP_WORKLOAD_MTLS.md), [resource policy](docs/RESOURCE_POLICY.md) |
| Reduce repeated backend work | Response caching with configurable memory and disk policy | [Caching](docs/CACHE.md) |
| Adapt payloads and streams | Native JSON/XML/text transformations and bounded Lua body transforms | [Transformations](docs/TRANSFORMS.md) |
| Discover container workloads | Docker endpoints and Kubernetes Ingress reconciliation | [Docker](docs/DOCKER.md), [Kubernetes](docs/KUBERNETES.md) |
| Coordinate several instances | Shared configuration via SQLite, PostgreSQL, or Redis, with documented consistency boundaries | [Scale-out](docs/SCALE_OUT.md) |
| Deploy and operate | Compose templates, administrator accounts, signed updates, account audit | [Deployment](docs/DEPLOYMENT.md), [accounts](docs/ADMIN_USERS.md), [updates](docs/UPDATES.md), [audit](docs/ACCOUNT_AUDIT.md) |

For deployment beyond a local demo, start with the [Compose guide](docs/DEPLOYMENT.md) or [Kubernetes guide](docs/KUBERNETES.md). Supply private credentials, persistent state, and the documented management-listener protection. The [documentation index](docs/README.md) covers feature-specific setup and limitations; [OpenAPI](docs/openapi.json) defines management endpoints and configuration objects.

## Development

```sh
make check       # Rust formatting and Clippy
make test        # Rust tests and local integration scenarios
make test-web    # Console and browser tests
make check-docs  # Staged documentation and publication checks
```

Some integration targets need Docker or additional dependencies. See [development](docs/DEVELOPMENT.md) and [documentation conventions](docs/DOCUMENTATION.md). Hangang is licensed under [MIT](LICENSE).
