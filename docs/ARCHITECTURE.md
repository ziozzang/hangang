# Architecture

[Documentation](README.md) · [한국어 안내](README.ko.md)

Hangang is an asynchronous HTTP/TCP reverse proxy written in Rust. A process
serves public traffic and a separate administration interface. Optional Lua,
TLS, discovery, shared configuration and update facilities are enabled explicitly.

## Request path

HTTP routing evaluates listener scope, host, path, header and optional JSON
conditions against an immutable configuration snapshot. Routes select upstream
pools and may apply authentication, resource authorization, country/language
policy, caching and transformations. TCP routes forward byte streams or inspect
SNI before selecting an upstream. See [matching](MATCHING.md),
[upstreams](UPSTREAM.md) and [TCP admission](TCP_ADMISSION.md).

HTTP bodies stream by default. JSON route inspection and whole-body transforms
use bounded buffers and admission limits. Record transforms support lines,
NDJSON and SSE; WebSocket upgrades become bidirectional tunnels. See
[transformations](TRANSFORMS.md) and [caching](CACHE.md).

Lua runs in replaceable child processes with memory, instruction and wall-time
limits. Saturation fails closed instead of bypassing policy. Worker crashes do
not run Lua inside the forwarding process. See [Lua capacity](LUA_CAPACITY.md)
and the [editor and API guide](../web/LUA_EDITOR.md).

## Configuration and lifetime

Validated candidates are prepared before publication. Requests retain their
snapshot while new requests use the newly published configuration. Removed TCP
listeners stop accepting; established streams retain their existing ownership.
Named pool members expose serving, draining and maintenance states. See
[publication](CONFIG_PUBLICATION.md), [member lifecycle](MEMBER_LIFECYCLE.md)
and [retired members](RETIRED_MEMBERS.md).

Local JSON files, SQLite, PostgreSQL and Redis have distinct persistence and
coordination semantics. Revision checks prevent blind concurrent overwrites.
A shared-store commit is not an acknowledgement from every serving process.
Accounts, sessions and management journals are instance-local. See
[scale-out](SCALE_OUT.md) and [configuration operations](CONFIG_OPERATIONS.md).

## TLS and discovery

TLS can terminate at the gateway or pass through as opaque TCP after bounded
ClientHello inspection. File certificates are loaded and validated before
replacement; established TLS connections retain their generation. Native ACME
supports HTTP-01 and DNS-01. See [TLS/SNI](SNI.md), [ACME](ACME.md) and
[public listeners](PUBLIC_LISTENERS.md).

Docker discovery maintains endpoint generations independently from config
revision. Kubernetes can import Ingress resources offline or reconcile them
through its API. These mechanisms are separate configuration authorities; use
the documented compatibility constraints in [Docker](DOCKER.md) and
[Kubernetes](KUBERNETES.md).

## Management and operational boundaries

The management API and English/Korean console expose configuration, health, metrics,
account controls and bounded traffic metadata. Request/connection history is
process-local and is not a durable packet capture. Remote node observations do
not provide configuration rollout, command execution or cluster consensus.
See the [API reference](openapi.json), [API/UI map](API_UI_COVERAGE.md),
[account security](ADMIN_USERS.md) and [fleet observations](FLEET_OBSERVATIONS.md).

Supervised process replacement and signed binary updates have separate activation
and rollback constraints. Containers built from the scratch image use image
replacement when the root filesystem is read-only. See [updates](UPDATES.md)
and [deployment](DEPLOYMENT.md). UDP/QUIC routing is not implemented.
