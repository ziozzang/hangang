# Documentation

[한국어 목차](README.ko.md)

English is the reference language. Available Korean pages are full translations of their English sources; both versions must preserve the same behavior, examples, and limitations. Guides without a Korean translation link to English references. The [repository README](../README.md) has the local quick start. The [example configuration guide](../examples/README.md) explains the starting JSON field by field, and [OpenAPI](openapi.json) defines the management API and configuration objects.

## Start here

- [First configuration and examples](../examples/README.md) — JSON fields, initial setup, reload, and troubleshooting
- [Deployment templates](../deploy/README.md) — initial deployment JSON, ports, and persistent state
- [Documentation guide](DOCUMENTATION.md) — how the documentation is organized
- [Glossary](GLOSSARY.md) — shared terminology
- [Architecture](ARCHITECTURE.md) — system structure and request flow
- [Development](DEVELOPMENT.md) — development and test workflow
- [Single-node deployment](DEPLOYMENT.md) — Docker Compose deployment
- [OpenAPI specification](openapi.json) — management API and configuration schema

## Routing and listeners

- [Host matching and route priority](MATCHING.md) — route selection rules
- [Named public HTTP and HTTPS listeners](PUBLIC_LISTENERS.md) — public listener configuration
- [UDP and QUIC relays](UDP.md) — local-file UDP datagram routing and opaque QUIC passthrough
- [Standalone IPv4 IPVS DSR](DSR.md) — scoped direct-routing companion
- [Canonical domain redirects](CANONICAL_DOMAINS.md) — canonical host behavior
- [TLS termination and SNI passthrough](SNI.md) — TLS listener modes
- [Request and response transforms](TRANSFORMS.md) — body transformation policies
- [HTTP response caching](CACHE.md) — response cache behavior
- [ACME certificates](ACME.md) — native certificate issuance

## Backends, members, and health

- [Outbound connection policies](UPSTREAM.md) — backend connection and TLS settings
- [Named HTTP and TCP members](NAMED_MEMBERS.md) — reusable backend members
- [Member admission](MEMBER_ADMISSION.md) — HTTP member admission and activity
- [Member lifecycle controls](MEMBER_LIFECYCLE.md) — member state transitions
- [Retired member observations](RETIRED_MEMBERS.md) — retired member state
- [Initial active-health admission](HEALTH_ADMISSION.md) — startup health gates
- [HTTP Docker endpoint health](HTTP_DOCKER_HEALTH.md) — Docker health checks
- [TCP transport health](TCP_HEALTH.md) — TCP health checks
- [TCP member admission](TCP_ADMISSION.md) — TCP member admission and activity
- [TCP named-member stream activity](TCP_MEMBER_ACTIVITY.md) — TCP member activity
- [Lua capacity reporting](LUA_CAPACITY.md) — Lua worker capacity

## Access control and identity

- [Explicit HTTP access modes](ACCESS_POLICY.md) — access policy modes
- [Protected HTTP resources](RESOURCE_POLICY.md) — resource protection
- [Native access-token authentication](JWT_AUTH.md) — JWT authentication
- [HTTP workload identity with mutual TLS](HTTP_WORKLOAD_MTLS.md) — HTTP workload certificates
- [TCP workload identity with mutual TLS](TCP_MTLS.md) — TCP workload certificates
- [Country admission](GEOIP.md) — country-based admission
- [Native HTTP language preference](LANGUAGE_POLICY.md) — language selection policy
- [Administrator accounts](ADMIN_USERS.md) — account setup and administration

## Configuration and change control

- [Configuration publication](CONFIG_PUBLICATION.md) — publishing configuration revisions
- [Local configuration operation acceptance](CONFIG_OPERATIONS.md) — operation history and acceptance
- [Activate and deactivate](ACTIVATION.md) — route and certificate activation
- [Retained SQL configuration commit receipts](SQL_COMMIT_RECEIPTS.md) — SQL commit receipts
- [Sequenced SQL commit receipts](SEQUENCED_SQL_RECEIPTS.md) — ordered receipt records
- [V2 receipt protection and completion acknowledgement](SQL_RECEIPT_RELEASE.md) — receipt release
- [Signed updates and process replacement](UPDATES.md) — update and restart flow
- [Management API and console coverage](API_UI_COVERAGE.md) — native API and console coverage

## Audit and traffic observations

- [Durable local account audit](ACCOUNT_AUDIT.md) — account audit records
- [Selective account audit recording](ACCOUNT_AUDIT_FILTERS.md) — audit filters
- [Recent traffic metadata](TRAFFIC_HISTORY.md) — HTTP traffic history
- [Selective HTTP response-head recording](HTTP_RECORDING.md) — HTTP recording
- [HTTP request listener attribution](HTTP_TRAFFIC_LISTENERS.md) — listener attribution
- [Live TCP connection history](TCP_CONNECTION_HISTORY.md) — TCP connection history
- [Selective raw TCP completion recording](TCP_RECENT_RECORDING.md) — TCP completion recording
- [Certificate inventory and issuer observation](CERTIFICATE_INVENTORY.md) — certificate inventory

## Deployment and integrations

- [Docker discovery](DOCKER.md) — Docker service discovery
- [Kubernetes Ingress controller](KUBERNETES.md) — Kubernetes integration
- [Scale-out operation](SCALE_OUT.md) — shared configuration and multi-node operation
- [Redis configuration store](REDIS.md) — Redis-backed configuration
- [Node observation identity](FLEET_OBSERVER.md) — fleet observer identity
- [Authenticated remote node observations](FLEET_OBSERVATIONS.md) — read-only fleet observations

## Related guides

- [Embedded Lua editor](../web/LUA_EDITOR.md) — browser editor behavior and build
- [Upstream transport example](../examples/upstream/README.md) — executable backend transport example
- [Fleet observations example](../examples/fleet-observations/README.md) — fleet observation example
- [GeoIP fixture](../tests/fixtures/geoip/README.md) — GeoIP test fixture

The console is available at `/ui/` on the management listener. The same build serves its API specification at `/openapi.json`. `hangang --help` lists command-line options.
