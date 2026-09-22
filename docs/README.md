# Documentation

Start with the [English](../README.md) or [Korean](../README.ko.md) README for a local run. The [example JSON configuration](../examples/hangang.json) is a small starting point; [OpenAPI](openapi.json) defines the management API and configuration objects. `hangang --help` lists command-line options.

## Routing and traffic

- [Architecture](ARCHITECTURE.md), [host matching and priority](MATCHING.md), [named public HTTP/HTTPS listeners](PUBLIC_LISTENERS.md), and [canonical domain redirects](CANONICAL_DOMAINS.md)
- [Backend connections and outbound TLS](UPSTREAM.md), [named backend members](NAMED_MEMBERS.md), [member admission](MEMBER_ADMISSION.md), [member lifecycle](MEMBER_LIFECYCLE.md), [retired members](RETIRED_MEMBERS.md), [HTTP health](HTTP_DOCKER_HEALTH.md), [initial health admission](HEALTH_ADMISSION.md), and [TCP health](TCP_HEALTH.md)
- [Response cache](CACHE.md), [request/response body transforms](TRANSFORMS.md), [TLS/SNI routing](SNI.md), and [ACME certificates](ACME.md)
- [TCP admission](TCP_ADMISSION.md), [TCP member activity](TCP_MEMBER_ACTIVITY.md), and [Lua worker capacity](LUA_CAPACITY.md)

## Access and management

- [Administrator accounts](ADMIN_USERS.md), [access modes](ACCESS_POLICY.md), [Basic/JWT/external identity and protected resources](RESOURCE_POLICY.md), [JWT](JWT_AUTH.md), and [HTTP workload mTLS](HTTP_WORKLOAD_MTLS.md)
- [TCP workload mTLS](TCP_MTLS.md), [country admission](GEOIP.md), and [language preference](LANGUAGE_POLICY.md)
- [Configuration publication](CONFIG_PUBLICATION.md), [configuration operation history](CONFIG_OPERATIONS.md), [SQL commit receipts](SQL_COMMIT_RECEIPTS.md), [sequenced SQL receipts](SEQUENCED_SQL_RECEIPTS.md), and [receipt release](SQL_RECEIPT_RELEASE.md)
- [Account audit](ACCOUNT_AUDIT.md) and [audit recording filters](ACCOUNT_AUDIT_FILTERS.md)
- [HTTP traffic history](TRAFFIC_HISTORY.md), [HTTP recording](HTTP_RECORDING.md), [HTTP listener attribution](HTTP_TRAFFIC_LISTENERS.md), [TCP connection history](TCP_CONNECTION_HISTORY.md), and [TCP completion recording](TCP_RECENT_RECORDING.md)

## Deployment and operations

- [Single-node Compose deployment](DEPLOYMENT.md), [Docker discovery](DOCKER.md), [Kubernetes integration](KUBERNETES.md), [shared-store operation](SCALE_OUT.md), and [Redis configuration](REDIS.md)
- [Fleet observer identity](FLEET_OBSERVER.md) and [read-only fleet observations](FLEET_OBSERVATIONS.md). These observations do not provide fleet membership or deployment control.
- [Route and certificate activation](ACTIVATION.md), [certificate inventory](CERTIFICATE_INVENTORY.md), [signed updates and restart](UPDATES.md), [native console/API coverage](API_UI_COVERAGE.md), [Lua editor](../web/LUA_EDITOR.md), and [development/testing](DEVELOPMENT.md)

The console is available at `/ui/` on the management listener. The same build serves its API specification at `/openapi.json`.
