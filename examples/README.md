# Your first Hangang configuration

[Project quick start](../README.md#quick-start) · [Documentation](../docs/README.md) · [한국어](README.ko.md)

Start with [hangang.json](hangang.json) for a local HTTP proxy. Use
[deploy/hangang.example.json](../deploy/hangang.example.json) for an empty
Docker deployment. These are different starting points: the local example has
one working demo route; the deployment template has no application routes.

## Understand the local example

```json
{
  "revision": 0,
  "http": [
    {
      "id": "api",
      "path_prefix": "/",
      "backends": ["http://127.0.0.1:8081"],
      "lua": "if hangang.header('x-block') == 'yes' then hangang.reject(403) end"
    }
  ],
  "tcp": []
}
```

| Field | Meaning and what to change |
| --- | --- |
| `revision` | Initial configuration revision. Start at `0`; management writes use revision checks. Preserve the current revision when editing an existing installation rather than resetting it to this example. |
| `http` | HTTP route definitions. An empty array forwards no application requests. |
| `http[].id` | Stable route identifier used by the console and API. Use a unique name across HTTP, TCP, and UDP routes. |
| `path_prefix` | Request-path match. `/` matches all paths on this route; it does not strip a prefix or rewrite the upstream path. |
| `backends` | Destination URLs, including scheme and optional port. Replace the loopback demo address with a backend reachable from the gateway process. The backend must already be running. |
| `lua` | Optional request policy. This example returns HTTP 403 when `X-Block: yes` is supplied. Remove the field if this demonstration policy is unnecessary. |
| `tcp` | Raw TCP routes, each with its own listening address and backends. `[]` creates none. |

JSON does not accept comments or trailing commas. Put explanations in this
README rather than inside the configuration file. Unknown configuration fields
are rejected; use the [OpenAPI configuration schema](../docs/openapi.json) for
exact names and types.

The route defaults to enabled, priority `0`, and legacy access mode. It has no
host restriction and no user authentication policy: the Lua demonstration is
not authentication. Requests without `X-Block: yes` can reach the backend.
See [access policy](../docs/ACCESS_POLICY.md) before exposing a protected service.

## Run and verify

Run commands from the repository root. Build with `cargo build --locked`, then
start the demo backend in a separate terminal:

```sh
HANGANG_DEMO_BACKEND="$(mktemp -d)"
printf 'Hello through Hangang!\n' > "$HANGANG_DEMO_BACKEND/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$HANGANG_DEMO_BACKEND"
```

Copy the configuration into a private, writable runtime directory. Keep the
tracked example unchanged so it remains useful for future installations:

```sh
umask 077
export HANGANG_DEMO_DIR="$(mktemp -d)"
cp examples/hangang.json "$HANGANG_DEMO_DIR/hangang.json"
openssl rand -hex 32 > "$HANGANG_DEMO_DIR/admin-token"
export HANGANG_ADMIN_TOKEN="$(cat "$HANGANG_DEMO_DIR/admin-token")"
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json" --check
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json"
```

`--check` validates the configuration and Lua without starting listeners. It
does not prove that the backend is reachable or that a runtime port is free.
In another terminal:

```sh
curl --fail http://127.0.0.1:8080/
# Hello through Hangang!
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Block: yes' http://127.0.0.1:8080/
# 403
```

Open `http://127.0.0.1:9000/ui/` and create the first administrator using the
setup token from the private `admin-token` file, a username, and a password of
at least 12 bytes. The directory variable belongs to the terminal where it was
created. The token remains an administrative credential after setup; it is not
a one-time password. See [administrator accounts](../docs/ADMIN_USERS.md).

Stop the gateway and backend with Ctrl+C. Reuse the same runtime directory to
retain configuration and local account state; `mktemp` creates a different
installation each time, and temporary storage is not suitable for persistence
across host cleanup or reboot.

## Configuration file versus process and container settings

| Setting | Where it belongs |
| --- | --- |
| HTTP route hosts, paths, policies, backends | `http` in JSON. |
| Default public listener | CLI `--listen`; default `127.0.0.1:8080`. |
| Management listener | CLI `--admin`; default `127.0.0.1:9000`. This is independent of application routing. |
| Additional public HTTP/HTTPS listeners | JSON `public_http`; HTTPS also needs configured certificate material. See [public listeners](../docs/PUBLIC_LISTENERS.md). |
| TCP/UDP listening addresses | Each JSON route's `listen`. See [TCP/SNI](../docs/SNI.md) and [UDP](../docs/UDP.md). |
| Administrator setup token | `HANGANG_ADMIN_TOKEN` environment variable, separate from route JSON. |
| Published container ports and mounted files | Compose configuration; a JSON edit cannot change Docker port mappings. |
| Optional runtime policy defaults | JSON `settings`; a supplied field overrides its corresponding process value, while omitted/null fields retain that value. |

Inside a container, `127.0.0.1` means that container. A backend on another
container needs its reachable service name/address and a shared network; a
backend on the host needs an address reachable from the container. Binding the
gateway to `0.0.0.0` does not make a loopback backend address refer to the host.

## Adapt the route to your service

For two domains sharing the same backend and policy, replace the `api` route
with a route such as this fragment:

```json
{
  "id": "site",
  "hosts": ["example.com", "www.example.com"],
  "path_prefix": "/",
  "priority": 10,
  "enabled": true,
  "preserve_host": true,
  "backends": ["http://127.0.0.1:8081"]
}
```

This is one route object, not a complete configuration document. `preserve_host`
passes the incoming Host to the backend; enable it when the backend expects the
public domain. It defaults to false. Merely adding domain names does not create
DNS records, acquire certificates, or enable HTTPS. For a local test, send
`curl -H 'Host: example.com' http://127.0.0.1:8080/`.

Higher priority wins; ties use configuration order. Remove or disable the old
catch-all route if unmatched domains should not reach it. For wildcard/regex
matching and path rules, read [matching](../docs/MATCHING.md). For certificate
issuance and public TLS, read [ACME](../docs/ACME.md) and
[public listeners](../docs/PUBLIC_LISTENERS.md).

## Change a running configuration

The local-file mode watches the runtime JSON for changes. A candidate must pass
validation and runtime preparation before replacing the active configuration;
an invalid edit leaves the previous working configuration active. Check status
and logs after a change, since an edited file alone is not proof of activation.

Prefer the console or revision-checked management API for normal edits. Read
`GET /v1/config`, retain its revision/ETag, and use the documented `If-Match`
precondition for `PUT /v1/config`. A conflict means reload and reconcile the
latest configuration. Do not race file edits against UI/API writes. See
[configuration publication](../docs/CONFIG_PUBLICATION.md) and
[OpenAPI](../docs/openapi.json) for concurrency and persistence behavior.

For direct file editing, write complete valid JSON using an atomic file
replacement and retain appropriate ownership/permissions. Keep the directory
writable for sibling locks and state files. Back up the runtime configuration
and its local administrator state together; see [deployment](../docs/DEPLOYMENT.md).
Changes to security policy can intentionally revoke streams. UDP route changes
reset affected flows; UDP/QUIC process handoff remains deferred.

## Extend the example

Examples that reference services, certificates, keys, or databases require those
resources to be provisioned. They are not all standalone startup configurations.

| Goal | Example | Guide |
| --- | --- | --- |
| Shared domain policy and canonical redirects | [domain-group.json](domain-group.json) | [Canonical domains](../docs/CANONICAL_DOMAINS.md) |
| Named backends and weights | [named-members.json](named-members.json) | [Named members](../docs/NAMED_MEMBERS.md) |
| Public HTTP/HTTPS listeners | [public-listeners.json](public-listeners.json) | [Public listeners](../docs/PUBLIC_LISTENERS.md) |
| Cache configuration | [cache/hangang.json](cache/hangang.json) | [Cache](../docs/CACHE.md) |
| JSON/XML/stream transformations | [transforms/hangang.json](transforms/hangang.json) | [Transforms](../docs/TRANSFORMS.md) |
| DNS, SOCKS5, forced upstream address | [upstream guide](upstream/README.md) | [Outbound policies](../docs/UPSTREAM.md) |
| UDP or QUIC passthrough | [udp/config.json](udp/config.json) | [UDP/QUIC](../docs/UDP.md) |
| Standalone Linux IPVS DSR | [dsr/config.json](dsr/config.json) | [DSR](../docs/DSR.md); a separate companion schema, not gateway JSON. |
| Explicit application/public/protected access | [access-mode.json](access-mode.json) | [Access modes](../docs/ACCESS_POLICY.md) |
| Resource-level authorization | [resource-policy.json](resource-policy.json) | [Resource policies](../docs/RESOURCE_POLICY.md) |
| JWT authentication | [jwt-auth.json](jwt-auth.json) | [JWT](../docs/JWT_AUTH.md) |
| HTTP workload mutual TLS | [http-workload-mtls.json](http-workload-mtls.json) | [HTTP workload identity](../docs/HTTP_WORKLOAD_MTLS.md) |
| TCP workload mutual TLS | [tcp-mtls.json](tcp-mtls.json) | [TCP workload identity](../docs/TCP_MTLS.md) |
| Country filtering | [country-policy.json](country-policy.json) | [GeoIP](../docs/GEOIP.md) |
| Country lookup and observation | [geoip-observation.json](geoip-observation.json) | [GeoIP](../docs/GEOIP.md) |
| Accept-Language admission | [language-policy.json](language-policy.json) | [Language policy](../docs/LANGUAGE_POLICY.md) |
| Initial backend health gating | [initial-health.json](initial-health.json) | [Health admission](../docs/HEALTH_ADMISSION.md) |
| HTTP metadata recording | [http-recording.json](http-recording.json) | [HTTP recording](../docs/HTTP_RECORDING.md) |
| TCP completion recording | [tcp-recording/hangang.json](tcp-recording/hangang.json) | [TCP recording](../docs/TCP_RECENT_RECORDING.md) |
| TLS SNI passthrough | [sni/hangang.json](sni/hangang.json) | [SNI](../docs/SNI.md) |
| Host matching examples | [upstream/matching.json](upstream/matching.json) | [Matching](../docs/MATCHING.md) |
| Lua body and stream policies | [transforms/lua/](transforms/lua/) | [Transforms](../docs/TRANSFORMS.md) |
| Remote node observations | [fleet-observations/README.md](fleet-observations/README.md) | [Fleet observations](../docs/FLEET_OBSERVATIONS.md) |
| Local node observation demo | [fleet-observer/run.py](fleet-observer/run.py) | [Node observer](../docs/FLEET_OBSERVER.md) |
| Kubernetes import input | [kubernetes/ingress-list.json](kubernetes/ingress-list.json) | [Kubernetes](../docs/KUBERNETES.md); an input resource list, not gateway JSON. |
| External rollout planning | [enterprise-rollout.json](enterprise-rollout.json) | [rollout_plan.py](../tools/rollout_plan.py); planner input with placeholder image digest, not gateway JSON or an automatic deployment. |

## Troubleshooting

| Symptom | First check |
| --- | --- |
| Configuration rejected | Strict JSON syntax, exact field names, unique route IDs, and `--check` output. |
| Gateway starts but proxying fails | Backend availability and address from the gateway's own network namespace. |
| Route does not match | Host, path, enabled state, priority, and any named listener scope. |
| Management page unreachable | Actual `--admin` address and Docker host port; application and management ports differ. |
| Restart asks for first setup again | Whether the same config path and persistent administrator state directory were reused. |
| A valid edit does not activate | Runtime bind/certificate errors and active revision; validation alone does not guarantee preparation succeeds. |
