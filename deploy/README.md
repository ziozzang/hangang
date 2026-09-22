# Deployment configuration templates

[Detailed deployment guide](../docs/DEPLOYMENT.md) · [JSON walkthrough](../examples/README.md) · [한국어 설정 안내](../examples/README.ko.md)

This directory contains a single-node Docker Compose starting point. Follow the
[deployment guide](../docs/DEPLOYMENT.md) for the complete build, ownership,
validation, startup, and administrator setup commands.

| File | Purpose |
| --- | --- |
| [hangang.example.json](hangang.example.json) | Empty gateway configuration to copy to private runtime storage. |
| [compose.yaml](compose.yaml) | Container image, listener arguments, port publication, private state mount, and runtime user. |
| [.env.example](.env.example) | Compose substitution variables; copy to `.env` and adjust paths, ports, and UID/GID. |
| `admin.env` (create locally) | Private `HANGANG_ADMIN_TOKEN` value. Separate from `.env` and route JSON; ignored by Git. |
| `state/` (create locally) | Writable runtime JSON and adjacent account/lock state; ignored by Git. |

## Read the initial JSON

```json
{
  "revision": 0,
  "settings": { "health_path": "/healthz" },
  "http": [],
  "tcp": []
}
```

- `revision: 0` starts a new installation. Do not reset a running installation's revision when adding routes.
- `settings.health_path` reserves `/healthz` as a public, unauthenticated readiness endpoint. Its success does not prove an application backend is healthy.
- `http: []` configures no application HTTP routes. A healthy empty deployment is therefore not yet an application proxy.
- `tcp: []` creates no TCP route listeners. Omitted `udp` likewise creates no UDP listeners.

Add application routes through the console or edit the runtime copy after
reading the [field-by-field JSON guide](../examples/README.md). Do not point a
container route at `127.0.0.1` unless its backend runs in that same container.
Use a reachable service address and the correct backend protocol and port.

## Addresses and persistence

The template listens inside the container on `0.0.0.0:8080` for public HTTP and
`0.0.0.0:9000` for management. Defaults publish these on the host at
`127.0.0.1:8080` and `127.0.0.1:49000`, respectively. Open the console at
`http://127.0.0.1:49000/ui/` on that host. Changing `HANGANG_PUBLIC_PORT` or
`HANGANG_ADMIN_PORT` changes host publication, not the internal listener ports.

The writable state directory is mounted at `/data`. The non-root runtime user
must be able to create adjacent locks and administrator state, so mounting only
a read-only JSON file is insufficient. Preserve this directory across container
replacement. Keep private runtime files out of the public repository.

Additional HTTP/HTTPS, TCP, and UDP listeners require corresponding Docker port
mappings. UDP publication must explicitly use `/udp`. JSON reload does not
change container networking. The initial template does not enable TLS, ACME,
shared configuration storage, or supervised in-place binary updates; configure
those features according to their linked guides before relying on them.
