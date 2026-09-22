# Docker discovery

[Documentation](README.md) · [한국어 요약](ko/DOCKER.md)

Hangang can resolve HTTP and TCP backends from Docker container metadata. Enable it by passing the Docker Unix socket to the daemon:

```console
hangang --config /etc/hangang/config.json \
  --docker-socket /var/run/docker.sock
```

A Docker backend uses this exact form:

```text
docker://CONTAINER/NETWORK/PORT
```

For example, an HTTP backend of `docker://api/edge/8080` resolves to `http://<container-ip>:8080`. A TCP backend of `docker://postgres/edge/5432` resolves to `<container-ip>:5432`.

`CONTAINER` and `NETWORK` must be 1 to 128 characters. The first character must be ASCII alphanumeric; later characters may also contain `_`, `.`, or `-`. `PORT` must be a canonical decimal integer from 1 through 65535, without a leading zero. The reference must have exactly these three path components. Other backend strings retain their normal static behavior.

Hangang performs an initial refresh before it begins serving and refreshes the runtime discovery table every second. It inspects at most eight containers concurrently. The configured `docker://` reference remains unchanged, so address changes do not modify the active configuration or its revision.

Only containers reported as running and attached to the named network are published. A stopped or removed container, a missing network or IP address, or an inspect error removes that mapping on the next refresh. Requests then fail closed because the backend is unavailable. A later successful refresh restores the mapping. The container IP must be reachable from the network namespace where Hangang runs.

Docker inspection uses bounded requests: the resolver has a three-second request timeout and accepts at most 1 MiB per response. Hangang calls the read-only container inspection endpoint; it does not start, stop, execute in, or modify containers. Access to a Docker daemon socket is nevertheless highly privileged in typical deployments. Limit filesystem access to the socket and consider a least-privilege Docker socket proxy when possible.

The admin `POST /v1/docker/resolve` endpoint remains available for explicit inspection diagnostics. Dynamic route discovery does not require calls to that endpoint.

The discovery tests use a fake Unix-socket Docker API. They cover address changes, stopped and removed containers, strict reference parsing, native backend passthrough, the eight-inspection concurrency limit, and configuration-revision stability without creating real containers.

## Connection management UI and API

The **Docker** console page manages a single active Docker daemon connection per Hangang instance. It supports local Unix sockets and remote HTTPS with mutual TLS. **Test connection** sends Docker `GET /_ping` for the current draft without saving it. **Save connection** atomically persists and activates the draft for new discovery operations. **Resolve backend** uses the saved connection and returns the container network address; it does not test application connectivity to that address.

- `GET /v1/docker/connection`: active configuration, source, revision and ETag.
- `PUT /v1/docker/connection`: save a connection with `If-Match` matching the current revision.
- `DELETE /v1/docker/connection`: remove the managed override and restore the process default, or disable when no default exists.
- `POST /v1/docker/connection/test`: test a candidate without saving.

All four operations require administrator access. A saved `{"transport":"disabled"}` explicitly disables Docker even when a CLI default is present. Connection file paths refer to the gateway filesystem and must be accessible there. Certificates and keys are never returned by the API; only file references are returned. The client private key must be a private regular file owned by the gateway process. Remote endpoints must be HTTPS origins without URL credentials, paths or queries. Redirects and environment proxy inheritance are disabled, and daemon certificate verification cannot be skipped.

A remote connection request looks like:

```json
{
  "transport": "https",
  "url": "https://docker.example.com:2376",
  "ca_file": "/data/docker-tls/ca.pem",
  "client_cert_file": "/data/docker-tls/cert.pem",
  "client_key_file": "/data/docker-tls/key.pem"
}
```

A Unix connection request is `{"transport":"unix","socket_path":"/run/hangang/docker/docker.sock"}`. The socket must already be accessible to the gateway; a UI setting cannot create a host mount or grant daemon permission. No daemon connection is silently enabled by installing this release. Docker connection configuration is instance-local and is separate from shared route configuration. Saving or disabling a connection invalidates old discovery generations immediately, preventing an in-flight lookup from republishing an old daemon's address.

The implementation only calls daemon ping and container inspect. It does not start or stop containers, execute commands, publish Docker ports or provide an unrestricted Docker API tunnel. Docker documents Unix, SSH and TLS access; this implementation supports Unix and verified mutual TLS. [Docker daemon access protection](https://docs.docker.com/engine/security/protect-access/)

## TCP ports and container networking

A TCP route binds in Hangang's network namespace. In Docker bridge mode, a successful route creation does not publish the listener on the host. Bind to `0.0.0.0:PORT` and publish the port in the container deployment; a listener bound to `127.0.0.1` is container-local. Linux host networking removes this publication step but changes DNS, port ownership and proxy identity. See the [deployment template](DEPLOYMENT.md).

Connection state defaults to the full route configuration filename plus `.docker-connection.json`. `--docker-connection-state /private/instance/docker.json` selects another instance-local path; an exclusive writer lock prevents two instances from modifying the same sidecar. Shared route-store replicas must choose separate local state paths if they share a bootstrap config path. Corrupt connection state disables Docker, including any CLI fallback, until an explicit administrator repair.

Supervised restarts freeze Docker writes and pass the sidecar lock to the next generation. The DockerLock handoff descriptor requires a supervisor that understands this release; update the supervisor binary before using this feature through a long-lived older supervisor. Container replacement restarts the supervisor/binary together and does not use this descriptor handoff.
