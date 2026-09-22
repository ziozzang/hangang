# Deploy a single Hangang gateway with Docker Compose

This template runs one gateway with an HTTP listener and a local management port. It starts with no routes and no named HTTPS or TCP listeners. The sample configuration does not point to any real service. It is not the configuration of any existing deployment.

The repository [Dockerfile](../Dockerfile) packages the static `hangang` binary only. Build that binary on Linux x86_64 first, then build the image from the repository root:

```sh
make static
docker build -t hangang:local .
```

Create the runtime files beside [compose.yaml](../deploy/compose.yaml). Generate a unique random administrator token, and keep it out of version control and terminal output. The gateway reads `HANGANG_ADMIN_TOKEN` from the private environment file:

```sh
cp deploy/.env.example deploy/.env
mkdir -p deploy/state
cp deploy/hangang.example.json deploy/state/hangang.json
umask 077
{ printf 'HANGANG_ADMIN_TOKEN='; openssl rand -hex 32; } > deploy/admin.env
chmod 600 deploy/.env deploy/admin.env
chmod 700 deploy/state
chmod 600 deploy/state/hangang.json
sudo chown -R 65532:65532 deploy/state
```

The example image runs as UID/GID 65532. If you change `HANGANG_UID` and `HANGANG_GID` in `deploy/.env`, give that user ownership of `deploy/state` instead. Hangang must be able to create a sibling config writer lock and its private administrator SQLite database under `/data`; a read-only config bind mount is insufficient. Back up the config and `hangang.json.admin` directory together. Do not place the account database on a shared network filesystem.

The environment file keeps the token out of the Compose template and command line, but Docker administrators can inspect container environment values. Restrict access to the Docker daemon and to `deploy/admin.env`. Once ownership changes, edit the state file through the authenticated management API or with an explicitly privileged file operation; the host user may no longer read it.

Validate the Compose model without printing its resolved environment and check the config with the built binary:

```sh
docker compose --env-file deploy/.env -f deploy/compose.yaml config --quiet
./target/x86_64-unknown-linux-gnu/release/hangang \
  --config deploy/hangang.example.json --listen 127.0.0.1:8080 --check
```

Start the gateway:

```sh
docker compose --env-file deploy/.env -f deploy/compose.yaml up -d --no-build
```

`http://127.0.0.1:8080/healthz` is the public readiness path configured by the sample. Management is published only at `http://127.0.0.1:49000/ui/`. The gateway binds management on the container interface using `--allow-insecure-admin` because Docker forwards the host loopback port into the container; management traffic is plaintext on that local bridge. Keep the host publish address at `127.0.0.1`, do not expose port 49000 through a firewall or reverse proxy, and use TLS or the private Unix-socket relay design for remote administration. Use the installation token to bootstrap an administrator account as described in [administrator accounts](ADMIN_USERS.md).

Edit `deploy/state/hangang.json` or publish changes through the authenticated management API. For a route example, add an `http` item with an example-only backend such as `http://backend.example.invalid:8080`; replace it with an actual reachable service address before expecting successful proxy responses. Route and listener syntax is documented in [matching](MATCHING.md) and [public listeners](PUBLIC_LISTENERS.md).

Named listeners are configured in `public_http` and need matching Docker `ports` entries. A named HTTPS listener also needs readable certificate/key files mounted into the container at the configured paths. If changing listener ports or adding TCP listeners, publish those ports explicitly and restart Compose after editing the port mappings. Avoid binding the public port to a non-loopback host address until route, TLS, and firewall policy are set. The default CLI listener remains the single `--listen` port above. This single-node template does not configure a shared store, fleet collection, ACME, or a Kubernetes controller.
