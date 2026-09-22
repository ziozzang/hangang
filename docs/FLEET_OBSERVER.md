# Node observation identity

[Documentation](README.md) · [한국어 안내](README.ko.md)

The optional fleet observer exposes a small read-only document about one Hangang process. It does not publish configuration, register peers, or authorize management operations. Configure it with a private local JSON file:

```json
{
  "node_id": "edge-a",
  "token_file": "/path/to/private/observer-token"
}
```

Start Hangang with `--fleet-observer-config /path/to/private/observer.json`. The node ID is a stable operator assignment; the response also carries a process instance ID that changes on restart. A remote collector must verify its configured endpoint and credential before accepting the node ID. The file and token must be private regular files owned by the process user or root, without group or other permissions. The token is a distinct 48–256 character ASCII value of letters, digits, `-` or `_`; one final newline is allowed. Reusing the administrator token is rejected. The JSON file is limited to 16 KiB.

Hangang checks the files about once per second. Atomic token replacement rotates access without a route change or restart. Missing or invalid material withdraws observer access until corrected. A node ID change requires a process restart; the running process will not silently adopt another identity. Filesystem scheduling means the polling interval is not a guaranteed revocation deadline.

`GET /v1/fleet/observation` requires the dedicated observer bearer credential. Its fixed, noncacheable response contains the node ID, process instance ID, observer generation, configuration source, revision and digest, readiness, and optional store epoch. It does not contain routes, traffic records, accounts, or credentials. The observer token cannot read or change management state.

`GET /v1/fleet/observer-status` requires administrator access. The Operations panel shows whether this instance's observer identity is disabled, available, or unavailable, without exposing the credential or its path. Observer generation is process-local: interpret it together with the instance ID. Reported readiness and configuration digest are observations, not proof that other nodes activated the same configuration.

To collect remote observations, use the separate [HTTPS peer inventory](FLEET_OBSERVATIONS.md). Keep machine credentials separate from administrator and browser session tokens.
