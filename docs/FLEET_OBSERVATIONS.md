# Authenticated remote node observations

[Documentation](README.md) · [한국어 안내](README.ko.md)

A Hangang collector can poll an explicitly configured set of peer [observer endpoints](FLEET_OBSERVER.md) over verified HTTPS. Collection is read-only: it does not distribute configuration, change peers, or decide fleet health or rollout completion.

```json
{
  "peers": [
    {
      "node_id": "edge-a",
      "group_id": "edge",
      "role": "gateway",
      "endpoint": "https://edge-a.example.test:9443",
      "token_file": "/path/to/private/edge-a.token",
      "ca_file": "/path/to/private/fleet-ca.pem"
    }
  ]
}
```

Pass the inventory file with `--fleet-inventory-config /path/to/private/fleet.json`. The inventory is limited to 128 KiB and 64 peers; node IDs and HTTPS origins must be unique. The endpoint is an origin without credentials, path, query, or fragment. The collector requests only `/v1/fleet/observation`, does not follow redirects or use environment proxies, and verifies the hostname and certificate. Optional `ca_file` replaces the normal trust roots for that peer; it is limited to 128 KiB and 32 certificates. The inventory and referenced credentials must be private files owned by the process user or root.

`group_id` and `role` are optional operator labels. Each uses 1–64 ASCII letters, digits, `.`, `_`, or `-`; omitted labels appear as `null`. They are for display and local filtering, not verified workload roles or authority. A label or credential change creates a new local inventory generation and withdraws prior samples. Invalid or missing material makes coverage unknown until a valid inventory is restored. These changes do not change route configuration or forwarding readiness.

The collector checks files about once per second and polls at most four peers concurrently. Each request has a three-second deadline and 16 KiB response-body limit; a peer is normally eligible every 30 seconds. Results are bounded local observations, not a simultaneous snapshot or a guaranteed fleet-wide deadline. A sample is fresh for less than 60 seconds using the collector's monotonic clock. `fresh_nodes` counts fresh responses even when a peer reports `ready:false`; it is a reporting count, not a health count.

| Condition | Meaning |
| --- | --- |
| `unknown` | No accepted sample yet. |
| `fresh` | An accepted response from the expected peer identity is recent; inspect reported readiness separately. |
| `stale` | The last accepted sample has aged out. |
| `unavailable` | The latest poll failed; any retained sample is historical. |
| `identity_mismatch` | The endpoint reported a different node ID; any retained sample is historical. |

`GET /v1/fleet/observations` requires administrator access and returns the current bounded collector snapshot without initiating a poll. Its `observer_instance_id` identifies the collector process; `generation` is meaningful only within that process. Configured-but-unavailable inventory has unknown coverage (`null` expected/fresh counts), distinct from a valid empty inventory (zero counts). The response contains neither tokens nor local file paths.

The English/Korean Operations panel shows peer origins, optional labels, conditions, age, coverage, and last accepted observation. It polls while visible and marks retained data as historical after refresh failure. The browser never receives peer credentials. This view does not establish durable membership, centralized authority, activation receipts, or drain decisions.
