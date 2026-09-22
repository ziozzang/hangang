# Fleet observation examples

Run `make test-fleet` from the repository root after installing the browser test dependencies (`cd web && npm ci && npx playwright install chromium`). The owned examples use temporary private files, loopback listeners and short-lived child processes. OpenSSL must be available. They never contact production peers or print credentials.

The sequence demonstrates a dedicated observer token, live rotation and withdrawal, verified HTTPS collection from three peers, native English/Korean UI, identity and TLS failures, historical samples, inventory relabeling, and removal. A prior successful sample is not current evidence after a failed request. Group and role values are operator-assigned labels, not authenticated execution roles or available capacity. The HTTPS example waits for the collector's real polling interval.

An operator-managed inventory can include:

```json
{
  "peers": [
    {
      "node_id": "edge-a",
      "group_id": "region-east",
      "role": "gateway",
      "endpoint": "https://edge-a.example.net:9443",
      "token_file": "/private/hangang/edge-a.token",
      "ca_file": "/private/hangang/fleet-ca.pem"
    }
  ]
}
```

Start the collector with `--fleet-inventory-config /private/hangang/fleet.json`. Both labels are optional; omitted labels appear as null. Inventory and referenced files must be private and owned by the process user or root. The token is the peer's dedicated observer credential; the HTTPS identity must match the origin and expected node ID. An explicit CA replaces the public trust-root set for that peer.

Atomic inventory replacement is detected dynamically. Changing a label starts a new inventory generation and retires its prior samples; malformed labels withdraw the inventory and make coverage unknown. Restoration resumes collection. The Operations panel filters locally by group while retaining the full-inventory reporting headline.

See the [collector contract](../../docs/FLEET_OBSERVATIONS.md) for limits and authority boundaries. These examples establish functional behavior, not maximum fleet size performance or commercial product superiority.
