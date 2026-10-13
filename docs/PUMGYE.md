# Independent Pumgye authority

[한국어](ko/PUMGYE.md)

Pumgye owns policy storage, compilation, CAS publication, revision and audit.
Hangang owns route service/method/class bindings and request enforcement, and
hosts administrator controls through a fixed owning-domain delegation.

Configure `pumgye_authority` at the configuration root. It is mutually exclusive
with the earlier embedded `pumgye` policy. Remote endpoints require mTLS; local
plaintext may only use loopback. Example references use synthetic names and do
not contain credentials:

```json
{
  "decision_address": "192.0.2.10:9085",
  "management_address": "192.0.2.10:9084",
  "decision_token_env": "PUMGYE_DECISION_TOKEN",
  "admin_token_env": "PUMGYE_ADMIN_TOKEN",
  "tls": {
    "server_name": "pumgye.example.test",
    "ca": "/private/pumgye/ca.pem",
    "certificate": "/private/pumgye/gateway.pem",
    "key": "/private/pumgye/gateway.key"
  },
  "pool_size": 64,
  "timeout_ms": 100,
  "minimum_revision": 1
}
```

The native client verifies the fixed endpoint's name/CA, presents its client
certificate, authenticates a decision credential and reuses bounded persistent
PPG1 connections. Common single-permission decisions avoid batch allocations;
multiple required permissions use at most 64 correlated requests. Unknown service,
guest, unavailable/fail-open/observe network evidence and rights/class/AAL mismatch
cannot grant. This path uses verified native Hopae headers and fresh Guard evidence,
not caller claims. Protection bypasses response/auth caches.

The native policy probe runs every 500 ms, preserving the observed monotonic
revision and a 1-second authority freshness bound. Protected streams retire on
revision change, authority loss/expiry or Hangang configuration retirement, including
publications made directly at Pumgye. This does not yet implement distributed
membership, persisted observed revision watermarks, authority-incarnation pinning
or Hopae/session/Guard stream revocation across the complete fleet.

The native Pumgye console reads and writes its owning policy rather than replacing
Hangang's configuration. These Hangang APIs require a live administrator; Viewer
and anonymous access is denied:

- `GET /v1/pumgye/policy`, `/v1/pumgye/status`, `/v1/pumgye/audit`.
- `PUT /v1/pumgye/policy`: JSON `{revision, policy}`, quoted Pumgye revision in
  `If-Match` and quoted Hangang authority configuration revision in
  `X-Hangang-Config-Revision` (returned by reads).

Both scope fences are required. Admission is serialized with account revocation;
admitted external publication continues if the browser disconnects. Re-read after
an unconfirmed operation rather than assuming rollback. Live role and selected
authority are rechecked before disclosure. Paths, methods, response sizes, body
sizes, concurrency and redirects are restricted; no client URL, credential or
arbitrary header is relayed. Data-plane nodes may omit the local administrator
secret; policy enforcement works while management fails closed. Owning Pumgye
records its verified transport caller; individual delegated user audit remains
subsequent work.

The earlier embedded policy is a migration baseline, not the new policy owner.
There is no automatic assignment/grant or automatic schema/DB transfer. Validate
and publish any migration into the owning Pumgye authority before enabling routes.

Qualification includes library and existing administrator/config/resource tests,
OpenAPI references, browser owner/CAS/logout fences and actual Hangang/Pumgye mTLS
processes with owned HOP1/HGD1 peers. Real Hopae/Sumunjang remote transports, mixed
authentication, realistic-cardinality traffic and whole-stack 100k HTTP QPS remain
separate acceptance work.
