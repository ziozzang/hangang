# Named public HTTP and HTTPS listeners

[Documentation](README.md) · [한국어 안내](README.ko.md)

`public_http` adds independently configured public HTTP/HTTPS sockets to the existing CLI public listener. All listeners use the same configuration revision, administrator authority, route inventory and process metrics. This is one node; it does not establish fleet membership or multi-node deployment acknowledgement.

A named listener has an ASCII `id` (1–64 alphanumeric, `.`, `_`, `-` characters), nonzero socket `listen`, optional `enabled` (default true), `certificates` and `trusted_proxy_cidrs`. At most64 listeners and1,024 named certificate entries are accepted per document. The reserved ID `default` identifies the existing CLI public listener and cannot name an additional listener.

An empty certificate list means HTTP. A nonempty list means HTTPS, including a list whose certificates are all disabled: that listener rejects TLS handshakes rather than falling back to plaintext. Each set uses the existing certificate ID/host/default/enabled/file/issuer-status fields. Certificate files and keys remain on the node; PEM content is not part of API configuration. Named listeners accept at most1 MiB combined certificate/key PEM input per listener; the legacy global set retains its16 MiB limit. These limits bound accepted input, not total process memory.

## Route scope and trust

HTTP route `listener_ids` selects named public listeners or `default`. Omitted or empty scope preserves the existing CLI and dedicated workload routing behavior; it does not expose a legacy route on any named public listener. A route with dedicated `workload_auth` cannot declare public listener IDs. Unknown and repeated IDs are rejected. An inactive listener can remain referenced so its policy survives deactivation.

Listener identity comes from the accepted socket. Request headers cannot choose another listener. Scope is checked before host/path/JSON matching and before protected resource namespace checks. Protected resource scopes cannot move to a different listener set without first explicitly releasing enforcement in the existing scope. Multiple routes for the same resource must agree on their normalized listener set.

Each named listener has its own trusted-proxy CIDRs. Empty means no delegated forwarding identity, even if global/CLI settings trust that socket peer. This applies to forwarded client address and scheme, access rules, TLS requirements, authorization, cache context, and response-head recording including capacity rejections. Dedicated workload mTLS keeps its verified direct-peer identity.

## Configuration publication and connection lifetime

Configuration prepares TLS material and binds every newly required socket before publishing. A failed bind or material load retains the previous revision and active sockets. A normal edit that leaves a listener definition unchanged reuses its socket and connection generation. An active socket cannot change between TCP, workload HTTP, public HTTP and public HTTPS roles in one revision: deactivate/remove it first, then publish the new role.

Changes or withdrawal of a named listener's definition retire its connection generation. Old HTTP keepalives cannot submit requests with stale trust; SSE/WebSocket/HTTP IO observes generation retirement on a250ms check timer and closes (subject to runtime scheduling). Re-enabling an identical definition creates a fresh generation and cannot revive old connections. This is policy revocation, not a promise to finish every long-lived stream. Unchanged listeners and ordinary route/configuration updates preserve established connections, subject to existing route authentication and idle policies.

Certificate file rotation within an unchanged listener replaces its TLS resolver for subsequent handshakes. Invalid, partial or oversized replacements retain the last verified set; reload errors are logged without printing PEM content. Rotation does not itself revoke already established TLS sessions. Public TLS handshake admission is separately bounded to64 handshakes and does not consume the dedicated workload-mTLS handshake budget.

Supervisor export/import carries a separate named-public descriptor role, validates it against the frozen configuration and retains listener sockets through generation handoff. Existing private-UDS administrator deployments still cannot use the in-process supervisor; that earlier restriction is unchanged.

## API and native console

Use `GET`/`PUT /v1/config` and `POST /v1/config/validate`, with existing revision preconditions. Configuration → Public HTTP listeners provides native English/Korean add/edit/remove, activation, socket address, explicit proxy trust and certificate fields. Changes are staged until Apply configuration. HTTP route editors expose Public listener IDs and retain other route policies. The JSON document remains available for advanced edits.

Named listener policies currently require local file authority. Shared stores and controller-owned configuration reject the new listener wire format until reader capabilities and controller ownership are coordinated. `GET /v1/certificates?listener_id=<id>` selects a named listener’s certificate inventory. Omission or `listener_id=default` retains the CLI/global set. Responses identify their scope; unknown names return404 and malformed or repeated query fields return400. Named inventories never inherit the default listener’s in-process ACME status.

See the [configuration example](../examples/public-listeners.json). Creating these listeners does not automatically merge accounts or configuration from independent deployments. A migration must preserve route scope, Host behavior, certificate defaults, audit history and trusted network identities.
