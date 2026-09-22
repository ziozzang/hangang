# Admin API and console coverage

This matrix compares the published operations in `docs/openapi.json` with the embedded console. “Automatic” means the page invokes the operation as part of a visible workflow; it is not an arbitrary API request form. The API reference only displays the schema and does not count as a control for other operations. `web/tests/api_ui_coverage.spec.js` checks that every management operation remains mapped to a real UI selector and caller. The separately authenticated machine observation endpoint is explicitly inventoried as machine-only; the console manages its visible status through the administrator status endpoint and never receives its credential.

| Method and path | Console feature and control | Access / behavior |
| --- | --- | --- |
| `GET /openapi.json` | API reference view | Public schema, displayed on demand |
| `GET /healthz` | Diagnostics → Check health | Authenticated readiness check |
| `GET /metrics` | Diagnostics → Load Prometheus metrics | Authenticated text metrics |
| `GET /v1/cache` | Cache view and refresh | Admin cache policy and counters |
| `GET /v1/certificates` | Certificates → listener selector and paged certificate inventory | Admin-only file/issuer metadata; scope-bound edits and stale-response rejection; visible-view refresh every 30 seconds |
| `GET /v1/geoip/status` | Configuration → GeoIP database source → Refresh local GeoIP status | Admin-only, on-demand observation from this instance; readiness is separate from the configured path and other nodes |
| `GET /v1/geoip/lookup` | Configuration → GeoIP database source → Look up country | Admin-only, explicit IPv4/IPv6 address query against this instance's ready database; unavailable differs from unknown country |
| `POST /v1/cache/purge` | Cache → Purge cache, confirmation | Admin mutation |
| `GET /v1/events` | Status → live stream indicator and chart | Automatic SSE with Bearer header |
| `GET /v1/traffic` | Status → Recent requests | Automatic admin-only bounded metadata snapshot; accepted listener scope, EN/KO and search ([details](HTTP_TRAFFIC_LISTENERS.md)) |
| `GET /v1/connections/tcp/active` | Status → Active TCP connections, refresh and next page | Admin-only best-effort active page; IDs and byte counters remain decimal strings |
| `GET /v1/connections/tcp/recent` | Status → Recent TCP completions, refresh | Admin-only bounded completion history; separate event cursor and local TTL |
| `GET /v1/fleet/observations` | Operations → Fleet observations, operator group/role labels, local group filter, reporting coverage and refresh | Admin-only cached HTTPS peer observations, producing collector process identity, current failures and historical samples; no browser-held peer credentials |
| `GET /v1/fleet/observer-status` | Operations → Node observation identity and refresh | Admin-only local availability, assigned ID and credential generation; no remote collection |
| `GET /v1/fleet/observation` | Machine-only observation; native Operations panel shows the corresponding local capability | Dedicated observer bearer only; intentionally never sent from the browser |
| `GET /v1/operations` | Operations → target table, refresh and paging | Admin-only, instance-local target state |
| `GET /v1/retired-members` | Operations → Retired members table, independent refresh and paging | Admin-only; active retired generations on this instance, not drain completion |
| `GET /v1/status` | Status dashboard and Refresh | Admin or viewer |
| `POST /v1/lifecycle/restart` | Status → Graceful restart, confirmation | Admin; shown only when supervised |
| `GET /v1/update/status` | Status → signed update state | Admin or viewer, automatic |
| `POST /v1/update/check` | Status → Check and apply update, confirmation | Admin; shown only when updater enabled |
| `GET /v1/config` | Configuration → JSON document and native settings, including ordered HTTP recording rules | Admin; also refreshes editor bases |
| `PUT /v1/config` | Configuration → Apply configuration | Admin; conditional `If-Match` write |
| `POST /v1/config/validate` | Configuration → Validate; route rejection explanation | Admin; no publish |
| `GET /v1/routes/http` | HTTP routes inventory and Refresh | Admin |
| `POST /v1/routes/http` | HTTP routes → New HTTP route → Create route | Admin |
| `GET /v1/routes/http/{id}` | HTTP routes → Edit, refreshes selected route | Admin |
| `PUT /v1/routes/http/{id}` | HTTP routes → Edit → Save route | Admin; conditional revision |
| `DELETE /v1/routes/http/{id}` | HTTP routes → Edit → Delete route, confirmation | Admin |
| `GET /v1/routes/tcp` | TCP routes inventory and Refresh | Admin |
| `POST /v1/routes/tcp` | TCP routes → New TCP route → Create route | Admin |
| `GET /v1/routes/tcp/{id}` | TCP routes → Edit, refreshes selected route | Admin |
| `PUT /v1/routes/tcp/{id}` | TCP routes → Edit → Save route | Admin; conditional revision |
| `DELETE /v1/routes/tcp/{id}` | TCP routes → Edit → Delete route, confirmation | Admin |
| `GET /v1/docker/connection` | Docker → connection state and Reload saved settings | Admin; shows saved override or process default |
| `PUT /v1/docker/connection` | Docker → Save connection | Admin; conditional revision write |
| `DELETE /v1/docker/connection` | Docker → Use process default | Admin; removes saved override |
| `POST /v1/docker/connection/test` | Docker → Test connection | Admin; tests the draft Docker daemon connection without saving |
| `POST /v1/docker/resolve` | Docker → Resolve container; also route editor helper | Admin; resolves an address only |
| `POST /v1/util/hash-password` | Utilities → Generate credential; also HTTP route editor helper | Admin; password is not mirrored into route JSON |
| `GET /v1/auth/setup` | Login → first-run setup or account sign-in screen | Public, automatic discovery |
| `POST /v1/auth/bootstrap` | First-run Create administrator form | Existing administrator bearer token required |
| `POST /v1/auth/login` | Account Sign in form | Public; session token stays in this tab |
| `GET /v1/auth/me` | Status → Verify my session; signed-in identity and role | Account-session revalidation, automatic and manual |
| `POST /v1/auth/logout` | Log out | Revokes account session; bearer-token sign-out clears browser state |
| `GET /v1/audit/users` | Account audit → ordered pages and current-page JSON export | Admin-only; successful local account changes, explicit coverage and capacity |
| `POST /v1/audit/users/prune` | Account audit → prune through current page, confirmation | Admin; latest-sequence precondition and durable prune event |
| `GET /v1/users` | Users → account list | Admin |
| `POST /v1/users` | Users → Create user | Admin |
| `PUT /v1/users/{id}` | Users → Save changes on account card | Admin |
| `DELETE /v1/users/{id}` | Users → Delete user, confirmation | Admin |

The unversioned `/healthz`, `/metrics`, and `/openapi.json` paths above are part of the admin listener API. `/ui` redirects to `/ui/`; `GET`/`HEAD` of `/ui/`, `/ui/index.html`, the embedded JS/CSS, and locale modules serve public console assets. The public listener has its own configurable readiness path. There are no additional `/status`, `/config`, or `/routes` aliases in the current admin router.

The Docker page can test whether Hangang can reach the configured Docker daemon. The route-editor dialog and Docker page also call `POST /v1/docker/resolve` and can insert the resulting endpoint into a route. Resolution does **not** prove that the target container's application accepts TCP connections or completes a TLS handshake. The daemon test and target reachability are separate checks.

Creating a TCP route binds its `listen` address inside the Hangang runtime. In Docker, the default `0.0.0.0:9001` accepts connections on the container network, but host or internet clients also need that port published in Docker and allowed by the host firewall. A route API write does not change an existing container's published ports.

Existing Playwright `ui.spec.js`, `auth-actual.spec.js`, `console.spec.js`, `operations.spec.js`, and `route_inventory.spec.js` exercise the major workflows. The coverage test guards the operation inventory and UI call sites; it does not replace backend authorization or network tests.

HTTP route CRUD and full-configuration APIs also carry `access_mode`. The dedicated HTTP editor selector and Security classification implement this field in EN/KO; server validation rejects contradictory modes and removal of the last authenticator from a protected route. See [access policy](ACCESS_POLICY.md). This does not add an operation or establish complete Zero Trust.

The HTTP route editor enhances policy and request/response Lua fields with the [embedded Lua editor](../web/LUA_EDITOR.md). It uses the existing route read/write API and introduces no execution endpoint. Context-specific completions mirror the actual worker API; saving still performs server-side route validation.

HTTP routes also provide native EN/KO active and passive health-policy forms,
including initial `checking` admission, probe path/Host, timing, status sets and
thresholds. Operations distinguishes the initial pending gate from later
unhealthy exclusion using `initial_check_pending`. Older servers without that
field retain generic observation labels. See [health admission](HEALTH_ADMISSION.md).

TCP routes expose every optional transport-health policy field through the
native EN/KO editor. Operations labels `active_tcp` as transport checks, with
independent first-check pending and probe-observed state. See [TCP health](TCP_HEALTH.md).

HTTP and TCP route editors also offer explicit conversion from legacy string
backend arrays to named members with stable IDs, addresses and per-member
weights. Existing string arrays retain their representation until conversion.
The HTTP editor transfers positional `balance.weights` into members and clears
the legacy weight vector. Named-member rows expose `serving`, `draining`, and
`maintenance`: draining closes new admissions while existing work continues;
maintenance also stops probes. Reverse conversion to legacy addresses is
blocked until all members are serving, so it cannot silently reopen admission.
Named members require a
local-file configuration authority because mixed-version shared-store readers
cannot safely consume the new wire format. Operations shows `member_id` when
reported and keeps the configured address, effective weight, desired state,
local admission gate, and current admission leases visible. These are
instance-local observations, not fleet drain-completion or force-close controls.

`GET /v1/config/operations` has a dedicated EN/KO configuration-operation history view with bounded paging, current-page export and a revision-consistent full retained-history export. It distinguishes durable acceptance from local candidate activation and unresolved outcomes. `POST /v1/config/operations/prune` has explicit archive/retention confirmation and revision fencing; it preserves unresolved operations and does not automatically retry or activate a fleet.

`GET /v1/config/operation-proof` has an independent EN/KO current-store proof panel in Change history with manual refresh and server observation time. It shows SQL epoch/revision/operation stamp, unsupported stores, absent current proof and unavailable reads separately. It does not infer local-history ownership, activation or fleet acknowledgement; logout/navigation scrubs late responses.

`GET /v1/config/commit-receipt` has a dedicated EN/KO historical SQL commit lookup in Change history. The administrator supplies acceptance authority and operation IDs; the panel distinguishes a retained receipt, absence, unsupported stores and unavailable reads, and reports receipt capacity. It does not change local outcomes or initiate replay. Safe receipt pruning and export remain unfinished.

`GET /v1/config/commit-receipt-v2` has a distinct EN/KO sequenced mode, high-water and authority-registry capacity display. Journal receipt-version labels and raw export fields keep V1/V2 identities separate; missing versions from older servers are explicitly legacy V1. See [sequenced receipts](SEQUENCED_SQL_RECEIPTS.md).

`GET /v1/config/commit-receipts-v2` has a dedicated EN/KO V2 retained receipt export in Change history, with bounded snapshot-prefix paging, stale-response invalidation and a final retention-fence probe. V1 export and safe pruning remain unfinished.

HTTP route CRUD includes native EN/KO `language_policy` controls (mode, allow/deny ranges, missing-header behavior and enforcement). The filter runs before cache/Lua/origin and is not country or identity authorization. HTTP and TCP inventory rows also expose confirmed deletion using the displayed revision; conflicts require a new confirmation and server-side protected-resource checks still apply.

`POST /v1/config/operations/release` has a dedicated per-operation EN/KO recovery action. It displays protected/pending/acknowledged state, requires explicit confirmation, rejects stale session/view responses and does not automatically replay a failed request. Local pruning keeps V2 records without durable release acknowledgement. This action releases protection only; SQL receipt deletion, archival verification and capacity recovery remain separate. See [V2 completion acknowledgement](SQL_RECEIPT_RELEASE.md).

`GET` and `PUT /v1/audit/policy` have a native EN/KO editor within Account audit. Default record/drop, ordered rules, action/actor/target conditions, revision-CAS confirmation and cumulative omission display are implemented. Policy-change snapshots remain exportable. This account policy does not filter HTTP/TCP observations or recovery journals.


This operation mapping does not establish full response-field coverage. Operations preserves unknown balance/health modes and unreported capability/configuration authority instead of inventing round-robin, unmonitored, disabled or local-file states. Invalid paging envelopes and target rows retain an explicitly stale prior snapshot.

Status also exposes nine additional existing security counters in a native EN/KO diagnostics section: JWT/HTTP mTLS/TCP mTLS/workload rejections, JWT unavailability/capacity, and HTTP mTLS/TCP mTLS/workload stream terminations. The JWT stream termination summary remains separate. Counts are cumulative for this instance, with exact safe integers and explicit unknown values; they do not establish a persistent audit trail or fleet totals. SSE updates and logout scrubbing use the existing authenticated status lifecycle.

General public HTTP/HTTPS listeners are now edited natively through Configuration → Public HTTP listeners using existing configuration APIs. HTTP route editors expose public listener IDs; default/unknown scope, per-listener trust, certificate fields, activation and failed publication behavior are covered in [the contract](PUBLIC_LISTENERS.md). This remains one-node local-file configuration; fleet authority and listener-specific certificate inventory are separate follow-ups.

TCP recent-completion recording has dedicated ordered EN/KO controls under Settings, separate from HTTP/account recording. Recent records display available recording revisions, and intentional omissions have their own counter. Active inventory remains unfiltered. See [TCP completion recording](TCP_RECENT_RECORDING.md).

The HTTP route editor exposes `canonical_domain` as native EN/KO controls for active state, exact member host, scheme, status, methods and segment-boundary include/exclude paths. Saving still uses existing route CRUD with revision fencing. The redirect is an operator policy, not cookie/session sharing or proof that merging routes preserves upstream Host behavior.
