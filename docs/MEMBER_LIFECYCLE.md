# Member lifecycle controls

[Documentation](README.md) · [한국어 안내](README.ko.md)

Named HTTP and TCP members under local-file configuration accept `desired_state: serving`, `draining`, or `maintenance`. Edit the state in the HTTP/TCP member editor and save the revision-checked configuration. All member changes in that document publish atomically with the normal configuration transaction. Legacy string members behave as serving. Shared ConfigStore named documents remain rejected pending fleet reader capability coordination.

- `serving`: allows new backend admissions subject to health, route enablement and policy.
- `draining`: blocks new backend admissions while existing HTTP bodies, upgraded tunnels and established TCP streams finish. Health probes continue.
- `maintenance`: the same admission hold, also suspending active HTTP/TCP probes. It persists until explicitly changed. Probe monitors reconcile the published snapshot asynchronously; an already dispatched probe may complete while that reconciliation runs.

A changed desired state gets a fresh generation. Preparation never closes a currently serving gate. After successful persistence, publication retires displaced gates immediately before exposing the successor. Held owners remain tracked in `/v1/retired-members`. Returning to serving creates a new gate and fresh initial health; old probes and owners cannot reopen an old gate. An unchanged state may retain compatible nodes across reorder or weight edits.

A pending TCP dial retired before its final gate check is rejected before forwarding application bytes. Retirement can race after that check: this is not synchronous revocation of already admitted work. HTTP Lua selection by member ID, configured address or returned address must pass the same final admission gate. Automatic balancing skips held members; a Lua-pinned selection fails rather than falling back to an unapproved member. Cache hits do not need a backend admission and may still be served.

`GET /v1/operations` reports `desired_state`, `admission_open`, and `active_admissions` for each current generation, alongside health and the route's `enabled` flag. `admission_open` is the member generation gate only; a disabled route or failed health can still make the member unavailable. TCP admissions include pending dials; the existing named `member_active_streams` counter instead aggregates established streams across continuously present logical IDs. Outstanding previous generations have their own retired table.

A current zero does not mean the logical member or fleet is drained. Inspect retired generations as well; the observations are local and can change between requests. No aggregate `drained`/`maintenance_ready` assertion, per-member deadline, forced close or distributed coordination is provided yet. The bounded retired registry may reject preparation when its 4096 slots cannot cover the worst case. No production rollout is implied by source support.
