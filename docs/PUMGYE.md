# Independent Pumgye authority

[Documentation](README.md) · [한국어](ko/PUMGYE.md)

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

## Service principals

Native Hopae nonhuman authentication uses one `x-hopae-principal-kind: service`
or `x-hopae-principal-kind: workload`,
`x-hopae-aal: 0` and a canonical `s_` plus 48 lowercase hexadecimal subject.
The authenticated `x-hopae-service-id` must match the Pumgye gate exactly.
Legacy human evidence retains AAL 1–3; service/workload namespaces cannot become human
assurance, and unknown/duplicate/contradictory typed metadata fails closed.
Canonical workload AAL 0 is supported; network-only principals remain unsupported.
Hopae must verify the workload source and its own publication/revocation fences;
these headers are accepted only from the authenticated native Hopae response.

Configure the route to forward `authorization` to Hopae and to receive
`x-forwarded-user`, `x-hopae-aal` and `x-hopae-principal-kind`. The authenticated
service must have an enforced Pumgye gate, an explicit service-scoped subject
role and matching method, information class and network rights. Its role must
explicitly permit `minimum_aal: 0`; a human/MFA requirement remains unsatisfied.
An API credential alone never grants application access, including legacy routes
without a resource gate. Service authentication cannot use terminal-response
mode to bypass the permission decision.

The incoming API Authorization credential is consumed after native verification
and removed before policy/transform processing and again immediately before
upstream dispatch. It does not become the application's credential. Dedicated
service-bound translation and streaming credential revocation remain follow-up
work. The current regression uses an owned native Hopae protocol peer and real
Hangang/Pumgye policy evaluation; actual multi-process API-key deployment is
still a separate qualification step.


## Native machine evidence expiry

Hangang binds successful native service/workload authentication to a monotonic
expiry. Hopae's optional `x-hopae-evidence-ttl-ms` must be a single decimal integer
from 1 to 1000; invalid, duplicate or already exhausted values fail closed. A
legacy trusted peer without the header receives a local one-second cap. The
clock starts before the exchange, so transport time consumes the budget. This
control metadata is read from the authenticated response, never client headers.

The shared route lease protects response bodies, pending operations, upgrades
and authenticated upload bodies. Idle streams close when evidence expires even
if policy and origin remain unchanged. Retirement checks currently run at 250 ms
intervals; this is a scheduler bound, not an exact wire-level one-second promise.
Machine requests lasting longer than the lease can fail or close. Non-renewing routes close at expiry. Opt-in reauthentication is described below;
targeted Hopae revocation subscriptions and fleet qualification remain required. This behavior
has not yet been deployed into the existing production gateway image.


## Opt-in native evidence renewal

Set `auth.renew_native_evidence: true` on a route with native Hopae transport to
maintain a valid long request. This applies only to authenticated service/workload
identities. Renewal requires the upgraded peer's explicit evidence TTL and at
least 100 ms remaining lifetime; a legacy missing TTL cannot enable renewal.
The gateway verifies the original method/path/client context through the same
bounded authenticated native pool around halfway through each lease. Subject,
principal kind, AAL and service must remain exactly unchanged. No body or incoming
credential is sent to the application for this purpose.

Denial, source failure, capacity exhaustion, changed identity, malformed lifetime
or expiry permanently retires that lease. A reply arriving after its previous
expiry cannot revive it. Existing Pumgye/route/JWT/workload retirement still applies
independently. The original selected authentication headers, including the bearer
credential, remain private in process memory for the operation; they are not
persisted or exposed to the backend. Closing the last lease reference aborts its
verification task and drops this context. At most 4096 renewal leases are active
per process, in addition to native pool limits. There is no result cache.

The default remains non-renewing expiry. Owned native-peer tests sustain unchanged
streams beyond two seconds and then exercise denial, unavailable verifier, changed
subject and short/expired evidence. These establish the gateway renewal mechanism,
not fleet-scale performance or real-cluster watch availability. Kubernetes source
polling can independently withdraw a stream during collection; sustained source
availability still requires the pending watch/follower work.


Renewal lifecycle qualification additionally exhausts all 4096 slots and verifies
admission refusal, cancellation of a real in-flight native socket on last-owner
drop, recovery of every slot, and timeout/irreversible expiry when no reply arrives.
The remaining-lifetime minimum also applies to renewal replies; short TTL tests
keep the authenticated identity unchanged so identity rejection cannot mask this
check. Retained header values are marked sensitive for debug formatting. These are
owned transport/lifecycle tests, not a fleet saturation throughput measurement.


## Request-local network evidence

The authenticated Guard decision taken during admission can satisfy the same
request's Pumgye check while it remains current. It binds the Guard instance,
canonical client IP, observed policy revision and deadline capped at one second
from the original query start. An expired proof or changed binding triggers a
fresh mandatory query. Snapshot, fail-open and optional cache hits never produce
reusable proof. This removes a redundant RPC within one request; every new request
still follows normal Guard admission and no shared decision cache is introduced.
The in-flight request can use its still-valid issued network proof; it does not
claim instantaneous remote policy-change notification or a signed permit receipt.

## Optional gRPC decision transport

Set `pumgye_authority.transport` to `grpc` and point `decision_address` at the
Pumgye gRPC listener. The default remains `native` (PPG1). gRPC always requires the
configured mTLS identity, including on loopback. Management remains HTTPS with
its separate administrator credential. Building requires `protoc` through the
pinned Pumgye schema crate.

The client reuses an HTTP/2 channel, bounds concurrent admission by `pool_size`,
applies `timeout_ms` to the entire decision batch and sends an RPC deadline.
It bounds protobuf input/output, rejects unspecified/inconsistent replies and
nonzero cache hints, advances its revision floor monotonically and refuses a
batch containing different revisions. Every permission must allow. Unavailable
responses, stale revisions, transport failure and capacity exhaustion fail closed;
there is no native or HTTP fallback. The revision watcher uses the selected transport.
A batch currently sends individual RPCs under one deadline; it is not a server-side
batch method. Credential/material rotation and channel retirement need separate
qualification before production adoption.

Owned-process qualification:

```sh
cargo build --example pumgye_grpc_qualification
python3 tools/pumgye_grpc_smoke.py --server /path/to/pumgye --client target/debug/examples/pumgye_grpc_qualification
```

This mutates only a disposable fixture database. Actual Hangang request-chain,
Kubernetes gRPC and production rollout remain separate qualification gates.

## Native resource catalog (unreleased)

The pinned Pumgye core and contract crates support owner-managed `resources`:
service, information class, action-to-permission mappings and minimum AAL.
Typed configuration round trips retain the catalog and reject invalid relationships
when compiling policy. The Pumgye console displays the catalog and preserves it
when publishing service/user/network changes through the existing CAS endpoint.
Edit the policy JSON to change catalog entries; source-managed policies remain
read-only. This does not yet connect resource RPC decisions to gateway dispatch
or create signed permits. Existing service gates continue their current behavior.

The reusable gRPC client also exposes `decide_resource`, taking native
resource/action/subject and verified IP/AAL/guard evidence. It shares the existing
channel, admission, deadline, correlation sequence and monotonic revision fence.
Only exact recognized verdict/reason pairs with zero TTL are accepted; unavailable,
stale, conflicting and unknown replies fail closed. The owned two-process fixture
qualifies resource Allow, minimum-AAL denial, administrator/server-name refusal,
CAS catalog removal on the same channel and unavailable revision floors alongside
legacy service decisions. Gateway route selection and dispatch adoption remain open.

Resource queries also carry the trusted native `service_id`; catalog membership must match it before rights are evaluated. The actual owning-server fixture includes cross-service denial even for an otherwise allowed identity.

## Resource gates (unreleased)

A protected route may use `resource_policy.pumgye_resource` instead of `pumgye`:

```json
{"service_id":"orders","resource":"db:orders","actions":{"GET":"select","POST":"update"}}
```

Choose exactly one gate and keep legacy `allow` empty. Native Hopae subject/AAL
is mandatory. Machine identities must match the gate's native service scope, and
the owner also checks resource membership. The gate supplies no information class
or permission; those come from the catalog. Unmapped methods and unknown resources
refuse access. An independent authority currently requires mandatory-mTLS gRPC;
PPG1 is rejected during configuration validation for this new gate. Embedded
Pumgye uses the same scoped core evaluation and validates catalog actions at load.
Successful remote decisions join the existing authority revision/health lease;
route retirement, backend dispatch and response streaming retain their fences.
No decision cache or transport fallback is introduced.

Local four-process mTLS gRPC qualification passed for the resource gate and the legacy service gate. The resource variant checks owner class changes, catalog deletion/restoration, method and service isolation, network blocks/outage, unchanged backend counts on refusal and durable Hopae/Pumgye revocation after restart. Seven resource-policy, seven Pumgye and 36 configuration tests plus strict all-target Clippy passed. Signed release and production rollout remain open; selected Kubernetes qualification is described below.

The same static candidate was qualified in the remote Kubernetes package with
actual Chromium: resource catalog display, owner class/AAL/service reassignment,
catalog removal/restoration, backend non-dispatch on refusal, owner CAS and
persistent authentication/authorization revocation across Pod replacement passed.
The first run timed out reading the diagnostic backend counter after a response.
Only that idempotent read now permits bounded transport retries; the passing run
needed none. Protected calls are never replayed. Existing nodes/DNS/Ingress and
backup copies were preserved; the owned namespace was removed. This is candidate
functional qualification, not production rollout or performance evidence.

## Signed release adoption

[Hangang v0.3.4](https://github.com/ziozzang/hangang/releases/tag/v0.3.4), source
bd2bdfc, includes the native resource gate and catalog console. All eight Linux
amd64 executables are static musl. Five uploaded/downloaded assets matched and
signatures were independently verified against the existing pinned identity.
The exact signed Hangang 0.3.4/Pumgye 0.1.3 images passed the remote Kubernetes
and real-browser resource fixture. Internal gateway and standalone console adoption
passed private rollback backups, production preflight, unchanged configuration,
credentials/UID/network, actual management health and current catalog UI assets.
Resource routes still require explicit owner configuration. This is selected
release/operating qualification; broader identity, projection, fleet and automatic
update requirements remain open.

## Native authenticated gRPC client (unreleased)

`pumgye_grpc_client::Client::decide_authenticated_resource` uses the existing
persistent mTLS channel, shared admission and revision tracking. Input identity,
service and assurance come only from the opaque checked Hopae service receipt;
the native query carries resource/action/IP and the final request digest. The
canonical Hopae protobuf context is shared with Pumgye. Encoding/decoding is
bounded to 4 KiB/128 bytes and deadlines are capped at receipt expiry.

Exact correlation, supported Allow/Deny, zero cache TTL, safe policy/network
revisions and monotonically observed floors are checked before returning.
Receipt verification captures its verification time and monotonic start so
rollback/stalled clocks cannot extend use. No native/HTTP fallback is introduced.
Adversarial reply and receipt time tests plus all-target Clippy passed. Actual Hangang-to-Pumgye positive RPC is qualified below. Gateway
dispatch/configuration remains to be connected; this library increment does not
change operating routes or issue signed permits.

Full all-target regression passed 1,267 tests with 58 explicit ignores after
the dependency/client/receipt-time changes; strict all-target Clippy passed.
This is source/library qualification, not live request dispatch activation.

The owned `authenticated_resource_qualification` example uses the actual Hangang
Hopae and Pumgye clients on persistent mTLS channels against all three authority
processes. `pumgye/tools/authenticated_resource_smoke.py --live-validation
--grpc-decisions` passed enforced resource Allow, network block/removal, signed
identity-profile withdrawal/restoration, owner outage and seven trust refusals.
Withdrawal and outage additionally query Pumgye with an unexpired previously
checked receipt and require refusal. This is local debug-process qualification;
static release, Kubernetes adoption and actual gateway dispatch remain separate
gates. Fixture credentials enter through environment references only.

The owning `AuthorityRuntime::observe_authenticated_resource` now accepts the
route-owned `ResourceGate`, method, IP, final digest and checked service receipt.
It enforces route/receipt service equality and configured method/action mapping,
then uses the same authority's bounded gRPC channel and revision floors. The
owned example exercises this runtime, including cross-service receipt, unmapped
method and changed-digest refusal. It returns an observation only: it does not
start or refresh the older authorization lease health watcher. Final request
transformation, receipt-owner/route freshness and upstream dispatch integration
remain required before activating this path in routes.
