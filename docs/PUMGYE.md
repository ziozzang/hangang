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

`hopae_native::Client::validate_service_receipt` re-queries the native Hopae
issuer on the existing mTLS channel using only a checked service receipt. Caller
authentication and admission are shared with issuance. Encoding/decoding is
bounded to 2 KiB/64 bytes; the deadline is capped at one second and original
receipt expiry. Exact request correlation and unchanged original expiry are
required, with local wall/monotonic time and observed profile-revision fences.
The result is a fresh issuer observation, not an authorization lease or permit.
The actual three-authority fixture additionally verifies this Hangang client
accepts current proofs and rejects still-unexpired withdrawn/outage proofs.
Before querying Pumgye afterward, it asserts the cached proof is still valid,
so expiration cannot substitute for the remote lifecycle refusal.

`projection_binding::digest_upstream` binds the exact path/query of the selected
HTTP(S) upstream URI and complete final entity. The actual gateway URI-composition
test includes a backend base path, rewritten path, duplicate/encoded query fields
and host override; pre-composition paths or empty replacement bodies produce
different digests. Origin-only targets, unsupported schemes, userinfo authorities
and ambiguous/invalid paths refuse in this adapter. Service/audience and backend
owner binding remain separate requirements: the canonical request digest does
not include the URI authority. This helper does not buffer streams, issue a
receipt or activate dispatch.

`projection_entity::prepare` materializes the complete final entity under
owner-supplied global admission, byte cap (1 byte–16 MiB) and deadline (up to five
seconds). Admission remains with the prepared request and its dispatch body.
Single-frame bodies retain their original `Bytes` allocation; fragmented bodies
grow in power-of-two capacity buckets capped at the configured maximum, beyond
source frame buffers; allocation failure refuses. The read
loop yields every 64 frames so continuously ready empty frames cannot starve
deadline/cancellation. Capacity, length ambiguity/mismatch, excess bytes, body
errors, unsupported trailers and invalid final targets refuse. Dispatch framing
is regenerated from the preserved bytes. This phase grants no permission.

Ten entity tests cover byte preservation, admission lifetime/cancellation,
allocation reuse and adversarial inputs. The actual Hangang three-authority
fixture now derives its receipt digest from this prepared final request. Both
empty and `--nonempty-entity` runs pass Allow, network/identity lifecycle, outage
and trust refusals. The nonempty run also passes with Pumgye's own client. These
are local preparation/authority tests, not actual gateway transformation or
upstream dispatch, static release, Kubernetes or production adoption.

Reservation tests verify that a 13-byte fragmented entity needs 16 bytes of
vector capacity with a 16 MiB limit, logarithmic growth under non-power-of-two
limits, and size/overflow refusal without further allocation. The owned fixture's
`--nonempty-entity --fragmented-entity` mode feeds two real data frames through
Hangang preparation before issuance; the actual three-authority Allow/lifecycle/
outage/trust fixture passes. It requires the selected client to report two
prepared frames, and refuses a nonparticipating client. Default empty-body and
Pumgye's single-entity compatibility modes also pass. These are local functional
and capacity checks, not complete gateway throughput qualification.

The unreleased `native_resource::Binding` compiles an immutable resource gate,
service/audience scope and issuer pin once. `prepare_scoped` reuses that scope
without per-request string copies. The prepared request retains the exact scope
object, and another binding is refused even when its scalar values are identical.
The service receipt scope and digest come from the prepared request itself.

`Binding::observe` composes actual receipt issuance, authenticated Pumgye resource
lookup and positive-result Hopae revalidation. Before returning a positive
observation it checks proof expiry and the same client's locally observed policy/
network floors, without refreshing the older authorization-health lease. The
actual three-authority fixture now uses this phase; empty and fragmented nonempty
entity lifecycle/trust tests pass. Ten entity tests and four gRPC response/floor
tests pass. Local floors do not prove remote freshness after return. The result
remains an observation; selected gateway config/route fences, upstream effects,
signed permits/projection, release and operating adoption remain open.

`native_resource::Configuration` is the public-only compiler input for this
library phase: `audience`, `issuer_ref`, `key_epoch`, canonical Base64 Ed25519
`public_key`, `maximum_body_bytes` (default 1 MiB, 1 byte–16 MiB) and
`body_timeout_ms` (default 1000, range 1–5000). The resource/service/action gate
comes from its owning caller. Unknown fields, including signing seeds, refuse;
weak/malformed public keys, unsafe epochs and invalid budgets refuse compilation.
`Binding::prepare` applies the compiled budget using caller-supplied shared
admission. Two compiler/budget tests and the actual fragmented three-authority
lifecycle fixture pass. At this compiler increment, route activation was still
open; the subsequent dispatch qualification below connects it.

## Final native service dispatch (unreleased candidate)

Set `auth.native_resource` to the public configuration above on an explicitly
protected route with enforced `resource_policy.pumgye_resource`. Both native
Hopae and independent Pumgye transports must use gRPC with mTLS. Invalid pins,
embedded/unencrypted/native-only authority combinations and disabled permission
gates refuse configuration validation. Ordinary configurations omit the field.

The gateway captures the trusted native authentication input before consuming
the service credential. After request transforms and actual backend URI
composition, each upstream attempt prepares the complete entity using shared
128-request admission, issues its bound receipt, queries Pumgye's combined live
authorities and revalidates Hopae. It checks local policy/network floors and the
existing configuration/permission retirement fences immediately before sending.
The outgoing body retains admission and exact bytes, regenerates framing and
removes Authorization. Protected routes retain their existing cache bypass.
Existing authorization leases continue guarding request/response work; the new
zero-TTL observation does not create or refresh a stream lease.

Hopae's `tools/service_stack_smoke.py --grpc --resource-catalog --native-resource
--durable-restart` passes with the actual four debug binaries and HTTP origin.
The origin receives the composed `/api/secure` target and nonempty entity with
no service credential. Wrong public pin/issuer/audience and a reduced entity cap
refuse without origin calls, then restoration allows. Resource/class/AAL/service
changes, guest/credential refusal, durable permission/authentication withdrawal,
network block/removal and authority outages also pass. The existing resource
fixture without this option passes. A focused configuration matrix rejects
unsafe transport/enforcement/pin combinations. Static release, remote Kubernetes,
production adoption, streaming application protocol coverage, signed permission/
projection/replay and throughput qualification remain separate gates.

Full all-target regression after dispatch wiring passes 1,282 tests with 58
explicit ignores; strict all-target Clippy and 922 local documentation links pass.
The first full run hit an existing delayed-worker Lua saturation deadline. Its
unchanged isolated test and the complete rerun pass; the original failed log is
retained privately. This does not establish a timing-test fix or throughput.

## Static 0.3.5 / 0.1.6 candidates

Hangang 0.3.5 pins all four Pumgye libraries to the same 0.1.6 source
609e552604d693fc3ac5410a4ef593463200b25b, with no unrelated lockfile updates.
Full 1,282-test/58-ignore regression, strict Clippy and five release boundary
tests pass. All eight musl executables are static and match their archive.
Existing pinned-key OpenSSL signatures, exact payloads and asset hashes verify
for Hangang/Pumgye and the published Hopae 0.0.7/Sumunjang 0.3.5 artifacts.
That exact four-static-binary combination passes native final dispatch, trust/
budget refusal without upstream effects, network/permission/class/AAL/service
checks, restoration and durable authority-restart withdrawal. These are prepared
local candidates, not new published releases or operating replacements. Remote
Kubernetes and deployment/rollback qualification remain required.

## Native signed permission evidence (unreleased source)

A protected native resource route may set `auth.native_resource.permission_permit`
to a separate public-only object with `issuer_ref`, `key_epoch` and canonical
Base64 Ed25519 `public_key`. This is the Pumgye permit-purpose key, independent
of the Hopae authentication key. Unknown fields and invalid/weak pins refuse.
This mode requires configured native route ownership and Pumgye route/plan live
clients plus its permit signer. Missing service or failed issuance never falls
back to ordinary Decide.

After Hopae authentication the gateway calls `ProjectionPermits/Issue` on its
existing persistent bounded mTLS channel. It verifies purpose/signature, exact
identity/generation/service/audience/final-request hash, the authentication
receipt hash, resource/action, revision floors, zero cache TTL and expiry bounded
by authentication. Canonical binding validation rejects zero owner revisions.
Native permission denial returns 403; invalid/unavailable evidence returns 503.
The opaque checked permit stays in the native observation and expires through
its final dispatch fences. It is never forwarded as an application header.

This increment verifies signed permission evidence. Hopae receiver verification,
paired replay consumption and actual upstream credential projection remain
separate required gates; a signature alone is not replay admission or a remote
lease. Existing routes without `permission_permit` retain observation mode.

Local source qualification passes: 1,300 workspace tests (58 existing explicit
ignores), strict Clippy and 942 documentation links. The actual four-server
`--permit-issuance` fixture passes final request dispatch, wrong permit public
key/issuer/epoch refusal and restoration, durable permission/profile withdrawal,
route/plan trust failures and authority outages. This qualifies issuance and
gateway verification, not receiver replay/projection, static release, Kubernetes,
operating adoption, multi-owner epoch retirement or throughput.

The permit mode also calls `ProjectionPermits/Validate` on the same admitted
persistent mTLS channel after signature checks. It sends the original native
request and exact signed proof; the configured server rechecks its current
incarnation, native identities/network/route/plan and policy snapshot. A missing
validation RPC or failed validation refuses without fallback. Validation shares
the original request's elapsed timeout budget, uses 8192/128-byte request/reply
limits and requires exact correlation, zero cache TTL and an expiry no later
than the signed permit. The final checked evidence adopts the shorter deadline.
This is still a point-in-time owner observation; Hopae must independently check
its receiver owners and consume paired replay before projection.

The current local four-server permit fixture passes with mandatory live
validation, wrong pin/owner refusal, restoration, durable permission/profile
withdrawal and authority outages. The no-permit mode passes separately. Workspace
1,301 tests (58 existing explicit ignores), strict Clippy and 942 documentation
links pass. Receiver replay/projection, fleet/restore fences, static release,
Kubernetes/operating adoption and throughput remain separate qualifications.


### Opt-in final credential projection (source implementation)

Set `auth.native_resource.project_credentials: true` together with
`permission_permit` and native route-owner queries. The gateway retains the
original native permission request, then sends it and the checked permit to the
fixed Hopae mTLS `CredentialProjection/Project` endpoint on its existing bounded
channel. Contract 1 embeds Pumgye's protobuf rather than duplicating its schema.
Unsupported transports and missing route ownership refuse without fallback.

The private result validates request correlation, service, audience, final request
hash, signed plan revision and a deadline within the original signed permit.
Independent live observations can differ because remaining durations are anchored
before each RPC; the final credential uses the minimum of the reply deadline and
the gateway's already accepted deadline. This never extends prior authority. Only
`authorization` with a bounded RFC 6750 bearer or `x-hopae-subject` matching the
checked subject is accepted. Credential bytes have zeroizing storage and no
Debug/Clone/serde, and the installed header is sensitive. The gateway strips
incoming authorization and subject headers before installing the result. Existing
route/snapshot/authority fences and the result's monotonic deadline still apply
at final dispatch. This mode is disabled by default.

Compilation, strict Clippy and the real four-server origin-delivery fixture pass.
An initial restoration refusal was traced to independent conservative live
deadlines differing by one millisecond. The result now intersects deadlines
instead of rejecting a still-signed reply that is later than an earlier live
observation. A regression shortens accepted permission to 650, accepts a reply
ending at 700 within the signed 800 limit, and confirms the final header refuses
at 650. Replies exceeding the signed limit remain rejected.

The corrected full four-server fixture passes twice consecutively, including
configuration/information-class restoration, wrong keys/issuer/audience/peer/
caller refusal without origin effects, durable withdrawal and restart tombstones.
Every successful fixture request asserts the separate referenced origin bearer
and absence of the incoming API credential. The earlier full regression passed
1,301 tests (58 existing exclusions); four focused permit/projection tests and
strict Clippy pass after the correction. The corrected final full workspace passes 1,302 tests (58 existing exclusions);
no-permit/no-projection compatibility and 942 local documentation links pass. This is not a release or operating-adoption claim.
