# HTTP member activity and lifecycle

[Documentation](README.md) · [한국어 안내](README.ko.md)

## Activity accounting

Every HTTP balancing mode now retains one backend request lease from admission
through the final response-body or upgraded-tunnel owner. Cloning ownership does
not increment the request count. Finishing or abandoning the body and closing
the tunnel releases it. Compatible snapshot changes retain the shared count.
`/v1/operations` exposes numeric `active_requests` for all HTTP modes. TCP
keeps `active_requests: null`; named TCP members instead expose numeric
`member_active_streams` for established streams. Legacy TCP rows have no
per-member stream count. The English/Korean Operations table distinguishes the metrics.

Admission refusal is terminal before the first outbound send. A retry must
acquire its newly selected member before sending; it cannot treat a refused
lease as an untracked request. Existing no-replay and Lua-pinning rules remain.

## Admission and generation lifecycle

The internal `MemberAdmission` primitive combines activity with pending/retired
flags in one atomic state. Retirement prevents new acquisition while old owners
finish. A retired generation cannot activate again, even from an outdated plan.
Counter overflow is rejected. Current legacy balancers start serving; lifecycle
publication must explicitly prepare closed generations and activate them only
after the authoritative configuration commit. The primitive alone does not
provide operator drain/maintenance or fleet-wide drain completion.

Snapshot preparation compares predecessor HTTP/TCP admission nodes against
the successor by shared-pointer identity. A node absent from the successor is
retired by `Snapshot::activated` immediately before the new snapshot becomes
visible, after the authoritative write. Candidate preparation and failed
validation, bind, save or CAS do not run that candidate's plan. A reconciled CAS
winner can separately publish its own plan. Compatible shared
nodes remain open. Replaced HTTP nodes start fresh when enablement, outbound
transport or prepared CA trust changes, including legacy string routes. A
fresh shared-authority attachment creates independent runtime/cache state but
still retires the actual replaced snapshot's nodes at publication. Old HTTP
leases and TCP streams keep their old ownership; pending TCP dials on a
retired gate fail the final pre-byte check.

## Named-member representation

HTTP and TCP routes accept homogeneous string arrays or object arrays with
explicit member IDs, addresses, and weights. Existing string JSON round-trips
unchanged. Object members with `desired_state: serving` (the default) can be
activated only under local-file configuration authority; `draining` and
`maintenance` are supported under local-file authority, including disabled routes. A mixed array, duplicate
object ID/address, or object weights combined with legacy `balance.weights` is
invalid. Every shared `ConfigStore` path rejects named-member seed, write, and
read until fleet reader capability coordination exists.

For a serving object pool, a snapshot maps each member by **ID and address**.
Reordering or editing weights builds a new selector but retains compatible
HTTP health and active-request nodes; a held response still decrements its
original node. Route transport, enabled state, health policy, or prepared CA
trust changes create fresh health state. TCP health also follows the stable
ID/address across reorder and weight edits. TCP `/v1/operations` keeps
`active_requests: null` but reports `member_active_streams` for named members.
This instance-local count follows a continuously present route ID/member ID,
including established streams on old endpoints after endpoint, health, or
enablement changes. It excludes pending dials. Rename or removal and re-add
starts a fresh count; a removed ID has no Operations row. The count is not a
drain-completion or retired-endpoint report. Operations exposes `member_id`
for object members and `null` for legacy entries.

Local-file per-member drain/maintenance controls now use generation retirement.
Cross-revision HTTP connection-pool reuse is not claimed. See
[member lifecycle](MEMBER_LIFECYCLE.md) for publication and coordination details.

## Observation boundaries

[Retired members](RETIRED_MEMBERS.md) documents the bounded active-generation registry and dedicated API/UI. It includes pending TCP admissions and removed endpoints; operator lifecycle and fleet completion are separate concerns.
