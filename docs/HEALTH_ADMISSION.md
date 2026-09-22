# Initial active-health admission

[Documentation](README.md) · [한국어 안내](README.ko.md)

`balance.active_health.initial_state` controls whether a newly constructed HTTP
backend may receive application traffic before active probes qualify it:

| Value | Initial admission | Qualification |
| --- | --- | --- |
| `healthy` (default, omitted on serialization) | Eligible until configured failure thresholds exclude it | Existing compatibility behavior; eligibility is not evidence of reachability |
| `checking` | Excluded from selection and explicit Lua backend selection | Only the configured `healthy_successes` threshold permits initial admission |

A failed HTTP probe, transport failure, timeout, or merely observing a probe
does not open the initial gate. Existing active/passive health policies decide
subsequent exclusion and recovery. For `checking`, neutral status codes also reset
the consecutive success streak; default `healthy` retains its historical neutral-status no-op behavior. Probe intervals and timeouts remain bounded;
there is no blocking wait in an application request and no fallback to an
excluded member when all members are unavailable (backend-forwarding requests return 503). Local responses, authenticator terminal responses and eligible cached responses may complete without a backend dial.

Operations exposes `initial_check_pending`: `null` without active health,
`true` while the mandatory initial gate remains closed, and `false` otherwise.
This is independent of `probe_observed`, which becomes true on failures as well
as successes, and of `available`, which can become false after qualification.
Route deactivation overrides eligibility and stops its probes. Passive healthy-status reports do not reset failure counters or recover quarantined members; active probe success clears passive quarantine, preserving the existing compatibility semantics.

All active-health modes reset their observations when route enablement or
configured upstream transport changes. A newly prepared snapshot also compares
a SHA-256 fingerprint of the exact parsed custom CA certificates used by its
TLS verifier; replacing CA contents at the same path resets HTTP and TCP health.
PEM whitespace alone does not change that fingerprint. Files are read only once
per TLS preparation, so the reuse decision and verifier use the same trust.
This takes effect when a new snapshot is prepared and published, not merely
when a CA file changes on disk. Failed preparation leaves live health intact.
For `checking`, these transitions require fresh successful qualification;
`healthy` preserves its initial eligibility default. Legacy string backends
retain ordered-array reuse semantics, so reorder can reset health. Serving
object members reuse compatible health nodes by exact member ID **and** address
when reordered or reweighted. A changed health policy creates fresh state;
route transport, enablement, and prepared CA trust fence reuse even when the
member ID stays the same. Unrelated route changes preserve compatible state.
Requests already admitted retain their snapshot; deactivation is not
retroactive termination of an established response or stream.

## Administration

The native HTTP route load-balancing editor exposes active/passive health
configuration and initial admission in English and Korean. Legacy cooldown
health and active health are mutually exclusive, and passive health requires
active health. Existing API route/config writes remain authoritative and
validate the same contracts. No new management write endpoint is introduced.

## Boundaries

This is HTTP initial admission, not completion of pool lifecycle.
Legacy members remain positional. Local-file routes can now use named serving
members whose compatible health and load follow ID/address across reorder and
weight edits. Local-file `draining` and `maintenance` controls and a bounded
retired-generation view are implemented; fleet-wide completion is still separate. TCP active probes and Docker endpoint-generation fencing
are described in [TCP health](TCP_HEALTH.md).

HTTP Docker references now resolve before probing and fence active/passive results by discovery epoch, including checking startup. See [HTTP Docker health](HTTP_DOCKER_HEALTH.md) for selection, pool reuse and already-admitted work boundaries.

A first successful probe is a bounded observation, not a permanent connection
or identity guarantee. DNS changes at the same configured hostname and external
endpoint changes can happen between a probe and an application request. Docker discovery epochs now fence those changes; generic hostname DNS changes
do not have the same epoch contract. TCP transport
probes do not prove application-level readiness.

The initial gate excludes application requests, including explicit Lua backend
selection, until enough successful probes have been observed. Reactivation and
configured transport changes require fresh observations under `checking`.

HTTP probe generations are owned by a task set. Replacement aborts and joins
all previous probe tasks before starting the latest snapshot's generation;
shutdown also joins outstanding tasks. This bounds monitor-owned probe tasks
across reloads. It does not count independent HTTP pool connection drivers or
claim a global instantaneous network-socket limit.
