# TCP member admission

[Documentation](README.md) · [한국어 안내](README.ko.md)

See [member lifecycle](MEMBER_LIFECYCLE.md) for serving, draining and maintenance states.

## Admission lease

Each TCP backend has an internal generation-specific admission gate in the
prepared snapshot. The gate is separate from the named member's logical
`member_active_streams` counter. Selection skips a closed gate. After SNI
route selection and before the outbound dial, an accepted connection acquires
one RAII admission lease; refusal ends the connection without dialing that
member. The lease covers SOCKS/TLS negotiation and any other pending dial work,
then remains held through ClientHello forwarding and the established stream.
Cancellation, dial failure, idle expiry and stream completion release it.
The gate atomically combines open-state checking with count acquisition and
rejects count overflow.

After an asynchronous dial, the runtime checks the selected endpoint and
discovery epoch, health eligibility, and admission gate again immediately
before forwarding any downstream bytes. A gate retired during the dial cannot
turn that dial into a newly forwarded stream. This check does not promise
zero-gap revocation: retirement can race *after* the final check, so work
already admitted may forward and finish. Existing established streams are not
forcibly closed.

## Snapshot compatibility

Snapshots retain a gate only for a compatible backend generation. Named pools
match exact member ID and address; route enablement, health policy, outbound
settings and the prepared CA trust must also match. Legacy string pools require
the exact ordered backend array and the same enablement, health policy,
outbound settings and prepared trust.
Other changes start a fresh serving gate. The logical named stream counter
instead follows a continuously present route ID/member ID across endpoint,
health and enablement changes, including old-endpoint streams. Its public
`member_active_streams` value counts only **established** streams; pending
dials are counted by the internal admission lease but are absent from that UI
value. TCP `active_requests` remains `null`.

## Retirement and observation boundaries

Snapshot preparation records which predecessor gates are absent from the
successor by shared-pointer identity. It does not mutate the live generation:
a failed validation, bind, save or CAS drops the plan. After persistence,
`Snapshot::activated` retires displaced gates before the new snapshot becomes
visible. Compatible shared gates remain open; old leases on retired gates can
finish. A fresh attachment to a shared authority builds new runtime/cache
state yet still retires the actual replaced snapshot's gates at activation.

Automatic replacement retirement also underpins local-file operator lifecycle controls.
New generations use their configured desired state; nonserving generations start closed. Operations has no
pending-dial count, retired-endpoint breakdown, or drain-completion result;
removed member IDs have no current row. A local zero established-stream count
cannot prove that all pending work or work on other instances has finished.
Shared-store and Kubernetes startup keep the TCP accept gate closed until
initial authority readiness. Hot-restart processes have separate gate memory:
retiring a node in one process does not synchronously revoke an admission in
its predecessor. See the [member lifecycle](MEMBER_LIFECYCLE.md) for
publication and fleet coordination details.

[Retired members](RETIRED_MEMBERS.md) documents the bounded active-generation registry and dedicated API/UI. It includes pending TCP admissions and removed endpoints; operator lifecycle and fleet completion are separate concerns.
