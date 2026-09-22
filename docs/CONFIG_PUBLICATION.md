# Configuration publication

Hangang prepares a candidate before replacing the active immutable snapshot.
Validation, TLS material loading and listener binding must succeed first.
A failed candidate leaves the prior configuration active. Administration writes
use revision checks; a conflict requires reading and reconciling the current
configuration rather than blindly retrying an old document.

## Activation and cancellation

Publication acquires the TCP listener mutation lock before exposing the
candidate. Under that lock it retires displaced admission nodes, adopts the
cache generation, swaps the snapshot, installs prepared listeners and cancels
removed listeners without an asynchronous suspension between those steps.

Cancellation before acquiring the lock leaves the prior snapshot/listeners
intact. Cancellation while waiting for removed accept tasks afterward does not
undo publication. Existing admitted requests and streams retain their owners;
new selections cannot acquire a retired gate. A pending TCP dial rechecks the
generation before forwarding bytes. This is not synchronous revocation of work
that already passed its final check.

Compatible named members retain admission and health state across supported
edits. Changed generations retire separately. See [member lifecycle](MEMBER_LIFECYCLE.md),
[TCP admission](TCP_ADMISSION.md) and [retired member observations](RETIRED_MEMBERS.md).

## Persistence and recovery

Administrative writes run in bounded detached transactions so a disconnected
client cannot abandon persistence. File reload and shared-store preparation
remain cancellable. Persistence and local activation are separate events:
shutdown or an ambiguous store response can leave a durable write without a
confirmed local activation. Inspect [configuration operations](CONFIG_OPERATIONS.md)
and the selected store's proof before retrying or rolling back.

Shared-store and Kubernetes startup keep TCP acceptance closed until the initial
authority is ready. Independent processes do not share in-memory admission gates.
A successful local publication is not a fleet transaction or proof that every
node has activated the revision. See [scale-out](SCALE_OUT.md).
