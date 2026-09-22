# Local configuration operation acceptance

HTTP whole-configuration, route and fleet cache-generation writes now carry authenticated authority through the bounded manager queue and preparation work. Immediately before attempting configuration persistence, the account store checks the live session and enabled administrator role and inserts a durable accepted-operation row in one SQLite immediate transaction. Static-token requests use explicit system authority.

A logout, demotion, password reset, disable or deletion committed before acceptance rejects the queued write with 403. A request already invalid at HTTP admission receives 401. **Acceptance is the authorization linearization point:** an accepted operation may finish after a later logout. No account database transaction is held across file or remote-store I/O. This avoids claiming a transaction spanning separate stores and avoids blocking account writers while a remote configuration store stalls.

## Evidence and outcomes

Schema version 3 added a stable random account-authority ID and separate configuration-operation journal. Schema version 4 adds explicit retention and preserves that identity, all retained operations, accounts, sessions and audit sequences. The authority ID survives normal process restart and namespaces local user IDs. It is not a central enrollment credential or an independent anti-rollback anchor; copied/restored databases retain copied/restored identities. Quiesce older account-store writers and preserve a consistent backup before migration. The migration preserves accounts, sessions and the existing account audit.

An operation records a random operation ID, ordered local sequence, actor kind and optional local user ID, authority ID, acceptance time, expected configuration revision, normalized candidate SHA-256, store kind and optional observed store epoch. The local journal accepts expected revisions in the JSON safe-integer range (0–9007199254740991); an authority beyond that range cannot accept another governed HTTP write through this journal. It stores no candidate body, username, password, bearer token or session digest. The fingerprint identifies the prepared candidate bytes; it is not a signature, remote commit receipt or secret-proof commitment and is visible only to administrators.

The manager records these observations after the store/activation attempt:

- `accepted`: durable authorization exists, but no final observation is recorded. It can be running or interrupted; do not infer failure after restart.
- `candidate_activated`: this manager observed activation of the prepared candidate. It is not an acknowledgement from other nodes and does not prove exclusive authorship of a shared CAS that recognized an identical candidate.
- `conflict`: the operation observed a configuration revision conflict.
- `indeterminate`: the attempted operation failed without sufficient evidence for a narrower outcome. The candidate may have been stored or activated.
- `failed`: reserved for a future execution path with definite non-application evidence; current manager errors are conservatively indeterminate.

If acceptance storage fails or is full, no configuration store write begins. If final journal storage fails after configuration activation, the HTTP result is 503 and the accepted row remains unresolved; inspect configuration and history before deciding on a new write. Response cancellation does not cancel the detached manager transaction. Process termination can leave an accepted row; there is no automatic replay or reconstruction of an outcome from a matching document.

## API and console

`GET /v1/config/operations?after=0&limit=100` requires administrator authority rechecked in the same account-store read snapshot. It returns no-store responses with instance scope, explicit coverage, stable authority ID, history start time, oldest/latest sequence, ordered records, exclusive sequence cursor, capacity, history revision and observation time. `pruned_through` and `truncated` disclose prior retention; retained IDs can be sparse because unresolved operations are preserved. The limit is 1–100 and the cursor must be a nonnegative JSON safe integer. Unknown and duplicate parameters are rejected.

The dedicated EN/KO console shows acceptance separately from candidate activation and unresolved results. Paging retains bounded browser state. Current-page export remains available; full retained-history export fetches at most 100 pages/10,000 records and requires one unchanged authority, history start, history revision and retention boundary across all pages. It emits a download only after all retained rows are collected and validated; a mutation, read error or logout aborts without a partial download. A failed read is unavailable evidence, not an empty successful history. No retry or remote deployment is triggered by opening this view.

The journal is bounded to 10,000 operations with no silent eviction. Acceptance and history reads validate retained count, bounds and a digest of sorted retained IDs in their SQLite transaction so unauthorized deletion gaps cannot be hidden by a later cursor, while legitimate sparse retention remains readable. This aggregate check is O(retained rows), bounded by 10,000, and runs only on these management operations; it is not part of proxy request selection. Structural checks do not authenticate a database against a machine administrator who can replace consistent data or restore an earlier backup. Full capacity rejects new governed HTTP configuration writes; authentication, reads and data-plane service remain separate. Explicit pruning can recover capacity when terminal records are available. Automatic archival and outcome reconciliation are not implemented. If all retained operations remain accepted or indeterminate, they are preserved and capacity remains exhausted until a future authoritative recovery mechanism can resolve them. Do not delete or replace the account database to bypass the limit: that also destroys accounts, sessions and history.

## Explicit terminal-history retention

Archive required evidence before using `POST /v1/config/operations/prune`:

```json
{"through_id": 100, "expected_latest_id": 250, "expected_history_revision": 500}
```

The administrator-selected boundary covers **all eligible terminal records at or below that ID**, including earlier pages. Only eligible `candidate_activated`, `conflict` and `failed` rows are deleted. V2 rows additionally require a durable SQL release acknowledgement; all other V2 rows stay protected, including terminal rows. A database deletion guard also rejects an already-running older pruner that attempts to bypass this condition. `accepted` and `indeterminate` rows are retained even when they lie below the boundary; the response reports how many unresolved rows were retained in that range. A current-page export is not a complete archive. Use full retained-history export for a consistent retained snapshot and confirm it was saved before pruning. Previously pruned records are excluded and cannot be reconstructed by this export. The server does not verify that an external archive exists; a browser download action is not proof of durable external storage.

The latest sequence and history revision must exactly match the read used for the decision. Every acceptance, completion, release preparation/acknowledgement and prune advances the history revision, so a completion occurring after inspection also produces 409 rather than deleting a newly eligible record under an old decision. Unknown fields and query parameters are rejected. No eligible row also returns 409 without changes. The console requires explicit confirmation and never automatically retries a stale prune.

The same SQLite immediate transaction rechecks live administrator authority, deletes eligible rows, updates the retained-ID digest and retention metadata, and appends a `config_operations_prune` record to the account/retention audit. That record identifies the actor, configuration-operation boundary and deleted count. Its `through_id` belongs to the configuration journal and can exceed its own account-audit ID. New configuration-operation IDs continue above prior history and are never reused.

Audit append failure or exhausted account-audit capacity rolls back the deletion and all retention metadata. If the account audit is full, archive and explicitly prune that audit first using its existing controls; then refresh the configuration history and make a new retention decision. Normal full-journal recovery does not require deleting or replacing the account database. The receipt is local evidence, not an immutable external archive; an administrator can later explicitly prune account-audit records under that audit's documented policy.

## Remaining authority work

This is a local acceptance journal, not a store-coupled configuration audit or transactional outbox executor. It does not provide central scoped authority or recovery; current SQL operation identity is described below and retained SQL commits have a separate lookup. File reload, Kubernetes reconciliation and direct system manager calls have separate system paths and are not fabricated as HTTP user operations. Docker connections, instance-only cache purge and lifecycle/update effects are not covered by this journal.

## Current SQL operation identity

SQLite and PostgreSQL support operation-aware CAS. Governed HTTP writes on these stores atomically write the configuration and an operation stamp in the same configuration row. The stamp contains the local acceptance authority ID, operation ID and SHA-256 of the encoded candidate at its assigned revision. An identical document from a different operation is a conflict; an exact current-operation retry can be recognized. The account acceptance database and configuration authority remain separate transactions.

`GET /v1/config/operation-proof` is administrator-only and returns a no-store observation:

```json
{"scope":"configuration_authority","supported":true,"proof":{"epoch":"0123456789abcdef0123456789abcdef","revision":1,"stamp":{"authority_id":"0123456789abcdef0123456789abcdef","operation_id":"abcdef0123456789abcdef0123456789","candidate_sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}},"server_time_unix_ms":1700000000000}
```

The dedicated EN/KO Change history panel loads this observation independently of local acceptance history. It distinguishes unsupported stores, supported stores without current proof, and unavailable reads. The endpoint rechecks live administrator authority after the store read; it does not hold an account transaction across remote I/O or promise a cross-store snapshot.

File and Redis stores currently return `supported:false, proof:null`; their ordinary CAS behavior remains unchanged. SQL bootstrap and legacy writes have no operation proof. SQL schema migration adds nullable stamp columns. New legacy writers clear the stamp; readers reject a stamp left by an older writer as unproven when its revision or encoded-document digest differs from the current row. A malformed stamp is an unavailable proof, with no raw database error exposed through this endpoint.

This is evidence about the **current configuration row**, not a retained commit receipt. A later writer replaces it. Missing proof cannot establish that an earlier operation never committed. Matching proof does not establish local activation, fleet acknowledgement, immutable audit, or ownership by the account currently reading it. The local journal's outcome semantics remain unchanged, and unresolved operations are not automatically replayed or reconciled. Retained SQL commits are available through the separate [receipt lookup](SQL_COMMIT_RECEIPTS.md). Central scoped authorization, safe retention recovery and authoritative local-outcome reconciliation remain required.

## Retained SQL commit lookup

[SQL commit receipts](SQL_COMMIT_RECEIPTS.md) preserve operation-aware SQL commits after a later configuration replaces the current proof. They are distinct from this local journal and do not rewrite its activation observations or unresolved states. Retention is bounded and currently fail-closed without pruning; safe archival requires durable replay fencing.

Account schema 5 preserves V1 IDs and adds `receipt_version`. New supported SQL acceptance uses canonical V2 IDs derived inside the acceptance transaction from authority and the non-reused journal sequence. See [V2 identity and recovery limits](SEQUENCED_SQL_RECEIPTS.md).

## V2 completion protection

Account schema 6 adds durable release work and acknowledgement. The operation API includes `release_state` and an optional `release_id`; the EN/KO view displays protection and supports explicit recovery. See [SQL receipt release](SQL_RECEIPT_RELEASE.md) for the exact tuple, recovery endpoint and failure boundaries. This protection does not itself recover SQL receipt capacity or reconcile accepted/indeterminate outcomes.
