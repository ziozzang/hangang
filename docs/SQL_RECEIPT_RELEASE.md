# V2 receipt protection and completion acknowledgement

V2 SQL receipts begin protected, including receipts imported by migration. A receipt can become eligible for future retention only after its originating instance has durably recorded `candidate_activated` and verified the exact SQL commit. This release does **not** delete a receipt, recover receipt capacity, prove fleet activation, or acknowledge an archive.

## Completion protocol

The local account database records a stable release identity and the complete expected receipt before requesting SQL release. Eligibility binds local authority, acceptance sequence, canonical operation ID, candidate SHA-256, acceptance epoch, and `expected_revision + 1`. Accepted, indeterminate, conflict and failed operations cannot automatically release a receipt, even when a matching SQL commit exists. They require a separate reconciliation protocol.

SQL commits the pin change and a separate durable release record together. Exact retries return historical evidence; identity reuse with a different receipt is rejected. Local acknowledgement is written afterwards. The release ledger must survive future deletion of the original receipt so an interrupted local acknowledgement can still recover. It has its own 100,000-record capacity; filling it fails safely and requires a future qualified archival/retention protocol.

Local V2 operation rows stay protected until acknowledgement is durable. The database deletion guard also rejects an older process's attempt to delete those rows. V1 and local-file operations retain their existing retention semantics. The account schema upgrade is not a promise that arbitrary older binaries can reopen the upgraded database.

Successful governed configuration writes attempt this protocol after recording local activation. If release cannot be confirmed, the already applied configuration remains successful and the operation stays protected or pending. Clients must not replay the configuration mutation merely to recover a release acknowledgement.

## Online management

`GET /v1/config/operations` includes `release_state`:

| State | Meaning |
| --- | --- |
| `not_applicable` | V1 or local-file operation; V2 release does not apply. |
| `protected` | V2 local operation without durable release work; not eligible for local pruning. |
| `pending` | Stable release work exists; SQL outcome or local acknowledgement is not yet confirmed. |
| `acknowledged` | SQL release acknowledgement is durable locally. |

`release_id`, when present, identifies the durable work. The dedicated EN/KO operation view displays protection and offers explicit recovery for eligible completed V2 records. A missing release state from an older server is not proof of acknowledgement.

Administrators can request recovery using:

```http
POST /v1/config/operations/release
Content-Type: application/json
Authorization: Bearer <administrator-token>

{"operation_id":"<32 lowercase hexadecimal characters>"}
```

The endpoint rejects unknown fields and query parameters. It verifies current local administrator authority while durably preparing the release. Work accepted before revocation may finish afterwards; the response is checked against live authority again. SQL credentials remain the SQL authority boundary: the SQL database does not independently validate the originating account session. The operation actor identifies the original configuration acceptance, not necessarily the administrator who later requests recovery. This release work does not yet retain separate recovery-actor audit provenance; central mutation auditing remains unfinished.

A successful no-store response contains `scope: "instance"`, `operation_id`, `release_id`, and `release_state: "acknowledged"`. A 409 reports ineligible/mismatched local evidence. A 501 means the store does not implement release. A 503 means confirmation is unavailable; it does not establish that the SQL transaction failed. Refresh the local history and explicitly recover using the same operation identity. The browser does not automatically repeat the mutation.

## Failure and recovery boundaries

- Failure before durable local completion leaves the SQL pin protected.
- Failure after local preparation but before SQL commit retains pending work and the pin.
- Lost SQL acknowledgement leaves durable SQL evidence and pending local work. Recovery reads that evidence before attempting any mutation.
- Failed local acknowledgement cannot permit local pruning. A later recovery uses the same release identity.
- Missing SQL evidence for an already acknowledged local release is an error, not permission to recreate it.
- A migrated SQL receipt whose originating local operation was already pruned stays protected. This interface does not fabricate an eligible local outcome.

Account restore, SQL restore, authority retirement and independently anchored rollback detection remain separate requirements. In particular, consistent rollback of both databases cannot be detected solely from their own rolled-back records. Archive verification, protected-prefix pruning and deletion receipts are still required before SQL receipt deletion or capacity recovery can be exposed.
