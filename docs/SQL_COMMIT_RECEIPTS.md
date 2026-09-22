# Retained SQL configuration commit receipts

[Documentation](README.md) · [한국어 안내](README.ko.md)

SQLite and PostgreSQL record an operation-specific commit receipt in the same atomic write as a governed HTTP configuration CAS. A later configuration update replaces the current-row proof but does not remove this receipt. The receipt contains the configuration authority epoch, committed revision, acceptance authority ID, operation ID and candidate digest. It contains no configuration body, account name or bearer credential.

This is evidence that the operation's candidate was committed at that epoch and revision. It does not establish current configuration, local activation, fleet acknowledgement or an immutable external audit. Account acceptance and SQL configuration persistence are separate transactions. SQL credentials remain the store's authority; central scoped actor authorization is not implemented by adding this table.

## Administrator lookup

`GET /v1/config/commit-receipt?authority_id=<32 lowercase hex>&operation_id=<32 lowercase hex>` requires administrator authority. Both query parameters are required exactly once; unknown parameters are rejected. The endpoint rechecks live account authority after the external store read and returns `Cache-Control: no-store`. Database errors are returned as a generic 503 without database details.

```json
{
  "scope": "configuration_authority",
  "supported": true,
  "receipt": {
    "epoch": "0123456789abcdef0123456789abcdef",
    "revision": 1,
    "stamp": {
      "authority_id": "0123456789abcdef0123456789abcdef",
      "operation_id": "abcdef0123456789abcdef0123456789",
      "candidate_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    }
  },
  "stored_records": 2,
  "capacity": 100000,
  "writes_available": true,
  "server_time_unix_ms": 1700000000000
}
```

A supported store with `receipt:null` has no retained receipt for those identifiers. That is not proof of non-commit: older writers did not create receipts, a backup may predate the write, and a different store may be queried. File and Redis stores return `supported:false` with null receipt, count, capacity and availability. The dedicated English/Korean Change history lookup keeps historical evidence separate from current proof and local acceptance history. Lookup does not replay an operation, change local outcomes or activate a configuration.

## Atomicity and compatibility

SQLite commits the configuration, current stamp, receipt and capacity counter in one immediate transaction. PostgreSQL uses one atomic statement so acknowledgement loss cannot separate the configuration and receipt. Receipt insertion failure or exhausted capacity rolls back the configuration write. Exact current retries do not append duplicates. A retained old receipt is never sufficient to return an old candidate as currently applied; callers can inspect historical commitment separately while CAS preserves its current-document contract.

Receipt identity is the acceptance authority ID and operation ID; the stored epoch and revision describe its original commit. Reusing a retained identity for a different candidate or precondition is rejected. Configuration row deletion and rebootstrap do not erase the receipt ledger or reset its capacity counter. No backfill is synthesized from a preexisting current stamp. Older SQL writers and ordinary system CAS remain readable and can advance configuration without a new receipt, so this ledger has explicit operation-aware coverage rather than complete SQL writer coverage.

## Capacity and recovery boundaries

The ledger retains at most 100,000 receipts, with no automatic eviction. Capacity applies to new operation-aware writes, not to receipt reads or proxy request handling. `writes_available` describes receipt capacity only; it is not a promise that account acceptance, revision preconditions, storage availability or configuration validation will succeed.

There is no pruning endpoint. Deleting receipts for arbitrary random operation IDs would erase the evidence needed to reject their reuse. Safe archival and capacity recovery require durable generation or monotonic-sequence fencing before deletion is introduced. A full ledger rejects new governed SQL configuration writes; do not delete receipt tables or reset counters as a workaround. Ordinary legacy writes are not a supported capacity bypass.

This ledger does not provide safe retention recovery, authoritative reconciliation of unresolved local operations, central scoped identity, outbox execution or fleet rollout receipts. Receipt storage is not tamper-proof against an administrator who can replace the database or restore an earlier consistent backup. Logical rollback behavior does not establish physical power-loss or full-disk recovery guarantees.

New SQL HTTP writes use [sequenced V2 receipts](SEQUENCED_SQL_RECEIPTS.md). This document’s authority/random-ID lookup is the separate V1 namespace. V2 retains per-authority committed-sequence fences and shares the receipt cap; neither version has a pruning endpoint yet.
