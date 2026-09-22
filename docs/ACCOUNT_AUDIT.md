# Durable local account audit

[Documentation](README.md) · [한국어 안내](README.ko.md)

The account store records successful bootstrap and selected account creation, update and deletion events in the same SQLite transaction as the account/session changes. Account schema 7 adds [ordered recording filters](ACCOUNT_AUDIT_FILTERS.md); the initial policy records all three account-change actions. Intentional omissions increment a durable counter in that same transaction. It also records explicit audit pruning and `config_operations_prune` retention receipts for the local configuration-operation journal. This is **instance-local account change and retention-action coverage**, not configuration-commit/fleet audit, login/logout history, denied-attempt logging or a general security event stream.

## Atomicity and identity

Account-session authority is checked inside the mutation transaction. A selected audit append or intentional-omission counter failure rolls back the account change, any associated session revocation and ID allocation. No HTTP success is sent before that transaction commits. Cancelling a response after commit does not remove the audit event.

Records contain an ordered ID, wall-clock timestamp, action, system/account actor kind, actor/target IDs, before/after role and enabled state, and a password-set-or-change boolean. They do not contain usernames, passwords, tokens, session digests, salts, password hashes, raw bodies or full configuration. IDs are the historical identity; the user list may no longer contain a deleted target. Sequence order is authoritative when wall time changes.

Schema version 2 adds a non-reusing user-ID allocator and the audit tables. Existing accounts and sessions are preserved; allocation starts above the current maximum ID. A baseline event records the observation boundary and number of existing accounts. It does not reconstruct earlier changes or establish non-reuse before migration. All sequence values exposed to the console stay within the JSON safe-integer range.

Migration is transactional. Stop older account-store writers before upgrading and keep a consistent backup of the database and its committed state. Older binaries reject schema version 2 at startup, but a process already running old code cannot acquire the new audit contract retroactively. A binary rollback must not silently discard the audit schema. Restoring an older backup can roll back history and identities; this local store has no independent anti-rollback authority or tamper-proof external anchor.

## API and console

Administrators use `GET /v1/audit/users?after=0&limit=100`. The sequence cursor is exclusive, nonnegative and at most 9007199254740991; the page limit is 1–100. Unknown or duplicate parameters are rejected. The response has `Cache-Control: no-store` and returns:

- `records`, `next_after`, `has_more`, `oldest_id` and `latest_id` for ordered paging.
- `scope`, `coverage` and `started_at_unix_ms` for the exact observation boundary.
- `pruned_through` and `truncated` to disclose unavailable earlier history.
- `stored_records`, `capacity`, `writes_available` and `server_time_unix_ms` for observed retention capacity and freshness.

The English/Korean Account audit view provides paging, refresh, current-page JSON export and explicit retention controls. Export is only the currently displayed page, not a complete-history archive. The console retains the current page and a bounded recent back-navigation history; forward paging continues through the retained sequence. Pages are independent read snapshots; concurrent appends can appear in later pages, and concurrent pruning can create an explicitly reported history gap. Viewer access is rejected by the API independently of navigation visibility. Unavailable audit data is not an empty successful result.

## Capacity and explicit retention

The fixed capacity is 100,000 retained records. This is a row-count bound, not a disk-byte quota. Records are never silently evicted. When capacity is exhausted, operations requiring another audit record return 503 without changing accounts or sessions. An account event explicitly selected for Drop can still commit with its filtered-counter update. Mandatory policy changes require record capacity. Authentication, audit reads and explicit pruning remain available; data-plane routing is not gated by this audit capacity. `writes_available` reports observed record capacity, not eligibility of every filtered account mutation or a promise that a later disk write will succeed.

Archive required evidence before using `POST /v1/audit/users/prune`:

```json
{"through_id": 100, "expected_latest_id": 250}
```

This permanently deletes retained records with IDs at or below `through_id`. It requires current administrator authority and an exact latest-sequence precondition. Stale state returns 409 with no deletion; refresh and choose explicitly again instead of automatically retrying. Query parameters and unknown request fields are rejected.

Deletion, retention metadata and a new prune record commit together. The prune record identifies its actor, boundary and number of removed records, including when the previous page contained only a baseline. Its ID continues above prior history. This operation can recover capacity at the limit because it removes records before appending its own event, within one transaction. A failure rolls back both effects. The gateway does not verify that the caller actually archived the deleted evidence, and pruning is not a tamper-proof retention service.

## Scope and boundaries

Central scoped authority, durable configuration intent/outcome records, store-specific commit uncertainty, remote activation receipts, actor/service enrollment, login/denial event policy and fleet rollout are outside this account-only journal. It does not provide a complete configuration or fleet audit.

Schema version4 adds the `config_operations_prune` action while preserving prior records and sequence IDs. Its `through_id` is a configuration-operation boundary, not an account-audit boundary. See [configuration operation retention](CONFIG_OPERATIONS.md) for the atomic deletion/receipt and capacity recovery contract. It does not record configuration contents or establish configuration-store commit authorship.

Schema version 7 adds a native English/Korean policy editor and `GET`/`PUT /v1/audit/policy`. Audit pages expose `policy_revision`, cumulative `filtered_total` and `coverage_filtered`; policy-change receipts retain exact policy snapshots. Account recording policy is instance-local and does not govern HTTP/TCP logs or configuration recovery journals. See [audit filters and upgrade boundaries](ACCOUNT_AUDIT_FILTERS.md).
