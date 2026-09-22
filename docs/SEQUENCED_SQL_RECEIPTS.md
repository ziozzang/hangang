# Sequenced SQL commit receipts (V2)

[Documentation](README.md) · [한국어 안내](README.ko.md)

V2 gives each accepted SQL configuration operation an identity derived from its durable local acceptance sequence. SQL retains the highest committed sequence for each acceptance authority independently of individual receipts and of the current configuration epoch. This supplies replay fencing for receipt retention. It does not implement pruning, archive verification, central scoped authorization or fleet activation.

## Identity and acceptance

Account schema 5 adds `receipt_version` to operation history. Existing operations keep their original IDs and become explicit V1 records. New HTTP configuration writes select V2 when the SQL store advertises support; File/Redis and V1-only stores retain V1 acceptance behavior. V2 requires a known SQL authority epoch.

Inside the same SQLite immediate transaction as live account authorization and acceptance, the journal allocates `id` from its non-reused sequence. That value becomes `acceptance_seq`. The V2 correlation ID is 32 lowercase hexadecimal characters: a 16-character hexadecimal sequence prefix followed by the first eight SHA-256 bytes of `"hangang-op-v2" || decoded_authority_id || sequence_as_8_big_endian_bytes`. The suffix is a checksum, not a credential. SQL store entrypoints validate this canonical identity and the assigned candidate digest before writing.

The authoritative V2 receipt key is `(authority_id, acceptance_seq)`. V1 lookup remains `(authority_id, operation_id)` in a separate namespace. A coincidentally equal V1 random ID must never be interpreted as a V2 operation. The common current-proof endpoint displays the current row's correlation fields; it does not select a historical receipt namespace or prove activation.

## SQL commit fence

A successful V2 write atomically updates configuration, current stamp, retained V2 receipt, shared receipt count and the authority's committed-sequence high-water mark. PostgreSQL performs these steps in one invoker-rights server function call; an exception rolls back all effects. SQLite uses one immediate transaction. An exact current V2 retry can be observed as applied without another receipt. A historical receipt alone cannot reactivate an old candidate.

A sequence at or below the stored high-water mark cannot publish a new configuration. If a later acceptance sequence commits first, an earlier accepted operation is stale and must be prepared and accepted again as a new operation. A configuration-row deletion and new epoch do not reset the authority fence. The V1 and V2 receipt tables share a 100,000-record cap. The authority registry is separately bounded at 4,096 entries and has no automatic eviction; a registered authority can continue when registry slots are exhausted if receipt capacity remains.

## Upgrade and writer compatibility

Quiesce old management processes before migrating account or SQL configuration storage. Older account binaries reject newer account schemas at startup; this is not a per-request fence for a process that was already running. Mixed-version reads or writes after migration are not qualified. SQL adds current stamp version/sequence and a write-generation counter with a database trigger; upgraded write paths advance that counter when replacing protected stamps. Older writers that cannot satisfy this guard are rejected. Ordinary system CAS remains a distinct trusted path that explicitly clears stamps; this is not a claim that every direct SQL writer is centrally authenticated or audited.

Existing V1 receipts are not relabeled or backfilled into V2. Older current stamps continue to have their existing evidence semantics. The console treats a missing `receipt_version` from an older server as legacy V1 only, labels that compatibility case and preserves the raw record during export. Explicit versions other than 1 or 2 are invalid.

## Administrator lookup and UI

`GET /v1/config/commit-receipt-v2?authority_id=<32 lowercase hex>&acceptance_seq=<positive safe integer>` requires exactly those two parameters. The sequence is canonical decimal, without a sign or leading zero, from 1 through 9007199254740991. Unknown/duplicate parameters are rejected. Live administrator authority is rechecked after the store read; the response is no-store and storage errors are redacted.

The observation contains `scope:"configuration_authority"`, `supported`, `receipt`, `high_water`, `stored_records`, `capacity`, `registered_authorities`, `authority_capacity`, `writes_available` and `server_time_unix_ms`. A supported, unregistered authority has high-water zero. Unsupported stores return null for the receipt and all fence/capacity values. A receipt contains `epoch`, `revision` and `stamp` with `authority_id`, `acceptance_seq`, `operation_id` and `candidate_sha256`.

The English/Korean lookup has separate V1 and V2 modes. It shows the committed-sequence fence and both capacity limits; `writes_available` describes capacity for the queried authority, not overall write readiness. Changing mode, identifiers, role, login state or page invalidates delayed results. Reading a receipt never replays a write or changes local operation outcomes.

## Bounded retained-receipt export

`GET /v1/config/commit-receipts-v2` enumerates retained V2 receipts for one required `authority_id`. Optional `after_seq` defaults to 0 and `limit` to 100 (range 1–100). Continuations supply both `snapshot_high_water` and `retention_generation`; a nonzero cursor requires both, with `after_seq <= snapshot_high_water`. All numbers are canonical nonnegative decimal safe integers; unknown and duplicate parameters fail with 400.

The first page reads the authority fence and rows from one SQL snapshot. Later pages select only `after_seq < acceptance_seq <= snapshot.high_water` in ascending sequence order and preserve that snapshot token. New commits above the pinned high-water can continue without restarting an export. Each page reads at most 101 candidate rows. A generation mismatch or high-water regression returns 409; discard partial results and start again. Storage failures are generic 503. Administrator authority is rechecked after storage I/O, including unsuccessful observations.

The response has `scope`, `supported`, `authority_id`, `receipts`, `snapshot:{high_water,retention_generation}`, `next_after`, `has_more` and `server_time_unix_ms`. An empty terminal page retains the supplied cursor. Unsupported stores return empty receipts and null snapshot/cursor/has_more. A never-registered authority has an empty prefix at high-water and generation zero; later registration does not change that empty prefix.

The English/Korean console exports at most 1,000 pages / 100,000 receipts, followed by an empty terminal probe under the same fence. It rejects inconsistent pages, stale authority/query/session state and partial exports. The downloaded JSON represents retained V2 SQL commit evidence through the pinned high-water. Sequence gaps are valid and do not prove missing or uncommitted operations. The download does not verify archival storage durability, include V1 receipts or prove local/fleet activation.

`retention_generation` starts at zero in existing and new authority rows. No pruning is exposed. A supported deletion must atomically advance that generation, preserve high-water and supply its own authorization/audit protocol. Direct database edits and a restore recreating the same fence values can evade this token; independent rollback anchoring remains separate. A final probe is an observation at its own read boundary, not a lock held until the user stores the file.

## Retention and recovery boundaries

There is still no receipt-pruning endpoint. Safe deletion needs an explicit archive/retention decision and audited authorization, with the durable identity fence retained after deletion. V1 random-ID receipts require an additional V1 writer retirement boundary before they can be safely removed. Authority registry entries themselves cannot be silently dropped to recover space.

High-water zero or missing receipt does not prove that an operation never committed. Older writers, another store or a backup restore can explain missing evidence. A restored local account database can reuse previously allocated sequence numbers; a surviving SQL fence rejects already committed sequences, but cannot reconstruct lost acceptance provenance for sequences that never reached SQL. A supported recovery procedure must rotate the restored account authority and retire its old pending work. Restoring both stores to an earlier consistent state cannot be detected without an independent anti-rollback anchor.

These mechanisms do not make account acceptance and SQL commit one transaction, do not resolve all local Accepted/Indeterminate rows, and do not provide central enrollment, scoped actor authorization, outbox execution or fleet deployment acknowledgements. No mixed-version production rollout, physical disk-full or power-loss qualification is implied by the logical rollback tests.

Online capacity recovery is not exposed. It requires unresolved pins, durable local release acknowledgement, archive verification and SQL-coupled deletion evidence before retained receipts can be removed safely.

The [V2 release workflow](SQL_RECEIPT_RELEASE.md) adds SQL-coupled default pins, account schema-6 completion acknowledgement and explicit English/Korean recovery. Receipt-schema migration is atomic; existing V2 receipts start protected. Neither pin release nor local journal pruning deletes SQL receipts.
