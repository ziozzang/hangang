# Selective account audit recording

The instance-local account audit supports ordered `record` and `drop` rules for successful account creation, update and deletion. Its initial policy records everything. Selecting `default_action: "drop"` explicitly omits every eligible event that matches no rule.

This policy controls the durable account audit. HTTP request history, TCP connection history, access tracing, login/denial events and other management effects have separate recording boundaries; they are not silently covered by these rules.

## Policy semantics

The first matching rule decides. Conditions on different fields are combined with AND; values within an array are combined with OR. An omitted or empty array is unrestricted, and an empty `match` is an explicit catch-all. Rules are evaluated in their configured order, not sorted by their identifiers.

```json
{
  "default_action": "record",
  "rules": [
    {
      "id": "omit-routine-system-updates",
      "action": "drop",
      "match": {"actions": ["update"], "actor_kinds": ["system"]}
    },
    {
      "id": "retain-specific-account",
      "action": "record",
      "match": {"target_user_ids": [42]}
    }
  ]
}
```

In this example, a system update to user 42 matches the first rule and is omitted. Move the specific-account rule first if it should take precedence.

Supported conditions are `actions` (`create`, `update`, `delete`), `actor_kinds` (`system`, `account`), `actor_user_ids` and `target_user_ids`. IDs are positive JSON-safe integers; a system actor has no account ID and cannot match a nonempty actor-ID list. No username, credential, request body, header or query value enters the policy matcher.

Policies contain at most 64 rules; condition arrays contain at most 64 values. Rule IDs are unique, 1–64 ASCII letters, digits, dots, underscores or hyphens. Canonical serialized policy size is at most 64 KiB. Duplicate condition values, unknown fields and unsupported actions are rejected. Retention capacity remains a record-count limit, not a disk-byte quota; a policy-change record can include that full bounded snapshot.

## Durable behavior and coverage

The account mutation, live actor authorization, policy evaluation and audit append or filtered-counter increment share one SQLite immediate transaction. If the counter, selected record, ID allocator or transaction fails, the account/session change rolls back too. A filtered operation consumes neither an audit row nor an audit sequence ID.

Every retained audit record carries its `policy_revision`; migrated records use revision zero. Policy changes retain the exact new `policy_snapshot` in a mandatory `policy_change` record. `filtered_total` counts intentional omissions since policy support began and survives audit pruning. `coverage_filtered` remains true after any omission, even if the current policy records everything. Missing records must not be interpreted as evidence that no account mutation happened.

Baseline, bootstrap, policy changes and retention receipts remain recorded. Those receipts explain the policy and retention boundaries of the selected stream. Configuration acceptance, release work/acknowledgement, SQL commit receipts, pins and high-water records are recovery state, not optional observation events; this filter cannot discard them.

The audit's `writes_available` describes capacity to append another record. At the 100,000-record limit, an explicitly dropped account event can still commit with its counter update. A recorded event or policy change needs an available record slot; use the existing explicit audit-retention workflow to free capacity first. An unavailable database still prevents governed account changes.

## Administrator API and UI

`GET /v1/audit/policy` returns the instance scope, policy revision, current policy, cumulative filtered count and last-change time. `PUT /v1/audit/policy` accepts:

```json
{"expected_revision": 0, "policy": {"default_action": "record", "rules": []}}
```

The setter rechecks administrator authority and compares the revision inside the writer transaction. A changed policy, its mandatory audit receipt and its new revision commit together. A stale revision returns 409. An identical policy at the current revision is a no-op. Unknown query parameters/fields and invalid policies return 400; unavailable storage or audit capacity returns 503. Responses are no-store. A lost response is resolved by reading the policy/history, not automatic mutation replay.

The EN/KO Account audit view provides a native editor for default action, ordered rules, actions and actor/target IDs. It shows cumulative omissions and partial coverage, preserves policy snapshots in history/export, and invalidates delayed responses after view/session changes.

## Upgrade and remaining boundaries

Account schema 7 installs the policy metadata and audit revision guard atomically. Already-running audited older writers use revision zero; after a policy change, their stale audit inserts are rejected, rolling back the associated transaction. This does not fence pre-audit binaries that never append audit records. Quiesce older management processes for the upgrade; this is not a general mixed-version rollout guarantee.

This local policy does not provide central actor enrollment, tamper-proof external retention, account-only/whole-store restore detection, or a transactional audit of every management backend. The next recording-policy integrations must separately define trusted HTTP client versus socket peer, response-head versus body completion, and TCP active versus completed connection visibility. A filter applied to one output must not be advertised as suppressing another output.
