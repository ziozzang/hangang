# Selective raw TCP completion recording

`settings.tcp_recent_recording` chooses which completed raw TCP connections enter the instance-local recent-history ring. An absent or `null` policy records every tracked completion. The active-connection inventory is independent of this policy.

```json
{
  "default_action": "record",
  "rules": [
    {
      "id": "omit-routine-echo",
      "action": "drop",
      "match": {
        "route_ids": ["echo"],
        "outcomes": ["eof"]
      }
    }
  ]
}
```

Rules run in order; the first matching rule chooses `record` or `drop`. Populated fields are combined with AND, entries within a field are alternatives, and empty criteria match every completion. If no rule matches, `default_action` applies.

| Match field | Meaning |
| --- | --- |
| `listen_addresses` | Exact raw TCP listener socket address captured at accept, including port. An old address can remain useful while an existing connection finishes after the route moves. |
| `peer_cidrs` | Socket peer IP; IPv4-mapped IPv6 peers are treated as IPv4. |
| `route_ids` | Exact route IDs captured for the connection. |
| `route_matched` | Explicit matched/unmatched choice. `false` cannot be combined with route IDs. |
| `outcomes` | Final TCP outcome, such as `eof`, `dial_failed`, `mtls_rejected`, or `capacity`. |

The policy permits at most 64 ordered rules and 64 entries per match list, with a 64 KiB serialized limit. It has no payload, raw SNI, credential, backend-member, or country condition. Invalid policies reject publication and leave the current configuration serving.

At completion, Hangang captures one current recording policy and configuration revision. A connection opened earlier uses the policy active when it finishes, while its route, peer, and outcome retain their original connection meaning. Changing a policy does not delete existing history. A recorded row carries `policy_revision` as decimal text; `null` means no configuration-authority revision is known.

`filtered_total` is a process-lifetime decimal counter of deliberately omitted tracked completions. An intentional omission receives no completion event ID. Capacity or retention eviction is counted separately in `dropped_total`; untracked connections use `omitted_total`/`active_untracked` and have no final record. Forwarding, active visibility, byte counters, and aggregate metrics do not depend on recording selection. The English/Korean console edits ordered rules with configuration revision checks and displays intentional omissions separately from capacity loss.

The ring is bounded and process-local, not a complete or durable traffic audit. This policy does not govern HTTP history, account audit, debug output, or workload HTTP listeners. See the [example configuration](../examples/tcp-recording/hangang.json) and [TCP history fields](TCP_CONNECTION_HISTORY.md).
