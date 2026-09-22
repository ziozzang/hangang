# Named HTTP and TCP members

[Documentation](README.md) · [한국어 안내](README.ko.md)

Use [the local example](../examples/named-members.json) with two origins listening on loopback ports 18081 and 18082. HTTP and TCP both select blue and green with 3:1 weights when both are eligible. Run the gateway with:

```sh
cargo run --bin hangang -- --config examples/named-members.json --listen 127.0.0.1:18080 --admin 127.0.0.1:19001
```

The route editor converts legacy address lists to named rows and edits IDs, addresses and weights. Operations exposes `member_id` (null for legacy entries). A route must use either strings or objects throughout. IDs and addresses must be unique within a named route; weights are 1–1000. Named HTTP routes leave `balance.weights` empty.

Reordering members or changing weights retains compatible health and HTTP activity by ID and exact address. Changing identity, endpoint, health policy, enabled state or transport/trust starts fresh health state as applicable. Named TCP `member_active_streams` instead counts established streams by continuously present route ID/member ID across endpoint, health and enablement changes, including streams on an old endpoint. Pending dials are excluded. Rename or removal and re-add starts a fresh count, and a removed ID has no Operations row. TCP `active_requests` remains null; the stream count has no retired-endpoint breakdown or drain-completion meaning. See [TCP member activity](TCP_MEMBER_ACTIVITY.md).

`serving`, `draining`, and `maintenance` are accepted; see [member lifecycle](MEMBER_LIFECYCLE.md). Named members require local file authority: shared ConfigStore bootstrap, writes and reads reject them until fleet reader capability coordination exists. Upgrade every reader of a local configuration before changing its representation. Lua `hangang.select_member(id)` selects an exact ID within the matched route; address-based selection remains available. Both selections are pinned against retry to another backend and cannot bypass health or member admission. The last selection call wins; a returned Lua string overrides either call as an address selection.

Run the disposable actual-server qualification after building the binary and installing the browser test dependencies:

```sh
cargo build --bin hangang
python3 tests/named_members_smoke.py
```

This starts owned origins and a temporary gateway, converts both routes through the browser, checks persistence and Operations IDs, and verifies actual HTTP/TCP weighted traffic. It terminates the fixture afterward.

Current retirement observation: [Retired members](RETIRED_MEMBERS.md) documents the bounded active-generation registry and dedicated API/UI. It includes pending TCP admissions and removed endpoints; operator lifecycle and fleet completion remain separate work.
