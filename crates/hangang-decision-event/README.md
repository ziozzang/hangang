# Hangang Decision Event

[한국어](README.ko.md) · [Hangang](../../README.md) · [Guide](../../docs/DECISION_EVENTS.md)

Bounded `hangang.decision.v1` access-decision event contract (ADR 0019). It owns
the protobuf schema (`proto/decision.proto`), length-delimited batch framing,
receiver validation, the console JSON projection and the stable reason-code
registry with English and Korean messages. It owns no key, no policy and no
storage. Builds require `protoc`.

Encoded events are capped at 2 KiB and every list has a fixed maximum. Validation
rejects raw IP literals, e-mail addresses, request paths with queries, encodings
or parameters, free-text reasons, out-of-order or duplicate stages and sealed
values outside the `standard` profile. Unknown enum values are accepted and
projected as `unspecified`, never as allow. The JSON projection never contains
sealed values; `without_sealed` produces the copy for any sink other than the
local store.
