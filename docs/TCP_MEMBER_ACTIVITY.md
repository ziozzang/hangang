# TCP named-member stream activity

[Documentation](README.md) · [한국어 안내](README.ko.md)

See [member lifecycle](MEMBER_LIFECYCLE.md) for serving, draining and maintenance states.

`GET /v1/operations` reports `member_active_streams` for each configured
backend row. It is an integer for a named TCP member, including zero when no
stream is established. It is `null` for HTTP and legacy string-based TCP
targets. The Operations UI also treats a missing field from an older server as
unavailable; it never turns that absence into a measured zero.

The count is local to one Hangang instance and belongs to a continuously
present `(route ID, member ID)` pair. It counts established TCP streams after
the upstream dial succeeds. Pending dials are excluded. If the member's
address, health policy, or route enablement changes while streams remain open,
the count includes streams on the earlier endpoint generation. Renaming a
member or removing and later re-adding its ID starts a fresh identity and
count. The route's `route_active_connections` remains a separate route-wide
admission value, repeated on each row; HTTP `active_requests` remains a
separate HTTP request count and is `null` for TCP.

This observation is **not a drain-completion signal**. A local zero cannot
establish that another instance has no streams, and this first release accepts
only the `serving` desired state. No drain or maintenance action is exposed. A dial already in progress when a
route is disabled may still establish afterward; this counter does not add a
publication-time admission fence. Removed members have no current Operations
row even while an old stream survives.
Read the [named-member guide](NAMED_MEMBERS.md) for the configuration format
and [OpenAPI](openapi.json) for the response schema.

The internal [TCP admission lease](TCP_ADMISSION.md) separately owns pending
dials and established work. It does not change the meaning of this public
established-stream counter.

Current retirement observation: [Retired members](RETIRED_MEMBERS.md) documents the bounded active-generation registry and dedicated API/UI. It includes pending TCP admissions and removed endpoints; operator lifecycle and fleet completion remain separate work.
