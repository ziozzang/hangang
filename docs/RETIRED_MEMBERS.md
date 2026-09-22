# Retired member observations

[Documentation](README.md) · [한국어 안내](README.ko.md)

`GET /v1/retired-members` is an administrator-only, process-local view of displaced HTTP and TCP generations that still own work. The Operations page has a dedicated English/Korean table. Query parameters `offset` and `limit` use the Operations pagination rules; limit is 1–128.

Each row contains `retirement_id`, `protocol`, `route_id`, optional `member_id`, `address`, and `active_admissions`. HTTP counts held request/body/upgrade leases. TCP counts both pending outbound dials and established streams; it is not the established-only logical `member_active_streams` counter. Removed routes and members remain visible here while their old generation owns work. IDs increase within the process and reset after restart.

Preparation reserves space for every displaced generation, even one currently idle: old admission can increase before publication. Reservation failure rejects preparation before a local administrative write persists. Abandoned candidates release their reservation without closing live gates. Publication closes the gates and retains only generations with outstanding ownership. The last release makes a row eligible for pruning on the next read or preparation. Ordinary and fresh-authority snapshots share this registry within one process.

The registry allows at most 4096 active records plus pending reserved slots. It never evicts active records. Consequently a change displacing more than the available capacity can fail even if the affected generations are currently idle; split a large change or wait for outstanding work to finish. Storage is allocated during preparation, before persistence. Response pagination is a moving observation: completion between requests can change offsets and totals.

This is active retirement observation, not durable history or a fleet drain-completion assertion. An empty result does not count current-generation work or other processes. Local-file named members support operator `draining`/`maintenance`; see [member lifecycle](MEMBER_LIFECYCLE.md). No deadline, forced connection closure, or cross-process revocation is introduced.
