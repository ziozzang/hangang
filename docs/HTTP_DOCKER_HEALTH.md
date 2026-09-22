# HTTP Docker endpoint health

[Documentation](README.md) · [한국어 안내](README.ko.md)

## Discovery and health state

HTTP active health checks support discovered `docker://CONTAINER/NETWORK/PORT` targets, including `initial_state: checking`. Discovery resolves these references to plain HTTP endpoints. Explicit HTTP upstream TLS options still require HTTPS backends; this change does not add HTTPS inference from a Docker port.

The proxy and probe monitor share the same discovery handle. Before selection, each Docker candidate must resolve and its monotonic discovery epoch is observed. A changed epoch resets active, passive and cooldown health evidence; checking starts closed until the new target passes its configured success threshold. The default healthy initial policy retains its compatibility behavior and can admit before a first successful probe. Missing references are excluded, allowing another eligible route member to be selected. Lua-pinned selection still cannot fall back onto an unapproved member.

Probe callbacks re-resolve the exact endpoint and epoch after asynchronous work. Old callbacks cannot update a newer generation. HTTP request leases also capture the epoch: a delayed response or transport failure from an old container releases its ownership normally but cannot qualify or quarantine the replacement.

Outbound pools use the configured route/backend identity plus the resolved endpoint, epoch, runtime and discovery handle. Replacement at the same IP and port replaces the pool entry; repeated refreshes of an unchanged identity reuse it. Epochs do not accumulate separate map entries. A held old client can finish work already admitted to it. New connector calls validate discovery before and after outbound dialing, including SOCKS negotiation; the proxy checks again immediately before sending through a selected client. Publication can race after that final check, so this is not synchronous revocation of already admitted work. Idle connection reuse remains enabled within a generation.

The existing bounded pool map remains in force. Operations combines current discovery with health evidence, so missing or unobserved replacement endpoints are not advertised as eligible using old probe results. Counts remain associated with the configured member node: a discovery epoch changes endpoint health and connection reuse, not the configuration retirement registry's logical association. Dynamic old-endpoint activity does not yet have a separate retired-members row.

## Scope boundaries

Ordinary DNS changes behind a static hostname have no Docker discovery epoch and are outside this contract. Shared-store named-member capability coordination, aggregate/fleet drain completion and fleet-wide operation remains outside this feature.
