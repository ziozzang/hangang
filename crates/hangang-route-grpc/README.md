# Hangang Route gRPC

[한국어](README.ko.md) · [Hangang](../../README.md)

Independent generated Rust contract for request-scoped native route observations.
It owns no policy, provider, database, permission or credential projection logic.
Builds require `protoc`, as with the existing authority contracts. Rust consumers
use `hangang_route_grpc::v1`; the package is statically linked into its consumers.

`RouteOwnership/Observe` accepts a native 32-byte reference, the exact prepared
request digest and SHA-256 of the UTF-8 display of the complete final absolute
upstream URI. Request IDs are 1 through 9,007,199,254,740,991. Hashing the destination
includes its scheme/authority, unlike the separate canonical path/entity binding.
The server captures both digests once; lookup does not rehash entities.

The server library requires mTLS and a dedicated Bearer credential before native
lookup. Duplicate/missing/wrong credentials refuse. Credentials are referenced by
environment variable and must be bounded, graphical ASCII; supplied conflicting
role credentials refuse. Queries are bounded to 512 bytes and replies to 1,024.
Shared runtime limits apply to connections, streams, headers and request deadlines.

Replies derive route, service, audience, resource, action and packed client IP from
the retained native owner. Unknown/cancelled/expired references, changed digests or
snapshot replacement fail without owner metadata. The public configuration revision
is diagnostic; it is not an owner incarnation. Remaining time is 1–1,000 milliseconds
and is only a point-in-time observation. Clients must account for exchange time;
a successful reply is neither an authorization grant nor a distributed lease.

The current Hangang source has a server library, [CLI startup and supervised
handover](../../docs/ROUTE_OWNER.md), with actual socket/process qualification.
Outbound Pumgye reference delivery, remote decision clients, signed permits,
projection/replay and Kubernetes release adoption remain integration work. Never accept a caller-selected URL or an application
classification/allow claim as authoritative owner state.
