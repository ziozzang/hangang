# Hopae gRPC gateway client

[Documentation](README.md) · [한국어](ko/HOPAE_GRPC.md)

Set a route's `auth.native.transport` to `grpc`, with `address` pointing at Hopae's
`listen.grpc_gateway`. The default is `native` (HOP1). Set the existing `tls`
server name, CA, client certificate and key; mTLS is required even on loopback.
The existing route gateway key is sent as a sensitive Bearer RPC credential.
Provider code stays in Hopae; Hangang depends only on the pinned `hopae-grpc` contract.

The client reuses an HTTP/2 channel, applies `pool_size` admission, caps protobuf
messages at 128 KiB and validates the HOP1 header/body bounds. It matches response
IDs and rejects invalid status/headers. HTTP status, repeated cookies, verified
identity and upstream projections continue through the existing authentication
response path. Transport success alone is not authentication success.
No HTTP/native fallback or decision cache is introduced. RPCs have a 1-second
upper deadline; the route's existing shorter authentication timeout still cancels
the exchange. Credential/material rotation and channel retirement remain separate
qualification gates. Console SSO continues using HOP1 in this change.

The owned Hopae scenario can invoke the actual gateway client and terminate its
session between two calls on the same channel:

```sh
cargo build --example hopae_grpc_qualification
HANGANG_HOPAE_GRPC_CLIENT=/absolute/path/to/hangang/target/debug/examples/hopae_grpc_qualification cargo test --manifest-path /absolute/path/to/hopae/Cargo.toml --test scenarios grpc_mtls_session_revocation_and_http_parity
```

Actual complete gateway request-chain, Kubernetes deployment and production rollout
remain separate gates. Building the shared schema requires `protoc`.

## Shared projection request binding (unreleased)

The pinned provider-independent Hopae contract is now 3121f993. Hangang
`projection_binding::digest` uses its exact request-binding implementation and
accepts an origin-form `Request<Bytes>` plus native service/audience scope. It
hashes the complete final entity; header claims are not scope inputs. Callers
must run it after route/body rewriting and must not substitute empty bytes for
unknown streaming entities. Fixed owner-vector, changed entity/query/scope and
ambiguous target refusal tests pass. This helper is not yet invoked by credential
projection dispatch and does not enable receipt RPC or credential delivery.

## Pinned authentication receipt receiver (unreleased)

The contract pin advances to 0225145d. `projection_receipt::IssuerPin` validates
a native configured issuer/key epoch/public key and refuses weak keys. It checks
authentication purpose, signature, exact current native context binding and time
bounds using the shared contract. Its opaque checked result supplies receipt bytes,
chain hash and expiry; it is not a permission or credential-output capability.

Native adapters must authenticate the context, recheck live key/identity/policy
state, enforce clock monotonicity and consume replay state at the owning authority.
Passing a stale or caller-invented context is not made safe by this helper. The
helper is not wired into request dispatch or receipt RPC. Tests cover every-byte
tampering, context/generation/key epoch changes and expiry with a real signature.
