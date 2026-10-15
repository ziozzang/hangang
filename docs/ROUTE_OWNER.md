# Native route observation service

[Documentation](README.md) · [한국어](ko/ROUTE_OWNER.md) · [Overview](../README.md) · [Contract](../crates/hangang-route-grpc/README.md)

The optional `--route-owner-config` starts a separate, read-only mTLS gRPC
listener backed by actual request-scoped native route references. It does not
authorize a principal, sign permission or issue an upstream credential. Pumgye
reference delivery and the resulting permit/projection path remain pending.

## Private configuration

Keep the file, credential environment and private key operator controlled.
Use a dedicated 32–256-byte graphical ASCII credential; reusing the Hangang
administrator credential is rejected. No token or inline private key belongs
in this document. TLS identity and client CA are mandatory.

```json
{
  "listen": "0.0.0.0:19086",
  "certificate": "/private/tls/route.pem",
  "key": "/private/tls/route.key",
  "client_ca": "/private/tls/decision-ca.pem",
  "token_env": "HANGANG_ROUTE_OWNER_TOKEN"
}
```

The JSON file is limited to 16 KiB and rejects unknown fields. Shared-runtime TLS
file bounds apply. The listener cannot overlap another declared process, public
HTTP, workload HTTP or TCP listener. Supervised mode requires a fixed nonzero port.

## Validation and startup

Provide the referenced credentials through the private process environment.
Validation loads credentials, certificates and CA and checks declared address
conflicts, without binding the route socket. This lets a replacement validate
while the active generation still holds that port.

```sh
hangang --config /private/config.json --route-owner-config /private/route-owner.json --check
hangang --config /private/config.json --route-owner-config /private/route-owner.json --supervised
```

Queries require both a trusted client certificate and the dedicated Bearer
credential. Existing administrator/browser authentication is not a fallback.
The service uses the common bounded gRPC runtime and fails on invalid resources.

## Restart and shutdown

The supervisor transfers the listener using its own typed descriptor role.
The successor adopts the exact declared address and reloads private resources
before activation. Duplicate/unexpected roles and missing inherited listeners
refuse. A failed candidate leaves the active generation serving.

Request reference records are not handed over. Each successor has a fresh registry;
an old reference cannot become a new reference through configuration revision
reuse. Observations remain point-in-time and do not create a distributed lease.

Shutdown cancels and bounds the observation task. Unexpected listener termination
withdraws readiness and drains the gateway through its normal lifecycle. Actual
process tests cover standalone startup/shutdown, validation without binding,
supervised handover and rejection of an invalid replacement. These are local
functional checks, not Kubernetes, throughput or a new operating release.
