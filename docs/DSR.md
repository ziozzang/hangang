# Linux IPVS direct routing

[Documentation](README.md) · [한국어](ko/DSR.md)

`hangang-dsr` is a standalone companion for operators who have an explicitly
designed Linux direct-routing network. It validates a small, strict JSON file
and installs or removes only the listed IPVS virtual services. It does not change
Hangang route configuration, advertise a VIP, install routes, configure ARP,
perform health checks, or provide a failover controller.

The companion requires Linux IPVS (`/proc/net/ip_vs`) and the `ipvsadm`
executable. It fails closed when either is unavailable.

Example configuration: [examples/dsr/config.json](../examples/dsr/config.json).
Each service is an IPv4 VIP/port/protocol tuple with one or more IPv4 real
servers. `tcp` and `udp` are supported. Real servers use IPVS direct routing
(`-g`); the network must arrange VIP ownership, ARP suppression and a direct
return path. The client source address and VIP destination remain in the IP
packet, so a correctly configured backend can return directly to the client.

Validate and render the owned plan without touching IPVS:

```sh
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --check
```

The config file must be an owner-only regular file. For example:

```sh
install -m 600 /path/to/dsr.json /absolute/private/dsr.json
```

Apply or remove only those configured services:

```sh
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --apply
cargo run --locked --bin hangang-dsr -- --config /absolute/private/dsr.json --cleanup
```

The JSON parser rejects unknown fields, duplicate services/backends, unsafe
scheduler text, loopback or unspecified addresses, zero ports, oversized
lists, and files larger than 256 KiB. The config path must be absolute,
regular, and private to its owner. Commands are built from validated argument
arrays; shell interpolation is never used. Apply refuses to overwrite an
existing IPVS service, adds the exact configured VIP service and its real
servers, and rolls back services created by that invocation if a later add
fails. Cleanup requires the existing service's scheduler, direct-routing
method, destinations, and weights to exactly match the JSON before deleting
it. It never invokes `ipvsadm -C`, and cleanup never removes an unlisted
service.

This companion does not claim production readiness for ARP ownership,
multi-host routing, endpoint fencing, draining, health transitions, IPv6,
fragmentation, TLS, or performance. UDP is rendered through IPVS, and the
Docker test exercises TCP and UDP through the companion's `--apply` and
`--cleanup` paths, checks source-IP preservation, and observes backend Ethernet
source MACs. It fails with a diagnostic when IPVS or Docker networking is not
exposed; it does not use host networking, privileged containers, host sysctls,
or production resources. The companion is a one-shot installer/remover;
operators must serialize writers for the configured VIP/port tuples. Changes
are not a kernel-wide transaction. Rollback failures are reported and require
operator reconciliation; a command cannot guarantee recovery from a concurrent
external writer or kernel failure.

## Verification

```sh
make test-dsr
```

The target runs configuration validation, builds the companion, and runs
`tests/dsr_container.py` against the local Docker Unix socket. Linux IPVS,
Docker, and network access for the Debian test image are required. The runner
owns its containers and bridges and cleans them up on exit. It checks both
TCP and UDP backend distribution and direct-return MACs, rejects cleanup when
any service differs from the configured shape, verifies apply rollback after
a conflict, and preserves an unrelated IPVS service during successful cleanup.

For a prebuilt static companion, run:

```sh
HANGANG_DSR_BIN="$PWD/target/x86_64-unknown-linux-gnu/release/hangang-dsr" python3 tests/dsr_container.py
```

Direct routing requires the director and real servers to be reachable at
layer 2 for the configured delivery path. The isolated bridge test qualifies
that topology; routed multi-host or cloud networks need their own qualification.
