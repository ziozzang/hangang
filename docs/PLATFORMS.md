# Platforms and native binaries

[Documentation index](README.md) · [한국어](ko/PLATFORMS.md)

## From laptop to enterprise deployment

Use the same gateway, configuration format, Lua policies, management UI, and APIs on a development laptop and on Linux servers. macOS support focuses on local development, demonstrations, and proxy workloads. Linux is the reference platform for supervised upgrades and kernel-dependent deployment features. Moving a configuration between hosts still requires adapting listener addresses, file paths, credentials, certificates, and network permissions.

## Release targets

The native qualification workflow builds and tests these four targets independently. A target must pass its native build, library tests, and gateway smoke tests before its archive is eligible for a release. The workflow produces downloadable qualification artifacts; it does not automatically publish or sign them.

| Platform | Rust target | Archive suffix | Scope |
| --- | --- | --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` | `linux-amd64.tar.gz` | Reference deployment platform |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `linux-arm64.tar.gz` | 64-bit ARM servers and Linux machines |
| macOS Intel | `x86_64-apple-darwin` | `darwin-amd64.tar.gz` | Laptop development and ordinary gateway execution |
| macOS Apple Silicon | `aarch64-apple-darwin` | `darwin-arm64.tar.gz` | Native ARM64 laptop development and ordinary gateway execution |
| Native Windows | Not currently supported | None | Requires a Windows process, socket, and permissions implementation |
| 32-bit ARM | Not currently qualified | None | ARM64 support does not imply ARMv7 support |

An archive name is `hangang-v<VERSION>-<suffix>`. Only assets actually present on the [release page](https://github.com/ziozzang/hangang/releases) are published binaries. The initial `v0.2.1` release contains Linux x86-64 only; configuring a build matrix does not retroactively add binaries to it.

Native jobs use Ubuntu 24.04 for Linux, macOS 15 Intel for x86-64, and macOS 15 Apple Silicon for ARM64. See the [workflow](../.github/workflows/binaries.yml) for exact compiler versions and checks, and [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners) for runner specifications. These environments are the qualification baseline, not evidence that every older OS version works.

## macOS limits

- Normal HTTP/TCP routing, scoped UDP relay, the management console, APIs, Lua policies, and dynamic configuration use the same application code as Linux.
- Lua workers require explicit `--allow-unsandboxed-lua` on macOS. Without it, Lua operations fail closed; routes that do not use Lua can run normally. The opt-in retains separate processes, Lua VM limits, and operation timeouts, but has neither Linux seccomp nor the Linux process address-space limit. Use only trusted development scripts; do not treat this mode as an untrusted-code sandbox.
- `--supervised` and the internal serving-child mode are Linux-only and fail explicitly on macOS. Consequently, periodic binary installation through `--update-github` or `--update-manifest` is unavailable there. Read-only `--check-update` remains available. Stop and replace the binary manually for macOS upgrades; there is no promise of connection continuity during that replacement.
- `hangang-dsr` is omitted from macOS archives. IPVS DSR requires a Linux kernel and suitable networking privileges; a macOS host does not provide it.
- Docker discovery requires a reachable Docker API. Docker Desktop runs Linux containers in a VM; host networking, device access, and packet paths differ from a native Linux server.
- Archives are not Apple Developer ID signed or notarized. An Ed25519 update manifest or checksum is not Apple notarization. macOS security policy may require approval before execution.
- Account databases and disk caches reject symbolic links in their directory paths. macOS commonly aliases `/tmp` and `/var` into `/private`; use a physical path (for example, Python `os.path.realpath`) for writable state. The quick-start guide resolves its temporary state directory explicitly. The qualification workflow also canonicalizes `TMPDIR` without disabling the symlink checks.
- Host-local paths, Unix permissions, external services, and privileged ports still need environment-specific configuration. A passing laptop smoke test is not a Linux production capacity qualification.

## Windows path

Use Linux builds inside WSL2 or Linux containers while native Windows support is pending; match the binary architecture to the Linux environment. This is Linux execution, not a Windows `.exe` release. Check the VM's listener exposure and forwarding separately from the Windows host firewall.

Native Windows is currently blocked by Unix-domain administration and worker sockets, Unix signals/process control, descriptor passing, and Unix permission handling. The release workflow does not upload a Windows placeholder or mark an unbuildable target successful. A future port needs native gateway, Lua worker, shutdown, configuration persistence, and networking tests before publication; Windows service lifecycle and binary replacement also need their own design.

## Build and package

Run packaging on the target OS and architecture: the tool executes the compiled gateway to verify its version. Rust dependencies include vendored Lua and SQLite and require a working C compiler. Python 3.11 or newer is needed for packaging. For example, on a Linux ARM64 host:

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --locked --release --bins --target aarch64-unknown-linux-gnu
python3 tools/prepare_release.py --unsigned \
  --target aarch64-unknown-linux-gnu --output dist
```

Unsigned staging writes the gateway binary, archive, and `SHA256SUMS`; it does not write a signed manifest or public key and cannot be used as a trusted automatic update. The output directory must be empty. On macOS, select the matching `apple-darwin` target; the archive includes the gateway and five portable companion binaries, excluding DSR.

For an authorized release, use `--signing-seed-file` instead of `--unsigned` on a trusted native build host. Keep the private signing seed outside the repository and CI artifacts. The tool checks it against the repository's pinned public key. See [signed updates](UPDATES.md) for asset names, trust provisioning, and Linux installation behavior.
