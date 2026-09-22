# Signed updates and process replacement

Hangang has a signed release verifier, bounded downloader, atomic Unix
activation, and a stable-PID supervisor that hands listeners to a ready child.
Updates remain opt-in. They run only when `--supervised`, `--update-manifest`,
and an operator-provided update key are configured. Lua cannot request an update
or supply a release URL.

The sample [Docker Compose deployment](DEPLOYMENT.md) uses a read-only scratch
image and container replacement; it does not enable this in-place update path.
For that deployment, build and qualify a new immutable image, then replace the
container while preserving its private state volume. Do not add update flags
to the Compose example without separately designing a writable, verified
binary activation path.

## Trust bootstrap

There is no built-in signing key and no unsigned fallback. Before enabling an
update source, an operator must provision the base64 encoding of one 32-byte
Ed25519 public key with `--update-key` or `HANGANG_UPDATE_KEY`.
`TrustKey::from_base64`
rejects malformed, incorrectly sized, and weak keys. Key rotation requires an
explicit configuration change; a release manifest cannot rotate its own trust
root.

Keep the corresponding 32-byte signing seed offline or in a release signing
service. The release helper refuses a seed file that is accessible by group or
other users on Unix. It never prints the seed.

Ed25519 verification uses `VerifyingKey::verify_strict`, which performs the
library's additional signature-malleability checks. See the
[`ed25519-dalek` verification documentation](https://docs.rs/ed25519-dalek/2/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict).

## Manifest format

The published document is a small JSON envelope:

```json
{
  "payload": "eyJ2ZXJzaW9uIjoiMS4xLjAiLC4uLn0=",
  "signature": "base64-encoded-64-byte-Ed25519-signature"
}
```

`payload` is the base64 encoding of the exact JSON bytes that were signed. The
verifier checks those bytes before parsing them and never reconstructs or
reserializes the signed message. Unknown fields are rejected in both layers. The
decoded payload has this schema:

```json
{
  "version": "1.1.0",
  "target": "x86_64-unknown-linux-gnu",
  "artifact_url": "https://releases.example.net/hangang/1.1.0/hangang",
  "sha256": "64-lowercase-hexadecimal-characters",
  "size": 12345678
}
```

The signature covers all five fields. `version` must be valid SemVer and strictly
newer than the running version. `target` must exactly match the target selected by
the running binary. The artifact must have the signed byte length and SHA-256
digest. Empty artifacts and artifacts larger than 128 MiB are rejected. The
entire encoded envelope is limited to 64 KiB.

To create an envelope, first produce the compact payload JSON and then run:

```sh
cargo run --release --bin hangang-release-sign -- \
  release-payload.json ed25519-seed.base64 release-manifest.json
```

The helper validates the payload, writes through a temporary file, fsyncs it, and
renames it into place. The build pipeline should publish the artifact first and
the signed manifest last.

The same helper derives the public bootstrap value without exposing the seed:

```sh
hangang-release-sign --public-key ed25519-seed.base64
```

Enable supervised checks with:

```sh
hangang --supervised \
  --update-manifest https://releases.example.net/hangang/manifest.json \
  --update-key "$HANGANG_UPDATE_KEY" \
  --update-status-file /var/lib/hangang/update-status.json
```

The default interval is 300 seconds. `--update-interval-seconds` accepts values
of 10 seconds or more. A private release PKI can be added with `--update-ca`;
normal Web PKI roots remain available. Without `--update-status-file`, status is
stored beside the configuration as `*.update-status.json`.

## Network and staging rules

Production managers accept HTTPS URLs only. URL-embedded usernames and passwords
and URL fragments are rejected. Redirects are limited to five hops, must stay on
the original scheme, host, and effective port, and are rechecked for the HTTPS
rule. Requests carry no admin or application credentials. The updater does not
log manifest URLs or signed artifact URLs, which may contain release-system query
parameters.

The HTTP client uses rustls. Its redirect policy is explicit because a custom
Reqwest policy must implement its own hop limit; see the
[`reqwest::redirect::Policy` documentation](https://docs.rs/reqwest/0.12/reqwest/redirect/struct.Policy.html).
Hermetic tests can opt into a separate constructor that permits plain HTTP only
to an IP-literal loopback address. That constructor is not part of production
configuration.

The artifact response is streamed into a temporary file in the destination
directory. The implementation enforces both the global 128 MiB limit and the
signed size while reading, calculates SHA-256 over the bytes written, sets mode
`0700` on Unix, flushes and fsyncs the file, and only then exposes a
`StagedUpdate`. Dropping a staged update deletes it. A failed or cancelled
download stays under the temporary-file cleanup guard and cannot leave a
candidate that appears complete.

## Activation, readiness, and rollback

`UpdateManager::activate` accepts a `StagedUpdate` and an explicit install path.
It requires both files to be regular files in the same directory, verifies the
staged length and digest again, hard-links the existing install as a uniquely
named rollback, and atomically renames the staged file over the install path.
Directory metadata is fsynced around the swap. Tests use a temporary fake binary;
they never replace the test runner or current Hangang executable.

The returned `ActivatedUpdate` retains the rollback path. A caller may atomically
restore it with `UpdateManager::rollback`.

Under `--supervised`, the original process remains the stable supervisor PID. An
upgrade follows this transaction:

1. The supervisor stages the signed artifact and runs bounded `--version` and `--check`
   subprocesses. Reported version must exactly match the signed version.
2. It activates the candidate while retaining the old executable as a rollback
   hard link.
3. It freezes the old worker's configuration writes. The worker exports its
   public, admin, and dynamic TCP listeners, its exact
   runtime configuration snapshot, and its file lock when applicable through a
   private Unix `SCM_RIGHTS` channel. Descriptors remain close-on-exec outside
   this explicit handoff.
4. The candidate validates the snapshot, TLS files, Lua policies, descriptor
   roles, listener addresses, and listening-socket state. It reports `PREPARED`,
   waits for `COMMIT`, starts accepting, and reports `READY`.
5. Only after `READY` does the supervisor drain the old generation. Existing
   HTTP responses, WebSocket tunnels, and L4 streams stay in that generation
   until completion or the configured drain deadline.

If preflight, activation, descriptor validation, startup, or readiness fails,
the supervisor kills the candidate, atomically restores the rollback executable,
resumes the old worker, and keeps its listeners serving. After readiness, the
supervisor removes the rollback hard link and records the new version as active.
SIGINT/SIGTERM stop the active and draining generations within their deadlines;
SIGHUP and `POST /v1/lifecycle/restart` use the same listener-preserving handoff
without downloading a release.

`GET /v1/update/status` reports whether updating is enabled, the current phase
and version, and the last check time. `POST /v1/update/check` queues an immediate
check. Both require the admin bearer token. A signed manifest for the already
running version produces `up_to_date`; a downgrade remains a hard rejection.

## 한국어 요약

Hangang 업데이트 라이브러리는 운영자가 지정한 Ed25519 공개키로 서명된
매니페스트만 허용합니다. 내장 기본키나 무서명 우회 경로는 없습니다.
매니페스트는 버전, 빌드 대상, 아티팩트 URL, SHA-256, 정확한 크기를 모두
서명하며, 다운그레이드와 다른 빌드 대상은 거부합니다.

운영 환경에서는 HTTPS만 사용하고 리다이렉트의 출처 변경을 허용하지
않습니다. 다운로드는 128 MiB로 제한하고 임시 파일에 기록한 뒤 크기와
해시를 확인하고 fsync 합니다. 설치 시 기존 파일의 롤백 링크를 보관한 뒤
같은 디렉터리에서 원자적으로 교체합니다.

`--supervised` 모드에서는 상위 프로세스 PID를 유지한 채 공개/Admin/TCP
리스너를 새 자식 프로세스로 전달합니다. 새 프로세스가 설정과 리스너를
검증하고 READY를 보낸 뒤에만 이전 프로세스의 연결을 drain 합니다. READY
이전 실패 시 기존 실행 파일을 원자적으로 복구하고 이전 프로세스가 계속
서비스합니다. `/v1/update/status`와 `/v1/update/check`는 Admin bearer token이
필요합니다.
