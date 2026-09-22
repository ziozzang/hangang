# 서명된 업데이트와 프로세스 교체

[문서 목차](../README.ko.md) · [English](../UPDATES.md)

Hangang에는 서명된 릴리스 검증기, 제한된 다운로더, 원자적 Unix 활성화, 그리고 준비된 자식 프로세스에 리스너를 넘기는 안정적인 PID 감독자가 있습니다. 업데이트는 옵트인으로 유지됩니다. `--supervised`, `--update-manifest` 또는 `--update-github`, 그리고 운영자가 제공한 업데이트 키를 모두 구성했을 때만 실행됩니다. Lua는 업데이트를 요청하거나 릴리스 URL을 제공할 수 없습니다.

샘플 [Docker Compose 배포](../DEPLOYMENT.md)는 읽기 전용 scratch 이미지와 컨테이너 교체를 사용하며 이 인플레이스 업데이트 경로를 활성화하지 않습니다. 해당 배포에서는 새 불변 이미지를 빌드하고 검증한 뒤 개인 상태 볼륨을 보존하며 컨테이너를 교체하십시오. 쓰기 가능하고 검증된 바이너리 활성화 경로를 별도로 설계하지 않은 채 Compose 예시에 업데이트 플래그를 추가하지 마십시오.

감독 프로세스를 통한 바이너리 설치는 Linux 전용입니다. macOS는 읽기 전용 릴리스 확인과 수동 교체를 지원합니다. [플랫폼 제한](PLATFORMS.md)을 참고하세요.

## 연속성과 배포 모드

실시간 구성, 감독형 프로세스 교체, 서명된 바이너리 업데이트는 서로 다른 유지 관리 작업을 해결합니다.

| 모드 | 계속 사용할 수 있는 것 | 전제 조건과 제한 |
| --- | --- | --- |
| 실시간 구성 게시 | 프로세스와 영향받지 않는 리스너는 활성 상태를 유지하며, 스냅샷을 교체하기 전에 후보를 준비합니다. | [게시](../CONFIG_PUBLICATION.md)를 참조하십시오. 보안 정책 변경은 기존 스트림을 의도적으로 철회할 수 있으며 영속성은 로컬 활성화와 별개입니다. |
| 감독형 재시작 | 수신 소켓을 대체 프로세스로 전달하고 이전 세대는 배출하는 동안 수립된 응답과 터널을 유지합니다. | TCP 관리 리스너(`--admin-socket` 아님)를 사용하는 Unix `--supervised` 모드입니다. `SIGHUP` 또는 `POST /v1/lifecycle/restart`가 핸드오프를 시작합니다. 후보가 실패해도 이전 워커는 계속 사용할 수 있습니다. |
| 서명된 인플레이스 바이너리 업데이트 | 검증된 스테이징과 원자적 실행 파일 활성화 뒤에 같은 리스너 핸드오프가 이어집니다. | 명시적인 매니페스트/키 구성, 같은 파일 시스템의 하드 링크와 원자적 rename이 가능한 쓰기 가능 설치 디렉터리가 필요합니다. 준비 완료 전 실패는 실행 파일 롤백을 호출하며 복구는 여전히 정상 저장소에 의존합니다. |
| 컨테이너/이미지 교체 | 오케스트레이터와 주변 로드 밸런서가 결정합니다. | 읽기 전용 Compose 템플릿은 감독형 인플레이스 바이너리 업그레이드를 수행하지 않습니다. 이미지 교체에는 readiness, draining, 적절한 다중 인스턴스 롤아웃 설계를 사용하십시오. |

[UDP/QUIC 경로](../UDP.md)는 감독 모드를 거부합니다. 해당 소켓과 세션은 이 핸드오프의 일부가 아닙니다. UDP 경로를 업데이트하거나 프로세스를 교체하면 영향받는 흐름이 초기화됩니다. 독립형 [DSR 보조 프로그램](../DSR.md)도 게이트웨이 감독자 수명 주기 밖에 있습니다.

배출 예산의 기본값은 30초(`--drain-seconds`)입니다. 이를 넘겨 지속하는 이전 세대 연결은 닫힐 수 있습니다. 스트림이 배출되는 동안에도 승인/보안 검사는 계속됩니다. 연결을 보존한다고 해서 신원이나 신뢰 철회를 우회해서는 안 됩니다. 기존 연결은 새 프로세스로 이전되지 않고 원래 프로세스에 남습니다. 프로세스 로컬 관측값과 카운터는 새 세대와 함께 재시작될 수 있지만 로컬 계정 데이터베이스는 디스크에 남습니다.

자동 실행 파일 롤백은 서명된 업데이터의 활성화 경로에 속합니다. 운영자가 실행 파일을 수동으로 교체하고 재시작을 요청하면 후보 실패 시 이전 워커는 계속 제공할 수 있지만 재시작 경로는 수동으로 바꾼 파일을 복원하지 않습니다. 성공한 `READY` 뒤 업데이터는 롤백 링크를 제거합니다. 이후 애플리케이션 실패를 자동으로 롤백하거나 데이터베이스/스키마 변경을 되돌리지 않습니다. 모든 업그레이드 전에 writer/schema 호환성을 확인하십시오. 호스트, 감독자, 저장소 실패는 계획된 핸드오프의 연속성 보장 범위 밖입니다.

## GitHub 릴리스 검색

GitHub 원본은 `ziozzang/hangang`의 최신 게시 안정 릴리스를 사용합니다. 검색, 플랫폼 자산 선택, 임시 파일 교체 작업 흐름은 [Sugyeol의 self-update 설계](https://github.com/ziozzang/sugyeol/blob/main/selfupdate.go)를 참고합니다. Hangang은 추가로 기존 Ed25519 서명 매니페스트를 요구하고 구성 사전 점검, readiness 게이트 교체, readiness 전 롤백을 수행합니다.

게이트웨이 구성을 로드하거나 설치하지 않고 원격 버전을 확인합니다.

```sh
hangang --check-update
hangang --about
```

`--check-update`는 현재/최신 semantic version, `update_available` 플래그, `signed_assets_present`, 릴리스 페이지 URL을 담은 JSON을 출력합니다. 자산 존재는 서명이 검증되었다는 주장이 아닙니다. GitHub 네트워크/속도 제한 오류는 설치가 최신이라고 주장하지 않고 실패를 반환합니다. 공개 API는 자격 증명 없이 조회하며 비공개 저장소와 임의 저장소 재정의는 지원하지 않습니다.

독립적으로 프로비저닝한 base64 Ed25519 공개 키로 자동 확인과 설치를 활성화합니다.

```sh
export HANGANG_UPDATE_KEY="$(cat /private/update-public-key)"
hangang --config /private/hangang.json --supervised --update-github \
  --update-interval-seconds 300
```

`--update-github`와 `--update-manifest`는 함께 사용할 수 없습니다. GitHub 원본은 시스템 HTTPS 신뢰를 사용하며 `--update-ca`를 받지 않습니다. 기존 업데이트 상태/확인 API와 콘솔 제어도 이 원본에 적용됩니다. GitHub는 실행 대상에 다음 자산을 제공해야 합니다(아래는 Linux amd64).

- `hangang-x86_64-unknown-linux-gnu`: 릴리스 tarball이 아닌 원시 실행 파일입니다.
- `hangang-x86_64-unknown-linux-gnu.manifest.json`: 아래 설명하는 서명된 envelope입니다.

정규 안정 `vMAJOR.MINOR.PATCH` 릴리스 태그가 필요합니다. draft와 prerelease 메타데이터, 누락/중복 자산, 일치하지 않는 대상/URL/크기, 잘못된 서명, 다운그레이드는 거부됩니다. 서명 매니페스트 버전, artifact URL, 바이트 크기는 선택 릴리스 자산과 일치해야 하며 SHA-256 digest는 다운로드 중 검증됩니다. GitHub 릴리스 메타데이터와 `SHA256SUMS`만으로는 새 바이너리 실행 권한이 되지 않습니다.

이 GitHub 원본만 정확한 저장소의 `github.com` 릴리스 경로에서 `release-assets.githubusercontent.com`으로 HTTPS 리디렉션을 허용합니다. 일반 매니페스트 원본은 same-origin 전용 리디렉션을 유지합니다. 메타데이터는 4 MiB, 매니페스트는 64 KiB, 실행 파일은 128 MiB로 제한됩니다. 서명 seed는 게이트웨이 런타임이나 저장소에 포함되어서는 안 됩니다.

`--about`은 빌드 버전, 저장소 URL, `Jioh Jung <jung@jioh.net>`를 출력합니다. 보조 실행 파일도 동일한 정보 플래그를 지원합니다. `--version`은 업데이트 사전 점검 호환성을 위해 기계가 읽을 수 있는 하나의 버전 줄로 유지됩니다.

## GitHub 업데이트 자산 게시

프로젝트의 릴리즈 검증 공개키는 [release-public-key.txt](../../release-public-key.txt)에 공개됩니다. 검토한 사본을 실행 환경의 공개키 파일로 배치하세요. 업데이트 중 임의의 교체 키를 다운로드하면 서명 신뢰의 의미가 없어집니다. v0.2.1 이전 릴리즈에는 GitHub 소스에 필요한 원시 실행 파일과 서명된 manifest가 포함되어 있지 않습니다.

릴리즈 바이너리를 빌드한 뒤, 해당 공개키에 대응하는 비공개 서명 시드로 자산을 준비합니다.

```sh
make static
python3 tools/prepare_release.py \
  --signing-seed-file /private/release-signing/ed25519-seed \
  --output /private/release-assets
```

릴리즈 준비 도구는 Python 3.11 이상이 필요합니다. 출력 디렉터리는 비어 있어야 합니다. 이 도구는 빌드 버전을 확인하고 게이트웨이와 보조 프로그램을 패키징하며, 공개키를 내보내고 원시 게이트웨이의 manifest에 서명한 뒤 `SHA256SUMS`를 생성합니다. 로컬 파일만 준비합니다. 모든 출력 파일을 해당 `vMAJOR.MINOR.PATCH` GitHub 릴리즈의 자산으로 게시하세요. 서명 시드는 비공개로 유지하고 저장소 외부에 백업해야 합니다. 준비된 자산에 시드는 절대 포함되지 않습니다. 이 도구는 실행 중인 게이트웨이를 배포하거나 설정된 신뢰 키를 교체하지 않습니다.

## 신뢰 부트스트랩

내장 서명 키나 무서명 대체 경로는 없습니다. 업데이트 원본을 활성화하기 전에 운영자는 `--update-key` 또는 `HANGANG_UPDATE_KEY`로 32바이트 Ed25519 공개 키 하나의 base64 인코딩을 프로비저닝해야 합니다. `TrustKey::from_base64`는 잘못된 형식, 잘못된 크기, 취약한 키를 거부합니다. 키 회전에는 명시적인 구성 변경이 필요하며 릴리스 매니페스트가 자신의 신뢰 루트를 회전할 수 없습니다.

해당 32바이트 서명 seed는 오프라인 또는 릴리스 서명 서비스에 보관하십시오. 릴리스 도우미는 Unix에서 그룹이나 다른 사용자가 접근할 수 있는 seed 파일을 거부합니다. seed를 출력하지 않습니다.

Ed25519 검증은 라이브러리의 추가 서명 가변성 검사를 수행하는 `VerifyingKey::verify_strict`를 사용합니다. [`ed25519-dalek` 검증 문서](https://docs.rs/ed25519-dalek/2/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict)를 참조하십시오.

## 매니페스트 형식

게시 문서는 작은 JSON envelope입니다.

```json
{
  "payload": "eyJ2ZXJzaW9uIjoiMS4xLjAiLC4uLn0=",
  "signature": "base64-encoded-64-byte-Ed25519-signature"
}
```

`payload`는 서명한 정확한 JSON 바이트의 base64 인코딩입니다. 검증기는 파싱 전에 그 바이트를 확인하며 서명 메시지를 재구성하거나 다시 직렬화하지 않습니다. 두 계층 모두 알 수 없는 필드를 거부합니다. 디코드된 payload는 다음 스키마입니다.

```json
{
  "version": "1.1.0",
  "target": "x86_64-unknown-linux-gnu",
  "artifact_url": "https://releases.example.net/hangang/1.1.0/hangang",
  "sha256": "64-lowercase-hexadecimal-characters",
  "size": 12345678
}
```

서명은 다섯 필드 모두를 포함합니다. `version`은 유효한 SemVer여야 하고 실행 중 버전보다 엄격히 새로워야 합니다. `target`은 실행 바이너리가 선택한 대상과 정확히 일치해야 합니다. artifact는 서명한 바이트 길이와 SHA-256 digest를 가져야 합니다. 빈 artifact와 128 MiB보다 큰 artifact는 거부됩니다. 전체 인코딩 envelope는 64 KiB로 제한됩니다.

envelope를 만들려면 먼저 compact payload JSON을 만든 뒤 실행합니다.

```sh
cargo run --release --bin hangang-release-sign -- \
  release-payload.json ed25519-seed.base64 release-manifest.json
```

도우미는 payload를 검증하고 임시 파일을 통해 쓰며 fsync한 뒤 제자리로 rename합니다. 빌드 파이프라인은 artifact를 먼저, 서명 매니페스트를 마지막에 게시해야 합니다.

같은 도우미는 seed를 노출하지 않고 공개 bootstrap 값을 파생합니다.

```sh
hangang-release-sign --public-key ed25519-seed.base64
```

감독형 확인을 다음처럼 활성화합니다.

```sh
hangang --supervised \
  --update-manifest https://releases.example.net/hangang/manifest.json \
  --update-key "$HANGANG_UPDATE_KEY" \
  --update-status-file /var/lib/hangang/update-status.json
```

기본 간격은 300초입니다. `--update-interval-seconds`는 10초 이상 값을 받습니다. 비공개 릴리스 PKI는 `--update-ca`로 추가할 수 있고 일반 Web PKI 루트는 계속 사용 가능합니다. `--update-status-file`이 없으면 상태는 구성 옆의 `*.update-status.json`으로 저장됩니다.

## 네트워크와 스테이징 규칙

프로덕션 관리자는 HTTPS URL만 받습니다. URL 내장 사용자 이름과 비밀번호, URL 프래그먼트는 거부됩니다. 리디렉션은 최대 다섯 홉이며 원래 scheme, host, 유효 포트 안에 남아야 하고 HTTPS 규칙을 다시 검사합니다. 요청은 admin 또는 애플리케이션 자격 증명을 담지 않습니다. 업데이터는 릴리스 시스템 쿼리 매개변수를 포함할 수 있는 매니페스트 URL이나 서명 artifact URL을 로그에 남기지 않습니다.

HTTP 클라이언트는 rustls를 사용합니다. 사용자 정의 Reqwest 정책은 자체 홉 제한을 구현해야 하므로 리디렉션 정책은 명시적입니다. [`reqwest::redirect::Policy` 문서](https://docs.rs/reqwest/0.12/reqwest/redirect/struct.Policy.html)를 참조하십시오. hermetic 테스트는 IP-literal loopback 주소에만 평문 HTTP를 허용하는 별도 constructor를 선택할 수 있습니다. 이 constructor는 프로덕션 구성의 일부가 아닙니다.

artifact 응답은 대상 디렉터리의 임시 파일로 스트리밍됩니다. 구현은 읽는 동안 전역 128 MiB 제한과 서명 크기를 모두 강제하고, 기록한 바이트의 SHA-256을 계산하며, Unix에서 mode `0700`을 설정하고, 파일을 flush/fsync한 뒤에만 `StagedUpdate`를 노출합니다. 스테이징된 업데이트를 drop하면 삭제됩니다. 실패하거나 취소된 다운로드는 임시 파일 정리 가드 아래에 남아 완료된 것처럼 보이는 후보를 남길 수 없습니다.

## 활성화, readiness 및 롤백

`UpdateManager::activate`는 `StagedUpdate`와 명시적 설치 경로를 받습니다. 두 파일이 같은 디렉터리의 일반 파일이어야 하며, 스테이징 길이와 digest를 다시 검증하고, 기존 설치 파일을 고유 이름의 롤백으로 hard-link한 뒤, 스테이징 파일을 설치 경로 위에 원자적으로 rename합니다. 교체 전후로 디렉터리 메타데이터를 fsync합니다. 테스트는 임시 fake binary를 사용하며 테스트 러너나 현재 Hangang 실행 파일을 교체하지 않습니다.

반환된 `ActivatedUpdate`는 롤백 경로를 보존합니다. 호출자는 `UpdateManager::rollback`으로 이를 원자적으로 복원할 수 있습니다.

`--supervised`에서 원래 프로세스는 안정적인 supervisor PID로 남습니다. 업그레이드는 다음 트랜잭션을 따릅니다.

1. 감독자가 서명 artifact를 스테이징하고 제한된 `--version`, `--check` 하위 프로세스를 실행합니다. 보고 버전은 서명 버전과 정확히 일치해야 합니다.
2. 이전 실행 파일을 롤백 hard link로 보존하며 후보를 활성화합니다.
3. 이전 워커의 구성 쓰기를 동결합니다. 워커는 공개, admin, dynamic TCP 리스너, 정확한 런타임 구성 스냅샷, 해당하는 경우 파일 lock을 비공개 Unix `SCM_RIGHTS` 채널로 내보냅니다. descriptor는 이 명시적 핸드오프 밖에서 close-on-exec 상태를 유지합니다.
4. 후보는 스냅샷, TLS 파일, Lua 정책, descriptor 역할, 리스너 주소, 수신 소켓 상태를 검증합니다. `PREPARED`를 보고하고 `COMMIT`을 기다린 후 수락을 시작하여 `READY`를 보고합니다.
5. `READY` 뒤에만 감독자가 이전 세대를 배출합니다. 기존 HTTP 응답, WebSocket 터널, L4 스트림은 완료 또는 구성된 drain deadline까지 그 세대에 남습니다.

사전 점검, 활성화, descriptor 검증, 시작, readiness가 실패하면 감독자는 후보를 종료하고 롤백 실행 파일을 원자적으로 복원하며 이전 워커를 재개해 리스너 제공을 유지합니다. readiness 후 감독자는 롤백 hard link를 제거하고 새 버전을 활성으로 기록합니다. SIGINT/SIGTERM은 마감 안에 활성과 배출 세대를 중지합니다. SIGHUP와 `POST /v1/lifecycle/restart`는 릴리스를 다운로드하지 않고 같은 리스너 보존 핸드오프를 사용합니다.

`GET /v1/update/status`는 업데이트 활성화 여부, 현재 phase와 version, 마지막 확인 시간을 보고합니다. `POST /v1/update/check`는 즉시 확인을 대기열에 넣습니다. 둘 다 admin bearer token이 필요합니다. 이미 실행 중인 버전의 서명 매니페스트는 `up_to_date`를 만들고 다운그레이드는 계속 강한 거부입니다.

## 수명 주기 동작 검증

저장소 루트에서 바이너리를 빌드하고 관련 자동 검사를 실행합니다.

```sh
cargo build --locked --bin hangang
cargo test --locked --test restart --test update --test publication_retirement
python3 tests/restart_smoke.py
python3 tests/upgrade_smoke.py
python3 tests/smoke.py Smoke.test_file_reload_and_bad_edit_retention Smoke.test_z_graceful_shutdown_drains_websocket_and_tcp_streams
```

Python 픽스처는 임시 상태, loopback 서비스, 생성된 테스트 인증서, 소유한 실행 파일 복사본을 사용합니다. Python 3와 OpenSSL이 필요합니다. restart 픽스처는 실제 리스너 핸드오프, 수립된 TCP 및 workload HTTP 연결, 보존된 계정/audit 상태, 실패 후보 복구, API 트리거 교체를 검증합니다. smoke 검사는 실시간 파일 편집, 잘못된 편집 보존, WebSocket/TCP draining을 다룹니다.

서명 업그레이드 픽스처는 추가로 더 새로운 테스트 버전을 빌드하고, 비공개 테스트 HTTPS CA로 서명 매니페스트와 artifact를 제공하며, 실제 바이너리 교체를 통한 HTTP, WebSocket, TCP 연속성을 확인합니다.

Rust 검사는 descriptor 검증과 readiness timeout, 서명 artifact 검증, fake binary를 사용하는 staging/activation/rollback, update-fetch 취소, publication retirement을 다룹니다. 이 테스트는 메커니즘을 실행하지만, 모든 릴리스 버전 쌍 간 종단간 업그레이드 보장, 지속적인 무오류 처리량, 가용성 SLA를 수립하지는 않습니다. 프로덕션 업그레이드 전에 대표 트래픽으로 의도한 source/target 버전과 배포를 검증하십시오.
