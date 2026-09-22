# 플랫폼과 네이티브 바이너리

[문서 목차](../README.ko.md) · [English](../PLATFORMS.md)

## 노트북에서 엔터프라이즈 배포까지

개발 노트북과 Linux 서버에서 동일한 게이트웨이, 설정 형식, Lua 정책, 관리 UI와 API를 사용합니다. macOS 지원은 로컬 개발, 시연, 프록시 워크로드에 중점을 둡니다. Linux는 감독 프로세스를 통한 업그레이드와 커널 의존 배포 기능의 기준 플랫폼입니다. 호스트 간에 설정을 옮길 때는 리스너 주소, 파일 경로, 자격 증명, 인증서, 네트워크 권한을 환경에 맞게 조정해야 합니다.

## 릴리스 대상

네이티브 검증 워크플로는 아래 네 대상을 각각 빌드하고 테스트합니다. 각 대상은 네이티브 빌드, 라이브러리 테스트, 게이트웨이 스모크 테스트를 통과해야 릴리스용 아카이브로 사용할 수 있습니다. 워크플로는 다운로드 가능한 검증 산출물을 만들며, 이를 자동으로 게시하거나 서명하지는 않습니다.

| 플랫폼 | Rust 대상 | 아카이브 접미사 | 범위 |
| --- | --- | --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` | `linux-amd64.tar.gz` | 기준 배포 플랫폼 |
| Linux ARM64 | `aarch64-unknown-linux-gnu` | `linux-arm64.tar.gz` | 64비트 ARM 서버와 Linux 장비 |
| macOS Intel | `x86_64-apple-darwin` | `darwin-amd64.tar.gz` | 노트북 개발과 일반 게이트웨이 실행 |
| macOS Apple Silicon | `aarch64-apple-darwin` | `darwin-arm64.tar.gz` | ARM64 네이티브 노트북 개발과 일반 게이트웨이 실행 |
| 네이티브 Windows | 현재 미지원 | 없음 | Windows용 프로세스, 소켓, 권한 구현 필요 |
| 32비트 ARM | 현재 미검증 | 없음 | ARM64 지원이 ARMv7 지원을 의미하지 않음 |

아카이브 이름은 `hangang-v<VERSION>-<suffix>`입니다. [릴리스 페이지](https://github.com/ziozzang/hangang/releases)에 실제로 있는 자산만 게시된 바이너리입니다. 최초 `v0.2.1` 릴리스에는 Linux x86-64만 포함됩니다. 빌드 매트릭스를 설정한다고 기존 릴리스에 바이너리가 소급 추가되지는 않습니다.

네이티브 작업은 Linux에 Ubuntu 24.04, x86-64에 macOS 15 Intel, ARM64에 macOS 15 Apple Silicon을 사용합니다. 정확한 컴파일러 버전과 검사 항목은 [워크플로](../../.github/workflows/binaries.yml)를, 실행 환경 사양은 [GitHub 실행기 문서](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)를 참고하세요. 이 환경들이 검증 기준이며 모든 구버전 OS에서 동작한다는 근거는 아닙니다.

## macOS의 제한

- 일반 HTTP/TCP 라우팅, 지원 범위 내 UDP 릴레이, 관리 콘솔, API, Lua 정책, 동적 설정은 Linux와 동일한 애플리케이션 코드를 사용합니다.
- macOS의 Lua 워커에는 명시적인 `--allow-unsandboxed-lua`가 필요합니다. 이 옵션이 없으면 Lua 작업은 허용되지 않으며, Lua를 사용하지 않는 라우트는 정상 실행할 수 있습니다. 허용 시 별도 프로세스, Lua VM 제한, 작업 시간 제한은 유지되지만 Linux seccomp와 Linux 프로세스 주소 공간 제한은 제공하지 않습니다. 신뢰하는 개발 스크립트에만 사용하고 비신뢰 코드의 샌드박스로 취급하지 마세요.
- `--supervised`와 내부 serving-child 모드는 Linux 전용이며 macOS에서는 명시적으로 실패합니다. 따라서 `--update-github` 또는 `--update-manifest`를 통한 주기적 바이너리 설치는 macOS에서 사용할 수 없습니다. 읽기 전용 `--check-update`는 사용할 수 있습니다. macOS 업그레이드는 프로세스를 중지하고 바이너리를 직접 교체해야 하며, 교체 중 연결 유지는 보장하지 않습니다.
- macOS 아카이브에는 `hangang-dsr`가 포함되지 않습니다. IPVS DSR에는 Linux 커널과 적절한 네트워크 권한이 필요하며 macOS 호스트는 이를 제공하지 않습니다.
- Docker 검색에는 접근 가능한 Docker API가 필요합니다. Docker Desktop은 VM에서 Linux 컨테이너를 실행하므로 호스트 네트워킹, 장치 접근, 패킷 경로가 네이티브 Linux 서버와 다릅니다.
- 아카이브는 Apple Developer ID 서명이나 공증을 받지 않습니다. Ed25519 업데이트 매니페스트나 체크섬은 Apple 공증이 아닙니다. macOS 보안 정책에 따라 실행 전에 승인이 필요할 수 있습니다.
- 계정 데이터베이스와 디스크 캐시는 디렉터리 경로의 심볼릭 링크를 거부합니다. macOS에서는 흔히 `/tmp`와 `/var`가 `/private` 아래의 경로를 가리키므로 쓰기 가능한 상태에는 실제 경로(예: Python `os.path.realpath`)를 사용하세요. 빠른 시작 가이드는 임시 상태 디렉터리를 명시적으로 실제 경로로 변환합니다. 검증 워크플로도 심볼릭 링크 검사를 비활성화하지 않고 `TMPDIR`를 정규화합니다.
- 호스트별 경로, Unix 권한, 외부 서비스, 특권 포트는 환경별 설정이 필요합니다. 노트북 스모크 테스트 통과가 Linux 운영 환경의 처리 용량 검증을 의미하지는 않습니다.

## Windows에서의 실행 경로

네이티브 Windows 지원 전까지 WSL2 또는 Linux 컨테이너 안에서 Linux 빌드를 사용하고, 바이너리 아키텍처를 Linux 환경에 맞추세요. 이는 Linux 실행이며 Windows `.exe` 릴리스가 아닙니다. VM의 리스너 노출과 포워딩을 Windows 호스트 방화벽과 별도로 확인해야 합니다.

현재 네이티브 Windows의 장애 요인은 Unix 도메인 관리·워커 소켓, Unix 시그널과 프로세스 제어, 파일 디스크립터 전달, Unix 권한 처리입니다. 릴리스 워크플로는 Windows 자리표시자를 업로드하거나 빌드되지 않는 대상을 성공으로 표시하지 않습니다. 향후 포팅에서는 네이티브 게이트웨이, Lua 워커, 종료 처리, 설정 영속성, 네트워킹 테스트를 거친 뒤 게시해야 합니다. Windows 서비스 수명주기와 바이너리 교체도 별도 설계가 필요합니다.

## 빌드와 패키징

패키징은 대상 OS와 아키텍처에서 실행하세요. 도구가 컴파일된 게이트웨이를 실행해 버전을 확인합니다. Rust 의존성에 소스가 포함된 Lua와 SQLite가 있으므로 동작하는 C 컴파일러가 필요합니다. 패키징에는 Python 3.11 이상이 필요합니다. 예를 들어 Linux ARM64 호스트에서는 다음과 같이 실행합니다.

```sh
rustup target add aarch64-unknown-linux-gnu
cargo build --locked --release --bins --target aarch64-unknown-linux-gnu
python3 tools/prepare_release.py --unsigned \
  --target aarch64-unknown-linux-gnu --output dist
```

서명 없는 스테이징은 게이트웨이 바이너리, 아카이브, `SHA256SUMS`를 작성합니다. 서명된 매니페스트나 공개키는 작성하지 않으며 신뢰할 수 있는 자동 업데이트로 사용할 수 없습니다. 출력 디렉터리는 비어 있어야 합니다. macOS에서는 해당하는 `apple-darwin` 대상을 선택하세요. 아카이브에는 게이트웨이와 이식 가능한 보조 바이너리 5개가 포함되며 DSR은 제외됩니다.

승인된 릴리스에는 신뢰할 수 있는 네이티브 빌드 호스트에서 `--unsigned` 대신 `--signing-seed-file`을 사용하세요. 비공개 서명 시드는 저장소와 CI 산출물 밖에 보관해야 합니다. 도구는 저장소에 고정된 공개키와 시드가 일치하는지 확인합니다. 자산 이름, 신뢰 키 설정, Linux 설치 동작은 [서명된 업데이트](UPDATES.md)를 참고하세요.
