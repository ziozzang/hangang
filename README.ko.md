# Hangang

[문서 목차](docs/README.ko.md) · [빠른 시작](#빠른-시작) · [릴리스 노트](CHANGELOG.md) · [English](README.md)

**엔터프라이즈급 수명 주기 제어, 격리된 Lua 정책, 내장 관리 콘솔을 갖춘 HTTP, TCP, UDP 게이트웨이입니다.**

Hangang은 리버스 프록시, 부하 분산, TLS 인증서 관리, 접근 정책, 트래픽 가시성을 하나의 Rust 바이너리에 담았습니다. 별도의 콘솔 서비스를 배포하지 않고 브라우저나 API에서 경로를 설정하고, 실시간 트래픽을 살펴보고, Lua로 요청 처리를 확장할 수 있습니다. 콘솔은 영어와 한국어를 지원합니다. 이 README와 영문 가이드는 기준 문서입니다.

## Hangang을 선택하는 이유

- **HTTP와 TCP를 한곳에서 운영합니다.** 내장 콘솔에서 경로, 리스너, 백엔드 멤버, 인증서, 활성화를 관리합니다. 같은 서버가 문서화된 관리 API와 OpenAPI 명세를 제공합니다. [콘솔 지원 범위](docs/API_UI_COVERAGE.md)를 참조하세요.
- **정책 사용자 정의에 별도의 장애 경계를 둡니다.** Lua는 메모리, 명령어, 실행 시간 제한이 적용되는 교체 가능한 자식 프로세스에서 실행됩니다. 내장 편집기는 구문 강조와 API 자동 완성을 제공합니다. 워커가 포화되면 정책을 조용히 건너뛰는 대신 요청을 거부합니다. [아키텍처](docs/ARCHITECTURE.md)와 [Lua 편집](web/LUA_EDITOR.md)을 참조하세요.
- **일반 본문뿐 아니라 스트리밍 트래픽도 변환합니다.** 기본 제공 JSON/XML/텍스트 연산이나 Lua 변환을 적용합니다. 전체 문서 처리는 크기가 제한된 버퍼를 사용하며, 줄, NDJSON, SSE 모드는 완성된 레코드 단위로 처리합니다. 일반 본문은 기본적으로 스트리밍하고, WebSocket 업그레이드는 터널이 됩니다. [변환](docs/ko/TRANSFORMS.md)을 참조하세요.
- **트래픽을 제공하는 동안 설정을 변경합니다.** 파일 감시와 리비전 검사 API 갱신은 후보 설정을 게시 전에 준비합니다. 유효하지 않은 후보는 동작 중인 설정을 그대로 둡니다. 로컬 파일이 설정 권한을 가진 경우 이름이 있는 멤버에 드레이닝과 유지보수를 적용할 수 있으며, 연결 동작은 변경되는 정책을 따릅니다. [설정 게시](docs/CONFIG_PUBLICATION.md)와 [멤버 수명 주기](docs/MEMBER_LIFECYCLE.md)를 참조하세요.
- **대시보드 서비스를 추가하지 않고 상황을 확인합니다.** 실시간 콘솔 화면에서 상태, 지표, 최근 HTTP 메타데이터, 활성 및 최근 TCP 연결을 함께 볼 수 있습니다. Prometheus 엔드포인트는 외부 모니터링을 지원합니다. 기록 필터와 제한된 이력으로 게이트웨이가 보관하는 내용을 제어합니다. [HTTP 이력](docs/TRAFFIC_HISTORY.md)과 [TCP 이력](docs/TCP_CONNECTION_HISTORY.md)을 참조하세요.
- **라우팅과 보안 정책을 함께 관리합니다.** 호스트 glob/정규식 매칭 및 우선순위를 JWT, 워크로드 mTLS, 보호 리소스 규칙, 국가/언어 필터, 경로별 아웃바운드 DNS, SOCKS5, TLS 정책과 결합합니다. [라우팅](docs/MATCHING.md), [접근 제어](docs/RESOURCE_POLICY.md), [아웃바운드 연결](docs/UPSTREAM.md)을 참조하세요.
- **배포 경계가 허용하면 데이터그램을 중계합니다.** UDP 경로는 데이터그램 경계를 유지하고 각 클라이언트 흐름을 리터럴 백엔드에 고정합니다. `quic` 모드는 내용을 처리하지 않고 그대로 전달합니다. HTTP/3를 종료하거나 SNI를 검사하거나 연결 마이그레이션을 지원하지 않습니다. UDP 경로는 로컬 파일 설정만 사용하며 감독 재시작이나 핫 재시작에 참여할 수 없습니다. [UDP 및 QUIC 중계](docs/UDP.md)를 참조하세요.
- **범위가 분리된 직접 라우팅 보조 도구를 사용합니다.** `hangang-dsr`은 VIP 소유권, ARP 처리, 직접 반환 경로가 이미 마련된 네트워크에서 명시적으로 나열된 IPv4 Linux IPVS 서비스만 설치하고 제거합니다. 제한 사항은 [IPVS DSR](docs/DSR.md)을 참조하세요.

## 엔터프라이즈급 서비스 연속성

**게이트웨이의 리스닝 소켓을 유지하면서 설정을 변경하고, 서비스 프로세스를 교체하고, 서명된 바이너리를 활성화할 수 있습니다.** Hangang은 실행 중 설정 변경과 준비 상태를 확인하는 감독 프로세스 인계를 결합하므로, 계획된 유지보수 때 중지·시작 과정 없이 진행 중인 트래픽을 유지할 수 있습니다.

| 변경 | 연속성 유지 방식 | 운영 조건 |
| --- | --- | --- |
| 실행 중 설정 변경 | 후보를 게시 전에 준비하고 검증합니다. 준비에 실패하면 동작 중인 설정을 유지하며 새 트래픽은 새 스냅샷을 사용합니다. | 프로세스를 재시작할 필요가 없습니다. 보안 정책 변경은 영향을 받는 스트림을 의도적으로 닫을 수 있습니다. 저장과 로컬 활성화는 서로 다른 결과입니다. |
| 감독 재시작 | 기존 리스너 디스크립터와 런타임 스냅샷을 전달하고, 대체 프로세스가 `READY`를 보고할 때까지 기다린 뒤 이전 세대의 연결을 드레이닝합니다. | Unix `--supervised` 모드에서 `SIGHUP` 또는 인증된 재시작 API로 시작합니다. 기존 응답과 터널은 드레이닝 동안 이전 세대에 남습니다. |
| 서명된 바이너리 업그레이드 | 릴리스를 검증하고 버전/설정 사전 점검을 실행하며 실행 파일을 원자적으로 교체한 뒤, 동일한 준비 상태 확인 인계를 사용합니다. 준비 상태에 도달하기 전 교체에 실패하면 바이너리를 롤백하고 이전 워커를 재개합니다. | 업데이트 출처와 서명 키를 명시해야 하며 하드 링크/이름 변경을 지원하는 쓰기 가능한 설치 디렉터리가 필요합니다. 롤백에는 정상 동작하는 로컬 저장소가 필요합니다. |

여기서 **엔터프라이즈급 수명 주기 제어**란 실행 중 변경, 리스너 연속성, 시간 제한이 있는 드레이닝, 정의된 복구 경로를 뜻합니다. 기본 드레이닝 한도는 **30초**이며 `--drain-seconds`로 설정할 수 있습니다. 이를 넘는 연결은 닫힐 수 있습니다. 정책 철회도 스트림을 의도적으로 종료할 수 있습니다. 읽기 전용 Compose 템플릿은 컨테이너를 교체하므로 프로세스 내부 업그레이드 연속성을 **이어받지 않습니다**. 중단 없는 이미지 배포에는 적절한 다중 인스턴스 배포가 필요합니다.

[설정 게시](docs/CONFIG_PUBLICATION.md), [업그레이드 및 복구 의미 체계](docs/UPDATES.md#continuity-and-deployment-modes), [재현 가능한 수명 주기 점검](docs/UPDATES.md#verify-lifecycle-behavior)을 참조하세요. 이러한 방식은 계획된 유지보수를 지원하지만 호스트 장애나 모든 업그레이드 경로에 대한 포괄적인 무중단 SLA를 의미하지 않습니다.

## 통합된 엔터프라이즈 제어 기능

**고급 제어 기능을 일관되고, 살펴보기 쉽고, 실제로 운영하기 편하게 만들어 상용 엔터프라이즈 게이트웨이보다 나은 운영 경험을 제공하는 것이 목표입니다.** Hangang은 엔터프라이즈 게이트웨이에서 흔히 기대하는 기능을 MIT 라이선스 코드베이스에 담았습니다. 현재 가장 뚜렷한 강점은 통합입니다. 라우팅, 정책 편집, 트래픽 화면, 관리 API가 하나의 애플리케이션과 설정 모델을 공유합니다.

| 운영 요구 사항 | Hangang의 구현 | 이해해야 할 범위 |
| --- | --- | --- |
| ID 기반 접근 | JWT 검증, HTTP/TCP 워크로드 mTLS, 보호 리소스 규칙, 관리자/조회자 계정 | 워크로드 ID와 로컬 계정을 지원합니다. 중앙 집중형 기업 ID 플랫폼은 아닙니다. [접근 모델](docs/RESOURCE_POLICY.md) |
| 감사 가능한 관리 | 트랜잭션 기반 로컬 계정 감사, 기록 필터, 설정 작업 이력, SQL 커밋 영수증 | 적용 범위는 작업마다 다릅니다. 트래픽 이력은 영속적인 감사 기록과 별개입니다. [계정 감사](docs/ACCOUNT_AUDIT.md), [설정 이력](docs/CONFIG_OPERATIONS.md) |
| 통제된 설정 변경 | 리비전 검사, 후보 준비, 영속적인 작업 추적, SQL 영수증 조회 | 설정이 커밋되었다고 해서 모든 인스턴스에서 활성화되었음을 증명하지는 않습니다. [게시](docs/CONFIG_PUBLICATION.md), [SQL 영수증](docs/SQL_COMMIT_RECEIPTS.md) |
| 서비스 연속성 | 백엔드 상태 검사, 서비스/드레이닝/유지보수 상태, 감독 프로세스 교체, 서명된 업데이트 | 이름이 있는 멤버의 수명 주기 제어에는 로컬 파일 권한이 필요하며 공유 저장소에서는 거부됩니다. 연결 연속성은 정책 변경과 배포 모드에 따라 다릅니다. [수명 주기](docs/MEMBER_LIFECYCLE.md), [업데이트](docs/UPDATES.md) |
| 운영 가시성 | 실시간 콘솔 화면, Prometheus 지표, 크기가 제한된 연결/요청 이력, 인증된 원격 관측 | 원격 관측은 읽기 전용이며 복제본 집합의 배포 제어 기능이 아닙니다. [복제본 집합 관측](docs/FLEET_OBSERVATIONS.md) |
| 정책 사용자 정의 | 크기가 제한된 기본 제공 변환, 격리된 Lua 워커, 구문 강조와 API 자동 완성 | Lua와 본문에 명시적인 한도가 있습니다. 거부되거나 중단된 스트림은 이미 전달된 바이트를 회수할 수 없습니다. [변환](docs/ko/TRANSFORMS.md), [Lua 용량](docs/LUA_CAPACITY.md) |

이는 구현된 기능이며 엔터프라이즈 제품과의 완전한 동등성을 주장하는 것은 아닙니다. 이 프로젝트는 통합과 운영자 제어가 중요한 영역에서 상용 제품보다 개선된 경험을 목표로 합니다. 보편적인 성능, 가용성, 규정 준수 주장은 별도의 근거가 필요합니다.

## 다른 제품과 비교

Hangang은 **대화형 게이트웨이 관리, HTTP/TCP 트래픽 처리, 사용자 정의 Lua 정책을 하나의 배포 가능한 애플리케이션에서** 사용하려는 경우 특히 유용합니다. 아래 표는 처리량이나 완전한 기능 동등성이 아닌 운영 모델을 비교합니다. 다른 제품도 자체 모듈, 플러그인, 에디션을 통해 겹치는 사용 사례를 지원할 수 있습니다.

| 제품 | 문서에 설명된 접근 방식 | 이 사용 사례에서 Hangang을 선택하는 이유 |
| --- | --- | --- |
| **Hangang** | 하나의 바이너리에 HTTP/TCP 라우팅, 로컬 파일 기반 UDP/QUIC 통과, 영어/한국어 관리 콘솔, 리비전 검사 설정, 격리된 Lua 워커를 내장합니다. | 브라우저 관리, 정책 사용자 정의, 범위가 정해진 데이터그램 중계를 한 애플리케이션에 담은 간결한 자체 호스팅 게이트웨이 구성입니다. |
| **Caddy** | [자동 HTTPS](https://caddyserver.com/docs/automatic-https)와 [JSON 관리 API](https://caddyserver.com/docs/api)를 제공하며 [모듈 시스템](https://caddyserver.com/docs/modules)으로 확장합니다. | 내장 경로 관리 콘솔, TCP 관리, Lua 정책 편집기가 작업 흐름의 중심일 때 Hangang을 선택하세요. |
| **Kong Gateway** | [Services, Routes, Consumers, 플러그인](https://developer.konghq.com/gateway/entities/)으로 API 정책을 구성하며 [Kong Manager](https://developer.konghq.com/gateway/kong-manager/)로 관리합니다. | 기본 제공 정책이 요구 사항에 맞고, 로컬 파일 설정에서 시작해 프로세스 격리 Lua와 내장 콘솔을 사용하고 싶을 때 Hangang을 선택하세요. |
| **Traefik Proxy** | [프로바이더](https://doc.traefik.io/traefik/getting-started/configuration-overview/)가 [Docker 레이블 기반 라우팅](https://doc.traefik.io/traefik/reference/install-configuration/providers/docker/)을 비롯한 동적 설정을 검색합니다. | 프로바이더 중심 설정보다 직접적인 경로 편집, 사용자 정의 Lua, 요청/레코드 변환이 더 중요할 때 Hangang을 선택하세요. |
| **HAProxy** | [Lua API](https://www.haproxy.com/documentation/haproxy-lua-api/getting-started/introduction/)가 비차단 부하 분산기를 확장하며, 스크립트는 그 실행 모델을 따라야 합니다. | 게이트웨이 관리와 함께 프로세스 격리 Lua 워커와 통합 정책 편집기를 원할 때 Hangang을 선택하세요. |

비교 출처는 **2026-09-22**에 검토했습니다. 제품의 에디션과 설정에 따라 기능의 가용성이 달라집니다. 이는 배포상의 선택지를 비교한 것이며 Hangang이 언제나 더 빠르거나 모든 엔터프라이즈 기능을 대체한다는 주장이 아닙니다. UDP/QUIC 중계는 로컬 파일에서만 가능하고 감독 재시작/핫 재시작 인계를 지원하지 않습니다. 관리자 계정은 인스턴스 로컬에 남고 복제본 집합 관측은 읽기 전용입니다. 이전하기 전에 [아키텍처](docs/ARCHITECTURE.md)와 [규모 확장 의미 체계](docs/ko/SCALE_OUT.md)를 검토하세요.

## 빠른 시작

이 로컬 예제는 작동하는 프록시, Lua 거부 규칙, 관리 콘솔을 보여 줍니다. Git, Rust 1.96 이상, C 컴파일러, Python 3, OpenSSL, curl이 필요합니다. Node.js는 콘솔을 개발할 때만 필요하며 빌드된 자산은 이미 포함되어 있습니다.

Linux amd64 바이너리와 `SHA256SUMS`는 [v0.2.0 릴리스](https://github.com/ziozzang/hangang/releases/tag/v0.2.1)에서 받을 수 있습니다. 압축 파일에는 Hangang과 보조 도구가 들어 있습니다. 압축을 풀기 전에 `sha256sum -c SHA256SUMS`로 검증하세요. 아래 절차는 소스에서 빌드합니다.

필드별 설명, 실행 중 변경, 문제 해결은 [예제 설정 가이드](examples/README.ko.md)를 읽어 보세요.

### 1. 빌드

```sh
git clone https://github.com/ziozzang/hangang.git
cd hangang
cargo build --locked
```

### 2. 데모 백엔드 시작

별도 터미널에서 데모 페이지만 들어 있는 임시 디렉터리를 제공합니다.

```sh
HANGANG_DEMO_BACKEND="$(mktemp -d)"
printf 'Hello through Hangang!\n' > "$HANGANG_DEMO_BACKEND/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$HANGANG_DEMO_BACKEND"
```

### 3. Hangang 시작

첫 번째 터미널의 저장소 루트에서 다음을 실행합니다.

```sh
umask 077
export HANGANG_DEMO_DIR="$(mktemp -d)"
cp examples/hangang.json "$HANGANG_DEMO_DIR/hangang.json"
openssl rand -hex 32 > "$HANGANG_DEMO_DIR/admin-token"
export HANGANG_ADMIN_TOKEN="$(cat "$HANGANG_DEMO_DIR/admin-token")"
./target/debug/hangang --check --config "$HANGANG_DEMO_DIR/hangang.json"
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json"
```

예제는 `/`를 8081 포트의 백엔드로 전달합니다. Lua 규칙은 `X-Block: yes`가 들어 있는 요청을 거부합니다. 프록시는 `127.0.0.1:8080`에, 관리 기능은 `127.0.0.1:9000`에 바인딩됩니다. 둘 다 로컬 컴퓨터에서만 접근할 수 있습니다.

### 4. 확인하고 콘솔 열기

다른 터미널에서 다음을 실행합니다.

```sh
curl --fail http://127.0.0.1:8080/
# Hello through Hangang!

curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Block: yes' http://127.0.0.1:8080/
# 403
```

**http://127.0.0.1:9000/ui/**를 여세요. `$HANGANG_DEMO_DIR/admin-token`에 저장된 설정 토큰, 사용자 이름, 12바이트 이상의 새 비밀번호로 첫 관리자를 만듭니다. 토큰은 로컬 편집기로 읽으세요. 해당 디렉터리는 3단계에서 만든 값이며 다른 터미널에 변수가 자동으로 공유되지는 않습니다. 토큰은 계정 생성 후에도 비상 관리자 자격 증명으로 남으므로 비공개로 보관하세요.

HTTP 경로 편집기에서 Lua 정책을 살펴보고, 요청을 더 보내면서 대시보드를 관찰하세요. `--check`는 리스너를 시작하지 않고 설정과 Lua를 검증합니다. 데모를 멈추려면 게이트웨이와 백엔드 터미널에서 `Ctrl+C`를 누르세요. 임시 상태는 점검할 수 있도록 남습니다. 같은 설정 경로로 재시작하면 로컬 관리자 데이터베이스가 유지됩니다.

## 다음에 만들 수 있는 것

| 필요 사항 | 포함된 기능 | 가이드 |
| --- | --- | --- |
| 여러 도메인과 포트 제공 | 호스트 패턴, 우선순위, 표준 주소 리디렉션, 이름이 있는 HTTP/HTTPS 리스너 | [매칭](docs/MATCHING.md), [리스너](docs/PUBLIC_LISTENERS.md) |
| 인증서 갱신 자동화 | ACME HTTP-01 및 DNS-01, Cloudflare 또는 인증된 DNS 웹훅, ZeroSSL EAB | [ACME](docs/ACME.md) |
| 애플리케이션 서비스 보호 | JWT 검증, 워크로드 mTLS, 보호된 HTTP 리소스 | [JWT](docs/JWT_AUTH.md), [mTLS](docs/HTTP_WORKLOAD_MTLS.md), [리소스 정책](docs/RESOURCE_POLICY.md) |
| 반복되는 백엔드 작업 줄이기 | 메모리와 디스크 정책을 설정할 수 있는 응답 캐싱 | [캐싱](docs/CACHE.md) |
| 페이로드와 스트림 조정 | 기본 제공 JSON/XML/텍스트 변환과 크기가 제한된 Lua 본문 변환 | [변환](docs/ko/TRANSFORMS.md) |
| 컨테이너 워크로드 검색 | Docker 엔드포인트와 Kubernetes Ingress 조정 | [Docker](docs/DOCKER.md), [Kubernetes](docs/ko/KUBERNETES.md) |
| 여러 인스턴스 조정 | 문서화된 일관성 경계와 함께 SQLite, PostgreSQL, Redis를 통한 공유 설정 | [규모 확장](docs/ko/SCALE_OUT.md) |
| 배포 및 운영 | Compose 템플릿, 관리자 계정, 서명된 업데이트, 계정 감사 | [배포](docs/DEPLOYMENT.md), [계정](docs/ADMIN_USERS.md), [업데이트](docs/UPDATES.md), [감사](docs/ACCOUNT_AUDIT.md) |

로컬 데모를 넘어 배포하려면 [Compose 가이드](docs/DEPLOYMENT.md) 또는 [Kubernetes 가이드](docs/ko/KUBERNETES.md)부터 시작하세요. 비공개 자격 증명과 영속 상태를 마련하고 문서에 명시된 관리 리스너 보호를 적용하세요. [문서 목차](docs/README.ko.md)에는 기능별 설정과 제한이 정리되어 있으며 [OpenAPI](docs/openapi.json)는 관리 엔드포인트와 설정 객체를 정의합니다.

## 프로젝트 정보와 업데이트

```sh
hangang --about
hangang --check-update
```

`--about`은 버전, 저장소와 작성자 Jioh Jung <jung@jioh.net>을 표시합니다.
`--check-update`는 설치하지 않고 GitHub의 최신 안정 릴리즈를 조회합니다.
준비 상태를 확인하는 프로세스 교체와 서명된 자동 설치를 사용하려면
[업데이트 문서](docs/ko/UPDATES.md)에 따라 `--supervised --update-github`와
신뢰하는 공개키를 설정하세요. 다운로드는 유효한 Ed25519 서명을 요구하며,
릴리즈 메타데이터나 체크섬만으로 설치를 허용하지 않습니다.

## 개발

```sh
make check       # Rust formatting and Clippy
make test        # Rust tests and local integration scenarios
make test-web    # Console and browser tests
make check-docs  # Staged documentation and publication checks
```

일부 통합 테스트 대상에는 Docker 또는 추가 의존성이 필요합니다. [개발](docs/DEVELOPMENT.md)과 [문서 작성 규칙](docs/DOCUMENTATION.md)을 참조하세요. Hangang의 라이선스는 [MIT](LICENSE)입니다.
