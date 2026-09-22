# Hangang

[English](README.md) · [문서 목차](docs/README.ko.md) · [빠른 시작](#빠른-시작) · [릴리즈 변경점](CHANGELOG.md)

**엔터프라이즈급 수명 관리, 격리된 Lua 정책, 웹 관리 화면을 하나로 제공하는 HTTP·TCP·UDP 게이트웨이입니다.**

Hangang은 리버스 프록시, 로드 밸런싱, TLS 인증서 관리, 접근 정책, 트래픽 관측을 하나의 Rust 바이너리에 통합합니다. 별도의 관리 화면 서비스를 배포하지 않아도 브라우저나 API로 라우트를 관리하고, 실시간 트래픽을 확인하며, Lua로 요청 처리를 확장할 수 있습니다. 관리 화면은 영어와 한국어를 지원합니다. 이 문서는 한국어 보조 안내이며, 전체 기능 설명과 비교의 기준은 [영문 README](README.md)입니다.

## Hangang을 선택할 이유

- **HTTP와 TCP를 한 화면에서 운영합니다.** 라우트, 리스너, 백엔드 멤버, 인증서, 활성 상태를 관리 화면과 관리 API에서 다룹니다. [화면과 API 범위](docs/API_UI_COVERAGE.md)를 확인하세요.
- **Lua 확장에 별도의 장애 경계를 둡니다.** 교체 가능한 자식 프로세스에서 메모리·명령어·실행 시간 한도를 적용합니다. 워커 용량이 부족하면 정책을 생략하지 않고 요청을 거부합니다. 편집기는 문법 강조와 API 자동 완성을 제공합니다. [아키텍처](docs/ARCHITECTURE.md), [Lua 편집기](web/LUA_EDITOR.md)를 참고하세요.
- **일반 본문과 스트리밍 레코드를 모두 변환합니다.** 네이티브 JSON·XML·텍스트 연산과 Lua 변환을 지원합니다. 전체 문서는 크기가 제한된 버퍼를 사용하고, 줄·NDJSON·SSE는 완성된 레코드 단위로 처리합니다. [본문 변환](docs/ko/TRANSFORMS.md)을 확인하세요.
- **서비스 중 설정을 변경합니다.** 파일 감시와 리비전 조건부 API 쓰기를 지원하고, 잘못된 후보 설정은 적용하지 않습니다. 로컬 파일을 설정 원본으로 사용할 때 이름 있는 백엔드 멤버의 연결 종료 대기와 유지보수 상태도 관리합니다. [설정 적용](docs/CONFIG_PUBLICATION.md), [멤버 수명 관리](docs/MEMBER_LIFECYCLE.md)를 참고하세요.
- **운영 관측을 기본으로 제공합니다.** 실시간 상태, Prometheus 지표, 최근 HTTP 메타데이터, 활성·최근 TCP 연결을 볼 수 있습니다. 기록 필터와 보관 한도로 수집 범위를 관리합니다. [HTTP 기록](docs/TRAFFIC_HISTORY.md), [TCP 기록](docs/TCP_CONNECTION_HISTORY.md)을 확인하세요.
- **라우팅과 보안 정책을 함께 구성합니다.** 호스트 와일드카드·정규식·우선순위, JWT, 워크로드 mTLS, 리소스 보호, 국가·언어 필터, 업스트림별 DNS·SOCKS5·TLS 정책을 조합할 수 있습니다. [기능별 문서](docs/README.ko.md)에서 설정 조건을 확인하세요.
- **배포 조건이 맞을 때 데이터그램을 전달합니다.** UDP 라우트는 데이터그램 경계를 유지하고 클라이언트 흐름을 리터럴 백엔드에 고정합니다. `quic`은 불투명 통과 모드로 HTTP/3 종료, SNI 검사, 연결 마이그레이션을 제공하지 않습니다. UDP 라우트는 로컬 파일 설정에서만 사용하며 감독·핫 재시작 인계를 지원하지 않습니다. [UDP·QUIC 문서](docs/UDP.md)를 참고하세요.
- **별도 범위의 직접 라우팅 보조 도구를 제공합니다.** `hangang-dsr`은 VIP 소유권·ARP·직접 반환 경로를 이미 구성한 네트워크에서 명시한 IPv4 Linux IPVS 서비스만 조정합니다. 제한 사항은 [IPVS DSR 문서](docs/DSR.md)에 설명되어 있습니다.

## 엔터프라이즈급 서비스 연속성

**리스닝 소켓을 유지하면서 설정을 바꾸고, 서비스 프로세스를 교체하고, 서명된 새 바이너리를 적용할 수 있습니다.** 동적 설정과 준비 상태를 확인하는 프로세스 인계를 결합해 계획된 유지보수 중 트래픽을 이어가는 구조입니다.

| 변경 | 연속성을 위한 구현 | 적용 조건 |
| --- | --- | --- |
| 실행 중 설정 변경 | 후보를 준비·검증한 뒤 적용하며, 준비 실패 시 기존 설정을 유지합니다. 새 요청은 새 스냅샷을 사용합니다. | 프로세스 재시작이 필요 없습니다. 보안 정책 변경은 해당 스트림을 의도적으로 종료할 수 있고, 저장과 로컬 적용은 별도 결과입니다. |
| 감독 모드 재시작 | 리스너와 실행 중 설정을 전달하고, 새 프로세스의 `READY` 이후 기존 프로세스의 연결 종료를 기다립니다. | Unix `--supervised` 모드에서 `SIGHUP` 또는 인증된 재시작 API로 실행합니다. 기존 응답과 터널은 종료 대기 중 이전 프로세스가 처리합니다. |
| 서명된 바이너리 업그레이드 | 서명·버전·설정을 확인하고 실행 파일을 원자적으로 교체한 뒤 같은 인계 절차를 사용합니다. 준비 완료 전 교체 실패 시 바이너리 롤백과 기존 워커 재개를 수행합니다. | 업데이트 주소·서명 키를 명시하고, 하드 링크와 이름 변경이 가능한 쓰기 허용 설치 디렉터리가 필요합니다. 롤백에는 정상적인 로컬 저장소가 필요합니다. |

여기서 **enterprise-class**는 동적 변경, 리스너 연속성, 제한된 시간의 연결 종료 대기, 정의된 복구 절차를 의미합니다. 종료 대기는 기본 **30초**이며 `--drain-seconds`로 조절합니다. 기한을 넘는 연결이나 철회된 보안 정책의 스트림은 종료될 수 있습니다. 읽기 전용 Compose 템플릿은 컨테이너 교체 방식이므로 이 프로세스 인계 기능을 자동으로 제공하지 않으며, 이미지 무중단 배포에는 적절한 다중 인스턴스 구성이 필요합니다.

[설정 적용](docs/CONFIG_PUBLICATION.md), [업그레이드 조건](docs/UPDATES.md#continuity-and-deployment-modes), [검증 방법](docs/UPDATES.md#verify-lifecycle-behavior)을 확인하세요. 계획된 유지보수의 연속성을 위한 기능이며, 호스트 장애나 모든 업그레이드에 대한 무중단 SLA를 뜻하지는 않습니다.

## 엔터프라이즈 기능을 하나의 운영 경험으로

**상용 엔터프라이즈 게이트웨이보다 일관되고 직접 제어하기 쉬운 운영 경험을 제공하는 것이 목표입니다.** Hangang은 엔터프라이즈 게이트웨이에서 기대하는 기능을 MIT 라이선스 코드베이스에 통합하고 있습니다. 현재의 강점은 라우팅·정책 편집·관측·관리 API를 한 애플리케이션과 설정 모델에서 제공한다는 점입니다.

| 운영 요구 | 현재 구현 | 적용 범위 |
| --- | --- | --- |
| 인증과 권한 | JWT, HTTP/TCP 워크로드 mTLS, 보호 리소스, 관리자·조회자 계정 | 중앙 조직 계정 플랫폼을 대신하지는 않습니다. |
| 감사와 변경 추적 | 로컬 계정 감사, 기록 필터, 설정 작업 이력, SQL 커밋 확인 기록 | 작업별 감사 범위가 다르며 최근 트래픽 기록은 영구 감사가 아닙니다. |
| 안전한 설정 변경 | 리비전 검사, 후보 설정 준비, 작업 결과 추적 | 저장 성공과 모든 인스턴스의 적용 완료는 다릅니다. |
| 서비스 연속성 | 상태 점검, 멤버 연결 종료 대기·유지보수, 감독 프로세스 교체, 서명 업데이트 | 이름 있는 멤버의 수명 관리는 로컬 파일 설정에서 지원하며 공유 저장소에서는 거부합니다. 연결 처리 조건은 변경 정책과 배포 방식에 따라 다릅니다. |
| 운영 가시성 | 실시간 관리 화면, Prometheus, 연결 기록, 인증된 원격 관측 | 원격 관측은 조회 기능이며 플릿 배포 제어는 아닙니다. |
| 정책 확장 | 네이티브 변환, 격리된 Lua, 코드 편집기 | 실행·본문 한도가 적용되며 이미 전달한 바이트를 되돌릴 수는 없습니다. |

각 구현의 근거 문서는 [영문 엔터프라이즈 기능 표](README.md#enterprise-controls-integrated)에 연결되어 있습니다. 전체 상용 기능과의 동등성이나 보편적인 성능·가용성·인증 우위를 검증했다는 의미는 아닙니다.

## 다른 제품과 비교

| 제품 | 공식 문서에서 설명하는 접근 | Hangang을 선택할 이유 |
| --- | --- | --- |
| Caddy | [자동 HTTPS](https://caddyserver.com/docs/automatic-https), [JSON 관리 API](https://caddyserver.com/docs/api), 모듈 확장 | 웹 라우트 관리, TCP 관리, Lua 편집을 한 애플리케이션에서 운영하고 싶을 때 적합합니다. |
| Kong Gateway | [서비스·라우트·소비자·플러그인](https://developer.konghq.com/gateway/entities/), [Kong Manager](https://developer.konghq.com/gateway/kong-manager/) | 필요한 정책이 Hangang의 네이티브 기능에 맞고, 로컬 파일 설정과 프로세스 격리 Lua로 시작하고 싶을 때 적합합니다. |
| Traefik Proxy | [프로바이더 기반 동적 설정](https://doc.traefik.io/traefik/getting-started/configuration-overview/)과 Docker 레이블 연동 | 라우트 직접 편집, Lua 정책, 본문·레코드 변환이 운영의 중심일 때 적합합니다. |
| HAProxy | [비동기 실행 모델에 맞춘 Lua 확장](https://www.haproxy.com/documentation/haproxy-lua-api/getting-started/introduction/) | 별도 프로세스의 Lua 워커와 통합 편집기·관리 화면이 필요할 때 적합합니다. |

공식 문서 확인 기준은 **2026-09-22**입니다. 에디션·모듈·설정에 따라 기능 범위가 달라지며, 이 표는 처리량 순위가 아니라 운영 방식의 비교입니다. UDP/QUIC 릴레이는 로컬 파일 설정에서만 사용하고 감독·핫 재시작 인계를 제공하지 않습니다. 관리자 계정은 인스턴스별로 보관합니다. 이전 전 [아키텍처](docs/ARCHITECTURE.md)와 [다중 인스턴스 운영](docs/ko/SCALE_OUT.md)을 확인하세요.

## 빠른 시작

Linux amd64 바이너리와 `SHA256SUMS`는 [v0.2.0 릴리즈](https://github.com/ziozzang/hangang/releases/tag/v0.2.0)에서 받습니다. 압축 해제 전에 `sha256sum -c SHA256SUMS`로 검증하세요. 아래는 소스 빌드 절차입니다.

Git, Rust 1.96 이상, C 컴파일러, Python 3, OpenSSL, curl이 필요합니다. 기본 관리 화면은 빌드 산출물이 포함되어 있어 Node.js 없이 실행할 수 있습니다.

### 1. 빌드

```sh
git clone https://github.com/ziozzang/hangang.git
cd hangang
cargo build --locked
```

### 2. 데모 백엔드 실행

별도 터미널에서 데모 페이지만 있는 임시 디렉터리를 제공합니다.

```sh
HANGANG_DEMO_BACKEND="$(mktemp -d)"
printf 'Hello through Hangang!\n' > "$HANGANG_DEMO_BACKEND/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$HANGANG_DEMO_BACKEND"
```

### 3. Hangang 실행

첫 번째 터미널의 저장소 루트에서 실행합니다.

```sh
umask 077
export HANGANG_DEMO_DIR="$(mktemp -d)"
cp examples/hangang.json "$HANGANG_DEMO_DIR/hangang.json"
openssl rand -hex 32 > "$HANGANG_DEMO_DIR/admin-token"
export HANGANG_ADMIN_TOKEN="$(cat "$HANGANG_DEMO_DIR/admin-token")"
./target/debug/hangang --check --config "$HANGANG_DEMO_DIR/hangang.json"
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json"
```

예제는 `/` 요청을 8081 포트의 백엔드로 전달하며, `X-Block: yes` 헤더가 있으면 Lua 정책이 거부합니다. 프록시는 `127.0.0.1:8080`, 관리는 `127.0.0.1:9000`에 바인딩합니다.

### 4. 확인 및 관리 화면 접속

다른 터미널에서 실행합니다.

```sh
curl --fail http://127.0.0.1:8080/
# Hello through Hangang!

curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Block: yes' http://127.0.0.1:8080/
# 403
```

**http://127.0.0.1:9000/ui/** 에서 첫 관리자 계정을 만듭니다. 초기 설정 토큰은 3단계에서 만든 `$HANGANG_DEMO_DIR/admin-token` 파일을 로컬 편집기로 열어 확인하세요. 해당 변수는 다른 터미널에 자동으로 공유되지 않습니다. 사용자 이름과 12바이트 이상의 새 비밀번호를 지정합니다. 토큰은 계정 생성 후에도 비상 관리자 자격 증명이므로 비공개로 보관하세요.

HTTP 라우트 편집기에서 Lua 정책을 확인하고, 요청을 보내면서 대시보드를 살펴보세요. `--check`는 리스너를 열지 않고 설정과 Lua를 검증합니다. 종료하려면 게이트웨이와 백엔드 터미널에서 각각 `Ctrl+C`를 누릅니다. 임시 상태는 남아 있으며 같은 설정 경로로 재시작하면 관리자 데이터베이스를 유지합니다.

## 배포와 개발

운영 배포는 [Compose 템플릿 안내](docs/DEPLOYMENT.md) 또는 [Kubernetes 안내](docs/ko/KUBERNETES.md)에서 시작하세요. 비공개 자격 증명, 영속 상태, 관리 리스너 보호를 구성해야 합니다. [문서 목차](docs/README.ko.md)와 [OpenAPI 명세](docs/openapi.json)에서 기능별 설정과 제한을 확인할 수 있습니다.

```sh
make check       # Rust 서식 및 Clippy
make test        # Rust 테스트 및 로컬 통합 시나리오
make test-web    # 관리 화면 및 브라우저 테스트
make check-docs  # 스테이징된 문서 및 공개 대상 검사
```

일부 테스트에는 Docker 등의 추가 의존성이 필요합니다. [개발 안내](docs/DEVELOPMENT.md)와 [문서 작성 규칙](docs/DOCUMENTATION.md)을 참고하세요. 라이선스는 [MIT](LICENSE)입니다.
