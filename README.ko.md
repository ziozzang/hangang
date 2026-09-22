# Hangang

Hangang은 Rust로 작성한 HTTP·TCP 리버스 프록시입니다. 실행 중 JSON 설정 변경, 한국어·영어 웹 관리 화면, TLS, 라우트별 트래픽 정책을 한 서버에서 제공합니다. [English](README.md) · [문서 목차](docs/README.md)

HTTP 라우트는 호스트·경로·헤더·선택적 JSON 조건으로 요청을 매칭하고 HTTP 또는 HTTPS 백엔드로 전달합니다. TCP 라우트는 양방향 스트림을 전달합니다. 이름 있는 리스너, 백엔드 상태 점검과 분산, 접근 제어, 응답 캐시, 본문 변환, 별도 프로세스의 Lua 정책 워커를 설정할 수 있습니다. 관리 화면과 API에서 설정·상태·운영 정보를 볼 수 있습니다. ACME, Docker 검색, Kubernetes 연동, 공유 설정 저장소는 각각 별도 설정이 필요합니다.

## 로컬에서 실행하기

Rust 1.96과 C 컴파일러가 필요합니다. 먼저 예제에서 사용할 HTTP 백엔드를 별도 터미널에서 실행합니다.

```sh
python3 -m http.server 8081 --bind 127.0.0.1
```

다른 터미널에서 빌드하고 실행합니다.

```sh
cargo build --locked
cp examples/hangang.json /tmp/hangang.json
export HANGANG_ADMIN_TOKEN="$(openssl rand -hex 32)"
./target/debug/hangang --check --config /tmp/hangang.json
./target/debug/hangang --config /tmp/hangang.json
```

프록시는 `127.0.0.1:8080`, 관리 화면은 `http://127.0.0.1:9000/ui/`에서 열립니다. 처음 방문하면 생성한 설정 토큰과 새 비밀번호로 관리자 계정을 만듭니다. 이 토큰은 이후에도 비상 관리자 자격 증명이므로 비공개로 보관하세요. 로컬 외 배포에서는 비공개 비밀 저장소로 토큰을 공급하고 관리 리스너를 TLS 또는 전용 Unix 소켓으로 보호하세요. [관리자 계정](docs/ADMIN_USERS.md)과 [단일 노드 Compose 예제](docs/DEPLOYMENT.md)를 참고하세요.

설정 원본은 JSON입니다. Hangang은 로컬 파일을 감시하며 잘못된 변경이 들어오면 마지막 정상 설정을 유지합니다. 관리 API 쓰기에는 현재 개정 번호가 필요합니다. `--check`는 리스너를 열지 않고 설정과 Lua 정책을 검증합니다. 형식은 [예제 설정](examples/hangang.json), [라우트 매칭](docs/MATCHING.md), [OpenAPI 명세](docs/openapi.json)에 정리되어 있습니다.

## 빌드와 검증

```sh
make check      # Rust 서식 및 Clippy
make test       # Rust 테스트 및 로컬 통합 시나리오
make test-web   # 웹 관리 화면 및 브라우저 테스트
```

일부 통합 테스트에는 Docker 등의 로컬 의존성이 필요합니다. [개발 안내](docs/DEVELOPMENT.md)를 참고하세요. 라이선스는 [MIT](LICENSE)입니다.
