# Docker 서비스 검색

[문서 목차](../README.ko.md) · [English](../DOCKER.md)

Hangang은 Docker 컨테이너 메타데이터에서 HTTP 및 TCP 백엔드를 검색할 수 있습니다. 데몬의 Unix 소켓을 전달해 활성화합니다.

```console
hangang --config /etc/hangang/config.json \
  --docker-socket /var/run/docker.sock
```

Docker 백엔드는 다음 형식을 사용합니다.

```text
docker://CONTAINER/NETWORK/PORT
```

예를 들어 `docker://api/edge/8080` HTTP 백엔드는 `http://<container-ip>:8080`으로 해석되고, `docker://postgres/edge/5432` TCP 백엔드는 `<container-ip>:5432`로 해석됩니다.

`CONTAINER`와 `NETWORK`는 1~128자여야 합니다. 첫 문자는 ASCII 영숫자여야 하며 이후에는 `_`, `.`, `-`도 사용할 수 있습니다. `PORT`는 앞에 0을 붙이지 않은 1~65535 범위의 정규 십진 정수여야 합니다. 참조는 정확히 이 세 경로 구성요소를 가져야 합니다. 다른 백엔드 문자열은 기존 정적 동작을 유지합니다.

Hangang은 서비스 시작 전에 한 번 갱신하고, 이후 런타임 검색 표를 매초 갱신합니다. 동시에 최대 8개 컨테이너를 검사합니다. 설정된 `docker://` 참조는 그대로 유지되므로 주소 변경이 활성 설정이나 revision을 바꾸지 않습니다.

실행 중이며 지정된 네트워크에 연결된 컨테이너만 게시합니다. 중지·삭제된 컨테이너, 없는 네트워크나 IP 주소, 검사 오류는 다음 갱신 때 매핑에서 제거됩니다. 그러면 백엔드를 사용할 수 없어 요청이 fail closed 됩니다. 이후 갱신이 성공하면 매핑을 복구합니다. 컨테이너 IP는 Hangang이 실행되는 네트워크 네임스페이스에서 접근 가능해야 합니다.

Docker 검사는 제한된 요청을 사용합니다. resolver의 요청 제한 시간은 3초이고 응답은 최대 1MiB입니다. Hangang은 읽기 전용 컨테이너 검사 엔드포인트만 호출하며 컨테이너를 시작·중지·실행하거나 변경하지 않습니다. 그래도 일반적인 배포에서 Docker 데몬 소켓 접근은 매우 높은 권한입니다. 소켓 접근을 제한하고 가능하면 최소 권한 Docker 소켓 프록시를 사용하십시오.

관리자 `POST /v1/docker/resolve` 엔드포인트는 명시적 검사 진단용으로 계속 사용할 수 있습니다. 동적 라우트 검색에는 이 엔드포인트 호출이 필요하지 않습니다.

검색 테스트는 가짜 Unix 소켓 Docker API를 사용합니다. 주소 변경, 중지·삭제 컨테이너, 엄격한 참조 파싱, 네이티브 백엔드 통과, 8개 검사 동시성 제한, 실제 컨테이너를 만들지 않는 설정 revision 안정성을 검증합니다.

## 연결 관리 UI와 API

**Docker** 콘솔 페이지는 Hangang 인스턴스 하나의 활성 Docker 데몬 연결 하나를 관리합니다. 로컬 Unix 소켓과 상호 TLS를 사용하는 원격 HTTPS를 지원합니다. **연결 테스트**는 저장하지 않고 현재 초안으로 Docker `GET /_ping`을 전송합니다. **연결 저장**은 초안을 원자적으로 저장하고 새 검색 작업에 활성화합니다. **백엔드 해석**은 저장된 연결을 사용해 컨테이너 네트워크 주소를 반환하며, 해당 주소의 애플리케이션 연결성은 테스트하지 않습니다.

- `GET /v1/docker/connection`: 활성 설정, 출처, revision, ETag
- `PUT /v1/docker/connection`: 현재 revision과 일치하는 `If-Match`로 연결 저장
- `DELETE /v1/docker/connection`: 관리 오버라이드를 제거하고 프로세스 기본값으로 복구하거나 기본값이 없으면 비활성화
- `POST /v1/docker/connection/test`: 저장하지 않고 후보 테스트

네 작업 모두 관리자 권한이 필요합니다. 저장된 `{"transport":"disabled"}`는 CLI 기본값이 있어도 Docker를 명시적으로 비활성화합니다. 연결 파일 경로는 게이트웨이 파일시스템 기준이며 게이트웨이에서 접근 가능해야 합니다. 인증서와 키는 API가 반환하지 않고 파일 참조만 반환합니다. 클라이언트 개인 키는 게이트웨이 프로세스가 소유한 일반 비공개 파일이어야 합니다. 원격 엔드포인트는 사용자 인증정보·경로·쿼리 없는 HTTPS origin이어야 합니다. 리다이렉트와 환경 프록시 상속은 비활성화되며 데몬 인증서 검증을 건너뛸 수 없습니다.

원격 연결 요청:

```json
{
  "transport": "https",
  "url": "https://docker.example.com:2376",
  "ca_file": "/data/docker-tls/ca.pem",
  "client_cert_file": "/data/docker-tls/cert.pem",
  "client_key_file": "/data/docker-tls/key.pem"
}
```

Unix 연결 요청은 `{"transport":"unix","socket_path":"/run/hangang/docker/docker.sock"}`입니다. 소켓은 게이트웨이가 이미 접근할 수 있어야 하며 UI 설정은 호스트 마운트나 데몬 권한을 만들 수 없습니다. 이 릴리스를 설치해도 데몬 연결이 자동으로 활성화되지 않습니다. Docker 연결 설정은 인스턴스 로컬이며 공유 라우트 설정과 별개입니다. 연결을 저장하거나 비활성화하면 이전 검색 세대를 즉시 무효화해 진행 중인 조회가 이전 데몬 주소를 다시 게시하지 못하게 합니다.

구현은 데몬 ping과 컨테이너 검사만 호출합니다. 컨테이너를 시작·중지하거나 명령을 실행하거나 Docker 포트를 게시하거나 제한 없는 Docker API 터널을 제공하지 않습니다. Docker는 Unix, SSH, TLS 접근을 문서화하며 이 구현은 Unix와 검증된 상호 TLS를 지원합니다. [Docker 데몬 접근 보호](https://docs.docker.com/engine/security/protect-access/)

## TCP 포트와 컨테이너 네트워크

TCP 라우트는 Hangang의 네트워크 네임스페이스에 바인딩됩니다. Docker bridge 모드에서 라우트 생성이 성공해도 호스트에 리스너가 게시되지는 않습니다. `0.0.0.0:PORT`에 바인딩하고 컨테이너 배포에서 포트를 게시하십시오. `127.0.0.1` 바인딩은 컨테이너 내부 전용입니다. Linux host networking은 게시 단계를 없애지만 DNS, 포트 소유권, 프록시 식별을 바꿉니다. [배포 템플릿](../DEPLOYMENT.md)을 참고하세요.

연결 상태 기본 경로는 전체 라우트 설정 파일명 뒤에 `.docker-connection.json`을 붙인 값입니다. `--docker-connection-state /private/instance/docker.json`으로 다른 인스턴스 로컬 경로를 선택할 수 있으며 배타적 writer lock이 같은 sidecar를 두 인스턴스가 수정하지 못하게 합니다. 공유 라우트 저장소 복제본이 bootstrap 설정 경로를 공유한다면 서로 다른 로컬 상태 경로를 선택해야 합니다. 손상된 연결 상태는 CLI fallback을 포함해 Docker를 비활성화하며 명시적인 관리자 복구 전까지 유지됩니다.

감독 재시작은 Docker 쓰기를 동결하고 sidecar lock을 다음 세대에 전달합니다. DockerLock handoff descriptor를 이해하는 supervisor가 필요하므로 오래된 supervisor를 장기간 사용하는 상태에서 이 기능을 쓰기 전에 supervisor 바이너리를 업데이트하십시오. 컨테이너 교체는 supervisor와 바이너리를 함께 재시작하며 이 descriptor handoff를 사용하지 않습니다.
