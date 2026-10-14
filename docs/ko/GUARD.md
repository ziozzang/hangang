# 네이티브 hangang-guard 연계

[문서](../README.ko.md) · [English](../GUARD.md)

Hangang은 선택적 native hangang-guard admission을 지원합니다. 기본은 trusted-proxy
설정으로 client IP를 정한 뒤 라우트 security/auth 전에 인증된 POST /v1/decision을
요청합니다. allow 뒤에도 기존 모든 검사를 통과해야 합니다. deny는 403이며 통신 오류·
timeout·잘못된 판정은 기본 503입니다. --guard-failure-mode allow로 명시적 변경할 수
있습니다. 기존 unauthenticated health probe는 admission 밖이며 일반 proxy 경로의
ACME는 Guard 판정을 적용합니다.

```sh
# Provide the collector credential through your service environment or secret manager.
hangang --config config.json --guard-url http://127.0.0.1:8090 \
  --guard-honeypot-path /deliberate-trap --guard-scanner-path /configured-scanner
```

토큰은 HANGANG_GUARD_COLLECTOR_TOKEN에서 읽고 --guard-token-env로 이름을
바꿉니다. 명령 인자·URL에 토큰을 넣지 않습니다. 평문 HTTP는 literal loopback IP만,
원격은 HTTPS입니다. 리다이렉트를 거절해 자격이 다른 endpoint로 이동하지 않습니다.

| Flag | Default | 의미 |
| --- | --- | --- |
| `--guard-url` | absent | origin URL로 native Guard 활성화 |
| `--guard-source-id` | `hangang` | collector ID, 최대 ASCII 64자 |
| `--guard-mode` | `query` | query는 요청별, snapshot은 로컬 admission |
| `--guard-timeout-ms` | `100` | 전송 기한 1–5000ms |
| `--guard-failure-mode` | `deny` | query 실패 시 deny 또는 allow |
| `--guard-cache-ms` | `0` | 0 비활성, 1000–5000ms 활성 |
| `--guard-honeypot-path` | empty | 반복 가능한 exact honeypot 경로 |
| `--guard-scanner-path` | empty | 반복 가능한 exact scanner 경로 |

요청은 source_id·ip·선택적 kind만 전달하며 원문 path/query/host/header/자격/body를
내보내지 않습니다. 설정된 경로는 typed signal을 전달합니다. 서비스는 근거를 세기 전에
기존 block을 확인해 자체 거절로 근거가 강화되지 않도록 합니다. 일반 403은 자동 근거가 아닙니다.

기본 캐시는 꺼져 있습니다. 활성화 시 canonical IP 최대 10,000개를 설정 기간·응답 TTL
중 짧은 기간 캐시하며 네트워크 지연을 더하지 않도록 query 시작부터 측정합니다. TTL은
block 만료에도 제한됩니다. signal은 항상 서비스에 질의합니다. 새 정책 revision을 관찰하면
캐시를 비우지만 cached request 자체는 새 revision을 볼 수 없으므로 최대 5초 stale일 수
있습니다. 매 요청 현재 판정이 필요하면 기본 0 캐시를 사용합니다.

snapshot 모드는 명시적으로 비동기 batch와 2초 정책 polling을 선택합니다. 불변 prefix
인덱스가 allow/block별 IPv4 최대 33·IPv6 129 조회를 하고 mapped IPv6를 정규화하며
allowlist가 block보다 우선합니다. 게시 전 전체 version·정규 고유 network·집합당 100,000개·
4 MiB·시간/이유 길이를 검사합니다. 실패한 poll은 유효한 캐시를 유지하며 snapshot 만료는
query failure mode와 독립적으로 fail-open합니다. 만료 block과 observe snapshot은
차단하지 않습니다. evidence queue는 4096개, batch는 최대 256개이며 overflow/전송 실패는
tracing counter에 기록합니다.

snapshot은 요청 worker에서 전송하지 않습니다. query는 제한된 원격 요청을 기다리므로
proxy 트래픽에 맞는 가용성과 용량이 필요합니다. --guard-url이 없으면 task를 만들지 않습니다.

## 로컬 대량 트래픽의 지속 바이너리 판정

--guard-decision-tcp 127.0.0.1:9081은 일반 query를 서비스 --decision-listen 바이너리
listener로 보냅니다. evidence 제출용 --guard-url과 query mode가 필요하며 loopback literal
주소를 받습니다. collector token은 16–4096 bytes입니다. honeypot/scanner 신호는 HTTP
판정으로 계속 보내 service가 근거와 판정을 처리하도록 합니다.

최대 64개 인증 지속 socket을 풀로 사용하며 요청/응답은 각각 24 bytes입니다. correlation
ID·reserved fields·protocol version·action/mode/TTL을 검증한 뒤 반납합니다. mapped IPv6는
IPv4 wire 형태입니다. pool admission·connect·handshake·write·read에 전체 timeout을
공유합니다. timeout/잘못된 응답은 socket을 폐기하고 추가 HTTP 없이 failure policy를
따릅니다. 서버가 닫은 socket도 해당 요청은 실패하고 폐기하며 이후 다시 연결합니다.
idle 25초에 회수해 서비스 30초 기한보다 먼저 정리하고 shutdown cancellation에도 닫습니다.

기본 캐시 비활성과 선택적 1–5초 캐시는 두 전송에서 같은 의미입니다. 지속 전송은 일반
요청의 HTTP/JSON 비용을 없애지만 실제 성능은 서버·동시성·workload·토폴로지별로 측정합니다.

GeoIP와 동적 JSON/Lua는 query 모드의 HTTP/바이너리 모두 서비스에서 평가합니다.
prefix snapshot으로 표현할 수 없으므로 동적 규칙 활성 시 snapshot 조회를 거절합니다.
기본 query를 사용하며 기존 snapshot은 정상 만료 후 fail-open합니다.

## 원격 native mTLS

--guard-decision-tcp와 함께 --guard-decision-server-name·--guard-decision-ca·
--guard-decision-cert·--guard-decision-key를 모두 설정합니다. PEM은 절대 경로이며
loopback 밖에서 필수입니다. 목적지는 고정된 nonzero unicast socket입니다. 명시적 CA·
서버명을 검증하고 client 인증서·ALPN hgd1을 사용하며 TLS early data를 끕니다. 암호화
안에서도 collector key 인증은 필수입니다.

기존 제한된 풀과 전체 timeout은 TCP·TLS·요청/응답을 포함합니다. idle 25초와 연결
240초에 회수하며 서버 300초 한도보다 짧습니다. 취소·잘못된 응답·TLS 실패·timeout은
연결을 폐기합니다. native 실패 시 HTTP/평문으로 fallback하지 않습니다.

HTTP origin은 신호/evidence·snapshot을 계속 처리합니다. native CA는 HGD1에만 적용하므로
같은 권위의 HTTP origin을 인증된 HTTPS ingress 또는 로컬 broker로 구성합니다. 이 설정은
fleet discovery·영속 revision watermark·전체 경로 100k QPS를 구현한 것이 아닙니다.

네이티브 판단 주소는 제한된 Service DNS(`sumunjang.world.svc:9081`) 또는
IPv4/IPv6 주소를 받습니다. localhost도 DNS이면 mTLS가 필수입니다. 새 pooled
연결은 기존 요청 기한 안에서 조회하며 별도 설정한 서버 이름·CA를 검증합니다.
DNS·TLS 실패 시 평문 HTTP fallback하지 않습니다. 원격 근거 내보내기의
origin은 HTTPS를 유지합니다.

## 선택 gRPC 질의 전송

`--guard-decision-grpc`를 추가하면 `--guard-decision-tcp` 주소를 수문장 gRPC
엔드포인트로 사용합니다. 루프백에서도 서버 이름·CA·인증서·키가 필수입니다.
서버의 HGD1 포트 대신 `--grpc-listen` 포트를 지정하며 질의 모드·collector 자격을 사용합니다.

HTTP/2 채널을 재사용하고 동시 판정 64개, 메시지 크기, 연결·RPC를 포함한 전체
시간을 제한합니다. 기본값·사용 불가·잘못된 모드/TTL·요청 ID 불일치·리비전 후퇴는
거부합니다. 관찰 허용은 집행 근거가 아닙니다. 취소는 진행 중 질의를 중단합니다.
gRPC 실패에 HTTP/네이티브로 우회하지 않습니다. 선택적 네트워크 입장은 설정한
장애 정책을 따르지만 품계에 필요한 강제 네트워크 근거는 사용 불가로 닫힙니다.
허니팟·스캐너 근거 제출은 기존 HTTP 신호 경로를 사용합니다. 기본 전송은 HGD1입니다.
자격/채널 교체·실제 K8s 배포·전체 한강 요청 체인 검증은 후속 작업입니다.

격리된 서버·클라이언트 검증:

```sh
cargo build --example guard_grpc_qualification
python /path/to/sumunjang/tools/grpc_smoke.py --binary /path/to/sumunjang --hangang-client target/debug/examples/guard_grpc_qualification
```

입장 판정과 새 권한 근거는 이미 확인한 리비전을 공유하며 단조 증가합니다. HTTP 신호와 gRPC/네이티브 질의가 섞여도 오래된 응답이 최신 근거를 덮어쓰지 못합니다.
