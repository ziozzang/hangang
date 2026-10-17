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

### Query 예산과 캐시 수명

Linux의 양수 decision TTL은 원래 로컬 query 시작 시점부터 suspend를 포함하는
BOOTTIME으로 차감합니다. 연결·대기열·RPC·응답 body 읽기 시간도 포함합니다.
캐시 hit는 같은 원래 capture를 공유하며 TTL을 새로 시작하지 않습니다. 시계 읽기
실패나 역행이 확인된 capture는 이후 정상 읽기로 복구되지 않습니다. 소스의
밀리초 양자화 오차 1ms는 제외합니다. 캐시는 기존처럼
`min(configured_cache_ms, reply.ttl_ms)`로 최대 5초이며, native request evidence는
추가로 원래 query부터 최대 1초 및 정확한 client owner·정규화 IP·현재 revision에
묶입니다. 외부 절대 시각과 비교하지 않습니다. 다른 플랫폼은 기존 Instant 동작을
유지하며 Linux observed 계약을 충족한다고 간주하지 않습니다.

Classic 프로토콜 TTL은 제한된 캐시/재사용 힌트이며 원격 철회 lease나 이후 모든
proxy transport 쓰기를 보장하는 계약이 아닙니다. TTL 0은 timed rule의 마지막
1초 등에서 발생하는 유효한 단발 결정이며 캐시나 재사용 증거를 만들지 않습니다.
로컬 cache 비활성화도 authority TTL을 바꾸지 않습니다. 공개 numeric authorization
결과는 이 호환성을 유지하며 보존 가능한 증명으로 취급하면 안 됩니다. transport
이후 원래 양수 예산이 이미 만료된 응답은 unavailable입니다(admission은 설정한
failure mode 적용, mandatory fresh authorization은 unavailable 유지). 기존 legacy
연결 pooling과 단발 dispatch 동작은 유지합니다. 명시적인 observed native chain은
별도의 로컬 authority/output/transport fence를 사용하며, 이번 캐시 보강이 모든
legacy socket 쓰기를 network evidence로 검사한다는 의미는 아닙니다.
Native guard owner가 취소되면 캐시 및 보존된 capture도 철회되며, query admission은
해당 owner의 캐시를 재사용하거나 새 증거를 만들지 않습니다.
## 호패 위험 컨텍스트

한강은 요청에 대한 Sumunjang 네트워크 증거를 호패에 전달할 수 있고, 호패의 위험 규칙은 이를
보고 최근 인증 요소를 요구하거나 요청을 거부합니다(호패 ADR-0023, 호패 `GATEWAY_CONTRACT.md`
"위험 컨텍스트").

```sh
hangang ... --guard-decision-grpc ... \
  --risk-context-key-env HANGANG_RISK_CONTEXT_KEY \
  --risk-elevated-reason sumunjang.allow.rule --risk-elevated-country RU \
  --risk-elevated-asn 64666 --risk-unlisted-elevated
```

그리고 인증 서비스가 호패인 각 라우트에 `"auth": {..., "risk_context": true}`를 둡니다.

- **증거.** `--risk-context-key-env`를 주면 gRPC 질의가 Sumunjang Network 서비스에
  `include_evidence`를 요청합니다. 증거에는 사유 코드, 결정 단계, ASN, 국가, 집행했다면 내릴
  판정이 담깁니다. 이 추가 필드를 모르는 Sumunjang은 원래 응답을 돌려줍니다. 증거가 없으면
  헤더를 생략하고 호패의 `risk.missing`이 적용됩니다. 오래된 Sumunjang, HTTP·HGD1 전송,
  Sumunjang 장애, TTL이 0인 판정이 이 경우에 해당합니다.
- **수준.** 계약의 대응표를 따르며 임계값은 설정할 수 있습니다.
  - `high`: 집행했다면 거부되었을 요청. observe 모드에서만 보이며, 실제로 집행된 거부는 호패
    전에 거부되기 때문입니다.
  - `elevated`: 설정한 사유 코드(`--risk-elevated-reason`, 판정 사유나 집행했다면의 사유와
    대조), 국가(`--risk-elevated-country`), ASN(`--risk-elevated-asn`). 또는
    `--risk-unlisted-elevated`일 때 정책 기본값으로만 허용된 요청(observe 모드에서는
    집행했다면의 사유가 `sumunjang.allow.default`인 요청).
  - `low`: 그 밖의 모든 요청.
- **헤더.** 계약 그대로 `x-hopae-risk-context: v1.<P>.<T>`입니다.
  - `P`에는 `iat`, `level`, `source`, `mode`, `reason`, `rev`, `asn`, `country`가 담깁니다.
  - `T`는 클레임과 이 verify 호출의 `x-original-method`, `x-forwarded-for`,
    `x-original-url`에 대한 HMAC-SHA256입니다.
  - 키는 `--risk-context-key-env`에서 읽으며 32–4,096바이트이고 호패의
    `risk.context_key_env`와 같아야 합니다.

  헤더는 라우트의 인증 호출(HTTP forward-auth 또는 HOP1)에만 보내고 업스트림으로는 보내지
  않습니다. 같은 이름의 클라이언트 헤더는 입구에서 지우며, 이 이름은 전달 헤더나 고정 인증
  헤더로 설정할 수 없습니다. 단위 테스트 `the_contract_test_vector_is_reproduced`가 호패
  문서의 테스트 벡터를 바이트 단위로 재현합니다.
- **키 교체.**
  1. 호패 `risk.context_key_next_env`에 새 키를 둡니다.
  2. 한강을 새 키를 가리키는 `--risk-context-key-env`로 재시작합니다.
  3. 새 키를 호패의 현재 키로 올리고 이전 키를 지웁니다.
- **관측.**
  - `hangang_risk_context_sent_total{level}`과 `hangang_risk_context_omitted_total`이 보낸
    것과 생략한 것을 셉니다.
  - 결정 이벤트의 identity 단계에 `risk_level`이 기록됩니다
    ([결정 이벤트](DECISION_EVENTS.md)).
- **검증.** `tests/risk_context_smoke.py`는 증거를 주는 실제 Sumunjang, 위험 규칙이 있는
  실제 호패, 한강을 함께 돌립니다. `low`는 허용, `elevated`는 `/admin`에서 단계 상승,
  `high`는 거부되는지, 클라이언트가 보낸 헤더가 제거되어 업스트림에 닿지 않는지 확인합니다.

