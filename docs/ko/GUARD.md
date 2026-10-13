# 네이티브 hangang-guard 연동

[English](../GUARD.md) · [문서](README.md)

Hangang은 신뢰 프록시 설정으로 클라이언트 IP를 판별한 뒤, 경로 인증 전에
zero-trust 판단 서비스 hangang-guard에 요청별로 질의합니다. Guard 허용은
기존 인증을 우회하지 않습니다. hopae는 사용자·주체 관리, guard는 IP·네트워크
제어와 위험 판단을 담당합니다. 보호 범위는 향후 확대할 수 있습니다.

```sh
hangang --config config.json --guard-url http://127.0.0.1:9080 \
  --guard-honeypot-path /trap --guard-scanner-path /.git/config
```

Collector 토큰은 HANGANG_GUARD_COLLECTOR_TOKEN 환경 변수로 제공합니다.
--guard-token-env로 환경 변수 이름을 바꿀 수 있습니다. HTTP는 literal
loopback 주소만 허용하며 원격은 HTTPS를 사용합니다. 리다이렉트를 거부합니다.

| 옵션 | 기본 | 의미 |
| --- | --- | --- |
| --guard-url | 없음 | 네이티브 연동 활성화 |
| --guard-mode | query | 요청별 질의; snapshot은 제한된 로컬 정책 모드 |
| --guard-source-id | hangang | Collector 이름 |
| --guard-timeout-ms | 100 | 풀 대기·연결·인증·질의 전체 deadline |
| --guard-failure-mode | deny | 장애 시503; allow는 기존 정책으로 계속 처리 |
| --guard-cache-ms | 0 | 캐시 없음; 활성화 시1000~5000ms |
| --guard-decision-tcp | 없음 | 선택적 loopback 바이너리 decision 주소 |
| --guard-honeypot-path | 없음 | 명시적 허니팟 경로, 반복 지정 |
| --guard-scanner-path | 없음 | 명시적 스캐너 경로, 반복 지정 |

명시적 차단은403입니다. 캐시는 요청 시작부터 server TTL과 설정값 중 짧은
기간만 유효하며 최대1만 IP를 보관합니다. 탐지 신호가 있는 요청은 캐시를
사용하지 않습니다. Query 기본은 캐시 없이 항상 판단 서비스에 질의합니다.
Guard 자체 차단은 공격 증거를 갱신하지 않으며 일반403을 증거로 세지 않습니다.

TCP는 최대64개 인증된 연결을 재사용하고24바이트 프레임을 검증합니다. Idle
연결은25초 뒤 폐기해 server30초 deadline 전에 새로 인증합니다. 실패/잘못된
프레임/timeout이면 연결을 폐기하며 HTTP로 조용히 fallback하지 않습니다.
증거를 포함한 요청은 HTTP decision API로 보냅니다. 종료 시 풀을 닫습니다.

Snapshot은2초마다 bounded 배치/정책을 받아 로컬 index로 판단합니다.4MiB,
10만 prefix/목록,버전·만료·canonical CIDR을 검증하고 정상 정책만 원자적으로
반영합니다.4096 event queue/256 batch,만료 뒤 fail-open이며 query 장애 의미와
다릅니다. 동적 Lua/국가/ASN RuleSet은 snapshot v1에서 지원하지 않으므로
query를 사용하세요. 기존 기본 health probe는 guard admission 밖에 있습니다.
일반 proxy admission에 들어온 ACME 요청은 guard 판단을 받습니다.

## 원격 네이티브 mTLS

`--guard-decision-tcp`와 함께 `--guard-decision-server-name`·
`--guard-decision-ca`·`--guard-decision-cert`·`--guard-decision-key`를 설정합니다.
PEM 경로는 절대 경로여야 하며 literal 루프백 밖에서는 이 설정이 필수입니다.
네이티브 목적지는 고정된 0이 아닌 포트의 unicast 소켓 주소입니다. Hangang은
명시한 CA·서버 이름을 검증하고 클라이언트 인증서를 제시하며 ALPN `hgd1`을
요구하고 TLS early data를 끕니다. 암호화된 연결 안에서도 collector 키 인증은 필수입니다.

기존 제한된 연결 풀과 전체 판단 기한에 TCP 연결·TLS 핸드셰이크·요청/응답을
포함합니다. Idle 연결은 25초 후 종료하고 서버의 300초 제한보다 짧은 240초의
연결 수명도 적용합니다. 취소·잘못된 응답·TLS 실패·타임아웃은 연결을 폐기하며
네이티브 실패 시 HTTP 또는 평문으로 전환하지 않습니다.

HTTP origin은 여전히 신호/근거 제출과 snapshot export를 처리하고 네이티브 CA
설정은 HGD1에만 적용합니다. 같은 권한 서버의 기존 인증된 HTTPS ingress 또는
로컬 broker를 HTTP origin으로 설정합니다. 이 설정이 분산 discovery·영속 revision
watermark나 전체 스택 100k QPS를 구현·검증한 것은 아닙니다.
