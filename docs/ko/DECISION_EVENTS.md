# 판단 이벤트와 판단 내보내기 프로세스

[문서 목록](../README.ko.md) · [English](../DECISION_EVENTS.md)

판단 이벤트는 보호된 HTTP 요청에 대해 실제로 집행된 접근 판단을 제한된 크기의
가명 기록으로 남긴 것입니다. 하나의 이벤트는 네트워크 단계(수문장), 신원 단계
(호패 또는 게이트웨이 자체 인증), 권한 단계(품계)와 한강 자체 집행 단계를
안정적인 사유 코드와 함께 묶고, 판단에 참여한 모든 기관의 리비전을 기록합니다.
관리 콘솔의 판단 로그와 요청 상세 화면이 이 데이터를 사용합니다. 이 문서는
ADR 0019(`hangang.decision.v1`)의 D1 단계 구현을 설명합니다.

판단 이벤트는 **기본적으로 꺼져 있습니다**. `--decision-events-config`가 없으면
이미터가 만들어지지 않으며, 아무것도 기록하거나 할당하지 않고, 판단 API는 로그를
비활성 상태로 보고합니다.

판단 이벤트는 접근 로그가 아닙니다. 헤더, 쿠키, 본문, 쿼리 문자열, 원본 요청
경로, 자격 증명, 영수증, 허가, 제공자 토큰, 이메일 주소, 표시 이름을 절대 담지
않습니다.

## 준비 사항과 설정

판단 이벤트에는 다음 세 가지가 필요합니다.

1. 로컬 저장소를 가진 독립 내보내기 프로세스 `hangang-decision-exporter`.
2. 가명화 에포크 키를 담은 키 파일. 한 배포의 모든 한강 복제본이 같은 파일을
   읽어야 노드 사이에서 가명이 일치합니다. 관리 주체는 정확히 하나여야 합니다.
3. `--decision-events-config`(환경 변수 `HANGANG_DECISION_EVENTS_CONFIG`)로
   한강에 전달하는 판단 이벤트 설정 파일.

설정 조각:

```json
{
  "profile": "standard",
  "instance": "gw-a",
  "exporter_socket": "/run/hangang/decision-ingest.sock",
  "query_socket": "/run/hangang/decision-query.sock",
  "key_file": "/var/lib/hangang/decision-keys.json",
  "manage_keys": true,
  "key_rotation_hours": 24,
  "key_retention_hours": 192,
  "allow_sample_percent": 1.0,
  "audit_all_classes": ["restricted"],
  "routes": {"admin-api": {"audit_all": true}, "static": {"allow_sample_percent": 0}},
  "deny_bucket": {"burst": 20, "refill_per_second": 1.0, "window_seconds": 60},
  "rings": {"deny_slots": 8192, "allow_slots": 4096},
  "batch": {"max_events": 512, "interval_ms": 250},
  "bucket_slots": 4096
}
```

| 필드 | 기본값 | 의미 |
| --- | --- | --- |
| `profile` | 필수 | `off`, `strict`, `standard` 중 하나(개인정보 프로필 참고) |
| `instance` | 비어 있음 | 이미터 인스턴스 이름, 64자 이하 식별자 |
| `exporter_socket` | `off`가 아니면 필수 | 내보내기 프로세스의 수신 Unix 소켓 |
| `query_socket` | 없음 | 판단 API가 사용하는 내보내기 프로세스의 조회 Unix 소켓 |
| `key_file` | `off`가 아니면 필수 | 에포크 키 파일(비밀 참조, 권한 0600) |
| `manage_keys` | `false` | 이 노드가 에포크 키를 만들고 파기합니다. 정확히 한 노드에만 설정합니다 |
| `key_rotation_hours` | `24` | 에포크 길이, 1~720시간 |
| `key_retention_hours` | `192` | 에포크가 끝난 뒤 이 시간이 지나면 키를 파기합니다. 저장소 보존 기간에 에포크 하나를 더한 값으로 설정합니다 |
| `allow_sample_percent` | `1.0` | 허용 판단의 선두 샘플링 비율, 0~100 |
| `audit_all_classes` | `["restricted"]` | 이 품계 정보 등급을 쓰는 경로는 모든 허용 판단을 보존합니다 |
| `routes` | 없음 | 경로 ID별 `allow_sample_percent` 또는 `audit_all` |
| `deny_bucket` | 20 / 1.0 / 60 | 거부 판단에 대한 (경로, 클라이언트 프리픽스)별 토큰 버킷과 요약 창 |
| `rings` | 8192 / 4096 | 샤드별 거부용·허용용 링 슬롯 수. `shards` 기본값은 CPU 수입니다 |
| `batch` | 512 / 250 | 배출 배치 크기(최대 512)와 주기(밀리초) |
| `bucket_slots` | `4096` | 토큰 버킷 표의 고정 크기 |

내보내기 프로세스는 한강보다 먼저 또는 나중에 시작해도 됩니다. 어느 쪽도 다른
쪽을 기다리지 않습니다.

```sh
hangang-decision-exporter \
  --ingest-socket /run/hangang/decision-ingest.sock \
  --query-socket /run/hangang/decision-query.sock \
  --store /var/lib/hangang/decisions.db \
  --max-store-mib 2048 --retention-hours 168
```

내보내기 프로세스의 기본값은 저장소 2 GiB, 보존 7일이며 보존 기간의 최대값은
90일입니다. 두 소켓은 `0600` 권한으로 만들어집니다(그룹 공유가 필요하면
`--socket-mode 660`을 사용합니다). 내보내기 프로세스는 정책 자격 증명도, 가명화
키도 갖지 않습니다.

## 동작

### 기록 대상

보호 경로(외부 인증, JWT, Basic, 워크로드 mTLS, 집행 중인 리소스 정책, 네이티브
리소스 바인딩 또는 `access_mode: protected`)에 도달한 요청, 그리고 게이트웨이가
접근 사유(수문장 거부, IP 차단, 요청 차단, URL 허용 목록, 요청 한도, 네임스페이스
거부)로 거절한 요청에 대해 이벤트가 생깁니다. 일반 공개 트래픽은 이벤트를 만들지
않습니다.

| 단계 | 출처 | 기록 내용 |
| --- | --- | --- |
| `network` | 수문장 입장 판단 | 판정(`allow`, `deny`, `observe`, `unavailable`), 모드, 정책 리비전, 전송 방식, 지연 시간, 가명 IP·프리픽스 참조, 국가 |
| `identity` | 호패(`hop1` 또는 HTTP 인증) 또는 한강(JWT, Basic, 워크로드 인증서) | 판정, 주체 종류, AAL, 인증 요소, 가명 주체 참조, 지연 시간 |
| `authorization` | 품계 원격 판단 또는 컴파일된 정책 | 정확한 `pumgye_core::Decision` 변형(추가로 `UnknownResource`, `UnknownAction`, `Unavailable`, `NotMapped`), 정보 등급, 정책 리비전, 전송 방식, 지연 시간 |
| `enforcement` | 한강 | `refused`, `challenged`, `forwarded`, `redirected`, 펜스, 한강 설정 리비전, 업스트림 상태 등급 |

경로 블록에는 경로 ID, 리스너, 설정된 호스트, 경로 템플릿으로서의 설정된 경로
프리픽스, 메서드, 품계 서비스·리소스·동작이 들어갑니다. 수문장을 설정하지 않으면
네트워크 단계에는 클라이언트 참조만 들어갑니다. 도달하지 않은 단계는 생략되며,
결정 단계와 사유가 그 이유를 설명합니다. `revisions` 벡터에는 실제로 판단에
참여한 기관만 나열됩니다.

사유 코드는 네임스페이스(`sumunjang.*`, `hopae.*`, `pumgye.*`, `hangang.*`)를
가지며, `hangang-decision-event` 크레이트에 영어와 한국어 메시지로 등록되어
있습니다. 계약 테스트는 한강이 내보내는 모든 코드와 모든 품계 판단 변형이
등록되어 있는지 확인합니다.

### 샘플링과 폭주 상한

선두 샘플링은 한강 요청 ID에 대해 결정적입니다.

| 분류 | 보존 비율 | 상한 |
| --- | --- | --- |
| 거부, 인증 요구, 오류, 사용 불가 | 100% | (사유, 경로, IPv4 /24 또는 IPv6 /48 프리픽스)별 토큰 버킷. 초과분은 계수되며 창마다 원래 사유 코드를 유지하고 샘플링 분류가 `suppressed`이며 개수와 처음·마지막 시각을 담은 이벤트 하나로 요약되므로, 건수가 원래 사유에 그대로 귀속됩니다 |
| 허용 | `allow_sample_percent`(1%) | 경로별 재정의. `audit_all` 경로와 품계 게이트가 `audit_all_classes` 등급을 쓰는 경로는 100%(`audit` 분류)입니다 |

보존된 모든 이벤트는 샘플링 분류와 비율을 기록하므로 콘솔은 허용 건수를 추정치로
표시합니다. 정확한 요청 수는 계속 Prometheus 카운터가 기준입니다.

### 요청 경로, 링, 배출

요청 스레드는 스택 값에 고정 크기 필드만 씁니다. 요청이 끝나면 샘플링과 토큰
버킷을 적용하고 `try_push`로 제한된 링의 미리 할당된 슬롯에 이벤트를 옮깁니다.
샤드마다 거부용 링과 허용용 링이 분리되어 있어 허용 폭주가 거부 이벤트를 밀어낼
수 없습니다. 링이 가득 차면 버림 카운터만 올리고 즉시 반환합니다. 기능을 켜든
끄든 요청 경로는 판단 이벤트 때문에 I/O, 할당, 대기를 하지 않습니다(할당 계수
테스트로 검증합니다).

백그라운드 배출 작업은 `interval_ms`마다 실행됩니다. 끝난 버킷 창을 요약으로
만들고, 각 이벤트를 가명화·봉인·인코딩한 뒤(최대 2 KiB, 스키마 검증) 최대 512개
이벤트의 길이 구분 배치를 연결 1초, 쓰기 2초 제한으로 내보내기 소켓에 씁니다.
한강에는 디스크 스풀이 없고 재시도도 하지 않습니다. 쓸 수 없는 배치는 버리고
계수하며(`exporter_unavailable`), 재연결은 최대 30초의 제한된 백오프를 따릅니다.

### 개인정보 프로필과 키

| 프로필 | 이벤트 | 가명 | 봉인 값 |
| --- | --- | --- | --- |
| `off` | 없음, 로그는 비활성으로 보고 | — | — |
| `strict` | 있음 | 있음 | 없음, 정방향 조회만 가능 |
| `standard` | 있음 | 있음 | 에포크 키로 봉인한 불투명 주체 ID와 클라이언트 IP |

가명은 도메인이 분리된 값을 에포크 키로 `HMAC-SHA-256`한 결과를 80비트로 자르고
`ip~`, `pfx~`, `sub~`, `ses~` 뒤에 Crockford base32 16자로 적은 것입니다. 봉인 값은
이벤트 ID와 필드에 묶인 ChaCha20-Poly1305를 사용합니다. 봉인 값은 로컬 저장소에만
남고 콘솔 투영에는 포함되지 않으며, 존재 여부만 표시됩니다.

각 에포크는 고유한 256비트 무작위 키를 가집니다. 관리 노드는 현재와 다음 에포크
키를 미리 만들고, 에포크가 끝난 지 `key_retention_hours`가 지난 키를 모두 파기한
뒤 키 파일을 원자적으로 다시 씁니다. 파기 후에는 그 에포크의 가명을 주체나 주소로
다시 계산할 수 없고 봉인 값도 열 수 없습니다(crypto-shredding). 다른 복제본은 키
파일이 바뀌면 다시 읽습니다. 에포크 키가 없는 이벤트는 버리고 계수하며(`no_key`),
가명화하지 않은 채 저장하는 일은 없습니다.

### 로컬 저장소

내보내기 프로세스는 모든 이벤트를 검증하고, 보존 기간보다 오래되었거나 10분 넘게
미래인 이벤트를 거부하며, `event_id` 유일성을 가진 SQLite(WAL 모드)에 넣으므로
중복 전달은 해가 없습니다. 이벤트는 시간 단위 파티션에 보관되고, 시뮬레이션과
섀도 이벤트는 별도 구간에 저장되어 트래픽 조회에서 제외됩니다. 바이트 상한은 배치마다,
보존 기간 상한은 1분마다 확인하며, 둘 다 가장 오래된 파티션부터 통째로 삭제한 뒤
점진적 vacuum으로 집행합니다.

## 관리 API

모든 판단 작업은 관리 리스너에서 관리자 전용이며 `GET`만 허용합니다. 뷰어 계정은
`403`을 받습니다. 판단 이벤트가 꺼져 있으면 `200`과 `"state": "disabled"`로
응답하며, 콘솔은 이를 빈 목록이 아니라 비활성으로 표시해야 합니다.

| 작업 | 용도 |
| --- | --- |
| `GET /v1/observability/status` | 프로필, 링 용량과 대기 수, 버림·내보내기 카운터, 키 에포크 상태, 저장소 상태 |
| `GET /v1/observability/decisions` | 필터와 커서 페이지 나눔을 지원하는 최신순 판단 로그 |
| `GET /v1/observability/decisions/facets` | 결과, 단계, 사유, 경로, 서비스, 등급, 국가, ASN별 건수 |
| `GET /v1/observability/decisions/timeseries` | 시간 구간별 결과 건수 |
| `GET /v1/observability/requests/{request_id}` | 한 요청의 모든 이벤트를 시간순으로 |

필터: `from`과 `to`(Unix 밀리초, 기본값은 최근 24시간, 최대 31일), `limit`(1~200,
기본 50), `order`(`desc` 또는 `asc`), `cursor`, `kind`(`enforced` 또는
`simulation`), `outcome`, `stage`, `reason`, `route`, `service`, `resource`,
`class`, `principal`, `asn`, `country`, `pumgye_revision`, `bucket`(시계열, 60~86400초),
가명 참조 `subject_ref`, `ip_ref`, `prefix_ref`. 같은 필터를 반복하면 값 중 하나에
해당하는 것을 찾습니다. 조회 제한 시간은 3초입니다.

정방향 조회: `subject`, `ip`, `prefix`에는 호패 주체 ID나 주소 원본을 넣을 수
있습니다. 한강은 조회 창과 겹치는 보존 중인 모든 키 에포크의 가명으로 바꾸어 그것만
전달합니다. 원본 값은 내보내기 프로세스로 가지 않고 응답에도 나타나지 않습니다.
파기된 에포크는 검색할 수 없습니다.

```sh
curl -H "Authorization: Bearer $TOKEN" \
  "http://127.0.0.1:9000/v1/observability/decisions?outcome=deny&subject=u_example&limit=50"
```

각 항목은 `hangang.decision.v1`의 JSON 투영으로 `event_id`, `kind`, `request_id`,
`time`, `emitter`, `route`, `outcome`(`message_key` 포함), `stages`, `revisions`,
`sampling`, `privacy`, 요약 이벤트의 경우 `suppressed`를 담습니다. 샘플링된 허용
판단에는 `estimate_weight`가 붙습니다.

## 관측

판단 이벤트를 켜면 `/metrics`에 다음이 추가됩니다.

| 메트릭 | 의미 |
| --- | --- |
| `hangang_decision_events_dropped_total{class,reason}` | 잃은 이벤트: `ring_full`(`deny` 또는 `allow` 링별), `exporter_unavailable`, `no_key`, `invalid` |
| `hangang_decision_events_captured_total` | 관찰한 보호 판단 수 |
| `hangang_decision_events_kept_total{class}` | 링에 넣은 이벤트 수 |
| `hangang_decision_events_sampled_out_total` | 샘플링되지 않은 허용 판단 수 |
| `hangang_decision_events_suppressed_total` | 토큰 버킷이 흡수한 거부 수 |
| `hangang_decision_events_summaries_total` | 억제 요약 이벤트 수 |
| `hangang_decision_events_exported_total` | 내보내기 프로세스에 쓴 이벤트 수 |
| `hangang_decision_events_export_errors_total` | 내보내기 연결 또는 쓰기 실패 수 |
| `hangang_decision_events_queued` | 링에서 대기 중인 이벤트 수 |
| `hangang_decision_exporter_connected` | 내보내기 연결 상태 |

내보내기 프로세스는 조회 소켓의 `/metrics`에서 `hangang_decision_exporter_*`
카운터, 저장소 크기, 가장 최근 저장 이벤트의 지연을 제공합니다. 어떤 메트릭
레이블에도 가명, 경로, 주체가 들어가지 않습니다.

## 제한 사항과 호환성

이 문서는 D1 단계입니다. 아직 구현하지 않은 것:

- `POST /v1/observability/reveal`, 감사되는 봉인 해제, `decisions:reveal`과
  `network:reveal-ip` 권한. 범위 지정 콘솔 권한이 생기기 전까지 접근은 관리자
  전용입니다.
- 설명/시뮬레이션, 영향 분석, 운영자 추적 세션(D2 단계).
- ClickHouse 또는 장부(Jangbu) 싱크와 Kubernetes 판단(D3 단계).
- 원격 내보내기 프로세스와의 mTLS 전송. D1은 로컬 Unix 소켓을 사용합니다.
- 수문장 일치 규칙 ID와 ASN, 호패 제공자·세션 참조·상태 세대, 품계 일치 역할·요구
  AAL·허가 다이제스트: 현재 전송 계약이 이 값을 한강에 전달하지 않으므로 해당
  필드는 비어 있습니다.
- 거부 페이지에는 아직 요청 ID가 표시되지 않습니다.

- 키 보관: 공유 에포크 키 파일과 `manage_keys` 노드 하나를 두는 방식이 D1의
  결정입니다. KMS를 통한 에포크 키 배포나 유도는 D3 단계 후속 과제입니다(ADR 0019
  미결 질문 1).

### 측정한 오버헤드

`tests/decision_overhead.rs`는 기록과 완료 처리의 요청 경로 비용을 단독으로
측정합니다(단일 스레드, 릴리스 빌드, AMD Ryzen 7 8745HS, 3회 실행, 백분위수에는
약 20 ns의 시계 읽기가 포함됩니다).

| 경로 | 평균 | p50 | p99 |
| --- | --- | --- | --- |
| 꺼짐(비활성 기록) | 21–24 ns | 40 ns | 50–51 ns |
| 켜짐, 1% 샘플링 허용 판단 | 143–149 ns | 160–171 ns | 190–201 ns |
| 켜짐, 보존된 거부(버킷과 링 적재) | 179–203 ns | 190–210 ns | 230–281 ns |
| 켜짐, 버킷이 억제한 거부 | 179–208 ns | 200–221 ns | 231–301 ns |
| 보존 이벤트당 배출 인코딩(standard 프로필, 백그라운드) | 6.1–8.2 µs | — | — |

ADR 0019 예산과 비교하면 요청 경로에 더해지는 지연은 p99 기준 약 0.25 µs 이하입니다
(예산 5 µs). 초당 10만 판단, 허용 1% 샘플링에서 기록 비용은 초당 약 15 ms의 CPU,
보존된 약 1,000개 이벤트의 배출은 초당 약 8 ms로, 합쳐서 코어 하나의 약 2.3%이며
그 부하를 처리하는 게이트웨이 전체 코어의 2%보다 충분히 낮습니다. 거부가 많은
트래픽은 보존된 거부마다 약 8 µs의 배출 CPU를 쓰며, 보존 개수는 토큰 버킷이
제한합니다. 이 값은 마이크로벤치마크 결과이며 초당 1만·10만 요청의 종단 간 부하
검증은 아직 남아 있습니다.

## 검증과 관련 문서

```sh
cargo test -p hangang-decision-event -p hangang-decision-exporter
cargo test -p hangang --lib decision::
cargo test -p hangang --test decision_events --test decision_admin --test decision_overhead -- --nocapture
```

- [네이티브 hangang-guard 입장 판단](GUARD.md)
- [품계 권한](PUMGYE.md)
- [호패 gRPC 게이트웨이 클라이언트](HOPAE_GRPC.md)
- [관리자 계정 · 영문](../ADMIN_USERS.md)
