# 제로 트러스트 콘솔 섹션과 공용 UI 키트

[문서 목록](../README.ko.md) · [English](../ZERO_TRUST_CONSOLE.md)

관리 콘솔은 제로 트러스트 작업을 운영자 작업 단위로 묶습니다(ADR 0020 P0):
개요, 접근, 신원, 정책, 네트워크, 장치와 워크로드, 감사, 시스템. 구성 요소 페이지
(품계, 설치된 호패·수문장 패키지)는 작업 페이지가 나올 때까지 *구성 요소 페이지*
아래에 남습니다. 모든 섹션은 관리자 전용이며 기존 관리 API로 데이터를 읽습니다.

## 섹션

| 섹션 | 경로 | 내용 |
| --- | --- | --- |
| 개요 | `#overview` | 권한 기관 상태(한강, 호패, 수문장, 품계, 판단 내보내기), 1시간·24시간·7일 판단 지표와 거부율 추이, 주요 거부 사유·경로·국가, 최근 관리 변경. 화면이 보이는 동안 30초마다 갱신 |
| 접근 | `#access/decisions` | URL에 보관되는 서버 측 필터, 커서 페이지 나눔, 시간순 전환, 요청·사용자·IP 검색, 제한된 실시간 추적을 갖춘 판단 로그 |
| 접근 | `#access/requests/{request_id}` | 요청 상세: 결정 단계가 강조된 단계 타임라인, 현지화된 사유와 해결 방법, *이후 변경* 표시가 있는 리비전 벡터 |
| 신원 | `#identities/users/{id}` | 가능하면 호패 `subjects/resolve`로 확인한 주체, 아니면 불투명 ID. 정방향 조회로 찾은 최근 판단 |
| 네트워크 | `#network/…` | 수문장 패키지를 통한 개요, 위협 대기열, IP 상세, 차단·허용 목록, 규칙, 정책, ASN 풀(아래 참고) |
| 정책 | `#policies/services/{id}` | 품계 서비스의 최근 판단 |
| 감사 | `#audit` | 콘솔 계정, 콘솔 패키지 작업, 품계 게시를 모은 통합 관리 감사. 실패한 출처는 표시되며, 계정 변경은 구조화된 변경 전후 비교를 보여 줍니다. 콘솔 계정 감사의 보존·정책·내보내기는 `#account-audit`로 옮겼고, 이전 `#audit-trail` 링크는 리다이렉트됩니다 |
| 시스템 | `#system` | 구성 요소, 패키지, 판단 이벤트, 내보내기, 개인정보 프로필. 원본 JSON은 *원본 진단 보기* 안에서만 제공 |

신원, 정책, 네트워크, 장치와 워크로드 섹션은 그 밖에는 항목 열기 입력과 현재
구성 요소 페이지 링크를 보여 줍니다. 판단 이벤트가 꺼져 있으면 모든 판단 화면은 빈
목록 대신 *판단 이벤트 비활성*을 표시합니다. 이후 단계가 필요한 작업(시뮬레이터,
봉인 해제)은 이유와 함께 비활성 상태로 표시됩니다.

## 네트워크

모든 네트워크 페이지는 호스트 중계(`/v1/plugins/guard/<route>`)로 수문장 콘솔 패키지를
호출합니다. 이전 수문장 패키지 페이지는 탐색에서 빠졌고 `#plugin-guard` 링크는
`#network`로 리다이렉트됩니다.

| 경로 | 페이지 | 수문장 경로 |
| --- | --- | --- |
| `#network` | 개요: 모드 배너, 관찰 모드에서는 추적 주소 중 집행 시 거부될 주소, 대기열·차단·허용 목록·규칙 수, 한강 판단 로그의 네트워크 단계 거부 추이와 상위 국가, 상위 ASN, 최근 정책 변경 | `policy/document`, `candidates`, `blocks`, `rules`, `explain/batch`, `audit/query` |
| `#network/threats?q=&stage=&asn=&eligible=` | 위협 대기열: 점수, 단계, 이벤트, ASN, 최근 확인. 개수 입력 확인과 사유로 일괄 승인 | `candidates`, `candidates/approve` |
| `#network/ip/{ip}` | IP 상세: GeoIP/ASN, 점수와 단계, 일치 규칙, 만료가 있는 차단, 허용 목록, 설명 추적(게시본과 관찰 중에는 집행 시), 관련 판단. 사유와 함께 차단·해제·허용 | `lookup`, `explain`, `blocks`, `policy/document` |
| `#network/blocks[/allowlist]?kind=` | 차단(수동, 승인, 자동)과 만료 카운트다운, 허용 목록. 추가 시 CIDR 검증과 영향 미리 보기 | `blocks`, `networks/inspect`, `explain/batch`, `policy/document` |
| `#network/rules[/lua]?rule=` | 구조화 양식 또는 호스트 CodeMirror 편집기의 Lua 규칙. 검증, 변경 목록, 추적 주소 가정 분석, 사유와 함께 게시 | `rules`, `rules/validate`, `rules/lua`, `explain/batch` |
| `#network/policy` | 모드, 자동 차단, 창, 임계값, 차단 수명, 가중치. 변경 목록, 가정 분석, 사유가 있는 CAS 게시(`expected_revision`). 집행 전환은 모드 이름 입력 필요 | `policy/document`, `explain/batch` |
| `#network/asn` | 근거에 나타난 ASN과 이를 지정한 규칙(읽기 전용). 제안 절차는 예정으로 표시 | `candidates`, `rules` |

수문장 상태, GeoIP 데이터베이스(다시 불러오기), 서명된 업데이트(확인), Kubernetes 원천은
시스템으로 옮겼고 원본 진단은 접힌 상태로만 보입니다. 쓰기는 운영자 사유를
`x-hangang-change-reason`(작업 기록)으로 보내며, 정책 쓰기는 수문장 `reason`에도 담고
수동 차단은 사유를 차단 사유(128바이트)로 씁니다. 수문장 규칙 교체에는 리비전 전제
조건이 없어 콘솔이 게시 직전 게시된 규칙을 다시 읽고 바뀌었으면 거부합니다.

페이지가 알려 주는 수문장 API 후속 과제: 주소별 점수·신호 이력, 후보의 신호별 횟수와
국가, 차단 생성자와 생성 시각, `PUT /v1/rules`·`/v1/rules/lua`의 `expected_revision`,
Lua 원문 미보관, 읽을 수 있는 ASN 카탈로그와 ASN 제안 API, 차단·승인·규칙 쓰기의 사유
필드, `explain/batch`와 영향 추정은 추적 주소만 다룸.

## 공용 UI 키트

`web/kit/ui.js`(`@hangang/console-ui` 키트 1)는 `el`, `dataTable`, `entityLink`,
`statusBadge`, `freshnessBadge`, `stageTimeline`, `structuredDiff`,
`confirmDialog`(대상 이름 입력과 필수 사유), `emptyState`, `errorState`,
`loadingState`, `field`, `subjectResolver`를 제공합니다. 컴포넌트는 신뢰할 수 없는
값을 텍스트 노드로 렌더링하고, 호스트 CSP를 지키며, 밝은·어두운 테마의 River 토큰을
사용하고, 720 px 미만에서 카드 목록으로 바뀝니다.

콘솔 패키지는 마운트 문맥에서 `context.ui`로 키트를 추가로 받으며, 키 기반 번역기
`context.t`, `context.navigate(hash)`, `context.link({type, id})`도 함께 받습니다.
이 필드를 쓰지 않는 버전 1 패키지는 영향을 받지 않습니다.

## 메시지와 린트

섹션은 `web/kit/i18n.js`를 통해 키 기반 카탈로그 `web/zt/messages/en.json`과
`ko.json`을 사용합니다. 없는 키는 영어로 대체하고 기록합니다. `npm run lint:i18n`
(`npm test`에서도 실행)은 다음 경우에 실패합니다.

- 영어와 한국어 키 집합이 다르거나, 메시지가 비었거나 번역되지 않은 경우
- 사용 중인 메시지 키나 동적 키 묶음이 없는 경우
- 등록된 판단 사유 코드에 메시지나 해결 방법이 없는 경우
- 문자열 리터럴을 `textContent`, `innerHTML`, `title`, `placeholder`, `aria-*`
  또는 키트의 `text` 속성으로 직접 렌더링하는 경우

```sh
cd web
npm run lint:i18n
npx playwright test tests/zero_trust.spec.js
```

## 제한 사항

주체 표시는 호패 주체 디렉터리 계약(호패 `docs/SUBJECT_DIRECTORY.md`)을
따릅니다. `subjects/resolve`(최대 100개 ID)와 주체 선택기용 `subjects/search`를
사용하며, `active`, `disabled`, `deleted`(흔적만 남고 개인정보 없음),
`unknown`(사유 포함)을 서로 구분해 표시합니다. 호패 콘솔 패키지는
`subjects/resolve`, `subjects/search`, `subjects/lifecycle`,
`subjects/lifecycle/snapshot`, `explain/authentication`을 `"mutation": false`인
`POST` 경로로 선언해야 합니다. 그러면 브로커가 정확한 본문에 대한 서명된 수행자
주장과 함께 `/v1/<path>`로 전달하고, 변경 작업으로 기록하지 않으며, 호패의 위임
검증기가 JSON API 규칙을 적용합니다. 이 경로가 없거나 호패가 요청 한도에 걸리면
사용자 페이지는 불투명 ID를 표시합니다. 호패
`admin.*` 이벤트(`events/query`)와 수문장 정책 변경 감사(`audit/query`,
`sumunjang.audit.v1`)는 각 콘솔 패키지를 통해 통합 감사에 합류합니다. 패키지가 해당
작업을 선언하지 않은 출처는 연결 안 됨으로, 실패한 출처는 활동 없음이 아니라 실패로
표시됩니다. 시뮬레이터, 영향 분석,
봉인 해제, 저장된 보기, CSV 내보내기는 ADR 0020 P1·P2에서 제공됩니다. 기존
페이지는 이전될 때까지 영어 문장 기반 사전을 유지합니다.
