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
| 신원 | `#identities/…` | 호패 패키지를 통한 사용자, 사용자 상세, 세션, 그룹, 공급자, 인증 정책, 자격 증명 투영(아래 참고) |
| 네트워크 | `#network/…` | 수문장 패키지를 통한 개요, 위협 대기열, IP 상세, 차단·허용 목록, 규칙, 정책, ASN 풀(아래 참고) |
| 정책 | `#policies` | 품계 서비스 목록(권한 문맥, 수문장 요구, 역할·할당·네트워크·리소스 수, 최고 등급), 접근 매트릭스, 고급 JSON |
| 정책 | `#policies/services/{id}` | 서비스 상세 탭: 개요, 리소스와 동작, 역할, 할당, 접근 시뮬레이터, 변경 이력 |
| 정책 | `#policies/publish` | 검토 후 게시: 구조화된 차이, 변경 영향, 필수 사유, 이름 입력 확인, 충돌 해결 |
| 정책 | `#policies/simulate?subject={id}` | 다른 섹션(신원)에서 오는 시뮬레이터 진입점: `service`가 주어지거나 서비스가 하나뿐이면 그 서비스의 시뮬레이터 탭으로 이동하고, 아니면 서비스를 고르게 합니다(할당된 서비스 먼저). 주체는 유지됩니다 |
| 감사 | `#audit` | 콘솔 계정, 콘솔 패키지 작업, 품계 게시를 모은 통합 관리 감사. 실패한 출처는 표시되며, 계정 변경은 구조화된 변경 전후 비교를 보여 줍니다. 콘솔 계정 감사의 보존·정책·내보내기는 `#account-audit`로 옮겼고, 이전 `#audit-trail` 링크는 리다이렉트됩니다 |
| 시스템 | `#system` | 구성 요소, 패키지, 판단 이벤트, 내보내기, 개인정보 프로필. 원본 JSON은 *원본 진단 보기* 안에서만 제공 |

네트워크, 장치와 워크로드 섹션은 그 밖에는 항목 열기 입력과 현재
구성 요소 페이지 링크를 보여 줍니다. 판단 이벤트가 꺼져 있으면 모든 판단 화면은 빈
목록 대신 *판단 이벤트 비활성*을 표시합니다. 이후 단계가 필요한 작업(시뮬레이터,
봉인 해제)은 이유와 함께 비활성 상태로 표시됩니다.

## 신원

모든 신원 페이지는 호스트 중계(`/v1/plugins/hopae/<route>`)로 호패 콘솔 패키지를
호출합니다. 패키지 검색 결과가 패키지가 선언한 경로를 알려 주므로, 설치된 패키지가
선언하지 않은 작업은 실패하는 대신 이유와 함께 비활성으로 표시됩니다.

| 경로 | 페이지 | 호패 경로 |
| --- | --- | --- |
| `#identities/users?q=&status=&group=` | 사용자: 서버 검색, 그룹 필터, 일괄 비활성화(개수 입력 확인 + 사유) | `users/query`, `subjects/search`, `subjects/resolve`(`include_groups`), `groups/get`, `users/disable` |
| `#identities/users/{id}/{tab}` | 사용자 상세: 프로필과 연결된 신원, 인증(인증 요소 상태, 접근 테스트), 세션(개별·전체 종료), 그룹, 접근 권한(품계 할당, 시뮬레이터 링크), 활동(호패 이벤트와 한강 판단) | `subjects/resolve`, `sessions/query`, `events/query`, `subjects/groups`, `explain/authentication`, `users/enable`, `users/disable`, `users/sessions-terminate`, `sessions/terminate`, `groups/members/*` |
| `#identities/sessions?user=` | 기기, 바인딩 주소, 보증 수준, 활동이 있는 활성 세션 | `sessions/query`, `sessions/terminate` |
| `#identities/groups`, `#identities/groups/{ref}` | 그룹. 로컬 그룹은 `expected_revision`과 사유로 편집하고, LDAP/OIDC 그룹은 출처와 함께 읽기 전용 | `groups/search`, `groups/get`, `groups/create`, `groups/update`, `groups/delete`, `groups/members/add`, `groups/members/remove` |
| `#identities/providers` | 공급자 카드: 상태, 종류, 관리 주체, 재인증, 클라이언트 비밀, 리디렉션 URI, 최근 오류 | `status` |
| `#identities/authentication[/test]` | 서비스 인증 프로필 양식, 항목별 변경 목록, 사유가 있는 CAS 게시, 이동해도 유지되는 초안, "사용자로 접근 테스트" | `authentication/profiles`, `authentication/profiles/publish`, `explain/authentication` |
| `#identities/projections` | 서비스별 투영 계획과 커넥터 회로 상태, 계획 편집기 | `authentication/projections`, `authentication/projections/publish`, `status` |

모든 쓰기는 사유를 요구합니다. 호패 그룹 쓰기는 본문에 사유를 담고, 그 밖의 쓰기는
호스트 전용 `x-hangang-change-reason` 헤더(퍼센트 인코딩 UTF-8, 1–512자)로 보냅니다.
중계는 이를 비공개 작업 기록(통합 감사에 표시)에 남기고 백엔드로 전달하지 않습니다.

페이지가 그 자리에서 알려 주는 호패 API 후속 과제: 인증 요소 목록·초기화 HTTP API가
없음(CLI `hopae admin factors list|reset`만 제공), 위임된 `users/query`·
`sessions/query`·`events/query`는 `cursor`와 `limit`만 받음(상태·공급자·MFA·사용자
필터가 없어 사용자의 세션과 이벤트는 최신 기록의 제한된 검사로 찾고, 일부만 검사했으면
표시), 연결된 신원이 있는 사용자 상세는 위임되지 않음, 사용자·세션 쓰기는 사유를 받지
않음, `status`가 리디렉션 URI용 포털 주소를 보고하지 않음, 권한 방식(호패 자체 또는
한강 위임)이 보고되지 않음, 일괄 비활성화 API 없음.

## 정책

정책 섹션은 이전의 내장 품계 화면을 대체합니다. `#pumgye` 링크는 `#policies`로
(`#pumgye/policy`는 `#policies/advanced`로) 리다이렉트됩니다. 독립 품계 권한 기관의
정책 버전 1 문서를(권한 기관이 없으면 한강 설정의 `pumgye` 항목을) 편집합니다.

- **초안.** 모든 편집(서비스, 권한, 권한·명시적 정보 등급 목록·최소 AAL·상속을 가진
  역할, 할당, 네트워크 규칙, 리소스와 동작)은 기준 리비전에 묶인 초안을 바꿉니다.
  품계 v1은 나열된 등급만 정확히 부여하며 등급은 계층이 아니므로, 역할 편집기는
  등급마다 체크박스를 두고 상한 선택은 두지 않습니다. 초안은 같은
  탭에서 화면 이동, 언어 변경, 새로 고침 뒤에도 유지됩니다.
- **역할.** 편집기는 상속을 반영한 유효 권한과 그 역할을 가진 주체 수를 보여 주고,
  상속 순환과 사용 중인 역할 삭제를 거부합니다.
- **할당.** 주체는 호패 `subjects/search`로 고르고 확인된 이름과 함께 표시합니다.
  사용자, Human, 워크로드, Kubernetes API 주체는 서비스 문맥에 맞게 검증하며, 선택한
  할당은 이름 입력 확인 후 일괄 회수할 수 있습니다.
- **접근 시뮬레이터.** 게시본 또는 후보로서의 초안에 대해 품계 `POST /v1/explain`을
  실행하고 판단, 현지화된 사유, 해결 방법, 순서대로 된 평가 과정을 보여 줍니다. 품계
  검증 오류는 문제가 된 입력 항목에 표시합니다.
- **검토 후 게시.** 서비스별로 묶은 변경 문장(예: "Kim Analyst u_kim: analyst 역할
  회수")과 보조로 JSON 경로, 필요하면 원본 JSON 차이를 보여 줍니다. 주체는 차이·영향
  표·예시 모두에서 호패 표시 이름으로 나옵니다. 이어서 컴파일된 권한 차이
  (`/v1/explain/diff`), 바뀐 사용자 할당에서 만든 사례에 대한 허용→거부·거부→허용
  영향(`/v1/explain/batch`)을 보여 줍니다. 게시는 품계와 한강 권한 리비전을 함께 쓰는
  비교 후 교체이며 사유가 필수입니다(사유는 수행자와 결과 리비전과 함께 한강 감사
  로그에 남습니다). 허용 사례를 거부로 바꾸거나 최고 등급을 허용하는 서비스를 바꾸면
  서비스 이름을 입력해 확인해야 합니다. 409가 나면 3자 비교 화면(그 사이 게시된 변경,
  내 초안, 충돌 경로)을 열고 초안을 다시 맞춥니다.
- **고급 JSON**은 *JSON 편집*을 누르기 전까지 읽기 전용이며, 적용한 JSON은 초안이
  되어 같은 검토를 거칩니다.
- Kubernetes가 소유하거나 소유자가 보고되지 않은 정책 원천은 읽기 전용으로
  표시합니다.

관리 API는 콘솔을 위해 품계 시뮬레이션을 중계합니다: `POST /v1/pumgye/explain`,
`/v1/pumgye/explain/batch`, `/v1/pumgye/explain/diff`,
`GET /v1/pumgye/audit/simulations`. 관리자 전용이고, 품계 자체 한도보다 먼저 콘솔
계정별 한도(순간 20, 초당 2)를 적용하며, 세션에서 `on_behalf_of`를
`console:<account>`로 정하고, 품계의 구조화된 오류를 그대로 전달합니다.

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
| `#network/zones[/{id}]` | 네트워크 존(수문장 0.1.7): 64개 존·65,536개 접두사 한도 대비 사용량이 있는 목록, 접두사와 추적 주소가 있는 상세, 존 리비전 비교 후 교체와 사유로 생성·교체·삭제, 양식에 표시되는 수문장 `/zone/id`·`/zone/prefixes/N` 오류, 추적 주소의 소속 변화 미리 보기. IP 추적과 위협 대기열에 존 표시 | `zones`(GET/POST), `explain/batch` |
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
