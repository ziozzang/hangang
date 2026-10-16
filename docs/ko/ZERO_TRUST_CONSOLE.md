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
| 네트워크 | `#network/ip/{ip}` | 주소의 GeoIP 국가와 최근 판단 |
| 정책 | `#policies/services/{id}` | 품계 서비스의 최근 판단 |
| 감사 | `#audit` | 콘솔 계정, 콘솔 패키지 작업, 품계 게시를 모은 통합 관리 감사. 실패한 출처는 표시되며, 계정 변경은 구조화된 변경 전후 비교를 보여 줍니다. 콘솔 계정 감사의 보존·정책·내보내기는 `#account-audit`로 옮겼고, 이전 `#audit-trail` 링크는 리다이렉트됩니다 |
| 시스템 | `#system` | 구성 요소, 패키지, 판단 이벤트, 내보내기, 개인정보 프로필. 원본 JSON은 *원본 진단 보기* 안에서만 제공 |

정책, 네트워크, 장치와 워크로드 섹션은 그 밖에는 항목 열기 입력과 현재
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
