# Workload policy assignments

Source candidate only. Pumgye owns the policy; this adds an editor for its existing
optional `services.<service>.workload_users` map through the same policy CAS API.
It does not authenticate a Workload or activate a protected route.

Choose Workload explicitly. Its public subject must be `s_` followed by exactly
48 lowercase ASCII hexadecimal characters. This namespace is independent from
`users`, even for identical strings. Add/remove operates on the selected kind;
the last Workload removal omits the empty optional map. Ordinary User/network
edits and new services do not introduce an empty Workload map.

Authenticated Workloads are kind3, AAL0. The editor does not lower role/resource
minimum AAL or calculate an access verdict. Positive minimum AAL remains
ineligible for Workloads. Unassigned subjects and the guest role grant no rights.
Native source ownership, source-managed read-only state, both revision fences,
publication uncertainty, newer drafts, session generation/logout and server
validation remain authoritative. Invalid raw policy drafts survive structured
assignment attempts. Row removal is bound to its rendered service, matrix generation and owner/session generation, so detached callbacks cannot edit a newer render or session. Host labels use EN/KO translation; subject data is literal.

## 한국어

기존 품계 정책의 별도 `workload_users` 할당만 편집하며 같은 소유자 CAS API를
사용합니다. 동일 문자열이어도 User와 Workload 할당은 서로 독립적입니다. 주체는
`s_` 뒤 소문자 ASCII 16진수48자의 정규 형식이며 마지막 항목을 삭제하면 빈 선택
맵을 생략합니다. Workload는 종류3·AAL0이며 역할·자원의 최소AAL을 자동으로 낮추지
않습니다. 미할당·guest는 권한이 없고 이 화면은 워크로드 인증·집행 활성화나 실제
접근 허용을 증명하지 않습니다. 기존 원천 소유권·읽기 전용·리비전·초안·로그아웃과
서버 검사를 유지합니다.
