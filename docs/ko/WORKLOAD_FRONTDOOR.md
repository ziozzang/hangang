# 실제 HTTP 앞단의 typed observed 신원

observed Workload route는 고정 네이티브 설정 class로 Pumgye `WorkloadResourceAuthorization.Decide` 사전 리소스 metadata 질의를 선택한다. 같은 compiler/View의 workload_users만 평가하며 users 중복 grant나 early policy 우회로 해결하지 않는다. Workload는 untyped 로컬 정책으로 fallback하지 않는다. 기존 Service 질의와 nonobserved Human/기본 동작은 유지한다.

generic 인증 native Verify가 먼저 실행된다. 응답을 원점에 전달하기 전에 raw native 결과의 유일한 kind가 설정 class와 일치하고 AAL0인지 확인한다. 인증된 subject/AAL metadata만 사전 질의에 별도로 보존하므로 response_headers allowlist에 kind를 넣지 않아도 된다. client header나 응답 kind가 endpoint를 선택하지 않는다. 이 tuple은 receipt·opaque 인증 권한·signed permit·철회 lease가 아니다.

기존 앞단은 Workload도 users 질의로 평가하여 workload_users-only 허용 주체를 최종 typed 체인 전에403으로 거부했다. 수정은 enforced permission을 Lua보다 먼저 유지하며 최종 공개 SDK 인증·전용 signed permit·contract3/공유 replay 소비·TLS 아래 raw 출력 검사를 계속 요구한다.

실제 HTTP Proxy fixture는 별도 인증 peer/공개 SDK/네이티브 core compiler/실제 frontend·backend·raw transport를 사용한다. Workload/Service의 전용/기존 질의 선택, forward kind 생략 성공, 사전 거부·kind/AAL 불일치에서 Lua/SDK/permit/output/backend 미호출을 확인한다. RED a418+새 Pum pin+fixture는 legacy 질의1/typed0과 HTTP403을 재현했고 GREEN은 typed 질의 후 backend1회를 확인했다. 이는 Root 경계 fixture이며 실제 Kubernetes TokenReview 전체 네 서비스/배포 검증이 아니다.

공개 SDK Issue 직후 최종 opaque 인증은 보존된 사전 subject·고정 class·AAL0·설정 service/audience와 일치해야 한다. 두 subject 모두 허용한 회귀에서도 불일치는 permit/output/backend 전에 거부한다. 사전 주체로 이미 실행한 Lua 효과를 되돌린다는 뜻은 아니다.

고정 native subject/AAL/kind/service/evidence TTL/projected subject 헤더는 forwarding allowlist와 독립적으로 예약한다. 기존 snapshot 전체 union 모델을 유지하므로 observed route 하나가 있으면 같은 snapshot의 다른 route에서도 client 위조 헤더를 제거한다. observed route가 없는 snapshot의 기존 예약 범위는 유지한다. 전달 허용 신원 값은 인증 Verify 결과이며 생략한 kind는 backend에도 없다.
