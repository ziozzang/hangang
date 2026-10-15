# Hangang 0.3.11 — 검증된 release 준비

동결 runtime build source는 `0b15bfb7f7d199b6b653cd5de567ccc667df7055`다. 이번 검증 갱신은 문서만 변경하며 release target commit과 바이너리 build source를 구분한다. 서명·로컬 패키징은 공개나 운영 적용을 뜻하지 않는다. 준비 단계에서 기존 공개·운영 0.3.10 자산과 설정은 변경하지 않는다.

Pumgye 관리 UI는 Kubernetes API typed subject 편집·요약과 전체 native policy·선택 mapping metadata 보존을 제공하고 network-and-guard 문맥과 구분한다. UI 분류는 Kubernetes caller 인증이나 grant/receipt 발급이 아니다. 8개 x86_64 musl 바이너리는 production 기본 feature로 빌드했으며 test hook·임의 compiler override는 없다.

## 정확한 후보 검증

- Locked workspace all-feature 1321건 통과·기존 ignore 58건, strict all-target/all-feature Clippy·format 통과. 동결 8개 버전 0.3.11 및 INTERP/NEEDED 없는 정적 ELF를 확인했다.
- 실제 gateway·검증 TLS에서 HTTP/1 HSTS 16건, HTTP/2 HSTS 4건과 설치된 Sacho 가시성 조합 24건을 통과했다. 예약된 로컬 fixture로 중복·대소문자 혼합 위조 identity, 진짜 fixture admin cookie가 있어도 익명인 public route, 보호 route의 의도된 가시성을 확인했다. 모든 임의 identity header의 안전을 뜻하지 않는다.
- 이 Root, Pum runtime `435f1389`, Hop `848dc835`, Sum `d6fc1dec`의 소유 Kubernetes Service Any-composition/browser 검증을 통과했다. 실제 compiled host navigation·Pum responsive·설치 plugin locale, native source 철회·재시작·backend 비호출 검사를 포함한다. 전체 관리자 UX 항목 완료 주장은 아니다.
- 같은 core와 qualification tap `640a3dd4`, helper `73533380`으로 실제 Workload run4를 통과했다. 실제 TokenReview·공개 observed SDK·typed Pum 권한·Hop contract3, 첫 응답 반환 전 원래 pair 즉시 replay, owner 철회·Hop Pod 교체·bound Pod UID 교체 및 명시적 새 grant·ServiceAccount 철회를 검증했다. 거부 요청은 application backend를 호출하지 않았다. 원래 요청 예산·strict assertion을 유지했으며 정리 후 기존 12개 Pod UID/phase와 Ready 노드 2개를 독립 확인했다.
- 별도 Pumgye 0.1.9 runtime `435f1389`는 전용 실제 Kubernetes API-server SAR 검사 18건을 통과했다. 검증 mTLS·authorization cache 비활성·source 교체 없는 PATCH grant 철회·AAL/class 구분·장애 거부·복원을 포함한다. 기본-off SAR listener는 별도 Pum 기능이며 이 gateway release가 활성화하지 않고 기존 cluster authorizer도 교체하지 않았다.

앞선 Workload run1의 최초 HTTP 응답 timeout과 run2의 재시작 후 미인가 요청 기대403/실제503은 원인 미확정으로 남긴다. run3는 새 안전 Verify 진단 event와 검증 parser의 호환 누락으로 실패했다. 엄격한 혼합 event parser를 수정한 뒤 run4를 실행했으며 runtime 바이너리·replay 수는 변경하지 않았다. run4는 독립 통과이며 이전 전송 실패 해결 주장이 아니다. 기존 bounded restoration에서 503/backend0 두 번 뒤 성공을 관측했으며 proof 수명을 늘리지 않았다.

Pod 삭제 37.102초·ServiceAccount 삭제 10.881초 관측은 API 전파 시간이며 원래 비갱신 1초 proof 예산과 구분한다. 재시작 후 held proof 거부에는 원래 만료도 작용할 수 있다. 평탄화된 replay 거부는 특정 SQL row의 증거가 아니다. Human observed proof·Workload 관리자/browser 완료·H2 stream별 owner·극단 처리량 검증을 주장하지 않는다. raw 전송 경계 검사는 kernel 수락 bytes나 이미 허용한 작업·stream을 회수할 수 없으며 observed transport pooling 최적화는 별도다.
