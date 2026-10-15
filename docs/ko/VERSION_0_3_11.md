# Hangang 0.3.11 후보 — 운영 미적용

이 후보는 공개 d422c1c의 Pumgye 문맥 인식 관리 기능을 포함한다. Kubernetes API 권한 요약/typed subject 편집과 전체 native policy 및 선택적 mapping metadata 보존을 제공하고 network-and-guard 문맥과 구분한다. 이번 버전 변경 자체는 runtime/frontend/proto/의존성 의미를 수정하지 않는다. 검증된0.3.10과 동일하게 production 기본 feature의 x86_64 musl 바이너리8개를 빌드하며 test hook/임의 compiler override는 사용하지 않는다.

기존0.3.10의 선택된 domain/실제TLS HSTS 응답 정책과 예약 identity-header 처리는 그대로다. 기존 통과 검사·운영 적용은 그 당시 정확한 아티팩트의 근거이며 새로운0.3.11은 서명/공개/적용 전 자체 gate와 승인이 필요하다. 기존 공개0.3.10 파일/설정을 바꾸지 않는다.

Root의 Pumgye core pin은 typed API 문맥을 지원하지만 UI 분류가 Kubernetes caller를 인증하거나 grant/receipt를 만들지는 않는다. Pumgye0.1.9의 별도 기본-off SAR listener는 전용 실제 API-server, 고정 검증caller, authorizer순서/cache비활성/failurePolicyDeny/원천·grant철회를 검증해야 한다. 기존 main K3s authorizer 변경이나 전체 Kubernetes 관리 완료를 뜻하지 않는다. Human observed 증명/H2 stream별 owner/극단적 처리량은 별도 미완 항목이며 kernel 수락 bytes나 이미 허용된 작업·stream 회수는 보장하지 않는다.
