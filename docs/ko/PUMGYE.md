# 독립 품계 서버

품계가 정책 저장·컴파일·CAS 게시·리비전·감사를 소유합니다. Hangang은 라우트의
서비스/메서드/등급 연결과 요청 집행을 맡고 고정된 도메인 위임으로 관리 화면을 제공합니다.
[English](../PUMGYE.md).

설정 최상위의 `pumgye_authority`를 사용하며 기존 내장 `pumgye` 정책과 동시에 둘 수
없습니다. 원격은 mTLS가 필수이고 로컬 평문은 loopback만 허용합니다. 예제는 합성 값이며
자격 증명 자체는 설정에 넣지 않습니다.

```json
{
  "decision_address": "192.0.2.10:9085",
  "management_address": "192.0.2.10:9084",
  "decision_token_env": "PUMGYE_DECISION_TOKEN",
  "admin_token_env": "PUMGYE_ADMIN_TOKEN",
  "tls": {
    "server_name": "pumgye.example.test",
    "ca": "/private/pumgye/ca.pem",
    "certificate": "/private/pumgye/gateway.pem",
    "key": "/private/pumgye/gateway.key"
  },
  "pool_size": 64,
  "timeout_ms": 100,
  "minimum_revision": 1
}
```

고정 endpoint의 서버 이름/CA를 검증하고 클라이언트 인증서를 제시한 뒤 판단 자격 증명을
검증합니다. 제한된 지속 PPG1 연결을 재사용하며 권한 1개 판단은 배치 할당을 생략하고
복수 권한은 최대 64개 요청의 상관을 검증합니다. 서비스 없음·guest·필수 네트워크 근거의
판단 불가/fail-open/observe·권한/등급/AAL 불일치는 허용하지 않습니다. 검증된 네이티브
호패 헤더와 신선한 Guard 근거를 사용하며 호출자 주장을 신뢰하지 않습니다. 보호된 경로는
응답/인증 캐시를 우회합니다.

500ms마다 네이티브 정책 probe를 수행하고 관측 리비전의 단조 증가와 authority 신선도
1초를 유지합니다. 품계 직접 게시도 리비전 변경·판단 불가/만료·Hangang 설정 퇴역에 따라
보호된 스트림을 종료합니다. 분산 멤버십·관측 watermark 영속화·authority incarnation
고정·전체 fleet의 호패 세션/Guard 스트림 회수는 아직 별도 구현 항목입니다.

품계 관리 화면은 Hangang 설정을 덮어쓰지 않고 소유 서버의 정책을 읽고 게시합니다.
다음 Hangang API는 실시간 관리자 권한이 필요하며 Viewer/익명은 거부합니다.

- `GET /v1/pumgye/policy`, `/v1/pumgye/status`, `/v1/pumgye/audit`.
- `PUT /v1/pumgye/policy`: `{revision, policy}` JSON, `If-Match`에 따옴표로 감싼
  품계 리비전, `X-Hangang-Config-Revision`에 조회가 반환한 Hangang 연결 설정 리비전.

두 범위 조건을 모두 확인합니다. 계정 회수와 직렬화해 요청을 승인하며 승인된 외부 게시 작업은
브라우저가 끊어져도 완료될 수 있습니다. 결과가 불확실하면 롤백을 추정하지 말고 다시 읽습니다.
응답 공개 전 실시간 역할·선택 authority를 재검증합니다. 경로·메서드·응답/본문 크기·동시성·
리다이렉트를 제한하며 클라이언트 URL·자격 증명·임의 헤더를 전달하지 않습니다. 판단 전용
노드에는 관리자 비밀값을 공급하지 않아도 되며 집행은 동작하고 관리는 차단됩니다. 품계는
검증된 전송 호출자를 감사에 기록하며 개인별 위임 감사는 후속 항목입니다.

기존 내장 정책은 이전 기준 구현입니다. 자동 역할/권한 부여나 DB/스키마 전환을 수행하지
않습니다. 라우트 활성화 전 소유 품계 서버에 이전 정책을 검증·게시해야 합니다.

라이브러리·기존 관리자/설정/리소스 테스트·OpenAPI 참조·브라우저 소유권/CAS/로그아웃과
실제 Hangang/품계 mTLS 프로세스를 소유한 HOP1/HGD1 peer로 검증합니다. 실제 호패/
수문장 원격 전송·혼합 인증·큰 정책 규모·전체 스택 100k HTTP QPS는 별도 통과 조건입니다.
