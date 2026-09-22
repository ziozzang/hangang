# Terminology

[Documentation](README.md) · [한국어 안내](README.ko.md)

Use these terms consistently across guides and translations. API identifiers
remain exactly as defined in the [OpenAPI specification](openapi.json).

| English term | Korean term | Meaning |
| --- | --- | --- |
| Gateway | 게이트웨이 | A Hangang runtime that accepts and forwards traffic. |
| Instance | 인스턴스 | One running gateway; local state belongs to that instance. |
| Public listener | 공개 리스너 | An application traffic listener, distinct from the management listener. “Public” does not imply Internet exposure. |
| Management listener | 관리 리스너 | The endpoint serving management APIs, the console, health, and metrics. |
| Management console | 관리 화면 | The embedded browser interface at `/ui/`. |
| Management API | 관리 API | The administrator-facing HTTP API; code and flags may use `admin`. |
| Route | 라우트 | A configured match and forwarding policy for HTTP or TCP traffic. |
| Backend | 백엔드 | A configured destination service or address. |
| Upstream connection | 업스트림 연결 | The gateway's outbound connection to a backend, including DNS, proxy, and TLS policy. |
| Member | 멤버 | A named backend entry with identity, health, and lifecycle state. |
| Configuration publication | 설정 적용 | Preparing and making a validated configuration available to new traffic. Persistence and local activation have distinct outcomes. |
| Revision | 리비전 | The configuration version used for conditional updates. |
| Generation | 세대 | A runtime identity for resources or policy; it is not interchangeable with a configuration revision. |
| Shared configuration store | 공유 설정 저장소 | Storage used to coordinate configuration; it does not synchronize administrator accounts or every runtime resource. |
| Admission | 수락 판단 | Deciding whether a request or connection may proceed under the applicable policy and capacity limits. |
| Readiness | 준비 상태 | Whether an instance or binding reports that it can serve its intended traffic. |
| Draining | 연결 종료 대기 | Stopping new assignments while allowing applicable existing work to finish. |
| Fail closed | 거부 처리 | Refusing traffic when a required security or admission check cannot succeed. |
| Account audit | 계정 감사 기록 | Durable records for the documented account operations. |
| Traffic history | 최근 트래픽 기록 | Bounded, instance-local metadata; not a durable audit log or payload capture. |
| Fleet observation | 원격 인스턴스 관측 | Reading remote status and identity; it does not imply rollout control or consensus. |
| Setup token | 초기 설정 토큰 | The configured administrator token used to create the first account; it remains a break-glass credential. |
| Session token | 세션 토큰 | A revocable, time-limited credential issued after account login. |

Use “supports” only with the applicable setup and scope. For example, “supports
ACME DNS-01 with Cloudflare or an authenticated webhook” is more precise than
“supports every DNS provider.” Use “real-time view” for the periodically updated
console, not as a guarantee of zero latency or complete event retention.
