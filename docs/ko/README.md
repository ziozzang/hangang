# 문서

[문서 목차](../README.ko.md) · [English](../README.md)

영어를 기준 언어로 사용합니다. 제공되는 한국어 문서는 영문 원문의 완역이며, 두 언어에서 동작·예제·제약 조건을 동일하게 유지해야 합니다. 한국어 번역이 없는 가이드는 영문 기준 문서로 연결합니다. [프로젝트 README](../../README.ko.md)에 로컬 빠른 시작이 있습니다. [예제 설정 가이드](../../examples/README.ko.md)는 최초 JSON을 필드별로 설명하며, [OpenAPI](../openapi.json)는 관리 API와 설정 객체를 정의합니다.

## 먼저 읽기

- [최초 설정과 예제](../../examples/README.ko.md) — JSON 필드, 최초 설정, 다시 로드와 문제 해결
- [배포 템플릿 · 영문](../../deploy/README.md) — 초기 배포 JSON, 포트와 영속 상태
- [문서 작성 규칙 · 영문](../DOCUMENTATION.md) — 문서 구성 방식
- [용어집 · 영문](../GLOSSARY.md) — 공통 용어
- [아키텍처 · 영문](../ARCHITECTURE.md) — 시스템 구조와 요청 흐름
- [개발 · 영문](../DEVELOPMENT.md) — 개발과 테스트 절차
- [단일 노드 배포 · 영문](../DEPLOYMENT.md) — Docker Compose 배포
- [OpenAPI 명세](../openapi.json) — 관리 API와 설정 스키마

## 라우팅과 리스너

- [호스트 매칭과 라우트 우선순위 · 영문](../MATCHING.md) — 라우트 선택 규칙
- [이름 있는 공개 HTTP·HTTPS 리스너 · 영문](../PUBLIC_LISTENERS.md) — 공개 리스너 설정
- [UDP·QUIC 릴레이](../ko/UDP.md) — 로컬 파일 기반 UDP 데이터그램 라우팅과 불투명 QUIC 패스스루
- [독립 IPv4 IPVS DSR](../ko/DSR.md) — 명시한 범위의 직접 라우팅 보조 도구
- [대표 도메인 리디렉션 · 영문](../CANONICAL_DOMAINS.md) — 대표 호스트 동작
- [TLS 종료와 SNI 패스스루 · 영문](../SNI.md) — TLS 리스너 모드
- [요청·응답 변조](../ko/TRANSFORMS.md) — 본문 변조 정책
- [HTTP 응답 캐싱](../ko/CACHE.md) — 응답 캐시 동작
- [ACME 인증서](../ko/ACME.md) — 네이티브 인증서 발급

## 백엔드, 멤버와 상태 점검

- [아웃바운드 연결 정책 · 영문](../UPSTREAM.md) — 백엔드 연결과 TLS 설정
- [이름 있는 HTTP·TCP 멤버 · 영문](../NAMED_MEMBERS.md) — 재사용 가능한 백엔드 멤버
- [멤버 연결 수용 · 영문](../MEMBER_ADMISSION.md) — HTTP 멤버 연결 수용과 활동
- [멤버 수명 관리 · 영문](../MEMBER_LIFECYCLE.md) — 멤버 상태 전환
- [퇴역 멤버 관찰 · 영문](../RETIRED_MEMBERS.md) — 퇴역 멤버 상태
- [초기 능동 상태 점검 기반 연결 수용 · 영문](../HEALTH_ADMISSION.md) — 시작 시 상태 점검 관문
- [HTTP Docker 엔드포인트 상태 · 영문](../HTTP_DOCKER_HEALTH.md) — Docker 상태 점검
- [TCP 전송 상태 · 영문](../TCP_HEALTH.md) — TCP 상태 점검
- [TCP 멤버 연결 수용 · 영문](../TCP_ADMISSION.md) — TCP 멤버 연결 수용과 활동
- [이름 있는 TCP 멤버 스트림 활동 · 영문](../TCP_MEMBER_ACTIVITY.md) — TCP 멤버 활동
- [Lua 용량 보고](../ko/LUA_CAPACITY.md) — Lua 워커 용량

## 접근 제어와 인증

- [명시적 HTTP 접근 모드](../ko/ACCESS_POLICY.md) — 접근 정책 모드
- [보호된 HTTP 리소스](../ko/RESOURCE_POLICY.md) — 리소스 보호
- [네이티브 접근 토큰 인증](../ko/JWT_AUTH.md) — JWT 인증
- [상호 TLS를 사용하는 HTTP 워크로드 신원](../ko/HTTP_WORKLOAD_MTLS.md) — HTTP 워크로드 인증서
- [상호 TLS를 사용하는 TCP 워크로드 신원](../ko/TCP_MTLS.md) — TCP 워크로드 인증서
- [국가별 접근 허용 · 영문](../GEOIP.md) — 국가 기반 접근 허용
- [네이티브 HTTP 언어 선호 · 영문](../LANGUAGE_POLICY.md) — 언어 선택 정책
- [관리자 계정 · 영문](../ADMIN_USERS.md) — 계정 설정과 관리

## 설정과 변경 관리

- [설정 게시 · 영문](../CONFIG_PUBLICATION.md) — 설정 리비전 게시
- [로컬 설정 작업 수락 · 영문](../CONFIG_OPERATIONS.md) — 작업 이력과 수락
- [활성화와 비활성화](../ko/ACTIVATION.md) — 라우트와 인증서 활성화
- [보관된 SQL 설정 커밋 영수증 · 영문](../SQL_COMMIT_RECEIPTS.md) — SQL 커밋 영수증
- [순서가 지정된 SQL 커밋 영수증 · 영문](../SEQUENCED_SQL_RECEIPTS.md) — 순서가 있는 영수증 기록
- [V2 영수증 보호와 완료 확인 · 영문](../SQL_RECEIPT_RELEASE.md) — 영수증 해제
- [서명된 업데이트와 프로세스 교체](../ko/UPDATES.md) — 업데이트와 재시작 흐름
- [관리 API와 콘솔 지원 범위 · 영문](../API_UI_COVERAGE.md) — 네이티브 API와 콘솔 지원 범위

## 감사와 트래픽 관찰

- [영속 로컬 계정 감사 · 영문](../ACCOUNT_AUDIT.md) — 계정 감사 기록
- [선택적 계정 감사 기록 · 영문](../ACCOUNT_AUDIT_FILTERS.md) — 감사 필터
- [최근 트래픽 메타데이터 · 영문](../TRAFFIC_HISTORY.md) — HTTP 트래픽 이력
- [선택적 HTTP 응답 헤드 기록 · 영문](../HTTP_RECORDING.md) — HTTP 기록
- [HTTP 요청 리스너 식별 · 영문](../HTTP_TRAFFIC_LISTENERS.md) — 리스너 식별
- [실시간 TCP 연결 이력 · 영문](../TCP_CONNECTION_HISTORY.md) — TCP 연결 이력
- [선택적 원시 TCP 완료 기록 · 영문](../TCP_RECENT_RECORDING.md) — TCP 완료 기록
- [인증서 목록과 발급자 관찰 · 영문](../CERTIFICATE_INVENTORY.md) — 인증서 목록

## 배포와 연동

- [Docker 검색](../ko/DOCKER.md) — Docker 서비스 검색
- [Kubernetes Ingress 컨트롤러](../ko/KUBERNETES.md) — Kubernetes 연동
- [수평 확장 운영](../ko/SCALE_OUT.md) — 공유 설정과 다중 노드 운영
- [Redis 설정 저장소](../ko/REDIS.md) — Redis 기반 설정
- [노드 관찰 신원 · 영문](../FLEET_OBSERVER.md) — 플릿 관찰자 신원
- [인증된 원격 노드 관찰 · 영문](../FLEET_OBSERVATIONS.md) — 읽기 전용 플릿 관찰

## 관련 가이드

- [내장 Lua 편집기 · 영문](../../web/LUA_EDITOR.md) — 브라우저 편집기 동작과 빌드
- [업스트림 전송 예제 · 영문](../../examples/upstream/README.md) — 실행 가능한 백엔드 전송 예제
- [플릿 관찰 예제 · 영문](../../examples/fleet-observations/README.md) — 플릿 관찰 예제
- [GeoIP 픽스처 · 영문](../../tests/fixtures/geoip/README.md) — GeoIP 테스트 픽스처

콘솔은 관리 리스너의 `/ui/`에서 제공됩니다. 같은 빌드는 `/openapi.json`에서 API 명세를 제공합니다. `hangang --help`로 명령줄 옵션을 확인할 수 있습니다.
