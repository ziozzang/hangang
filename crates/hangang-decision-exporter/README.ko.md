# Hangang Decision Exporter

[English](README.md) · [한강](../../README.ko.md) · [안내](../../docs/ko/DECISION_EVENTS.md)

독립 프로세스 `hangang-decision-exporter`(ADR 0019)입니다. 한강으로부터 `0600`
Unix 소켓으로 `hangang.decision.v1` 배치를 받아 모든 이벤트를 검증하고,
`event_id` 유일성을 가진 SQLite(WAL)에 저장하며, 시간 단위 파티션을 통째로 삭제하는
방식으로 보존 기간과 바이트 상한을 집행합니다(기본 7일, 2 GiB, 최대 90일). 별도의
읽기 전용 Unix 소켓은 한강 관리 브로커에 판단 목록, 집계, 시계열, 요청 상세, 상태,
Prometheus 메트릭을 제공합니다.

내보내기 프로세스는 정책 자격 증명도 가명화 키도 갖지 않습니다. 수신은 연결 수,
프레임 크기, 유휴 제한 시간, 쓰기 대기열로 제한되고, 조회는 200행, 31일 창, 3초
제한 시간으로 제한됩니다.

```sh
hangang-decision-exporter --ingest-socket /run/hangang/decision-ingest.sock \
  --query-socket /run/hangang/decision-query.sock --store /var/lib/hangang/decisions.db
```
