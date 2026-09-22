# 다중 인스턴스 운영

[문서 목차](../README.ko.md) · [한국어 안내](README.md) · [English](../SCALE_OUT.md)

이 문서는 한국어 보조 요약입니다. 전체 설정과 동작 조건은 [영문 기준 문서](../SCALE_OUT.md)를 확인하세요.

## 개요

여러 인스턴스가 하나의 공유 스토어(SQLite/PostgreSQL/Redis)를 권한(authority)으로 두고 로드밸런서 뒤에서
동작합니다. 쓰기는 `(epoch, revision)` CAS로 중재되고, 각 인스턴스는 500ms 폴링으로 비동기 수렴합니다.
스토어 장애 시 `--store-grace-seconds`(기본 30초) 동안은 마지막 정상 스냅샷으로 계속 서비스하며 ready를
유지하고, 그 이후 unready가 됩니다. 롤백/분기/epoch 변경은 즉시 unready가 됩니다. 인증서 파일 등 호스트 로컬 자원은
쓰기 전에 모든 인스턴스에 먼저 배포해야 합니다. 종료 시 `--lame-duck-seconds` 동안 503을 알리고 나서
accept를 멈춥니다. 캐시 purge는 공유 스토어 모드에서 `cache.generation` CAS로 전체 인스턴스에 전파됩니다.
