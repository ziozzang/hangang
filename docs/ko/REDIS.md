# Redis 설정 저장소

[문서 목차](../README.ko.md) · [한국어](README.md) · [English](../REDIS.md)

Hangang은 `RedisConfigStore`를 통해 Redis를 전체 설정 공유 저장소로 사용할 수 있습니다. 저장소는 호출자가 지정한 키 아래에 버전이 있는 문자열 하나를 보관하며 형식은 `hangang-config-v2\n<epoch>\n<revision>\n<json>`입니다. 부트스트랩은 비어 있을 때만 원자적으로 삽입하고 authority epoch(32자리 16진수)도 생성합니다. CAS는 epoch와 정규 10진 revision 문자열을 비교한 뒤 둘 다 일치할 때만 전체 값을 교체하는 단일 Redis Lua 스크립트입니다. `revision + 1`에 이미 동일한 문서가 있으면 적용된 것으로 보고하므로 응답 유실 뒤 재시도해도 가짜 충돌이 발생하지 않습니다. JavaScript의 안전한 정수 범위를 넘는 값까지 모든 `u64` revision을 보존합니다. 이전 릴리스가 쓴 값(`hangang-config-v1`, epoch 없음)은 첫 읽기에서 원자적으로 제자리 업그레이드하며 여러 인스턴스가 경쟁하면 하나만 승자가 됩니다.

ACME HTTP-01 challenge token은 TTL과 함께 `<key>:acme:<token>` 아래에 공유되므로 로드 밸런서 뒤 어느 인스턴스도 검증 요청에 응답할 수 있습니다. 설정 키에는 예약된 `:acme:` 구분자가 들어가면 안 됩니다. 그런 키를 사용하는 배포는 업그레이드 전에 새 키를 선택해야 합니다. 이 키 공간에서는 Redis를 `maxmemory-policy noeviction`으로 실행하세요. 설정 키가 축출되면 `missing`으로 보고되고 `--store-grace-seconds` 후 모든 인스턴스가 준비 상태를 철회합니다.

원격 Redis에는 검증된 `rediss://` URL과 `RedisConfigStore::connect`를 사용합니다. 기본적으로 redis crate의 Web PKI 루트를 사용합니다. 사설 CA는 `RedisConfigStore::connect_with_ca(url, key, ca_pem)`를 사용하며, PEM 체인은 redis crate의 `TlsCertificates` API로 설치하고 호스트 이름 검증은 유지합니다. redis crate의 `#insecure` 옵션이 포함된 URL은 거부합니다.

평문은 개발·테스트에서만 명시적으로 사용하는 모드입니다. `RedisConfigStore::connect_unencrypted`는 호스트가 문자 그대로 `localhost`이거나 loopback IP일 때만 `redis://`를 허용합니다. 원격 DNS 이름은 그것이 loopback으로 해석되더라도 허용하지 않습니다.

인코딩된 설정 JSON은 1MiB로 제한합니다. Redis 값에는 작은 버전 있는 wire header가 포함되며 이 한도를 넘으면 디코딩 전에 거부합니다. 잘못된 스키마, 비정규 revision, revision 불일치, 잘못된 JSON과 잘못된 설정값은 오류입니다. 이전의 정상 값은 조용히 받아들이지 않습니다.

일회성 통합 fixture는 TLS listener를 포함한 고유한 이름의 loopback 전용 Redis 컨테이너 하나를 만들고 실행이 끝나면 제거합니다. 기존 컨테이너를 검색하거나 변경하지 않습니다.

```sh
python3 tests/redis_fixture.py
```

일반 테스트 스위트는 Redis 통합 테스트를 건너뜁니다. fixture는 `--include-ignored`로 이를 실행하고 `HANGANG_TEST_REDIS_*` 변수를 제공합니다.

## 명령줄 런타임

`--database rediss://redis.example:6379/0 --redis-key hangang:config`(또는 `HANGANG_DATABASE`)를 사용합니다. `--database-ca /path/to/ca.pem`은 사설 루트를 설치합니다. `--database-plaintext`는 명시적인 로컬 개발 override입니다. seed 파일은 빈 키를 부트스트랩할 때만 읽으며, 커밋된 Redis revision이 이후 권위가 되어 500ms마다 폴링됩니다. API 쓰기는 다른 공유 저장소와 같은 ETag/CAS 계약을 사용합니다. fixture는 소유한 Redis 인스턴스에 대해 실제 게이트웨이 프로세스 두 개가 충돌하고 갱신하고 재시작하는 경우도 검증합니다.
