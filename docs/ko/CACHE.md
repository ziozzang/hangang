# HTTP 응답 캐시

[문서 목차](../README.ko.md) · [English](../CACHE.md)

Hangang은 메모리 저장량을 제한하고 선택적으로 SQLite에 영속화하는 옵트인 공유 응답 캐시를 제공합니다. 최상위에서 저장소를 활성화한 뒤 캐시할 각 라우트에서 freshness 정책을 활성화해야 합니다. 두 설정이 모두 필요합니다.

```json
{
  "cache": {
    "memory": {
      "max_bytes": 8388608,
      "max_entries": 2000,
      "eviction": "lru"
    },
    "disk": {
      "directory": "/var/lib/hangang/cache/instance-a",
      "max_bytes": 67108864,
      "max_entries": 20000,
      "eviction": "lru"
    },
    "max_object_bytes": 262144,
    "max_fills": 16,
    "fill_timeout_ms": 3000,
    "generation": 0
  },
  "http": [
    {
      "id": "catalog",
      "path_prefix": "/catalog",
      "path_match": "exact",
      "cache": {
        "ttl_seconds": 30,
        "max_ttl_seconds": 120
      },
      "backends": ["http://127.0.0.1:8080"]
    }
  ],
  "tcp": []
}
```

실행 가능한 전체 설정은 [examples/cache/hangang.json](../../examples/cache/hangang.json)입니다. 캐시 필드는 알 수 없는 속성을 거부하며 잘못된 한도는 시작, 파일 reload, API 검증, API update에서 모두 거부됩니다. 거부된 reload는 마지막 유효 snapshot을 활성 상태로 유지합니다.

## 저장소 정책

| 설정 | 기본값 | 허용값 | 의미 |
| --- | ---: | --- | --- |
| `memory.max_bytes` | 67,108,864 | `0..isize::MAX` | 가중치가 적용된 메모리 항목 용량; 0이면 메모리 비활성화 |
| `memory.max_entries` | 10,000 | `0..1,000,000` | 메모리 항목 수; 메모리 사용 시 양수여야 함 |
| `memory.eviction` | `lru` | `lru`, `fifo` | 메모리 퇴출 순서 |
| `disk` | 생략 | 객체 또는 생략 | 선택적 영속 계층 |
| `disk.max_bytes` | 필수 | `65,536..8,796,093,018,112` | SQLite 본 파일과 rollback journal 한도 |
| `disk.max_entries` | 필수 | `1..1,000,000` | 디스크 항목 수 |
| `disk.eviction` | `lru` | `lru`, `fifo` | 디스크 퇴출 순서 |
| `max_object_bytes` | 1,048,576 | `1..16,777,216` | 완전한 한 항목의 최대 가중 크기 |
| `max_fills` | 32 | `1..1,024` | 동시에 캡처하는 응답 수 |
| `fill_timeout_ms` | 5,000 | `1..30,000` | 헤더 수신 후 응답 본문 캡처 deadline |
| `generation` | 0 | `0..4,294,967,295` | 전체 fleet 무효화 세대; 모든 키가 이 값으로 구분됨 |

최소 한 저장 계층은 활성화해야 합니다. 메모리는 색인된 LRU 또는 FIFO 큐로 항목 수와 가중 바이트를 모두 제한합니다. 적중은 저장된 `Bytes`의 값싼 clone을 반환하며 전체 본문을 복사하지 않습니다. 가중치에는 키, 본문, 헤더 이름과 값, 헤더 tuple 저장 공간, 고정 256바이트 항목 여유가 포함됩니다.

`memory.max_bytes`는 cache accounting 예산이지 RSS 한도가 아닙니다. 해시 테이블, 정렬 색인, 공유 본문, 활성 응답 캡처, 네트워크 버퍼, SQLite, allocator와 프로세스 나머지가 추가 메모리를 사용합니다. 특히 캡처는 저장 항목 LRU 예산 밖에서 최대 `max_fills * max_object_bytes`바이트의 응답 데이터를 보유할 수 있습니다(기본 32 MiB, 허용 최대 조합에서는 16 GiB). 응답 메타데이터와 전송 버퍼도 추가됩니다. 예상 동시성에서 측정한 프로세스 메모리 예산으로 값을 정하십시오.

디스크 저장은 절대 경로에 `cache-v1.db`를 만들고 논리 항목 수·크기를 제한하며 SQLite의 4,096바이트 `max_page_count`로 본 파일을 제한합니다. `TRUNCATE` rollback journal을 사용하므로 메모리 부족에 따른 강제 종료처럼 중단된 transaction도 파일을 손상시키지 않고 다음 open 때 rollback됩니다. `-journal` sidecar는 transaction이 바꾼 각 페이지의 이전 내용을 잠시 보유합니다. 페이지 예산은 본 파일 페이지마다 원래 4,096바이트와 8바이트 framing의 journal record를 계산하고 journal header·정렬에 10%를 예약합니다. 따라서 본 파일은 `disk.max_bytes` 절반 아래에 머물고 purge transaction의 최대치도 설정 범위에 들어옵니다. 이전 빌드에서 만든 데이터베이스가 이를 초과하면 수정 전에 거부되므로 다시 만들 수 있는 `cache-v1.db`를 제거해야 합니다. `GET /v1/cache`는 본 파일과 journal을 각각 `disk_bytes`, `disk_journal_bytes`로 보고합니다. 물리 한도에 도달한 insert는 퇴출 후 재시도하고, 빈 DB에도 들어가지 않는 객체는 우회되며 계수에 반영됩니다. 다른 저장 오류는 fail open됩니다. 클라이언트는 origin 응답을 계속 받고 메모리가 활성화되어 있으면 메모리 사본도 계속 사용할 수 있으며 저장 오류 counter가 증가합니다.

실행 중인 각 Hangang 인스턴스마다 전용 cache 디렉터리를 사용하십시오. 절대 경로이고 symlink 구성요소가 없어야 하며 없거나 owner 전용 `0700` 디렉터리여야 합니다. DB는 `0600`으로 만들고 symlink 파일과 application identifier가 없는 DB를 거부하며 관련 없는 파일을 덮어쓰지 않습니다. 저장소 수명 동안 비차단 배타 소유권 잠금을 유지합니다. Linux는 데이터베이스 파일을 잠그고, macOS는 SQLite의 데이터베이스 잠금을 방해하지 않도록 별도의 비공개 `0600` 파일인 `cache-v1.db.owner-lock`을 사용합니다. 저장소가 실행 중일 때 이 보조 파일을 그대로 두어야 합니다. 삭제하거나 교체하면 서로 다른 파일을 기준으로 소유권이 나뉠 수 있습니다. 빈 보조 파일에는 캐시 항목이 저장되지 않습니다. 플랫폼별 데이터베이스 잠금 동작은 [SQLite 잠금 방식](https://www.sqlite.org/compile.html#enable_locking_style)을 참고하세요.

일반적으로 디스크 앞에 메모리를 두는 구성을 권장합니다. 메모리 miss는 단일 디스크 I/O gate를 기다리지 않고 시도하며 동시 디스크 접근은 origin으로 우회합니다. 디스크 전용 모드는 용량과 재시작 지속성을 제공하지만 경쟁 때문에 우회할 수 있고 가까운 origin보다 latency가 개선된다는 보장은 없습니다.

최상위 cache 정책이 같으면 reload 후에도 같은 store를 재사용하며 `generation`만 바꾼 경우도 같습니다. 다른 최상위 필드를 바꾸면 즉시 새 메모리 store를 만듭니다. 이전 in-flight snapshot이 요청 drain까지 DB lock을 유지할 수 있어 새 store가 잠시 디스크를 우회할 수 있습니다. 각 시도는 저장 오류로 집계되고 다음 접근에서 다시 시도합니다. DB를 열 수 있게 되면 전체 정책과 key derivation fingerprint를 비교하고, 정책이 바뀌었으면 항목을 지운 뒤 `VACUUM`을 실행하고 새 물리 한도를 적용합니다. 따라서 이전 용량 또는 퇴출 정책에 따라 남은 데이터를 정책 변경 뒤에 제공하지 않습니다.

## 무효화 세대

`cache.generation`은 공유 설정 문서의 정수입니다. 모든 cache key가 이 값으로 구분되고 더 높은 값의 문서를 활성화하면 두 저장 계층을 activation 시점에 버립니다. 준비만 하다 거부된 write는 live cache를 건드리지 않습니다. runtime을 재구축하지 않으면서도 이전 값에서 시작된 진행 중 fill이나 조회는 제공하거나 게시할 수 없게 됩니다. 설정과 함께 전파되므로 공유 문서를 사용하는 모든 인스턴스에 도달하고 새 `revision`과 `ETag`를 만듭니다.

- 공유 저장소에서는 `POST /v1/cache/purge`가 다음 generation을 사용해 compare-and-swap으로 문서를 commit하는 fleet purge입니다. 각 인스턴스는 다음 poll에서 적용하며 그 전에는 기존 항목을 계속 제공합니다.
- 파일 모드에서는 요청을 받은 인스턴스만 purge합니다. 모든 인스턴스를 무효화하려면 파일의 `generation`을 편집하십시오.
- 값은 단조 증가합니다. gateway는 더 높은 generation만 채택하며 문서의 `cache_generation_floor`는 `cache`가 null일 때도 지금까지 commit한 최고값을 유지합니다. 전체 문서를 이전 값으로 되돌리거나 기본값 0으로 cache를 다시 켜는 등 generation을 낮추는 API write는 모든 인스턴스에서 이 floor까지 올려 저장됩니다. 따라서 그 사이 수행한 purge가 계속 유효하고 다음 purge를 건너뛰지 않습니다. 4,294,967,295에서는 field를 정책 변경으로 reset하기 전 purge가 422로 거부되며 wrap하지 않습니다. 생략하면 0입니다.
- generation은 디스크 DB에 기록됩니다. open 시 다른 세대의 행을 삭제하므로 충돌로 중단된 purge나 DB가 열리기 전에 수행된 purge도 다음 open에서 완료되고 현재 세대 행은 재시작 후 보존됩니다.
- 라우트 편집은 항목을 다른 key namespace로 옮기며 되돌리면 아직 fresh한 이전 항목이 돌아옵니다. 이는 무효화가 아니므로 이전 표현을 금지하려면 purge endpoint 또는 generation을 사용하십시오.

## 라우트 freshness

`ttl_seconds` 기본값은 30, `max_ttl_seconds` 기본값은 300이며 다음을 만족해야 합니다.

```text
1 <= ttl_seconds <= max_ttl_seconds <= 86400
```

완전한 `200 OK`만 저장합니다. `s-maxage`가 `max-age`보다 우선하고 route maximum으로 제한됩니다. 둘 다 없으면 `Date` 기준 `Expires`, 그 다음 route 기본값을 사용합니다. upstream `Age`, `Date`의 apparent age, response header 수신 시간을 계산합니다. entry는 저장 시각과 남은 수명의 합에서 만료되고 hit은 framing을 필요에 따라 바꾸며 누적 `Age`를 설정합니다.

응답 캐시는 보수적으로 동작합니다. `Set-Cookie`, `Content-Range`, trailers, SSE, 중복·잘못된 Content-Type, 잘못된 또는 wildcard `Vary`, 잘못된·중복 freshness metadata, `no-store`·`private`·`no-cache`가 있으면 우회합니다. 의미가 공유 저장소에 영향을 줄 수 있는 알 수 없는 Cache-Control 확장도 우회합니다. native buffered response transform은 변환 후 캐시할 수 있지만 Lua와 streaming response transform은 대상에서 제외됩니다.

외부 authorization, route Lua, JSON request matching, request transformation을 쓰는 라우트는 대상이 아닙니다. 요청은 빈 본문의 GET이어야 합니다. Cache-Control 또는 Pragma 지시는 일반 캐시를 우회하며 `only-if-cached`는 origin 요청 없이 `504`를 받습니다. Authorization, Proxy-Authorization, Cookie, Range, Content-Range, Upgrade, 모든 `If-*` 헤더도 우회합니다.

키는 SHA-256 hash이며 DB key column에 요청 헤더나 URI를 노출하지 않습니다. 원래 method, URI scheme/authority/path/query, TLS 상태, client peer-IP partition, 전체 route fingerprint, generation, proxy forwarding header와 body transform 전의 원래 end-to-end header를 포함합니다. header 이름은 정렬하고 반복 값 순서를 유지하며 hop-by-hop field는 제외합니다. key header material이 64 KiB를 넘으면 우회합니다. 폭넓은 key는 표현을 분리하는 대신 적중률을 낮춥니다. 저장된 status·header·body는 암호화 없이 SQLite에 있으므로 디렉터리를 보호하고 at-rest 암호화가 필요하면 암호화 저장소를 사용하십시오.

## Fill, 실패와 purge 동작

miss는 전달하면서 응답을 캡처합니다. 완전한 본문이 EOF 또는 최종 body frame의 end-of-stream 확인에 도달한 경우에만 게시합니다. 본문 오류, client 취소, trailers, capture timeout, 객체 가중치 초과는 partial 응답을 저장하지 않고 fill을 폐기합니다. 최대 `max_fills`개가 활성화되고 같은 key의 follower는 현재 fill을 최대 250ms 기다린 뒤 항목이 없으면 우회합니다. 관련 없는 초과 fill은 즉시 우회합니다.

유효한 proxy 요청은 storage failure로 실패하지 않습니다. 디스크 읽기·쓰기는 nonblocking admission을 사용하며 경쟁 중 우회할 수 있습니다. purge는 다릅니다. 메모리를 지우고 배타적 디스크 접근을 기다리며 persistent 삭제가 실패하면 오류를 반환합니다. publication control을 잡는 동안 local epoch를 전진시켜 purge 전에 시작한 fill이 다시 채우지 못하게 합니다. local epoch는 프로세스가 재시작하면 초기화되므로 저장 key에 넣지 않습니다. 이를 key에 넣으면 purge 뒤 작성된 모든 항목이 재시작 시 고립됩니다. 저장 key에는 configuration generation을 사용합니다.

인증된 관리 API는 다음을 제공합니다.

- `GET /v1/cache`: 활성 설정, 가중 메모리 통계, 실제 DB 바이트, 항목 수, 누적 hit/miss/eviction/error, 활성 fill. lazy DB가 열리기 전 디스크 값은 0입니다.
- `POST /v1/cache/purge`: 공유 모드에서는 다음 generation으로 설정을 commit하고 파일 모드에서는 이 인스턴스의 메모리·디스크를 지웁니다. cache가 비활성화되어 있어도 성공 시 `{"purged":true}`를 반환하며, cache 유지보수가 완료되지 않으면 `503`입니다.
- `GET /v1/status`: proxy 수준 `cache_hits_total`, `cache_misses_total`, `cache_bypasses_total`을 제공하며 store 내부 counter와 다를 수 있습니다.

두 endpoint 모두 관리자 bearer token이 필요합니다. 파일 교체와 `PUT /v1/config`은 gateway 실행 중 cache 설정을 바꿀 수 있고 API update에는 현재 `ETag`를 `If-Match`로 보내야 합니다.

## 예제 실행

```sh
cargo build --locked
python3 examples/cache/run.py
```

runner는 자체 loopback origin과 gateway를 시작하고 인스턴스 전용 비공개 디스크 디렉터리를 만들며 생성 설정을 먼저 `--check`합니다. 메모리 hit, file hot reload, ETag 보호 API update, 재시작 후 같은 public address를 통한 디스크 재사용, 또 다른 재시작 후 durable purge를 검증하고 모든 process와 임시 파일을 정리합니다. 다른 빌드 바이너리를 검증하려면 `HANGANG_BINARY`를 설정하십시오.
