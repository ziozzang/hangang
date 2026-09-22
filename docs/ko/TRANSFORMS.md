# 요청과 응답 변환

[문서 목차](../README.ko.md) · [English](../TRANSFORMS.md)

Hangang은 양방향에서 네이티브 본문 작업과 격리된 Lua 본문 스크립트를 지원합니다. HTTP 라우트에 `request_transform` 또는 `response_transform`을 추가하십시오. 매칭, 외부 authorization, 기존 라우트 수준 `lua` 정책은 요청 본문 변환보다 먼저 실행됩니다. 네이티브 작업은 설정 순서대로 실행한 다음 선택적 본문 Lua가 실행됩니다. 응답은 선택된 라우트의 response transform을 따릅니다. 진행 중인 stream은 원래 설정을 유지하고 이후 요청은 reload된 설정을 사용합니다.

```json
{
  "id": "public-api",
  "backends": ["http://127.0.0.1:8080"],
  "request_transform": {
    "mode": "buffered",
    "max_buffer_bytes": 65536,
    "max_output_bytes": 65536,
    "timeout_ms": 5000,
    "operations": [
      {"op": "json_remove", "pointer": "/client_role"},
      {"op": "json_set", "pointer": "/source", "value": "hangang"}
    ],
    "set_headers": {"x-gateway": "hangang"},
    "remove_headers": ["x-internal-debug"]
  },
  "response_transform": {
    "operations": [{"op": "json_remove", "pointer": "/secret"}]
  }
}
```

존재하지 않는 JSON 대상은 redaction이 성공한 것처럼 조용히 처리하지 않고 실패합니다. 입력 계약에 해당 필드가 있을 때만 이 예제를 사용하십시오. 선택적 필드는 Lua(`value.secret = nil`)를 사용합니다. 본문 작업은 Content-Type을 추측하지 않고 명시적으로 설정하므로 표현 형식에 맞는 라우트를 선택해야 합니다. 구조 파서는 올바른 UTF-8 JSON/XML을 요구합니다. XML 문서 buffering은 chunked와 fixed-length HTTP 본문 모두 지원합니다.

## Buffering과 streaming

| 모드 | 버퍼 단위 | 동작 |
| --- | --- | --- |
| `buffered` (기본) | 전체 본문 | 변환한 본문을 전달하기 전에 검증·변환. JSON/XML 문서와 바이너리 envelope에 적합 |
| `lines` | LF/CRLF 한 줄 | 임의 HTTP chunk 경계를 넘어 한 줄 안에서 작업; CRLF는 LF가 되고 끝에 개행이 없는 마지막 줄은 그대로 남음 |
| `ndjson` | LF/CRLF 한 줄 | 입력과 최종 출력이 각각 유효한 JSON 값 하나여야 함; 빈 줄·잘못된 줄은 실패. 지속적으로 전달되는 JSON record에 적합 |
| `sse` | 빈 줄로 끝나는 이벤트 하나 | chunk 경계를 가로지르는 CR/LF/CRLF를 받아들이고 첫 UTF-8 BOM을 제거하며 `data` 필드를 합쳐 변환하고 다른 field/comment를 보존; LF 줄 끝으로 직렬화 |

SSE comment와 data 없는 이벤트는 작업 없이 통과합니다. 여러 data 출력 줄에는 각각 `data: ` 접두사가 붙어 script가 newline으로 event/id field를 주입할 수 없습니다. 변환한 SSE data의 raw CR이나 잘못된 UTF-8은 실패하고 EOF의 미완성 이벤트는 완성된 이벤트로 dispatch하지 않고 실패합니다. lines/NDJSON 출력에는 CR/LF를 넣을 수 없습니다. `lines` 모드의 native XML 작업은 각 줄에 완전한 XML 문서를 요구하며 무제한 XML의 일반 XPath processor가 아닙니다.

stream wrapper는 demand-driven입니다. producer를 만들거나 다음 record를 prefetch하거나 무제한 queue를 할당하지 않습니다. upstream read는 downstream demand를 따릅니다. stream 전체는 record 한도보다 클 수 있지만 끝나지 않는 한 record는 크기와 deadline으로 제한됩니다. disk spill과 전체 stream 누적은 없습니다.

streaming 요청은 나중 record가 실패하기 전에 앞의 유효 record를 backend에 보낼 수 있으며 **transaction 또는 rollback을 보장하지 않습니다**. 본문 바이트를 하나도 보내기 전에 검증해야 하는 upload에는 `buffered`를 사용하고 애플리케이션이 transaction을 보장하게 하십시오. 자동 retry는 없습니다. header나 앞 record를 보낸 뒤 response가 실패하면 Hangang은 body/stream을 종료하며 HTTP 상태를 나중에 바꿀 수 없습니다. `hangang_body_transform_errors_total`은 buffered와 midstream 실패를 모두 셉니다.

## 한도와 admission

- `max_buffer_bytes`, `max_output_bytes`: 각각 기본 65,536, 허용 1..1,048,576. 입력·중간 native 표현·최종 출력을 제한합니다. lines는 delimiter를 input 한도에서 제외하고 SSE는 정규화 framing/metadata를 포함하며 event당 공백이 아닌 줄은 최대 1,024개입니다.
- Lua는 두 한도를 모두 명시적으로 16,384바이트 이하로 요구하고 source도 16KiB로 제한합니다. 한도는 Unicode 문자가 아니라 바이트입니다.
- `timeout_ms`: 기본 5,000, 범위 1..30,000. buffered read와 변환 전체에 하나의 deadline을 적용하고 streaming은 demand 시작 후 각 record의 완료·변환에 deadline을 적용합니다. 기존 Lua deadline은 별도로 적용됩니다.
- 방향별 native 작업 최대 32개, 합친 header mutation 32개, 설정된 작업 값/header data/script 64KiB입니다. 알 수 없는 field는 검증 실패입니다.
- `--max-body-transforms`는 기본 32, 허용 1..1024개의 동시 exchange입니다. JSON route inspection과 일반 admission과 별개이며 capacity 고갈은 queue 대신 503을 반환합니다. 느린 body는 소비·폐기될 때까지 capacity를 차지합니다.
- native parsing/serialization은 network reactor 밖에서 실행합니다. 취소된 blocking job은 끝날 때까지 admission permit을 보유합니다. Lua는 기존 memory, instruction, wall-clock, syscall 한도를 가진 격리 process에서 실행됩니다.

wire-byte 한도는 전체 RSS가 아닙니다. JSON tree, XML parser state, transport frame, output storage가 추가됩니다. 예상 배포 메모리와 record 한도를 함께 고려해 concurrency를 정하십시오. 기본값은 제한된 buffering이지 모든 조합이 작은 container에 맞는다는 보장이 아닙니다.

## Native 작업

| 작업 | 필드 | 의미 |
| --- | --- | --- |
| `replace` | `from`, `to` | 겹치지 않는 literal byte 치환; 빈 `from`은 불가, 정규식 engine 없음 |
| `json_set` | `pointer`, `value` | RFC 6901 pointer; 부모가 있어야 하며 object key를 삽입/교체하거나 기존 array 요소를 교체하고, 빈 pointer로 root를 교체 |
| `json_remove` | `pointer` | 기존 object member 또는 array element 제거; root와 없는 대상은 실패 |
| `xml_set_text` | `path`, `value` | 정확히 일치하는 모든 요소의 content/descendant를 escape한 text로 교체; attribute 보존 |
| `xml_remove` | `path` | 일치하는 subtree를 모두 제거; document root 제거 금지 |

JSON pointer는 `~0`, `~1`을 decode합니다. array index는 존재하는 canonical unsigned decimal이어야 하며 `-`, leading zero, 암시적 부모 생성, append는 지원하지 않습니다. JSON 형식과 key 순서는 바뀔 수 있고 일반 serde JSON duplicate-key 처리를 따릅니다. 이는 순서 있는 mutation 목록이지 RFC 6902 전체 JSON Patch가 아닙니다.

`/root/item/name` 같은 XML path는 prefix가 있으면 포함한 정확한 ASCII qualified name을 사용합니다(`/a:root/a:item`). XPath가 아니며 namespace URI 동등성을 해석하지 않습니다. XML depth는 최대 64이고 DTD/custom entity와 외부 entity retrieval을 거부합니다. 표준 escape와 유효한 numeric character reference는 지원합니다. 한 transform에서 XML과 JSON 작업을 섞을 수 없습니다.

## Lua 본문 API

```lua
local value = hangang.json_decode(hangang.body())
value.secret = nil
value.gateway = true
value.optional = hangang.null
value.items = value.items or hangang.array()
return hangang.json_encode(value)
```

| API | 결과 |
| --- | --- |
| `hangang.body()` | native 작업 후 현재 본문/record를 binary-safe Lua string으로 반환 |
| `hangang.set_body(bytes)` | 최대 16KiB 출력 설정 |
| `hangang.phase()` | `request` 또는 `response` |
| `hangang.json_decode(bytes)` | JSON을 Lua 값으로 변환하며 null·빈 array 보존 |
| `hangang.json_encode(value)` | cycle/repeated table, unsupported type, depth/node/size 초과, nonfinite 수를 거부하는 제한된 JSON encoding |
| `hangang.null` | JSON null sentinel; Lua `nil`은 table field를 제거 |
| `hangang.array()` | `{}`와 구별되는 빈 JSON array 생성 |

문자열 반환은 `set_body`보다 우선하고 `nil` 반환은 `set_body` 또는 변경 없는 입력을 사용합니다. 다른 반환 형식은 실패합니다. body/record마다 새 VM을 실행하므로 요청·record 사이 전역 상태가 없습니다. `string`, `table`, `math`만 사용할 수 있고 filesystem/network/process/debug/package 접근과 `string.dump`는 없습니다. host callback과 C library 작업도 parent worker deadline을 따릅니다. routing policy API(`header`, `method`, `path`, `select_backend`, `select_member`, `set_header`, `reject`)는 별도 phase이며 body script는 backend/member를 선택할 수 없습니다. header 변경은 body script와 함께 native `set_headers`/`remove_headers`를 설정하십시오.

object-mode HTTP route에서 `hangang.select_member(id)`는 정확한 ID의 member에 request를 고정합니다. ID는 1~64 ASCII이며 첫 문자는 영숫자, 이후 영숫자와 `.`, `_`, `-`입니다. 잘못된 ID는 Lua policy error이고, 유효하지만 알 수 없거나 사용할 수 없는 ID는 다른 member에 접속하지 않고 503입니다. 고정 request는 다른 backend로 retry되지 않습니다. `hangang.select_backend(address)`도 설정된 주소를 선택하며 두 selector 중 마지막 호출이 이깁니다. 반환된 설정 URL은 둘을 덮고 `return nil`은 마지막 선택을 유지합니다. [named-member policy 예제](../../examples/transforms/lua/select-member.lua)와 `blue` member가 포함된 [named-members 설정 예제](../../examples/named-members.json)를 참고하고 해당 HTTP route의 `lua` field에 source를 넣으십시오.

SSE 애플리케이션의 `[DONE]` sentinel은 JSON parse 전에 처리하십시오. [SSE script](../../examples/transforms/lua/sse.lua)를 참고하세요. native JSON 작업은 의도적으로 JSON이 아닌 sentinel을 거부합니다.

## HTTP 동작

변환된 표현은 낡은 Content-Length/Transfer-Encoding, Trailer 선언·frame, ETag/Last-Modified, digest/signature header와 range metadata를 버립니다. Hyper가 새 body의 올바른 framing을 제공하며 Set-Cookie 같은 무관한 반복 header는 유지됩니다. 사용자 mutation은 보호된 framing, forwarding, encoding, upgrade, range, validator header를 설정할 수 없습니다.

encoded request body는 415입니다. response transform을 설정하면 identity encoding을 요청하고, upstream이 계속 encoded data를 보내면 502입니다. 설정된 transform을 조용히 우회하지 않습니다. `Cache-Control: no-transform` 충돌도 실패하며 Range/If-Range는 416, representation precondition은 412입니다. partial upstream response는 502, Content-Range를 가진 partial request는 mutation 전에 400입니다. transform route의 tunnel/upgrade는 400이므로 WebSocket/CONNECT에는 별도 untransformed route를 사용하십시오. HEAD와 1xx/204/205/304는 body transform을 건너뜁니다.

한도를 넘은 buffered request는 413, read/transform timeout은 408, malformed input은 400, Lua failure는 503입니다. response의 해당 실패는 출력 전에 502 또는 504입니다. 고갈·재시작 중인 local Lua worker는 요청·응답 변환 모두에서 출력이 시작되기 전에 별도 capacity 상태로 503을 반환하며 upstream 502로 보고하지 않습니다. midstream failure는 stream을 종료합니다. 잘못된 script/configuration은 startup, API validation/update, file reload에서 거부되고 마지막 유효 설정이 유지됩니다.

## 예제와 테스트 실행

```sh
cargo build --locked
python3 examples/transforms/run.py
make test-transforms
make test-web
```

runner는 자체 loopback backend와 gateway만 시작하고 [10-route 설정](../../examples/transforms/hangang.json)을 임시 복사해 ephemeral port를 넣고 모든 script를 `--check`로 compile한 뒤 예제를 검증하고 process와 임시 파일을 정리합니다. 다른 빌드 바이너리는 `HANGANG_BINARY`로 지정합니다. 독립 예제는 `127.0.0.1:18081`을 대상으로 하므로 수동 사용 시 backend를 조정하십시오. script는 JSON 설정에 embedded되어 별도 `.lua` 파일만 수정해도 reload되지 않습니다. file 또는 API에서 route script/config field를 갱신하십시오.

웹 route editor는 request/response transformation JSON field를 제공하며 advanced document는 모든 옵션을 보존합니다. `/openapi.json`은 모든 field와 operation을 설명합니다.

프로토콜 참고: [SSE parsing](https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream), [HTTP transformation semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7), [RFC 6901 JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901).
