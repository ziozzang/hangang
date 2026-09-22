# Request and response transformations

[Documentation](README.md) · [한국어](ko/TRANSFORMS.md)

Hangang supports native body operations and isolated Lua body scripts in both directions. Add `request_transform` or `response_transform` to an HTTP route. Matching, external authorization and the existing route-level `lua` policy run before request body transformation. Native operations run in their configured order, then the optional body Lua script. Responses follow the selected route's response transform. An in-flight stream keeps its original configuration while later requests use a reloaded configuration.

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

Missing JSON targets fail instead of silently pretending a redaction succeeded. Apply this example only where the input contract contains those fields. Use Lua for optional fields (`value.secret = nil`). The body operations are explicitly configured rather than guessed from Content-Type; operators must select routes whose representation matches their transform. Structural parsers require valid UTF-8 JSON/XML. XML document buffering works with chunked HTTP input as well as fixed-length bodies.

## Buffering and streaming

| Mode | Unit buffered | Behavior |
| --- | --- | --- |
| `buffered` (default) | Entire body | Validates and transforms before forwarding the transformed body. Suitable for JSON/XML documents and binary envelopes |
| `lines` | One LF/CRLF line | Operations span arbitrary HTTP chunk boundaries within that line. CRLF becomes LF; a final unterminated line stays unterminated |
| `ndjson` | One LF/CRLF line | Input and final output must each be one valid JSON value; blank/malformed lines fail. Useful for continuously delivered JSON records |
| `sse` | One event terminated by a blank line | Accepts CR, LF and CRLF across chunks, strips an initial UTF-8 BOM, joins `data` fields, transforms their data, and preserves other fields/comments. Serializes LF line endings |

SSE comments and events without data pass without invoking body operations. Multiple output data lines receive separate `data: ` prefixes, so scripts cannot inject event/id fields with a newline. Raw CR or invalid UTF-8 in transformed SSE data fails. An unfinished SSE event at EOF fails; it is never dispatched as a complete event. Lines/NDJSON output cannot contain embedded CR/LF. A native XML operation in `lines` mode requires a complete XML document on each line; this is not a general XPath processor for an unbounded XML document.

The stream wrapper is demand-driven: it does not spawn a producer, prefetch subsequent records or allocate an unbounded queue. Upstream reads follow downstream demand. A stream can be much larger than the per-record limit. A single record that never completes is still bounded by its size and deadline. There is no disk spill and no full-stream accumulation.

A streaming request can deliver valid earlier records to the backend before a later record fails. It provides **no transaction or rollback guarantee**. Use `buffered` for uploads that must be fully validated before any body bytes reach the backend, and have the application enforce its own transaction. There are no automatic retries. If a response fails after its headers or earlier records were sent, Hangang terminates the body/stream; HTTP cannot retroactively change that response status. `hangang_body_transform_errors_total` counts both buffered and midstream transform failures.

## Bounds and admission

- `max_buffer_bytes` and `max_output_bytes`: default 65,536 each, allowed 1..1,048,576. Input, intermediate native representations and final output are bounded. Lines exclude their delimiter from the input limit; SSE includes normalized framing/metadata and permits at most 1,024 nonblank lines per event.
- Lua requires **both** limits to be explicitly at most 16,384 bytes. Source is also limited to 16 KiB. Limits are bytes, not Unicode characters.
- `timeout_ms`: default 5,000, range 1..30,000. The entire buffered read and transformation has one deadline; streaming mode applies a deadline to completing and transforming each record once demand starts. Existing Lua deadlines remain independently active.
- At most 32 native operations, 32 combined header mutations and 64 KiB of configured operation values/header data/script per direction. Unknown fields fail validation.
- `--max-body-transforms` defaults to 32 concurrent transforming exchanges, allowed 1..1024. This admission pool is separate from JSON route inspection and ordinary request admission. Capacity exhaustion returns 503 rather than queueing more bodies. Slow transformed bodies retain capacity until consumed or dropped.
- Native parsing/serialization runs outside the network reactor. A cancelled blocking job retains its admission permit until it finishes. Lua stays in the isolated worker process with the existing memory, instruction, wall-clock and syscall limits.

Wire-byte limits do not equal total RSS: JSON trees, XML parser state, transport frames and output storage add overhead. Size the concurrency limit together with per-record bounds and deployment memory. The default is bounded memory buffering, not a promise that every optional limit combination fits a small container.

## Native operations

| Operation | Fields | Semantics |
| --- | --- | --- |
| `replace` | `from`, `to` | Non-overlapping literal byte replacement. Empty `from` is invalid. No regular expression engine |
| `json_set` | `pointer`, `value` | RFC 6901 pointer; existing parent required. Inserts/replaces an object key, replaces an existing array element, or replaces the root with an empty pointer |
| `json_remove` | `pointer` | Removes an existing object member or array element; array elements shift. Root removal and missing targets fail |
| `xml_set_text` | `path`, `value` | Replaces the complete content/descendants of every exact matching element with safely escaped text; attributes remain |
| `xml_remove` | `path` | Removes every matching subtree. Removing the document root is forbidden |

JSON pointers decode `~0` and `~1`. Array indices are existing canonical unsigned decimal indices; `-`, leading-zero indices, implicit parent creation and array append are unsupported. JSON formatting/key ordering may change; ordinary serde JSON duplicate-key handling applies. This is an ordered mutation list, not the full RFC 6902 JSON Patch protocol.

XML paths such as `/root/item/name` use exact ASCII qualified names, including a prefix where present (`/a:root/a:item`). They are not XPath expressions and do not resolve namespace URI equivalence. XML is structurally parsed, with a maximum depth of 64; DTD/custom entities are rejected, and external entity retrieval is never performed. Standard escaped characters and valid numeric character references are supported. XML and JSON operations cannot mix in one transform.

## Lua body API

```lua
local value = hangang.json_decode(hangang.body())
value.secret = nil
value.gateway = true
value.optional = hangang.null
value.items = value.items or hangang.array()
return hangang.json_encode(value)
```

| API | Result |
| --- | --- |
| `hangang.body()` | Current complete body/record as a binary-safe Lua string, after native operations |
| `hangang.set_body(bytes)` | Sets the output, at most 16 KiB |
| `hangang.phase()` | `request` or `response` |
| `hangang.json_decode(bytes)` | JSON to Lua values with JSON null and empty arrays preserved |
| `hangang.json_encode(value)` | Bounded JSON encoding; rejects cycles/repeated tables, unsupported types, excessive depth/nodes/size and nonfinite numbers |
| `hangang.null` | JSON null sentinel; Lua `nil` removes a table field |
| `hangang.array()` | Creates an empty JSON array, distinct from `{}` |

Returning a string overrides `set_body`; returning `nil` uses `set_body` or the unchanged input. Other return types fail. A new VM runs for every body/record: there is no cross-request or cross-record global state. `string`, `table` and `math` are available; filesystem/network/process/debug/package access remains unavailable, and `string.dump` is removed. Host callbacks and C library work remain subject to the parent's worker deadline. The routing policy API (`header`, `method`, `path`, `select_backend`, `select_member`, `set_header`, `reject`) is a separate phase; body scripts cannot select a backend or member. Configure native `set_headers`/`remove_headers` alongside body scripts for header changes.

For an object-mode HTTP route, `hangang.select_member(id)` pins the request to the configured member with that exact ID. IDs are 1–64 ASCII characters, start with a letter or digit, and then allow letters, digits, `.`, `_`, and `-`. An invalid ID is a Lua policy error; a valid but unknown or unavailable ID returns 503 without contacting another member. A policy-pinned request is not retried on another backend. `hangang.select_backend(address)` still selects a configured address. The last call to either selector wins, and a returned configured URL overrides either selection. `return nil` keeps the last selection. See the [named-member policy example](../examples/transforms/lua/select-member.lua) with the `blue` member in the [named-members configuration example](../examples/named-members.json); place the Lua source in that HTTP route's `lua` field to try it.

For an SSE application with a `[DONE]` sentinel, handle it before parsing JSON; see [the SSE script](../examples/transforms/lua/sse.lua). Native JSON operations intentionally reject non-JSON sentinel data.

## HTTP behavior

Transformed representations discard stale Content-Length/Transfer-Encoding, Trailer declarations and trailer frames, ETag/Last-Modified, digest/signature headers and range metadata. Hyper supplies valid framing for the new body; unrelated repeated headers such as Set-Cookie remain intact. User mutations cannot set protected framing, forwarding, encoding, upgrade, range or validator headers.

Encoded request bodies fail with 415. Hangang requests identity encoding when response transformation is configured; an upstream that still sends encoded data fails with 502. It does not silently bypass a configured transform. `Cache-Control: no-transform` conflicts also fail rather than mutate the representation. Configured response transforms reject Range/If-Range (416) and representation preconditions (412). A partial upstream response fails with 502. Partial request bodies carrying Content-Range also fail with 400 before mutation. Tunnel/upgrade requests on a transform route fail with 400; use a separate untransformed route for WebSocket/CONNECT. HEAD and 1xx/204/205/304 responses skip body transformation.

A buffered request that exceeds its read limit gets 413, a buffered read/transform timeout gets 408, malformed input gets 400 and Lua failure gets 503. Corresponding response failures produce 502 or 504 before output begins. Exhausted or restarting local Lua workers are a distinct capacity condition and return 503 before output begins, on both request and response transforms; they are not reported as an upstream 502. Midstream failures instead terminate the stream, as described above. Invalid scripts/configurations are rejected during startup, API validation/updates and file reload; the last valid configuration remains active.

## Run the examples and tests

```sh
cargo build --locked
python3 examples/transforms/run.py
make test-transforms
make test-web
```

The example runner starts only its own loopback backend and gateway, substitutes ephemeral ports into a temporary copy of [the ten-route configuration](../examples/transforms/hangang.json), compiles all scripts with `--check`, verifies every example, and cleans up its processes. Set `HANGANG_BINARY` to qualify another built binary. The standalone example config targets `127.0.0.1:18081`; adapt that backend for manual use. Scripts are embedded in config JSON; editing a separate `.lua` file alone does not reload it. Update the route's script/config field through the file or API.

The web route editor has request and response transformation JSON fields; the advanced document preserves all options. `/openapi.json` describes every field and operation.

Protocol references: [SSE parsing and interpretation](https://html.spec.whatwg.org/multipage/server-sent-events.html#parsing-an-event-stream), [HTTP transformation semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7), and [RFC 6901 JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901).
