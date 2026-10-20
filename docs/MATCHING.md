# Host patterns and route priority

[Documentation](README.md) · [한국어 안내](README.ko.md)

HTTP Host routing and TCP ClientHello SNI routing support exact names, label-local glob patterns and explicit regular expressions. Route selection and certificate identity validation are separate: a route regex or `f??.bar.com` does not make that pattern valid in an X.509 certificate. Public certificate loading and hostname verification retain their existing rules.

## Glob patterns

`*` consumes zero or more characters within a single DNS label. `?` consumes exactly one character. Neither crosses a dot. Matching covers the whole hostname and ignores ASCII letter case. Hosts include no port; HTTP extracts the hostname from Host or HTTP/2 authority before matching. Use ASCII/Punycode for internationalized domain names.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `*.foo.com` | `api.foo.com`, `WWW.FOO.COM` | `foo.com`, `a.b.foo.com` |
| `f??.bar.com` | `foo.bar.com`, `fab.bar.com` | `f.bar.com`, `fooo.bar.com` |
| `api*.foo.com` | `api.foo.com`, `api42.foo.com` | `web.foo.com` |
| `a.*.foo.com` | `a.web.foo.com` | `a.foo.com`, `a.b.c.foo.com` |

A pattern `*` alone matches one label, not every qualified domain; use an absent HTTP host condition for an unconditional host match. Glob hosts and patterns are limited to 253 bytes, with 1–63 bytes per label. Exact legacy HTTP authorities retain their existing case-insensitive matching, including a trailing root dot; exact IP addresses are compared as addresses. SNI input retains strict DNS-hostname validation and rejects IP literals.

## Explicit regexes

HTTP accepts exactly one of `host`, `hosts`, or `host_regex`. The `hosts` array groups 1–32 distinct host patterns into one route: `"hosts": ["foo.com", "www.foo.com"]` uses the same backends, load-balancer state, authentication, Lua, transformations, and limits for both names. Any matching alias selects that single route. Group members do not create separate copies of its policies. An explicitly empty array is rejected; omit all three conditions to match any host. See [the domain-group example](../examples/domain-group.json).

The console's HTTP route editor provides Single, Domain group, and Regex modes. Priority and configuration order still determine competition between routes; a domain group adds no implicit priority. Grouping does not redirect one alias to another or automatically issue certificates: configure the desired HTTPS certificates and redirect rules separately. Cache keys still distinguish request hosts, preventing content for one authority from leaking to another.

TCP SNI uses `sni.host_regexes`, which can be combined with `sni.hosts` or used alone. An absent SNI `hosts` defaults to an empty list.

Regexes use [Rust regex syntax](https://docs.rs/regex/1.13.1/regex/): ASCII mode and case-insensitive matching are the defaults, and inline flags retain their normal meaning. Hangang validates each source independently, then anchors the compiled expression to the entire hostname. Thus `api[0-9]+[.]foo[.]com` matches `api12.foo.com`, but not a substring inside another hostname. Backreferences and lookaround are unsupported. Malformed or oversized regexes reject configuration publication, leaving the prior snapshot active.

Each regex source is at most 1,024 bytes. The compiled automaton and DFA-cache limits are 64 KiB each, with nesting at most 32; these limits do not represent total process memory. At most 256 host regexes are permitted across one configuration. HTTP regex input is ASCII and at most 253 bytes; SNI already has stricter parsed-name limits. Regex preparation runs on configuration workers, not per request. Rust regex search is bounded by pattern size times input length rather than backtracking exponentially; pattern/input limits remain important. Glob labels use stack bit masks and work proportional to pattern plus hostname length.

## Priority and ties

Both HTTP and TCP routes accept `priority`, a signed 32-bit integer with default `0`. A larger number is tried first. Configuration/API documents retain their original order; runtime indexes and the management route list order by descending priority.

For HTTP, equal priorities retain configuration order. Exact, glob and regex conditions have no additional implicit ranking. The existing path, header and JSON conditions must also match. A high-priority regex can therefore precede a lower-priority exact hostname.

For TCP SNI, matching is ordered by:

1. Higher route priority.
2. Exact hostname.
3. Simple `*.literal.suffix` wildcard.
4. General `*` / `?` glob.
5. Regex.
6. Configuration order within the same match class.

Identical SNI host patterns or identical regex source strings at the same priority on a shared listener are rejected. Overlapping but different patterns use the ordering above; they are not automatically ranked by string length. Identical host patterns at different priorities are allowed. At most 256 general SNI globs are accepted per listener; exact names and simple suffix wildcards retain indexed lookup within each priority group. A route permits a combined 1–128 SNI host/regex patterns, totaling at most 8,192 source bytes. Shared listener ClientHello limits must still agree.

Once a route is selected, authorization, source-IP denial, admission failure or an upstream failure does not fall through to a lower-priority route. Priority does not bypass policy enforcement. New configuration affects new work; existing tunnels retain the route under which they were admitted.

## Path case

`path_prefix` matching is byte-exact (`path_case: "sensitive"`) by default, except that a route with `auth`, `basic_auth`, `jwt_auth` or `access_mode: protected` and a `path_prefix` defaults to ASCII case-insensitive matching (`"insensitive"`) so a case variant cannot select a public sibling route. Folding is ASCII-only, affects comparison only (the upstream receives the original path) and leaves priority and ties unchanged. Routes whose prefixes differ only in case, on possibly overlapping hosts, with different effective `path_case` are rejected. See [Access policy](ACCESS_POLICY.md#path-case).

## Example

```json
{
  "http": [
    {
      "id": "numbered-api", "priority": 100,
      "host_regex": "api[0-9]+[.]foo[.]com",
      "backends": ["https://origin.example"],
      "upstream": {"dns_servers": ["192.0.2.53:53"]}
    },
    {
      "id": "other-foo", "priority": 0,
      "host": "*.foo.com",
      "backends": ["http://127.0.0.1:8080"]
    }
  ],
  "tcp": [
    {
      "id": "short-bar", "priority": 10,
      "listen": "127.0.0.1:9443",
      "sni": {"hosts": ["f??.bar.com"]},
      "backends": ["127.0.0.1:10443"]
    },
    {
      "id": "numbered-bar", "priority": 0,
      "listen": "127.0.0.1:9443",
      "sni": {"host_regexes": ["node[0-9]+[.]bar[.]com"]},
      "backends": ["127.0.0.1:11443"]
    }
  ]
}
```

The management route editor exposes priority, HTTP glob/regex fields and SNI JSON. The same fields are available in the full configuration and route CRUD APIs; see [OpenAPI](openapi.json). Route matching composes with [per-route outbound policies](UPSTREAM.md), including SOCKS5, selected DNS, forced address and TLS settings.

## Canonical domain policy

An exact-host or domain-group HTTP route may configure `canonical_domain` to redirect selected GET/HEAD paths to one exact member. The target scheme, host and status are configured; the request Host is never reflected. Segment-boundary include prefixes select paths, exclusions win, and the original path and query are preserved. See [Canonical domain redirects](CANONICAL_DOMAINS.md).

This policy does not make combining existing routes behavior-neutral. A merged route also shares Host-forwarding, upstream, authentication, transforms, limits and every other route setting. In particular, changing `preserve_host` or `upstream_host` can change whether an incoming explicit port reaches the application. Qualify those cases before consolidating routes.

## Gateway error pages

When Hangang itself answers 403, 404, 502, 503 or 504 (no matching route, backend unreachable, policy refusal, capacity, timeout), it normally sends a short plain-text message. `settings.error_pages` replaces that body for every route, and a route's own `error_pages` replaces it for that route, status by status (a route page wins; otherwise the global page; otherwise the plain text). Responses produced by an upstream are never rewritten, and the status code and other headers are kept.

```json
{
  "settings": {
    "error_pages": {
      "502": {"content_type": "text/html; charset=utf-8", "body_file": "502.html"},
      "404": {"content_type": "text/html; charset=utf-8", "body": "<h1>Not found</h1>"}
    }
  },
  "http": [{
    "id": "api", "path_prefix": "/api", "backends": ["http://127.0.0.1:8080"],
    "error_pages": {"502": {"content_type": "application/json", "body": "{\"error\":\"bad_gateway\"}"}}
  }]
}
```

Each page needs `content_type` and exactly one of `body` (inline) or `body_file` (a file name relative to the gateway's error pages directory). Bodies are limited to 64 KiB. Files are read and checked when the configuration is activated, not per request; a missing or oversized file rejects the configuration, and later edits to the file take effect at the next activation.

Security: `body_file` is served to anonymous visitors, so it is confined to one directory the operator chooses at startup with `--error-pages-dir` (or `HANGANG_ERROR_PAGES_DIR`). The shared configuration cannot change this directory. Without it, every `body_file` is rejected and only inline `body` works. The path must be relative and may not contain `..` or `.`; absolute paths are rejected when the configuration is loaded. When the file is read, the path is resolved with symbolic links followed and must stay inside the directory, the final component is opened without following links, and the opened file must be a regular file (not a directory, device or pipe) of at most 64 KiB. Keep only public pages in that directory and never point it at a directory holding keys or databases.

Errors answered before routing by the management listener, TLS layer or connection admission are not covered.

### 한국어 요약

Hangang이 직접 만드는 403·404·502·503·504 응답(맞는 라우트 없음, 백엔드 연결 실패, 정책 거부, 용량 초과, 시간 초과)의 본문을 바꿀 수 있습니다. `settings.error_pages`는 모든 라우트에, 라우트의 `error_pages`는 그 라우트에만 적용되며 상태 코드마다 라우트 쪽이 우선합니다. 업스트림(백엔드)이 보낸 응답은 바꾸지 않습니다. 각 페이지에는 `content_type`과 `body`(직접 쓴 본문) 또는 `body_file`(오류 페이지 전용 폴더 안의 상대 파일 이름) 가운데 하나가 필요하고, 본문은 64 KiB까지입니다. 파일은 설정을 활성화할 때 한 번 읽어 검사하므로, 파일이 없거나 너무 크면 설정이 거부되고 파일을 고친 내용은 다음 활성화 때 반영됩니다.

보안 제약: `body_file`의 내용은 인증 없는 방문자에게 그대로 나가므로, 운영자가 게이트웨이를 시작할 때 `--error-pages-dir`(또는 환경 변수 `HANGANG_ERROR_PAGES_DIR`)로 정한 폴더 하나 안의 파일만 읽습니다. 이 폴더는 공유 설정으로 바꿀 수 없습니다. 폴더를 정하지 않으면 `body_file`은 모두 거부되고 직접 쓴 `body`만 쓸 수 있습니다. 경로는 상대 경로여야 하고 `..`나 `.`을 쓸 수 없으며, 절대 경로는 설정을 불러올 때 거부됩니다. 파일을 읽을 때는 심볼릭 링크를 따라간 실제 위치가 그 폴더 안이어야 하고, 마지막 이름은 링크를 따라가지 않고 열며, 연 파일은 64 KiB 이하의 일반 파일이어야 합니다(폴더·장치·파이프 거부). 이 폴더에는 공개해도 되는 페이지만 두고, 키나 데이터베이스가 있는 폴더를 지정하지 마십시오.
