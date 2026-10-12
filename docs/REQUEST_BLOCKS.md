# Request parameter blocks

[Documentation](README.md) · [한국어](ko/REQUEST_BLOCKS.md)

The administrator Security settings menu edits `settings.request_blocks` as JSON. This generic policy denies selected parameter patterns before authentication services, cache, Lua or origins. Conditions within a rule are AND; matching rules are OR. Empty configuration leaves requests unchanged. Publish through the existing revision-checked configuration flow. There is no new API, product registry, automatic cookie exemption or authentication bypass.

## Configuration

```json
{
  "settings": {
    "request_blocks": [{
      "path": "/control",
      "hosts": ["app.example.test"],
      "include_subpaths": false,
      "methods": [],
      "params": [{"name": "action", "values": ["delete"], "match": "exact"}],
      "max_body_bytes": 65536,
      "timeout_ms": 2000
    }]
  }
}
```

Paths use the existing canonical absolute-path rules; descendants require `include_subpaths:true`. Empty `hosts` means all hosts, with at most 16 existing hostname/IP patterns. Empty `methods` means all methods; explicit lists allow up to eight distinct GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS or TRACE values. At most 128 rules and 32 KiB aggregate policy text are allowed. Rules have 1–16 conditions with unique canonical ASCII names, 1–64 letters/digits/underscores/hyphens. Each condition accepts up to 128 distinct values of at most 4,096 UTF-8 bytes.

## Conditions

Empty `values` tests actual presence. `match` defaults to `exact`; `prefix` tests a literal prefix, `segment_prefix` requires exact equality or slash-delimited descendants, and `path_prefix` additionally canonicalizes the parameter path, accepting a missing initial slash. `case_insensitive` defaults false and uses ASCII case comparison. `strip_pattern` is an optional Rust regex of at most 256 bytes, with bounded compiled resources; it modifies comparison only, never the forwarded request.

`negate:true` matches missing values or any extracted value that does not match. `default_value` substitutes a comparison value only after complete parameter absence is established; it requires nonempty `values` and no `json_field`, is at most 4,096 bytes and never inserts a forwarded parameter. A negated read-only allowlist can therefore admit known reads and reject unknown commands, including future mutators.

`json_field` extracts named scalar leaves recursively from a parameter JSON object, array or encoded JSON string. Extraction is limited to depth 16, 1,024 nodes and 16 KiB decoded strings. Malformed JSON and duplicate JSON object keys, including unrelated keys, fail closed. This is generic extraction, not an application-specific parser.

## Parsing and resource limits

Scoped requests inspect query parameters, URL-encoded forms, multipart forms and top-level JSON parameters. Multipart bodies are fully inspected before origin forwarding so later control fields cannot evade inspection. Protected-name percent encoding is decoded; ambiguous PHP-style aliases or duplicate protected names are rejected. Unrelated bracket names and duplicates remain unchanged. Method-override headers/fields are rejected within the protected scope. Original accepted request bytes and headers are preserved. Configured request-body transforms still apply: the transformed representation is re-inspected under the original ingress policy scope, and its protected controls cannot reuse the original spool cache. A streaming body transform can require another disk inspection slot while retaining its source; exhausted capacity returns 503.

Queries accept at most 16 KiB/256 pairs; URL-encoded forms 256 pairs; multipart 256 parts, 4 KiB part headers and a 70-byte boundary. JSON parsing caps depth 16 and 1,024 nodes; protected scalar values cap 4,096 bytes and reject controls. Body inspection has four concurrent slots; empty/query-only requests do not consume them. The default body cap is 64 KiB and deadline 2 seconds; explicit values accept 1–16,777,216 bytes and 1–5,000 ms. Selected upload endpoints inherit those limits, including when no deny condition ultimately matches: consider legitimate larger uploads before enabling broad host/path rules. Unscoped uploads are unaffected. Matched rules return 403; malformed or ambiguous input 400, unsupported types/encodings 415, oversized input 413, deadline 408 and exhausted inspection capacity 503. These responses reveal no parameter values.


## Multipart disk inspection

Disk inspection requires Linux anonymous `O_TMPFILE` support on the selected filesystem. Non-Linux builds reject `multipart_spool` configuration; ordinary bounded memory inspection remains available on Linux and macOS. There is no named temporary-file fallback.

Add `multipart_spool` to every scoped request-block rule that can apply to the upload. Large known-length multipart bodies above the RAM cap and unknown/chunked multipart bodies then use private disk inspection; if any scoped rule lacks the opt-in, the original RAM cap remains. Matching rules use the minimum configured limits. JSON and URL-encoded forms retain their existing limits. Empty bodies and unscoped uploads are unchanged.

```json
{
  "multipart_spool": {
    "directory": "/data/request-inspection-spool",
    "max_body_bytes": 68719476736,
    "timeout_ms": 7200000,
    "idle_timeout_ms": 60000,
    "max_field_bytes": 65536
  }
}
```

Pre-create the directory on a writable private mount, mode 0700 and owned by the gateway process UID. Its absolute path is at most 2,048 bytes with no traversal or symlink components; the server validates filesystem descriptors. The gateway uses anonymous 0600 files and does not forward any upload bytes until the complete multipart syntax and protected controls have passed inspection. Allowed uploads replay their original bytes on demand. Binary file parts are retained, not scanned for application content; text controls are bounded by `max_field_bytes`.

Maximum disk body size is 64 GiB. The total deadline defaults to one hour and accepts up to two hours; the examples explicitly select two hours. Idle timeout defaults to 60 seconds, maximum 120 seconds; text fields default to and cannot exceed 64 KiB. Two shared inspection slots and a total 128 GiB disk quota remain owned while replay or byte references are live. Size rejects return 413, deadline/idle rejects 408, quota/I/O failures 503, malformed multipart 400. The shared RAM/disk parser rejects ambiguous boundaries and bare-LF grammar rather than applying permissive PHP-style reinterpretation. Configure capacity and mount permissions before publishing. Unsafe directory permissions, ownership or symlink paths fail validation; a filesystem that cannot create Linux anonymous files fails closed with 503 during inspection.

## Application examples

[WordPress and Mangboard configuration](../examples/security/request-blocks/wordpress.json) and [DSM configuration](../examples/security/request-blocks/dsm.json) are explicit operator examples with placeholder domains, not core product behavior. Merge arrays into the current configuration and review actual parameter names and workflows before publishing. The WordPress example blocks XML-RPC by path, user REST aliases and author enumeration, and demonstrates dangerous-action/user-mode predicates plus a read-only command allowlist. Its broad profiles explicitly opt into 16 MiB/5-second JSON/form limits and 64 GiB/two-hour multipart disk inspection; selected administrative controls still apply regardless of a login cookie.

The DSM example denies `SYNO.Auth.ForgotPwd` directly and through JSON fields in `compound` or `params`; explicit [path blocks](PATH_BLOCKS.md) also reserve known CGI aliases. It intentionally blocks the selected password-reset operation for every matching request. These examples preserve neither arbitrary third-party workflows nor assumed cookie-based authorization; qualify required login, list, search and read flows against the deployed application.
