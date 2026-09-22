# Native HTTP language preference policy

[Documentation](README.md) · [한국어 안내](README.ko.md)

HTTP routes can configure `language_policy` independently of console translation, gateway authentication and country lookup. It inspects the incoming `Accept-Language` preference signal. A client can change that signal; it is not an authenticated identity or geographical restriction.

```json
{
  "id": "language-gated",
  "path_prefix": "/",
  "backends": ["http://127.0.0.1:8080"],
  "language_policy": {
    "mode": "preferred",
    "allow": ["ko", "en"],
    "deny": ["en-US"],
    "on_missing": "deny",
    "enforce": true
  }
}
```

`mode` and `on_missing` are required. `allow` and `deny` default to empty lists; their combined length must be 1–32. Each configured basic language range is at most 128 ASCII bytes, with 1–8 alphabetic characters in the first subtag and 1–8 alphanumeric characters in subsequent hyphen-separated subtags, or `*` alone. Matching ignores ASCII case. Duplicate ranges within either list are invalid; an overlap between allow and deny is legal and deny wins. Unknown configuration fields fail validation.

`mode:"any"` considers every positive-quality preference. `mode:"preferred"` considers only entries tied at the highest positive quality, including a wildcard if it has that quality. Header order does not break ties. Configured `ko` matches a client preference `ko-KR`; configured `ko-KR` does not match a client preference `ko`. Configured `*` matches every considered preference. A client `*` only matches a configured `*`, and never supplies evidence of a named language. A matching deny range refuses the request; otherwise an empty allow list passes a nonempty considered preference set, and a nonempty allow list requires at least one match.

A missing header follows explicit `on_missing:"allow"|"deny"`. A present empty header or a header containing only `q=0` entries is denied even by a deny-only policy. Zero quality entries are excluded from classification. This classifies the explicit client ranges; it does not expand every possible language implied by a broad range or perform content-language negotiation. For example, `ko;q=1,ko-KR;q=0` still expresses a positive `ko` preference while excluding `ko-KR`; it is not a reliable statement of the client's actual language.

Repeated header field lines are combined as a list within a 4,096-byte bound including separators. At most 32 ranges are accepted. Malformed values, empty list elements, duplicate case-insensitive ranges or exceeded bounds return HTTP 400; a valid but denied preference returns HTTP 403. The grammar and basic matching follow [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4) and [RFC 4647](https://www.rfc-editor.org/rfc/rfc4647.html#section-3.3.1). Strict duplicate rejection and weighted filtering are explicit product policy choices.

The policy applies to the already-selected route, before response-cache lookup, Lua and upstream execution. A denial does not continue to a lower-priority route. It is a route admission rule, not a host-wide namespace guard. Where public shadow routes must not bypass a protected resource, configure the existing `resource_policy` namespace boundary; routes sharing one resource ID must also share the exact language policy. Language refusal can precede the authentication challenge and does not imply any authentication result.

`enforce:false` keeps and validates the configuration while bypassing language parsing and enforcement. Removing the optional policy disables this filter. Changing this preference rule does not replace or release an enforced resource namespace. Existing governed configuration writes, live publication and route cache fingerprints apply to the policy. Established streams are not reclassified midstream by a later language-policy change.

The English/Korean route editor provides configure, enable/disable and remove controls, mode, missing-header behavior and allow/deny lists. Advanced JSON retains the same wire representation. Country lookup and country policy remain separate work; this feature does not implement GeoIP.
