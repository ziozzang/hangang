# Host patterns and route priority

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
