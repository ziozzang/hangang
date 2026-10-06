# Domain response security

[Documentation](README.md) · [한국어](ko/RESPONSE_SECURITY.md)

The administrator Settings menu provides **Response security** rules with explicit host patterns, a same-host HTTPS downgrade checkbox and security header lines. Add a rule and select its domains before using the conservative preset. Rules are opt-in; an empty list changes nothing. Publish through the existing revision-checked full configuration flow.

## Configuration

```json
{
  "settings": {
    "response_security": [{
      "hosts": ["example.test", "www.example.test"],
      "upgrade_same_host_redirect": true,
      "headers": {
        "strict-transport-security": "max-age=300",
        "x-content-type-options": "nosniff",
        "x-frame-options": "SAMEORIGIN",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=(), microphone=(), geolocation=()"
      }
    }]
  }
}
```

Profiles apply at the final public HTTP response boundary to every status, including redirects and early policy/authentication denials. Separate administrator responses are unaffected. Required `hosts` contains 1–16 existing host/IP patterns; `*` and `?` stay within a hostname label. There are at most 128 rules and 32 KiB aggregate host/header text. Matching profiles are processed in configuration order: later header values override earlier ones, and redirect upgrading is enabled if any matching profile enables it.

Header names are case-insensitive and restricted to `strict-transport-security`, `x-content-type-options`, `referrer-policy`, `x-frame-options`, `content-security-policy`, `content-security-policy-report-only` and `permissions-policy`. Values are at most 4,096 bytes and cannot contain control bytes; duplicate canonical header names are rejected. Missing `headers` means an empty map; missing `upgrade_same_host_redirect` means false. Other headers remain under existing response-header configuration.

## HTTPS and application compatibility

HSTS is emitted only for verified HTTPS, including trusted forwarding evidence where configured. Start with the short host-only `max-age=300` preset; it includes neither `includeSubDomains` nor `preload`. Review TLS coverage and application behavior before increasing retention. The gateway does not automatically extend a policy to other domains.

The downgrade checkbox changes an absolute `http://` Location only when the request was verified HTTPS, the destination hostname is the same and its HTTP port is the default 80. External hosts, relative redirects and explicit nondefault ports are preserved. This does not replace **Require TLS** or canonical-domain configuration for inbound plaintext requests.

The preset never adds CSP. Existing origin CSP remains intact unless the operator explicitly configures CSP here, which replaces that header. Review policies against the actual application content; frame restrictions, disabled browser permissions and referrer suppression can also affect integrations. The preset applies only to the selected domain rule and retains a CSP already entered in that rule.

## Metadata and file exposure

Response security headers do not remove application content. Use [URL blocks](PATH_BLOCKS.md) for known metadata endpoints or unnecessary files, scoped to the affected domains: for example `/readme.html` or `/license.txt` for a WordPress deployment. Verify the application's actual paths before adding DSM or other product-specific blocks. Blocks match an exact directory and slash-delimited descendants; they do not imply suffix, regular-expression or product-name matching. Preserve required authentication, health and integration endpoints.
