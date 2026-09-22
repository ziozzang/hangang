# Canonical domain redirects

[Documentation](README.md) · [한국어 안내](README.ko.md)

An HTTP route with an exact `host` or a `hosts` domain group can declare one member as its canonical host. Hangang answers selected requests with the configured 301, 302, 307 or 308 redirect when the effective host differs. The scheme selects the redirect destination; requests already using the canonical host are unchanged. Use `require_tls` separately to enforce HTTPS on that host. The configured target is fixed; Hangang never copies an untrusted `Host` value into the redirect. It preserves the original path and query string.

This is an operator redirect policy. It does not share cookies, login sessions, certificates, cache entries or application state between names. Provision every public name and certificate separately, and confirm the application's cookie-domain and callback policy.

Prefixes match a complete path segment. `/wp-admin` matches `/wp-admin` and `/wp-admin/...`, but not `/wp-administrator`. Exclusions win. Matching is bytewise, without percent decoding by this policy, and uses the request path without its query (or the normalized path already supplied by an enforced resource guard); query strings remain on the resulting `Location`. Backslashes, whitespace, dot segments, controls, query and fragment characters are rejected in configured prefixes. Each list permits at most 32 distinct entries, each prefix is at most 2,048 UTF-8 bytes, and the two lists together are at most 64 KiB. An exact prefix cannot appear in both lists.

For an application whose login form uses the canonical host, redirect the interactive login and administration pages before it sets host-only cookies. Keep AJAX and form handlers on their requested host:

```json
"canonical_domain": {
  "enabled": true,
  "host": "example.com",
  "scheme": "https",
  "status": 302,
  "path_prefixes": ["/wp-login.php", "/wp-admin"],
  "exclude_path_prefixes": [
    "/wp-admin/admin-ajax.php",
    "/wp-admin/admin-post.php"
  ],
  "methods": ["GET", "HEAD"]
}
```

Use 302 while verifying host aliases, TLS, application URLs and excluded callback behavior. Choose a permanent status only after that rollout is complete. A disabled policy stays in the route document but does not redirect. Removing it deletes the field on the next route save.

Only GET and HEAD are supported; login POST bodies are never redirected by this policy. Native redirects return `Cache-Control: no-store` so later policy changes can take effect without a cached redirect. They run after resource-namespace and workload-listener checks, before route authentication and upstream access, like the existing HTTPS redirect.
