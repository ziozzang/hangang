# Application Lua policies

[Synology public SessionData minimization](synology-session-redact.lua) is an
application-specific policy using Hangang's existing JSON body helpers and the
generic `response_transform.when_prefix` gate. It is not a native DSM integration.

The observed `/webapi/entry.cgi` `SYNO.Core.Desktop.SessionData` `getjs` response
uses the exact literal `when_prefix` shown below, including the newlines and
one ASCII space after the final `=`.

Configure the source file's contents as `response_transform.lua`, not a filename:

```json
{
  "mode": "buffered",
  "when_prefix": "if (typeof(SYNO) === 'undefined') {SYNO = {};}\nSYNO.SDS = SYNO.SDS || {};\nSYNO.SDS.Session = ",
  "max_buffer_bytes": 16384,
  "max_output_bytes": 16384,
  "timeout_ms": 5000
}
```

Add the `lua` field containing the script to that object, then assign it to an
exact DSM host/path route for `/webapi/entry.cgi`. Retain its existing upstream,
authentication, listener, IP, header, and other policies. GET query and POST form
aliases producing this JavaScript representation use the same response gate.
Unrelated JSON, binary, and large responses that do not start with the prefix
stream unchanged instead of entering the 16 KiB Lua buffer. The `get` method's
ordinary error JSON remains unchanged; this example makes no claim to cover a
future JSON SessionData representation or a different JavaScript wrapper.

For `isLogined: false`, the script removes hostname, full version, version,
build phase, internal HTTP/HTTPS ports, and PostgreSQL upgrade status. It removes
inactive SSO provider names/URLs only when all known provider flags are explicitly
false. It preserves `isLogined`, `enable_syno_token`, login settings, and provider
control flags. Authenticated responses are returned byte for byte. This policy
minimizes selected fields, not every possible device fingerprint.

A matched malformed wrapper, unsupported required-field schema, oversized body,
or extra JavaScript statement fails closed through the normal transform error
path. The script parses JSON and never evaluates JavaScript. Error messages do
not contain response values. The conditional route still requires identity
response encoding, rejects ranges/partial representations, and bounds inspection
and transformation. Unmatched responses retain their original headers/trailers.

Removing version/port fields can affect vendor JavaScript after firmware changes.
Qualify the public login bootstrap without submitting credentials, then verify
normal authenticated use separately. Recheck the exact wrapper and dependent
login behavior after DSM upgrades. Apply the script through the configuration
API or file; editing this example alone does not change a running gateway.

Path-scoped response transforms also reserve a strictly canonical namespace on their selected hosts: ordinary encoded letters such as `%65` normalize into the same route, while encoded separators, double escapes, semicolons and repeated slashes are rejected. Other hosts are unaffected. A disabled transform route keeps this namespace reserved and returns 404 rather than falling back to an unredacted public route. Delete the route to release the namespace, or explicitly remove the response transform to remove its transform guard.
