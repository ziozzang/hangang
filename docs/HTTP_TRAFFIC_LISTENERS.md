# HTTP request listener attribution

[Documentation](README.md) · [한국어 안내](README.ko.md)

`GET /v1/traffic` identifies the listener that accepted each recorded HTTP request independently of the route it matched. A route shared across ports can therefore produce records under several listener IDs. Recorded unmatched requests and admission failures retain their accepting listener when that information is available.

| `listener.kind` | `listener.id` | Meaning |
| --- | --- | --- |
| `default` | `default` | The CLI HTTP listener. |
| `public` | Named public listener ID | A configured HTTP/HTTPS listener. |
| `workload` | Workload listener ID | A dedicated workload mTLS listener. |
| `unknown` | `null` | Trusted listener information is unavailable. |

The server derives attribution from connection metadata, not client headers, a forwarded host, route ID, or TLS flag. It identifies the accepting transport; it does not grant access or identify a certificate subject. Missing or malformed provenance appears as unknown rather than being assumed to be the default listener.

Status → Recent requests shows the listener below the route and in request details, with English/Korean labels. Search accepts listener IDs or `listener:edge`. Records are captured at response headers, subject to [HTTP recording policy](HTTP_RECORDING.md), in a bounded process-local ring. They do not include query strings, request headers, or payloads, and are neither a durable access audit nor a measure of body-completion time. Health-probe responses retain their existing exclusion.
