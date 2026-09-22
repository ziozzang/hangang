# Activate and deactivate

HTTP routes, TCP routes, file certificate entries and the global cache policy accept `enabled`. It defaults to `true`; normal serialization omits `true` for compatibility with earlier configuration files. `false` remains in the saved document and survives reloads and restarts. The console provides dedicated actions rather than requiring deletion or JSON editing.

```json
{
  "http": [{
    "id": "shared-site",
    "enabled": false,
    "hosts": ["foo.com", "www.foo.com"],
    "backends": ["http://127.0.0.1:8081"]
  }],
  "tcp": []
}
```

A disabled HTTP route is skipped before matching or body inspection. Its policy, domains and backends remain configured; another enabled matching route can still serve the request. Disabling a route is therefore not a domain-wide deny rule. Already selected requests and streams can finish. Disabled routes do not start new active-health probes or Docker discovery requests; in-flight work can complete or be cancelled as the new snapshot is observed.

A disabled TCP route does not reserve its listen port or participate in SNI selection. A shared listener stays open for its other enabled SNI routes. Removing the last active route closes that listener for new connections while existing streams drain. Reactivating performs normal listener preparation: if another process owns the port, activation fails and the previous configuration/revision remains active. Docker discovery can require its next refresh before a reactivated Docker backend becomes available.

A disabled certificate entry is excluded from that instance's configured TLS resolver. It does not revoke the certificate or stop a separate ACME issuer renewing it. Other enabled/default certificates may still be selected. Certificate actions affect the current instance; an HTTP-only instance cannot change a separate HTTPS instance's TLS binding. Re-enabling requires the certificate/key files to validate before publication.

Setting `cache.enabled` to `false` retains memory/disk limits and other policy while disabling the cache runtime for new requests. Re-enabling restores that policy. This action does not promise a cache purge; use the purge operation when invalidation is intended.

All changes use existing administrator-only revision/CAS writes. Viewer accounts cannot toggle configuration. Invalid metadata remains invalid even when disabled; activation is not a way to bypass configuration validation. Kubernetes-controlled instances retain their controller-owned write restrictions, and shared configuration stores propagate these flags using their existing revision mechanism.

Earlier binaries do not understand `enabled:false`. A rollback must not remove it silently, because that would reactivate traffic. The guarded release procedure refuses such a rollback until the configuration is explicitly made compatible.

## 한국어

HTTP/TCP 라우트, 인증서 항목, 전역 캐시 정책을 삭제하지 않고 활성/비활성으로 전환할 수 있다. 설정값은 저장되며 새 요청에 반영된다. 비활성 HTTP 라우트 대신 다른 활성 라우트가 매칭될 수 있고, 공유 TCP SNI 리스너는 나머지 활성 라우트를 계속 처리한다. 기존 스트림은 유지되며 다시 활성화할 때 포트 충돌이나 인증서 오류가 있으면 이전 설정을 유지한다.

인증서 비활성화는 현재 인스턴스의 TLS 선택만 변경한다. 별도 ACME 발급기의 갱신이나 다른 HTTPS 인스턴스를 중지하지 않는다. 캐시 비활성화도 정책을 보존하며 데이터 삭제를 의미하지 않는다.
