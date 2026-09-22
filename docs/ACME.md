# Native ACME certificates

Hangang's acme module issues and renews certificates through ACME v2 using
the instant-acme client. The default directory is Let's Encrypt production;
operators should select staging while testing. A custom directory must be an
HTTPS URL. ZeroSSL is supported through its production directory and requires
an EAB KID and base64 or base64url encoded HMAC key.

Construct an AcmeConfig only after the operator has enabled certificate
management. AcmeConfig::new requires at least one DNS name and an account
path. AcmeEngine::new validates the names and paths before contacting the
directory, restores the account, or registers it. The account file is a
bounded JSON envelope containing the PKCS#8 account key and server account
credentials. It is written through a synced temporary sibling and rename with
mode 0600. The key is persisted before a normal (non-EAB) registration, so a
crash after account creation can recover the same account key. EAB
registrations use the client-generated key and persist the returned credential
atomically after registration; do not delete that file between restarts.
For a private or test CA, set `ca_path` to its PEM root bundle; the default
bundled WebPKI roots remain in use when it is omitted.

The root public HTTP listener should create one Arc<HttpChallengeStore> and
pass it to the engine. Before routing an ordinary request, call
store.response(&request). If it returns a response, send it directly;
otherwise continue normal routing. The store only answers:

    GET /.well-known/acme-challenge/{token}

for the exact normalized Host and token that the engine installed. It is
bounded to 4096 active challenges, does not answer other methods or paths, and
the engine removes entries after each order. `with_shared(store)` attaches a
`ConfigStore`: an insert then succeeds only once the store has acknowledged
the token's publication (three bounded attempts), the record is refreshed
while the token is installed, and a local miss falls back to a bounded store
lookup, so any instance of a fleet can answer the CA (see "Multiple
instances" below). Each installation of a token carries an ownership id and
the publication, refresh and withdrawal of one token are serialized in the
store itself — a mutation that misses its 5-second acknowledgement is awaited
(up to 30 seconds) rather than dropped, and one that outlives that limit keeps
the token's lock until the store has finished it — so reinstalling or removing
a token while a mutation of it is in flight never loses the newer record, and
an insert reports success only for an installation that is published and
still current. HTTP-01 is suitable for ordinary names. Wildcards always
use DNS-01; configuring HTTP-01 with a wildcard is rejected.

DNS-01 uses the DnsProvider trait. CloudflareDnsProvider calls the Cloudflare
v4 HTTPS API with a bearer API token. WebhookDnsProvider is the generic
adapter for an operator-owned HTTP DNS service and sends present/delete
requests with a bearer credential. A present response must contain an exact
{ "id", "name", "value" } receipt. The provider stores receipts in memory and
refuses to delete an ID it did not create or whose name/value changed. The
engine waits for the exact TXT value through the provider's bounded,
cancellation-aware propagation poll before notifying ACME. Credentials are
held in memory and are never included in Debug output or logs. The built-in
DNS-over-HTTPS resolver can be replaced in tests with a TxtResolver.

CertificateSink::publish is the root SNI publication callback. The engine
parses the complete returned chain and private key together, checks every
requested DNS name (including wildcard semantics), checks that the leaf is
currently valid, and only then calls the sink. If certificate and key paths
are configured, each is written atomically before that callback. The existing
last-good TLS configuration therefore remains responsible for retaining the
live configuration when an interrupted write or callback fails.

AcmeEngine::run performs an initial issuance when no usable certificate is
present, renews inside the configured renewal window (30 days by default), and
uses capped exponential retry backoff. Every ACME, DNS propagation, and sleep
operation observes the supplied CancellationToken. Callers should cancel the
task during listener shutdown before dropping the challenge store.

For mounted dynamic configuration, use load_config_file for one validated read
or watch_config_file for a bounded polling watcher. The JSON schema uses
directory values letsencrypt-production, letsencrypt-staging,
zerossl-production, or an HTTPS URL; challenge values auto, http-01, and
dns-01; and duration fields ending in _secs. The watcher sends a validated
Result<AcmeConfig, String> on its watch::Receiver; the controller can stop and
replace the renewal task when a new configuration is received. Invalid
replacements are reported on the channel and never replace the active engine.

Use a Let's Encrypt staging directory and test-owned DNS zone or webhook in
integration tests. `tests/acme_fixture.py --start` starts only already-local
Pebble and pebble-challtestsrv images on an isolated Docker network, prints the
test directory, CA bundle, and management endpoint as JSON, and removes both
containers/network on termination. Set `HANGANG_PEBBLE_TEST=1` to run the
opt-in Rust integration tests; without the variable they perform no network
operation. The implementation does not contact a production CA or change DNS
until an explicitly enabled engine is constructed with real directory/provider
configuration.

## Gateway runtime

For a gateway that serves several certificate groups through `--config-tls`,
`hangang-acme-issuer` can run separately from the public gateway. Start one
issuer process per group with distinct private account paths and output
directories. Each accepts `--config /absolute/private/issuer.json`; an
optional `--check` validates paths and private inputs without contacting ACME
or DNS. Configuration is polled every two seconds: a valid replacement cancels
and joins the previous order before starting another; invalid replacements
retain the last usable settings. Failures use bounded retry backoff and are
logged. Private configuration, Cloudflare token and account directories must
be accessible only to the process owner.

An issuer configuration uses the ACME duration fields below plus
`output_directory`. DNS-01 also requires `"dns":{"provider":"cloudflare",
"zone_id":"...","token_file":"/absolute/private/token"}`. HTTP-01 omits
`dns`, requires `"challenge":"http-01"` and a process flag
`--http-listen 0.0.0.0:8081`; route only
`/.well-known/acme-challenge/<token>` from public port 80 to this listener.
The issuer serves GET with the exact token and Host only; all other requests
return 404. Connection, header and request lifetime limits apply. Wildcard
names require DNS-01. A DNS provider instance has one fixed Cloudflare zone
ID: use separate issuers for different zones, or HTTP-01 where appropriate.

The issuer holds the per-account advisory file lock across issuance and pair
publication. It validates the returned chain and key, writes both into a
private synced immutable `generation-*` directory, then atomically replaces
the relative `current` symlink. Configure gateway `cert_file` and `key_file`
as absolute paths to `output_directory/current/cert.pem` and
`output_directory/current/key.pem`, mounting the directory read-only on
gateway replicas. The gateway's `--config-tls` watcher validates the complete
pair before swapping; a read across the pointer switch can be inconsistent,
in which case it keeps the previous certificate and retries. Old generation
directories remain as local rollback material. A failed output publication
can require another ACME order after an issuer process crash; ensure the
output directory is writable and backed up, and monitor renewal expiry.


Enable certificate management explicitly with a private, dynamically reloaded JSON file:

```sh
hangang --listen 0.0.0.0:443 --acme-http-listen 0.0.0.0:80 \
  --acme-config /data/acme.json --config /data/routes.json --supervised
```

Set `HANGANG_ADMIN_TOKEN` and keep administration on loopback or configure admin TLS. The process user needs permission to bind the selected ports and write the account directory. Container port mappings may forward public ports 80/443 to unprivileged internal ports instead. HTTP-01 requires public port 80 to reach the challenge listener. That listener only serves owned challenge tokens and returns 404 for other requests; it does not expose administration or proxy arbitrary traffic.

The sample [Compose deployment](DEPLOYMENT.md) leaves ACME disabled and publishes
only its base HTTP listener. Enabling HTTP-01 or HTTPS there requires explicit
additional port mappings, private ACME account storage under the writable state
directory, and certificate paths readable inside the container. Do not assume
that creating a listener in the JSON document publishes its container port.

Example `/data/acme.json` for ordinary names:

```json
{
  "directory": "letsencrypt-staging",
  "domains": ["app.example.com"],
  "account_path": "/data/account.json",
  "challenge": "http-01"
}
```

For wildcard DNS-01, omit `--acme-http-listen` and configure the provider:

```json
{
  "directory": "letsencrypt-staging",
  "domains": ["example.com", "*.example.com"],
  "account_path": "/data/account.json",
  "challenge": "dns-01",
  "dns": {
    "provider": "cloudflare",
    "zone_id": "0123456789abcdef0123456789abcdef",
    "token_file": "/run/secrets/dns-api-token"
  }
}
```

The token needs permission to manage DNS records in the selected zone. A provider webhook is also supported using `provider: "webhook"`, `endpoint: "https://dns-service.example.com/acme"`, and `token_file`. The webhook contract is described above. Credentials are read from files and are not returned by the management API.

Select `directory: "zerossl-production"` and supply both `eab_kid` and `eab_hmac_key_base64` for ZeroSSL external account binding. Store the configuration as a private secret because these fields contain account credentials. Use separate account paths when changing CA directories. Enabling the engine agrees to that directory's account terms; review the selected CA's terms before operating it.

The runtime stores `/data/account.tls.json` alongside `/data/account.json`. This private bundle contains the complete certificate and key and is synced and atomically renamed before publishing TLS. Do not configure the module's separate `certificate_path`/`private_key_path` fields in runtime mode. Preserve the account and bundle across container upgrades. Restart restoration validates the bundle before enabling its SNI names; an unavailable CA does not require re-registering or reissuing a still-usable certificate.

The configuration and DNS credential file contents are checked every 500 ms. Valid changes cancel the preceding issuance task before replacing it. Invalid replacements retain the active settings and certificate. `/v1/status` includes an `acme` object with enabled state, domain names, phase, expiry, `tls_available`, `bundle_digest` and `last_error`; the embedded UI displays it. `last_error` is the full error of the most recent failed issuance attempt (for example a shared store that would not accept the HTTP-01 token) and is cleared by the next successful attempt or loaded bundle; on a follower it reads "ACME account is being managed by another process". Every failed attempt is also logged (at warn, or at info when it only lost the account lock). `tls_available` is true only while a validated, unexpired certificate for the configured domains is loaded in the public resolver: it is false from start until the first bundle is restored or issued (HTTPS handshakes fail during that gap), and it drops back to false when the loaded certificate expires without a renewal. `bundle_digest` is the SHA-256 (hex) of the bundle file whose material is loaded, empty when none is. Private keys, tokens and EAB credentials are omitted.

The bundle file itself is checked every 5 seconds. A bundle written by another process (a second instance sharing the volume, or a manual restore) is validated off the executor and published to the resolver as soon as its digest changes; a replacement that fails validation is logged, parsed once, and the previous certificate stays in service. The watcher never schedules an order by itself: only this instance's own renewal schedule (and a settings change) does, so a foreign or corrupt file at a shared path cannot turn into repeated CA orders.

A per-account file lock serializes issuance on shared local state. Supervised replacement freezes the renewal task before exporting the challenge listener, and a failed candidate resumes the preceding generation. Existing TLS connections retain their negotiated certificate. Manual public TLS, Kubernetes Secret TLS and ACME TLS are mutually exclusive listener configurations in this release.

## 한국어 운영 안내

`--acme-config`로 명시적으로 활성화하며 일반 도메인은 HTTP-01, 와일드카드는 DNS-01을 사용한다. HTTP-01은 인터넷의 80번 포트가 `--acme-http-listen`으로 도달해야 한다. DNS 공급자는 Cloudflare 또는 인증된 HTTPS webhook을 지원한다. 공급자 토큰은 파일에서 읽으며, JSON 설정과 토큰 변경을 500ms 주기로 확인한다. ZeroSSL은 EAB KID와 HMAC 키를 함께 지정한다.

계정과 인증서·개인 키 번들은 쓰기 가능한 영속 디렉터리에 보관한다. 발급 실패나 잘못된 설정 교체 중에는 마지막으로 검증한 인증서를 유지한다. 상태 API와 웹 화면에서 발급 단계·도메인·만료 시각·`tls_available`·`bundle_digest`를 확인할 수 있다. 여러 인스턴스를 운영할 때는 공유 설정 저장소(`--database`)로 HTTP-01 토큰을 공유하고, 계정·번들 경로를 공유 볼륨에 두어 잠금 보유자 한 곳만 발급하게 하며, 나머지 인스턴스는 5초마다 번들 파일 변경을 감지해 인증서를 새로 적재한다(아래 "Multiple instances" 절 참고). 공유 모드에서는 저장소가 토큰 게시를 확인(최대 3회 시도)한 뒤에야 CA에 검증 준비를 알리며, 게시가 끝내 실패하면 해당 발급 시도는 오류로 중단되고 `last_error`에 이유가 남는다. 게시된 레코드는 주문이 끝날 때까지 주기적으로 갱신되므로 검증이 늦게 도착해도 어느 인스턴스에서든 응답할 수 있다. 실제 운영 전 도메인·공급자·네트워크 경로에 맞춘 검증이 필요하며, 개발 검증은 소유한 테스트 CA와 컨테이너에서만 수행한다.

Pending DNS cleanup receipts are bounded to 4096 per provider, with bounded record fields. New DNS mutations fail before contacting the provider when this bookkeeping budget is exhausted. This prevents repeated cleanup failures from growing retained memory without bound. Provider errors can still leave TXT records, and process-crash recovery of those receipts is not a distributed transaction guarantee.

### Multiple instances

Running several instances behind one load balancer needs four things to hold; each is covered by a different mechanism.

**Shared HTTP-01 tokens.** The CA's validation request for `/.well-known/acme-challenge/<token>` lands on an arbitrary instance. When a shared configuration store is configured (`--database`, SQLite on a shared path, PostgreSQL or Redis), every token the issuing instance installs is also published to the store under an opaque key derived from both the canonical host and token, with `<host> <key authorization>` as its value, and withdrawn when the order ends. Including the host in the storage identity prevents a token reused for two authorizations from overwriting or withdrawing the other host's record and lets the listener's full 256-character token limit fit stores whose key input is shorter. This storage-key format is incompatible with earlier builds that keyed shared challenges by the raw token: coordinate issuer and fleet upgrades while no HTTP-01 validation is in flight; previous and current builds cannot answer each other's shared tokens. The publication is acknowledged before the CA is told the challenge is ready: the issuer makes up to three attempts (a transport failure the store reports within 5 seconds is retried after 250 ms; a rejection of the content is not), and if the store still has not accepted the record the authorization is aborted with an error naming the host and the store failure, nothing is left installed locally, and the attempt is retried on the normal backoff schedule. A publication or withdrawal the store has not answered within 5 seconds is not dropped and not retried in parallel, because its write may still land (SQLite work runs on a blocking thread, a network store may still apply the request): it is awaited for up to 30 seconds from its start and its late outcome counts, and one that has not finished by then is abandoned to the background together with the token's mutation lock, which it releases only once the store has actually completed it. The insert then fails (the abandoned write, should it land, is a record for a token nothing will validate, and it expires on its own), and no later publication or withdrawal of that token can interleave with the abandoned write. The store is therefore on the issuance path in this mode: while it is down, no HTTP-01 order completes, but no order can be validated against an instance that would answer 404 either. Records are published with a 10-minute lifetime and re-published at half of it for as long as the token is installed (an order may legitimately run up to `acme_timeout_secs`), so a validation that arrives late in the order still finds the record on every instance; a failed refresh is retried more often and logged, and records left behind by a crashed instance expire on their own. Each installation of a token carries an ownership id, and a token's publication, refresh and withdrawal are serialized: reinstalling the same token publishes the new record only after a publication, refresh or withdrawal still in flight has completed in the store, a refresh that was overtaken by a replacement leaves the replacement's record alone, a failed publication rolls back only its own installation, and a removal withdraws the record only after any in-flight mutation and only while no newer installation exists. An insert reports success only when its installation is published and still the token's current one; an installation that was reinstalled or removed before or while it was published fails as superseded, so an issuer never marks a challenge ready on the strength of a record the fleet will not serve. Waiting for a token's previous mutation is bounded by the same 30 seconds: a reinstallation that cannot get its turn by then fails, and an individual removal skips its withdrawal when it cannot get a turn. Order cleanup first stops every local response and refresh, then withdraws at most eight shared records concurrently under one 30-second overall deadline. Mutations already launched retain their token locks and finish in the background; withdrawals that have not started are skipped, logged once, and left to the 10-minute TTL. A stopped shared store therefore delays certificate publication and release of the issuer lock by at most 30 seconds for HTTP cleanup, independent of the number of authorizations. An instance that does not own a token looks it up in the store on a local miss and answers only when the stored host equals the request's `Host`; a record without a host is never served. The lookup from the public listener is bounded to 2 seconds, at most eight are in flight at once, and it answers 404 on timeout or store failure (at most one warning per 30 seconds, so probes against a broken store do not flood the log). Without a store, tokens stay process-local, no acknowledgement is involved, and public port 80 must reach the issuing instance deterministically.

**One issuer.** Put the account path (and therefore the account lock `<account>.acme.lock` and the bundle `<account>.tls.json`) on a volume shared by all instances. The per-account file lock lets exactly one instance place orders; the others fail their attempt at the lock without contacting the CA and retry with backoff. The lock needs a filesystem that honours advisory locks across the participating hosts; instances with separate local volumes each issue independently and do not coordinate.

**Follower bundle refresh.** Every instance checks the bundle file every 5 seconds and loads a bundle whose digest changed, so a renewal written by the lock holder is served by the others within that interval without an order of their own. A bundle that fails validation (different domain set, corrupt file) is parsed once, logged, and the previous certificate stays loaded; it does not trigger an order. Instances sharing a bundle path must therefore run the same domain set, otherwise each one keeps overwriting the other's bundle on its own renewal schedule.

**DNS-01 alternative.** With DNS-01 no instance needs port 80 and no token sharing is needed: the shared volume plus the lock still keeps issuance to one instance, and the bundle refresh distributes the result. Wildcards always use DNS-01.

**First-issuance HTTPS gap.** Until the first bundle exists, the public resolver holds no certificate and every HTTPS handshake fails although the instance is otherwise running; `acme.tls_available` in `/v1/status` is false during that window (and again once a loaded certificate has expired). Load balancers that health-check over HTTPS see the gap directly; those that check the admin endpoint can use `tls_available` to keep an instance out of rotation until its certificate is loaded. Followers close the gap as soon as the issuer's bundle appears on the shared volume.

There is no issuer election: the lock holder is whichever instance took the lock first, and a lost shared volume returns instances to independent local state.

## Standalone DNS issuer recovery

The standalone `hangang-acme-issuer` keeps the same Cloudflare provider and its pending cleanup receipts across retries while its configuration is unchanged. If Cloudflare rejects a repeated TXT presentation with HTTP 400 after a process restart, the issuer queries that exact challenge name and key-authorization value. It adopts a receipt only when exactly one matching record exists, then verifies the record again before deletion. It never deletes an unrelated TXT record based on its name alone. Issuance logs show the authorization identifier, challenge type, presentation, propagation, readiness, certificate receipt, cleanup completion, and a bounded retry delay; they omit challenge values, credentials, private keys, and ACME authorization URLs.

Cleanup receipts are not durable across a crash. If the CA gives the restarted issuer a **different** authorization value, a TXT record left by the crashed attempt cannot be proven to belong to the new attempt and is not automatically deleted. Operators should inspect the DNS provider's record metadata and remove only records they can independently attribute to that issuer. Avoid concurrent issuers for the same account and zone. Credential file replacement alone does not change a cached provider during an active retry sequence; replace the issuer configuration to reload the provider, after the previous attempt has ended.
