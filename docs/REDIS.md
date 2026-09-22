# Redis configuration store

Hangang can use Redis as a shared whole-configuration store through
`RedisConfigStore`. The store keeps one versioned string under the caller's
key, laid out as `hangang-config-v2\n<epoch>\n<revision>\n<json>`. Bootstrap
is an atomic insert-if-empty operation that also creates the authority epoch
(32 hex characters). Compare-and-swap is a single Redis Lua script that
compares the epoch and the canonical decimal revision string and replaces the
complete value only when both match; a value that already holds the identical
document at `revision + 1` is reported as applied, so a retry after a lost
acknowledgement is not a false conflict. This preserves every `u64` revision,
including values above JavaScript's safe integer range. Values written by
earlier releases (`hangang-config-v1`, no epoch) are upgraded in place on the
first read, atomically, with one winner when several instances race.

ACME HTTP-01 challenge tokens are shared under `<key>:acme:<token>` with a
TTL, so any instance behind a load balancer can answer a validation request.
The configuration key must not contain the reserved `:acme:` separator; a
deployment using such a key must choose a new key before upgrading.
Run Redis with `maxmemory-policy noeviction` for this key space: an evicted
configuration key is reported as `missing` and withdraws every instance after
`--store-grace-seconds`.

Use `RedisConfigStore::connect` with a verified `rediss://` URL for remote
Redis. The redis crate's web PKI roots are used by default. For a private CA,
use `RedisConfigStore::connect_with_ca(url, key, ca_pem)`; the supplied PEM
chain is installed through the redis crate's `TlsCertificates` API and
hostname verification remains enabled. URLs containing the redis crate's
`#insecure` option are rejected.

Plaintext is an explicit development and test mode:
`RedisConfigStore::connect_unencrypted` accepts `redis://` only when its host
is the literal `localhost` or a loopback IP address. It does not permit a
remote DNS name, even when that name happens to resolve to a loopback address.

Encoded configuration JSON is limited to 1 MiB. Redis values include a small
versioned wire header and are rejected before decoding when they exceed that
bound. Malformed schema, noncanonical revisions, revision mismatches, invalid
JSON, and invalid configuration values are errors; the previous valid value
is never silently accepted.

The disposable integration fixture creates one uniquely named loopback-only
Redis container, including a TLS listener, and removes that container when the
run ends. It never discovers or changes existing containers:

```sh
python3 tests/redis_fixture.py
```

The regular test suite skips the Redis integration tests. The fixture runs
them with `--include-ignored` and supplies `HANGANG_TEST_REDIS_*` variables.

## Command-line runtime

Use `--database rediss://redis.example:6379/0 --redis-key hangang:config` (or `HANGANG_DATABASE`). `--database-ca /path/to/ca.pem` installs a private root. `--database-plaintext` is an explicit local-development override. The seed file is read only when bootstrapping an empty key; committed Redis revisions then become authoritative and are polled every 500 ms. API writes use the same ETag/CAS contract as other shared stores. The fixture also verifies two real gateway processes conflicting, refreshing and restarting against the owned Redis instance.

## 한국어

Redis는 검증된 TLS로 접속하고 하나의 키에서 전체 설정 revision을 원자적으로 비교·교체한다. 큰 u64 revision도 문자열 비교로 정밀도를 보존한다. 실제 테스트 전용 Redis의 TLS·잘못된 CA·재접속·경합과 두 게이트웨이 프로세스의 충돌·동기화·재시작을 검증했다. 장애 중에는 각 프로세스의 마지막 정상 설정을 유지한다.
