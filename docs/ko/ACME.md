# 네이티브 ACME 인증서

[문서 목차](../README.ko.md) · [English](../ACME.md)

Hangang의 ACME 모듈은 `instant-acme` client로 ACME v2 인증서를 발급·갱신합니다. 기본 directory는 Let's Encrypt production이므로 테스트 때는 staging을 선택하십시오. 사용자 directory는 HTTPS URL이어야 합니다. ZeroSSL은 production directory와 EAB KID 및 base64/base64url HMAC key를 요구합니다. 게이트웨이 배포는 [게이트웨이 런타임](#게이트웨이-runtime)부터 읽으세요. 다음 절은 Rust 모듈 통합 계약을 설명합니다.

## 모듈 통합

운영자가 인증서 관리를 활성화한 뒤에만 `AcmeConfig`를 만드십시오. `AcmeConfig::new`는 DNS name 하나 이상과 account path를 요구하고, `AcmeEngine::new`는 directory 접속·account 복원·등록 전에 이름과 path를 검증합니다. account 파일은 PKCS#8 account key와 server credential을 담은 크기 제한 JSON envelope이며, 동기화된 임시 sibling을 만든 뒤 mode 0600으로 rename합니다. 일반 등록은 account 생성 전에 key를 저장하므로 crash 뒤 같은 key로 복구할 수 있습니다. EAB 등록은 client 생성 key와 등록 뒤 받은 credential을 원자적으로 저장하므로 재시작 사이에 파일을 삭제하지 마십시오. private/test CA는 `ca_path`에 PEM root bundle을 지정하고 생략하면 WebPKI 기본 root를 사용합니다.

root public HTTP listener는 `Arc<HttpChallengeStore>` 하나를 만들고 engine에 전달해야 합니다. 일반 request routing 전에 `store.response(&request)`를 호출하고 response가 있으면 직접 보내며 없으면 정상 routing을 계속합니다. store는 engine이 설치한 정확한 정규화 Host와 token에 대한 다음 요청만 답합니다.

    GET /.well-known/acme-challenge/{token}

활성 challenge는 4096개로 제한되고 다른 method/path에는 답하지 않으며 order 뒤 engine이 항목을 제거합니다. `with_shared(store)`는 `ConfigStore`를 붙입니다. insert는 store가 token 게시를 확인한 뒤(제한된 3회 시도) 성공하고 설치 중 record를 refresh하며 local miss는 제한된 store lookup으로 fallback하므로 fleet의 어느 인스턴스도 CA에 답할 수 있습니다. token 설치에는 ownership id가 있고 게시·refresh·withdrawal은 store에서 직렬화됩니다. 5초 acknowledgement를 놓친 mutation은 버리지 않고 최대 30초 기다립니다. 그때까지 완료되지 않아도 store 작업이 실제로 끝날 때까지 token의 lock을 유지합니다. 따라서 한 token의 mutation이 진행 중일 때 다시 설치하거나 제거해도 더 새로운 record를 잃지 않으며, insert는 게시된 설치가 현재 설치일 때만 성공을 보고합니다. HTTP-01은 일반 이름에 적합하고 wildcard는 항상 DNS-01이며 wildcard에 HTTP-01을 지정하면 거부됩니다.

DNS-01은 `DnsProvider` trait을 사용합니다. `CloudflareDnsProvider`는 bearer API token으로 Cloudflare v4 HTTPS API를 호출하고 `WebhookDnsProvider`는 운영자 소유 HTTP DNS 서비스에 present/delete 요청을 보냅니다. present response는 정확한 `{ "id", "name", "value" }` receipt여야 합니다. provider는 receipt를 메모리에 보관하고 자신이 만들지 않았거나 name/value가 바뀐 ID는 삭제하지 않습니다. engine은 정확한 TXT 값이 전파될 때까지 취소 가능한 제한 poll을 수행합니다. credential은 메모리에만 있고 Debug/log에 나오지 않습니다. 테스트에서는 내장 DNS-over-HTTPS resolver를 `TxtResolver`로 바꿀 수 있습니다.

`CertificateSink::publish`는 root SNI 게시 callback입니다. engine은 반환된 전체 chain과 private key를 함께 parse하고 요청된 모든 DNS name과 wildcard, leaf 유효성을 확인한 뒤 sink를 호출합니다. 인증서와 key path가 있으면 callback 전에 각각 원자적으로 기록합니다. 중단된 write/callback에도 기존 last-good TLS 설정이 live 설정을 유지합니다.

`AcmeEngine::run`은 usable 인증서가 없으면 처음 발급하고, 기본 30일 renewal window 안에서 갱신하며 capped exponential retry backoff를 사용합니다. ACME, DNS propagation, sleep은 모두 `CancellationToken`을 관찰합니다. listener shutdown 때 challenge store를 버리기 전에 task를 취소하십시오.

동적 설정은 한 번 검증하는 `load_config_file` 또는 제한 polling watcher인 `watch_config_file`을 사용합니다. JSON의 directory는 `letsencrypt-production`, `letsencrypt-staging`, `zerossl-production`, HTTPS URL 중 하나이고 challenge는 `auto`, `http-01`, `dns-01`이며 기간 field는 `_secs`로 끝납니다. watcher는 `watch::Receiver`로 검증된 `Result<AcmeConfig, String>`을 전달합니다. controller는 새 설정을 받으면 renewal task를 중지·교체할 수 있고 잘못된 교체는 channel에 보고되지만 active engine을 바꾸지 않습니다.

통합 테스트는 Let's Encrypt staging directory와 테스트가 소유한 DNS zone/webhook을 사용하십시오. `tests/acme_fixture.py --start`는 이미 로컬에 있는 Pebble과 pebble-challtestsrv image만 격리 Docker network에서 시작하고 test directory, CA bundle, management endpoint를 JSON으로 출력한 뒤 종료 때 정리합니다. `HANGANG_PEBBLE_TEST=1`일 때만 opt-in Rust 통합 테스트가 실행되며 그 외에는 network 작업을 하지 않습니다. 명시적으로 실제 directory/provider 설정으로 engine을 활성화하기 전에는 production CA에 접속하거나 DNS를 바꾸지 않습니다.

## 게이트웨이 runtime

`--config-tls`로 여러 인증서 group을 제공하는 gateway는 `hangang-acme-issuer`를 public gateway와 별도로 실행할 수 있습니다. group마다 private account path와 output directory가 다른 issuer 하나를 시작하십시오. 각 issuer는 `--config /absolute/private/issuer.json`을 받고 선택적 `--check`는 ACME/DNS에 접속하지 않고 path와 private input만 검증합니다. 설정은 2초마다 poll하며 유효한 교체는 이전 order를 cancel/join한 뒤 시작하고 잘못된 교체는 마지막 usable 설정을 유지합니다. 실패는 제한 retry backoff로 기록합니다. private 설정·Cloudflare token·account directory는 process owner만 접근해야 합니다.

issuer 설정은 ACME 기간 field와 `output_directory`를 사용합니다. DNS-01에는 `"dns":{"provider":"cloudflare","zone_id":"...","token_file":"/absolute/private/token"}`가 필요합니다. HTTP-01은 `dns`를 생략하고 `"challenge":"http-01"`, `--http-listen 0.0.0.0:8081`을 사용하며 public port 80에서 이 listener로 `/.well-known/acme-challenge/<token>`만 전달합니다. issuer는 정확한 token과 Host의 GET만 제공하고 나머지는 404입니다. wildcard는 DNS-01이 필요하며 Cloudflare provider 하나는 고정 zone ID 하나만 사용하므로 zone마다 issuer를 분리하거나 적절한 경우 HTTP-01을 사용하십시오. 연결, 헤더, 요청 수명에 제한이 적용됩니다.

issuer는 발급과 pair 게시 동안 account별 advisory file lock을 유지합니다. chain과 key를 검증하고 private synced immutable `generation-*` directory에 함께 기록한 뒤 상대 `current` symlink를 원자적으로 교체합니다. gateway의 `cert_file`, `key_file`은 `output_directory/current/cert.pem`과 `output_directory/current/key.pem`의 절대 path로 설정하고 replica에는 directory를 read-only로 mount하십시오. gateway watcher는 pair 전체를 검증한 뒤 교체하며 pointer 전환 중 inconsistent read면 이전 인증서를 유지하고 재시도합니다. 이전 generation은 local rollback 자료로 남습니다. 출력 게시에 실패한 상태로 issuer process가 충돌하면 다른 ACME order가 필요할 수 있습니다. output directory를 쓰기 가능하게 유지하고 백업하며 갱신 만료를 감시하십시오.

인증서 관리는 비공개이며 동적으로 다시 읽는 JSON 파일로 명시적으로 활성화합니다.

```sh
hangang --listen 0.0.0.0:443 --acme-http-listen 0.0.0.0:80 \
  --acme-config /data/acme.json --config /data/routes.json --supervised
```

`HANGANG_ADMIN_TOKEN`을 설정하고 administration은 loopback에 두거나 admin TLS를 사용하십시오. process user는 port bind와 account directory write 권한이 필요합니다. container mapping은 public 80/443을 비특권 내부 port로 전달할 수 있습니다. HTTP-01은 public port 80이 challenge listener에 도달해야 하며 이 listener는 소유 token만 제공하고 다른 요청에 404를 반환하며 관리 기능을 노출하거나 임의의 트래픽을 프록시하지 않습니다.

샘플 [Compose 배포](../DEPLOYMENT.md)는 ACME를 끄고 기본 HTTP listener만 게시합니다. HTTP-01/HTTPS를 켜려면 port mapping, writable state의 private account storage, container 내부에서 읽을 인증서 path를 명시하십시오. JSON에 listener를 만들었다고 container port가 게시된다고 가정하지 마십시오.

일반 이름에 대한 `/data/acme.json` 예제:

```json
{
  "directory": "letsencrypt-staging",
  "domains": ["app.example.com"],
  "account_path": "/data/account.json",
  "challenge": "http-01"
}
```

wildcard DNS-01은 `--acme-http-listen`을 생략하고 provider를 설정합니다.

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

token은 선택 zone의 DNS record 관리 권한이 필요합니다. `provider: "webhook"`, `endpoint: "https://dns-service.example.com/acme"`, `token_file`로 webhook도 사용할 수 있습니다. webhook 계약은 위에서 설명했습니다. credential은 파일에서 읽어 관리 API에 반환하지 않습니다. ZeroSSL은 `directory: "zerossl-production"`, `eab_kid`, `eab_hmac_key_base64`가 필요합니다. 이 값은 credential이므로 설정을 private secret으로 저장하고 CA directory를 바꾸면 account path도 분리하십시오. engine을 활성화하면 해당 directory의 계정 약관에 동의하는 것이므로 운영 전에 선택한 CA의 약관을 검토하십시오.

runtime은 `/data/account.json` 옆에 `/data/account.tls.json`을 저장합니다. 이는 완전한 certificate/key bundle이며 TLS 게시 전에 동기화·원자 rename됩니다. runtime에서 별도 `certificate_path`/`private_key_path`를 설정하지 말고 container upgrade 동안 account와 bundle을 보존하십시오. restart 복원은 SNI name을 활성화하기 전에 bundle을 검증합니다. CA를 이용할 수 없어도 아직 사용할 수 있는 인증서는 재등록하거나 재발급할 필요가 없습니다.

설정과 DNS credential 파일의 내용은 500 ms마다 확인합니다. 유효한 변경은 이전 발급 작업을 취소한 뒤 교체합니다. 잘못된 교체는 활성 설정과 인증서를 유지합니다. `/v1/status`에는 활성화 여부, 도메인 이름, 단계, 만료 시점, `tls_available`, `bundle_digest`, `last_error`를 포함한 `acme` 객체가 있으며 내장 UI에도 표시됩니다. `last_error`는 가장 최근 발급 시도 실패의 전체 오류입니다(예: HTTP-01 토큰을 수락하지 않는 공유 저장소). 다음 성공적인 시도나 로드된 bundle이 있으면 지워지고, follower에서는 "ACME account is being managed by another process"라고 표시됩니다. 실패한 시도는 모두 로그에도 남습니다(account lock만 잃은 경우 info, 나머지는 warn). `tls_available`은 설정된 도메인에 대해 검증되었고 만료되지 않은 인증서가 공개 resolver에 로드된 동안에만 true입니다. 시작부터 첫 bundle 복원 또는 발급 전까지 false여서 이 기간에는 HTTPS handshake가 실패하며, 로드된 인증서가 갱신 없이 만료되어도 다시 false가 됩니다. `bundle_digest`는 실제 로드된 자료가 들어 있는 bundle 파일의 SHA-256 hex 값이고 없으면 비어 있습니다. private key, token, EAB credential은 포함되지 않습니다.

bundle 파일 자체는 5초마다 확인합니다. 공유 볼륨을 사용하는 두 번째 인스턴스나 수동 복원 등 다른 process가 쓴 bundle도 digest가 바뀌면 실행기 밖에서 검증해 resolver에 게시합니다. 검증에 실패한 교체는 한 번만 parse하여 로그에 기록하고 이전 인증서를 계속 제공합니다. watcher 자체는 order를 예약하지 않습니다. 이 인스턴스의 갱신 일정이나 설정 변경만 예약하므로 공유 경로의 외부 또는 손상된 파일 때문에 CA order가 반복되지 않습니다.

account별 파일 lock은 공유 로컬 상태에서 발급을 직렬화합니다. 감독 교체는 challenge listener를 내보내기 전에 갱신 작업을 동결하고 실패한 후보에서는 이전 세대를 재개합니다. 기존 TLS 연결은 협상한 인증서를 유지합니다. 이 릴리스에서는 수동 공개 TLS, Kubernetes Secret TLS, ACME TLS가 상호 배타적인 listener 설정입니다.

대기 중인 DNS 정리 receipt는 provider당 4096개로 제한되고 record 필드에도 크기 제한이 있습니다. 이 장부 용량이 가득 차면 새 DNS 변경은 provider에 접속하기 전에 실패합니다. 반복된 정리 실패로 보관 메모리가 무한히 늘지 않도록 하기 위함입니다. provider 오류로 TXT record가 남을 수 있으며 process 충돌 후 receipt 복구가 분산 트랜잭션을 보장하지는 않습니다.

## 여러 인스턴스

load balancer 뒤 여러 인스턴스를 운영하려면 네 가지 조건이 필요합니다.

**공유 HTTP-01 token.** `/.well-known/acme-challenge/<token>`에 대한 CA 검증 요청은 임의 인스턴스에 도착합니다. 공유 설정 저장소(`--database`, 공유 경로의 SQLite, PostgreSQL, Redis)를 설정하면 발급 인스턴스가 설치하는 모든 token을 정규화된 호스트와 token에서 만든 불투명한 key로 저장소에 게시하고 order가 끝날 때 철회합니다. 값은 `<host> <key authorization>`입니다. 저장소 식별자에 호스트를 포함하므로 두 승인에 재사용한 token이 다른 호스트의 record를 덮어쓰거나 철회하지 않습니다. 또한 입력 key 길이가 더 짧은 저장소에서도 listener의 최대 256자 token을 사용할 수 있습니다. 이 key 형식은 공유 challenge를 원래 token으로 저장하던 이전 빌드와 호환되지 않습니다. HTTP-01 검증이 진행되지 않을 때 issuer와 복제본 집합을 함께 업그레이드하세요. 이전 빌드와 현재 빌드는 서로의 공유 token에 응답할 수 없습니다.

CA에 challenge 준비를 알리기 전에 게시 확인을 받아야 합니다. issuer는 최대 세 번 시도합니다. 저장소가 5초 안에 보고한 전송 실패는 250 ms 후 다시 시도하지만 내용 거부는 재시도하지 않습니다. 저장소가 끝내 record를 수락하지 않으면 호스트와 저장소 실패를 명시한 오류로 승인을 중단하고, 로컬에 설치된 항목을 남기지 않으며 정상 백오프 일정에 따라 다시 시도합니다. 5초 안에 응답하지 않은 게시나 철회는 쓰기가 나중에 적용될 수 있으므로 버리거나 병렬로 다시 시도하지 않습니다(SQLite 작업은 blocking thread에서 실행되고 네트워크 저장소도 요청을 뒤늦게 적용할 수 있습니다). 시작부터 최대 30초 기다리고 늦은 결과도 반영합니다. 그때까지 끝나지 않으면 token mutation lock과 함께 백그라운드에 남겨 두며 저장소 작업이 실제로 끝났을 때만 lock을 해제합니다. 이 경우 insert는 실패합니다. 포기된 쓰기가 나중에 적용되더라도 아무것도 검증하지 않는 token의 record이며 자체 만료됩니다. 그동안 같은 token의 후속 게시나 철회는 포기된 쓰기와 엇갈려 실행되지 않습니다. 따라서 이 모드에서는 저장소가 발급 경로에 있습니다. 저장소 장애 중에는 HTTP-01 order가 완료되지 않지만, 404를 반환할 인스턴스에 CA가 검증 요청을 보내는 상황도 피합니다.

record는 10분 수명으로 게시하고 token이 설치된 동안 절반 시점마다 다시 게시합니다. order는 `acme_timeout_secs`까지 정상적으로 진행될 수 있으므로 늦게 도착한 검증도 모든 인스턴스에서 record를 찾습니다. refresh 실패는 더 자주 재시도하고 로그에 남기며, 충돌한 인스턴스가 남긴 record는 자체 만료됩니다. token 설치마다 ownership id가 있고 게시, refresh, 철회는 직렬화됩니다. 같은 token을 다시 설치하면 이전 게시, refresh, 철회가 저장소에서 완료된 뒤 새 record를 게시합니다. 교체로 뒤처진 refresh는 새 record를 건드리지 않고, 실패한 게시는 자기 설치만 되돌립니다. 제거는 진행 중인 mutation이 끝나고 더 새로운 설치가 없을 때만 record를 철회합니다. insert는 자신의 설치가 게시되고 여전히 token의 현재 설치일 때만 성공합니다. 게시 전이나 게시 중에 다시 설치 또는 제거되었다면 superseded로 실패하므로, 복제본 집합이 제공하지 않을 record만 믿고 issuer가 challenge를 준비 상태로 표시하지 않습니다.

이전 mutation 차례를 기다리는 시간도 30초로 제한됩니다. 그 안에 차례를 얻지 못한 재설치는 실패하고 개별 제거는 철회를 건너뜁니다. order 정리는 먼저 모든 로컬 응답과 refresh를 멈춘 뒤 전체 30초 기한 안에서 공유 record를 최대 여덟 개 동시에 철회합니다. 이미 시작한 mutation은 token lock을 유지한 채 백그라운드에서 완료됩니다. 시작하지 못한 철회는 건너뛰고 한 번 로그에 남기며 10분 TTL로 만료되게 둡니다. 따라서 저장소가 멈춰도 HTTP 정리로 인한 인증서 게시와 issuer lock 해제 지연은 승인 건수와 관계없이 최대 30초입니다. token을 소유하지 않은 인스턴스는 로컬에서 찾지 못하면 저장소를 조회하고 저장된 호스트가 요청의 `Host`와 같을 때만 응답합니다. 호스트가 없는 record는 절대 제공하지 않습니다. 공개 listener의 조회는 최대 2초, 동시 최대 여덟 개로 제한하며 시간 초과나 저장소 실패 시 404를 반환합니다. 고장 난 저장소를 향한 probe가 로그를 채우지 않도록 경고는 30초에 최대 한 번입니다. 저장소가 없으면 token은 process 로컬에만 있고 게시 확인은 필요 없으며 공개 포트 80이 발급 인스턴스에 결정적으로 도달해야 합니다.

**하나의 issuer.** account path와 `<account>.acme.lock`, `<account>.tls.json`을 모든 인스턴스가 공유하는 volume에 두십시오. advisory lock을 얻은 하나만 order를 만들고 다른 인스턴스는 CA에 접속하지 않고 backoff로 재시도합니다. 참여 호스트 사이에서 advisory lock을 지키는 파일 시스템이 필요합니다. 서로 다른 local volume이면 독립적으로 발급하며 조정되지 않습니다.

**Follower bundle refresh.** 모든 인스턴스가 5초마다 bundle을 확인해 lock holder가 쓴 갱신을 자체 order 없이 제공합니다. domain set이 다르거나 bundle이 손상되면 한 번 parse·log하고 이전 인증서를 유지합니다. 이 오류가 order를 유발하지는 않습니다. 공유 path의 인스턴스는 같은 domain set을 사용해야 합니다. 그렇지 않으면 각자의 갱신 일정에 따라 서로의 bundle을 덮어쓰게 됩니다.

**DNS-01 대안.** DNS-01은 port 80과 token 공유가 필요 없고 shared volume과 lock이 발급 하나를 보장하며 bundle refresh가 결과를 배포합니다. wildcard는 항상 DNS-01입니다.

**첫 발급 HTTPS 공백.** 첫 bundle 전에는 public resolver에 인증서가 없어 모든 HTTPS handshake가 실패하고 `/v1/status`의 `acme.tls_available`은 false입니다. HTTPS health check load balancer는 이 공백을 보며 admin endpoint를 검사하는 경우 인증서가 로드될 때까지 rotation에서 제외할 수 있습니다. issuer bundle이 shared volume에 나타나면 follower가 공백을 닫습니다. issuer election은 없고 lock을 먼저 얻은 인스턴스가 holder입니다. 공유 볼륨을 잃으면 인스턴스가 독립적인 로컬 상태로 돌아갑니다.

## 독립 DNS issuer 복구

standalone `hangang-acme-issuer`는 설정이 같은 동안 Cloudflare provider와 pending cleanup receipt를 retry 사이에 유지합니다. restart 뒤 Cloudflare가 같은 TXT presentation을 HTTP 400으로 거부하면 정확한 challenge name과 key-authorization value를 조회합니다. 일치 record가 정확히 하나일 때만 receipt를 adopt하고 삭제 전에 다시 확인합니다. 이름만으로 무관한 TXT를 삭제하지 않습니다. log에는 authorization ID, challenge type, presentation, propagation, readiness, certificate receipt, cleanup 완료, 제한 retry delay를 남기되 challenge value, credential, private key, ACME authorization URL은 남기지 않습니다.

cleanup receipt는 crash 뒤 영속적이지 않습니다. 재시작한 issuer에 CA가 다른 authorization value를 주면 이전 TXT가 새 시도 소유임을 증명할 수 없어 자동 삭제하지 않습니다. 운영자는 provider metadata를 검사해 독립적으로 귀속할 수 있는 record만 제거해야 합니다. 같은 account와 zone에 동시 issuer를 피하십시오. credential file만 교체해도 active retry의 cached provider는 바뀌지 않으므로 이전 시도가 끝난 뒤 issuer 설정을 교체해 provider를 reload하십시오.
