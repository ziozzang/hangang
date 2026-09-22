# 다중 인스턴스 운영

[문서 목차](../README.ko.md) · [English](../SCALE_OUT.md)

여러 인스턴스는 하나의 설정 저장소(`--database sqlite:…` 단일 호스트, PostgreSQL 또는 Redis)를 공유하면 외부 load balancer 뒤에서 같은 라우트를 서비스할 수 있습니다. 이 문서는 fleet이 보장하는 것, 각 인스턴스에 로컬로 남는 것, 운영 방법을 설명합니다. 아래에서 공유 저장소는 “authority”, 서버 process 하나는 “instance”라고 부릅니다.

## 일관성 모델

- **authority가 쓰기를 중재합니다.** API write는 리소스를 로컬에서 검증·준비한 뒤 authority에 compare-and-swap(CAS)을 수행합니다. durable state가 정확히 `(epoch, expected revision)`일 때만 성공하고, 동시에 오래된 writer는 409를 받습니다.
- **follower는 비동기로 수렴합니다.** 모든 인스턴스는 500ms마다 authority를 poll하고 로컬 준비 후 최신 revision을 활성화합니다. 500ms는 poll 간격이지 수렴 상한이 아닙니다. store latency와 preparation 시간이 더해지고 중간 revision은 건너뛸 수 있습니다. 진행 중 HTTP request는 시작한 snapshot을 유지하고 기존 TCP session은 자신의 route를 유지합니다.
- **authority epoch.** 빈 store의 최초 bootstrap은 CAS에서 바뀌지 않는 random epoch을 만듭니다. store를 지우고 다시 bootstrap하거나 다른 bootstrap 시점의 backup을 복원하면 다른 epoch이 됩니다. 이전 epoch에 붙어 있던 인스턴스는 `authority changed` 이유로 즉시 readiness를 철회하고 restart 전에는 새 history를 채택하지 않으며, 이들의 write는 CAS에서 거부됩니다. revision number만으로 history를 식별하지 않습니다.
- **멱등 CAS.** commit 후 connection drop으로 acknowledgement를 잃은 write는 PostgreSQL에서 한 번 재시도합니다. store는 `expected + 1`의 자신이 commit한 document를 알아보고 false conflict 대신 성공을 보고합니다. acknowledgement가 없는 시도 뒤 PostgreSQL은 `(epoch, expected + 1, our document)`일 때만 성공을 보고하며, 그 밖의 모든 durable state와 재조회 실패에는 HTTP 500 `Indeterminate Outcome`을 보고합니다. `(epoch, expected)`나 `expected + 1`에서 다른 document가 발견된 경우도 포함됩니다. 같은 epoch로 복원한 backup이 write 뒤 이전 state를 되살릴 수 있어 epoch 내부 history가 복원 사이에 단조 증가한다고 보장할 수 없기 때문입니다. Redis는 command를 재전송하지 않고 acknowledgement 유실을 indeterminate로 보고하므로 operator retry가 안전합니다. indeterminate면 retry 여부를 결정하기 전에 current revision을 reload하십시오.
- **precondition은 최신 base에서 판단합니다.** 다른 인스턴스에서 방금 읽어 local revision보다 앞선 `If-Match`는 write 판단 전에 authority와 reconcile합니다. 따라서 load balancer를 통한 read-then-write가 불필요하게 실패하지 않으며 conflict도 패배한 인스턴스를 reconcile해 다음 read가 최신이 됩니다.

## Readiness 정책

관리 listener의 `GET /healthz`와 public listener의 `--health-path`는 인스턴스가 ready일 때만 200을 답합니다. readiness는 “이 인스턴스 snapshot이 authority와 일치한다고 알려진 상태”를 뜻합니다.

| poll 관찰 | 효과 |
|---|---|
| 일치(같은 revision과 document) 또는 최신 revision 활성화 성공 | ready |
| store unreachable/timeout/read 불가 | 마지막 확인 이후 `--store-grace-seconds`(기본 30초) 동안 **허용**, 이후 unready. 어느 경우에도 마지막 정상 snapshot으로 서비스는 계속함 |
| store empty(`missing`) | 같은 grace window 뒤 unready |
| active보다 오래된 revision(`rollback`), 같은 revision의 다른 document(`divergence`), 다른 epoch(`authority changed`) | 즉시 unready |
| 이 인스턴스가 준비할 수 없는 최신 revision(인증서 누락, bind할 수 없는 TCP 주소 등) | 즉시 unready; writer 인스턴스는 ready 유지 |
| handoff 때문에 activation이 freeze된 동안의 최신 revision(`stale`) | 즉시 unready |
| poll이 아직 pending인 동안 grace window 종료(`stalled`) | poll과 무관하게 deadline에 unready |

grace window는 짧은 store 장애가 한 번에 전체 fleet을 철회하는 것을 막고 poll 단위 readiness flapping을 줄입니다. 첫 실패 poll에서 철회하려면 `--store-grace-seconds 0`을 사용하십시오. 철회 후에는 확인에 성공한 첫 poll에서 readiness가 돌아옵니다.

`GET /v1/status`는 `store.ready`, `store.reason`, `store.last_confirmed_seconds_ago`, `store.epoch`, `store.grace_seconds`와 process마다 random인 `instance.id`, 한 주소 뒤 인스턴스를 구분하는 `instance.config_digest`를 보고합니다.

## 운영 규칙

- **설정 write 전에 호스트 로컬 자료를 배포합니다.** 공유 document의 certificate path, upstream CA file, Lua script, Docker service reference는 모든 인스턴스에서 해석됩니다. write host에만 있는 file을 참조하면 그 host에서는 성공하지만 다른 인스턴스는 unready가 됩니다. 먼저 동일한 byte의 file을 배포하고(status에 digest가 노출됨) write하십시오. file 교체에 의한 certificate rotation도 host별입니다.
- **의도적인 store rollback(backup 복원).** 실행 중인 인스턴스는 설계상 restart 전까지 unready입니다. 복원 후 restart하십시오.
- **seed는 동일해야 합니다.** 빈 store로 여러 인스턴스를 시작하면 bootstrap 경쟁이 발생하고 승자의 seed가 authority가 됩니다. 하나의 seed file을 사용하십시오. insert acknowledgement가 없는 bootstrap은 뒤의 read가 document를 찾지 못하면 `indeterminate`를 보고합니다. 이후 store가 비었거나 읽히지 않는다고 seed가 authority가 아니었다는 뜻은 아니므로 같은 seed를 다시 넣기 전에 store를 읽어야 합니다. seed 전에 모든 TCP listen address를 process 자신의 listener와 함께 bind했다가 다시 release하므로 자기 자신, public/admin/ACME port와 충돌하는 seed는 저장되지 않습니다. `--no-bootstrap`은 빈 store seed를 거부하고 startup을 실패시키므로, 이미 운영 중인 배포에서 빈 store가 restart로 잘못 재시드되지 않게 권장합니다.
- **Redis**는 설정 key에 대해 `maxmemory-policy noeviction`으로 실행해야 합니다. key가 evict되면 `missing`으로 보고되고 grace window 뒤 fleet readiness가 철회됩니다.
- **공유 SQLite file**은 한 호스트에서만 인스턴스를 조정합니다. 다른 host의 같은 path는 서로 다른 store입니다.
- **Rolling upgrade.** 설정 schema는 알 수 없는 field를 거부합니다. 새 버전이 추가한 field를 사용하기 전에 모든 인스턴스의 executable을 upgrade하십시오. executable rollback은 공유 document를 되돌리지 않습니다.

## 종료와 교체

`SIGTERM`/`SIGINT`에서 인스턴스는 먼저 readiness를 철회해 health가 503이 되게 하면서 `--lame-duck-seconds`(기본 0) 동안 connection을 계속 받습니다. 그 뒤 accept를 멈추고 `--drain-seconds` 동안 drain합니다. 닫힌 listener로 connection이 가지 않도록 lame-duck window를 load-balancer probe interval과 failure threshold 합계 이상으로 설정하십시오. `deploy/` Kubernetes manifest도 readiness probe와 함께 이를 설정합니다. `--supervised`에서는 supervisor가 serving generation에 같은 두 단계를 수행합니다(`Withdraw` control, lame-duck wait, `Drain`). kill deadline은 둘을 모두 포함하므로 window가 잘리지 않습니다.

`--supervised`에서 교체 generation은 predecessor가 따르던 authority epoch과 listening socket을 상속하고 unready로 시작합니다. authority에 snapshot을 확인한 뒤(최대 10초 bounded wait) TCP accept gate를 엽니다. handoff 동안 write를 freeze해도 readiness는 철회하지 않지만 frozen generation은 agreement를 계속 확인합니다. authority가 activate할 수 없는 동안 이동하면 `stale` 이유로 철회하고 successor가 새 revision을 활성화합니다. 성공 handoff 뒤 retired generation은 accept loop를 즉시 닫고 drain하지만 readiness는 철회하지 않으므로 자신이 아직 소유한 connection의 probe는 healthy endpoint에 계속 답합니다.

## 인스턴스별로 남는 상태

| 상태 | fleet 동작 |
|---|---|
| 수동 backend health(failure quarantine) | 각 인스턴스가 독립적으로 failure를 관찰합니다. route의 backend나 balancing policy가 바뀌지 않는 설정 update에서는 quarantine과 least-connections counter가 유지됩니다. |
| Least-connections | backend 전체 load가 아니라 이 인스턴스 stream의 local count입니다. |
| Route admission 한도(`max_requests`, `max_connections`) | 인스턴스별입니다. N개 fleet은 N × limit을 허용합니다. upstream에서 hard aggregate cap을 적용하십시오. |
| Session affinity | 내장되어 있지 않습니다. affinity가 필요한 backend는 session state를 공유해야 합니다. |
| Response cache | 저장소는 인스턴스별입니다. 공유-store mode의 purge는 fleet-wide입니다. `POST /v1/cache/purge`가 CAS로 `cache.generation`을 올리고 각 인스턴스가 해당 revision을 활성화할 때 entry를 버립니다. 아직 실패할 수 있는 write 중에는 generation을 채택하지 않으며, generation은 단조 증가하고 document rollback 뒤에도 보존됩니다. file mode purge는 local입니다. 현재 document의 response header rule은 cache hit에도 적용됩니다. |
| Metrics | 인스턴스별이며 각 주소를 scrape하십시오. |
| Docker service discovery | local daemon을 기준으로 resolve합니다. 같은 reference도 host마다 다른 container로 resolve될 수 있습니다. |

## 여러 인스턴스에서 ACME

HTTP-01 validation은 load balancer가 임의 인스턴스로 보냅니다. shared-store mode에서는 challenge token을 ready로 표시하기 전에 store에 게시하고(acknowledged bounded retry; 게시할 수 없으면 CA가 어느 인스턴스에 도달할지 추측하지 않고 authorization을 중단) order가 진행되는 동안 refresh하므로 어디서 시작한 issuance든 모든 인스턴스가 답할 수 있습니다. 따라서 store가 내려가면 HTTP-01 issuance도 의존해 중단됩니다. local miss는 제한된 store lookup(2초, 동시 최대 8개, 그 외 404) 하나를 수행해 unauthenticated challenge path가 store traffic을 증폭하지 않게 합니다. issuance는 shared filesystem에서만 유효한 account lock으로 직렬화합니다. state volume이 분리되어 있으면 한 instance를 지정해 ACME를 실행하고 bundle을 배포하거나 DNS-01을 사용하십시오. follower는 교체된 bundle file을 5초마다 다시 읽습니다. 첫 certificate 전에는 configuration readiness가 true여도 HTTPS handshake가 실패하며 status의 `acme.tls_available`, `acme.bundle_digest`, `acme.phase`로 확인합니다. [ACME](ACME.md)의 “여러 인스턴스” 절을 참고하십시오.

## Kubernetes controller replica

[Kubernetes](KUBERNETES.md)를 참고하십시오. hostname ownership은 API-server 사실로 결정되고(가장 오래된 Ingress 우선), API를 `--kubernetes-stale-seconds` 동안 사용할 수 없으면 readiness가 만료되며, status address는 교체하지 않고 병합하고, relist는 replica별 간격과 jitter를 사용합니다.
