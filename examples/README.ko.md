# 첫 Hangang 구성

[프로젝트 빠른 시작](../README.ko.md#빠른-시작) · [문서 목차](../docs/README.ko.md) · [English](README.md)

로컬 HTTP 프록시는 [hangang.json](hangang.json)에서 시작하세요. 빈 Docker 배포에는 [deploy/hangang.example.json](../deploy/hangang.example.json)을 사용합니다. 두 파일은 출발점이 다릅니다. 로컬 예제에는 작동하는 데모 라우트 하나가 있고 배포 템플릿에는 애플리케이션 라우트가 없습니다.

## 로컬 예제 이해하기

```json
{
  "revision": 0,
  "http": [
    {
      "id": "api",
      "path_prefix": "/",
      "backends": ["http://127.0.0.1:8081"],
      "lua": "if hangang.header('x-block') == 'yes' then hangang.reject(403) end"
    }
  ],
  "tcp": []
}
```

| 필드 | 의미와 변경 방법 |
| --- | --- |
| `revision` | 초기 설정 revision입니다. `0`에서 시작하고 관리 write는 revision 검사를 사용합니다. 기존 설치를 편집할 때는 이 예제로 되돌리지 말고 현재 revision을 유지하십시오. |
| `http` | HTTP 라우트 정의입니다. 빈 배열이면 애플리케이션 요청을 전달하지 않습니다. |
| `http[].id` | 콘솔과 API가 사용하는 안정적인 라우트 식별자입니다. HTTP, TCP, UDP 라우트 전체에서 고유한 이름을 사용하십시오. |
| `path_prefix` | 요청 경로 매칭입니다. `/`는 이 라우트의 모든 경로와 일치하며 prefix를 제거하거나 upstream 경로를 rewrite하지 않습니다. |
| `backends` | scheme과 선택적 port를 포함한 destination URL입니다. loopback 데모 주소를 gateway process에서 접근할 수 있는 backend로 바꾸십시오. backend는 이미 실행 중이어야 합니다. |
| `lua` | 선택적 request policy입니다. 이 예제는 `X-Block: yes`가 있으면 HTTP 403을 반환합니다. 데모 policy가 필요 없으면 field를 제거하십시오. |
| `tcp` | 각자 listen address와 backend를 가진 raw TCP 라우트입니다. `[]`이면 만들지 않습니다. |

JSON은 주석과 trailing comma를 허용하지 않습니다. 설명은 설정 파일 안이 아니라 이 README에 적으십시오. 알 수 없는 설정 field는 거부되므로 정확한 이름과 type은 [OpenAPI 설정 schema](../docs/openapi.json)를 사용하십시오.

라우트의 기본값은 enabled, priority `0`, legacy access mode입니다. host 제한과 사용자 인증 policy가 없으므로 Lua 데모는 인증이 아닙니다. `X-Block: yes`가 없는 요청은 backend에 도달할 수 있습니다. 보호된 service를 공개하기 전에 [access policy](../docs/ACCESS_POLICY.md)를 읽으십시오.

## 실행과 확인

명령은 repository root에서 실행합니다. `cargo build --locked`로 빌드한 뒤 별도 terminal에서 데모 backend를 시작합니다.

```sh
HANGANG_DEMO_BACKEND="$(mktemp -d)"
printf 'Hello through Hangang!\n' > "$HANGANG_DEMO_BACKEND/index.html"
python3 -m http.server 8081 --bind 127.0.0.1 --directory "$HANGANG_DEMO_BACKEND"
```

설정을 비공개이고 쓸 수 있는 runtime directory로 복사하십시오. 추적 중인 예제는 이후 설치에도 유용하도록 변경하지 마십시오.

```sh
umask 077
export HANGANG_DEMO_DIR="$(mktemp -d)"
cp examples/hangang.json "$HANGANG_DEMO_DIR/hangang.json"
openssl rand -hex 32 > "$HANGANG_DEMO_DIR/admin-token"
export HANGANG_ADMIN_TOKEN="$(cat "$HANGANG_DEMO_DIR/admin-token")"
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json" --check
./target/debug/hangang --config "$HANGANG_DEMO_DIR/hangang.json"
```

`--check`는 listener를 시작하지 않고 설정과 Lua를 검증합니다. backend 접근 가능 여부나 runtime port가 비어 있는지는 증명하지 않습니다. 다른 terminal에서 다음을 실행하십시오.

```sh
curl --fail http://127.0.0.1:8080/
# Hello through Hangang!
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Block: yes' http://127.0.0.1:8080/
# 403
```

`http://127.0.0.1:9000/ui/`를 열고 비공개 `admin-token` 파일의 setup token, 사용자 이름, 12바이트 이상의 비밀번호로 첫 관리자를 만드십시오. directory 변수는 그것을 만든 terminal에 속합니다. setup 후에도 token은 관리자 자격 증명으로 남으며 일회용 비밀번호가 아닙니다. [관리자 계정](../docs/ADMIN_USERS.md)을 참고하세요.

gateway와 backend는 Ctrl+C로 중지합니다. 같은 runtime directory를 다시 사용하면 설정과 로컬 account state를 보존할 수 있습니다. `mktemp`는 매번 다른 설치를 만들며 host 정리나 reboot 뒤에도 보존해야 하는 저장소에는 적합하지 않습니다.

## 설정 파일과 process·container 설정의 구분

| 설정 | 위치 |
| --- | --- |
| HTTP route hosts, paths, policies, backends | JSON의 `http` |
| 기본 public listener | CLI `--listen`; 기본값 `127.0.0.1:8080` |
| Management listener | CLI `--admin`; 기본값 `127.0.0.1:9000`. 애플리케이션 routing과 독립적입니다. |
| 추가 public HTTP/HTTPS listener | JSON `public_http`; HTTPS에는 설정된 certificate material도 필요합니다. [public listener](../docs/PUBLIC_LISTENERS.md)를 참고하세요. |
| TCP/UDP listen address | 각 JSON route의 `listen`. [TCP/SNI](../docs/SNI.md)와 [UDP](../docs/UDP.md)를 참고하세요. |
| 관리자 setup token | `HANGANG_ADMIN_TOKEN` environment variable이며 route JSON과 별개입니다. |
| 게시할 container port와 mount file | Compose 설정; JSON 편집으로 Docker port mapping을 바꿀 수 없습니다. |
| 선택적 runtime policy 기본값 | JSON `settings`; 입력한 field는 대응 process 값을 덮고 생략/null은 그 값을 유지합니다. |

container 안에서 `127.0.0.1`은 해당 container를 뜻합니다. 다른 container의 backend에는 접근 가능한 service name/address와 공유 network가 필요하고, host의 backend에는 container에서 접근할 수 있는 주소가 필요합니다. gateway를 `0.0.0.0`에 bind해도 loopback backend 주소가 host를 가리키게 되지는 않습니다.

## service에 맞게 라우트 조정

같은 backend와 policy를 공유하는 두 domain에는 `api` route를 다음 fragment 같은 route로 바꾸십시오.

```json
{
  "id": "site",
  "hosts": ["example.com", "www.example.com"],
  "path_prefix": "/",
  "priority": 10,
  "enabled": true,
  "preserve_host": true,
  "backends": ["http://127.0.0.1:8081"]
}
```

이는 완전한 설정 문서가 아니라 route object 하나입니다. `preserve_host`는 들어온 Host를 backend에 전달하므로 backend가 public domain을 기대할 때 켜십시오. 기본값은 false입니다. domain name을 추가해도 DNS record를 만들거나 certificate를 얻거나 HTTPS를 활성화하지 않습니다. 로컬 테스트는 `curl -H 'Host: example.com' http://127.0.0.1:8080/`로 하십시오.

높은 priority가 이기며 동률이면 설정 순서를 사용합니다. 일치하지 않는 domain이 catch-all route에 도달하지 않아야 하면 기존 catch-all을 제거하거나 비활성화하십시오. wildcard/regex matching과 path 규칙은 [matching](../docs/MATCHING.md)을, certificate 발급과 public TLS는 [ACME](../docs/ACME.md)와 [public listener](../docs/PUBLIC_LISTENERS.md)를 읽으십시오.

## 실행 중 설정 변경

local-file mode는 runtime JSON 변경을 감시합니다. candidate는 active 설정을 교체하기 전에 validation과 runtime preparation을 통과해야 하며, 잘못된 edit는 이전 working 설정을 유지합니다. 변경 뒤 status와 log를 확인하십시오. 편집된 file만으로 activation을 증명할 수 없습니다.

일반 편집에는 console 또는 revision 검사 management API를 사용하십시오. `GET /v1/config`을 읽어 revision/ETag를 보존하고 문서화된 `If-Match` precondition과 함께 `PUT /v1/config`을 사용합니다. conflict면 최신 설정을 reload하고 reconcile하십시오. file edit와 UI/API write를 동시에 경쟁시키지 마십시오. 동시성과 persistence는 [configuration publication](../docs/CONFIG_PUBLICATION.md)과 [OpenAPI](../docs/openapi.json)를 참고하세요.

직접 file을 편집한다면 atomic file replacement로 완전하고 유효한 JSON을 쓰고 적절한 owner/permission을 유지하십시오. sibling lock과 state file을 위해 directory는 writable이어야 합니다. runtime 설정과 로컬 관리자 state를 함께 backup하십시오([deployment](../docs/DEPLOYMENT.md) 참고). 보안 policy 변경은 의도적으로 stream을 revoke할 수 있습니다. UDP route 변경은 영향을 받은 flow를 reset하며 UDP/QUIC process handoff는 아직 지원하지 않습니다.

## 예제 확장

service, certificate, key, database를 참조하는 예제는 해당 자원을 먼저 provision해야 합니다. 모두 독립적으로 시작할 수 있는 설정은 아닙니다.

| 목표 | 예제 | 안내 |
| --- | --- | --- |
| 공유 domain policy와 canonical redirect | [domain-group.json](domain-group.json) | [Canonical domains](../docs/CANONICAL_DOMAINS.md) |
| 이름 있는 backend와 weight | [named-members.json](named-members.json) | [Named members](../docs/NAMED_MEMBERS.md) |
| Public HTTP/HTTPS listener | [public-listeners.json](public-listeners.json) | [Public listeners](../docs/PUBLIC_LISTENERS.md) |
| Cache 설정 | [cache/hangang.json](cache/hangang.json) | [Cache](../docs/CACHE.md) |
| JSON/XML/stream 변환 | [transforms/hangang.json](transforms/hangang.json) | [Transforms](../docs/TRANSFORMS.md) |
| DNS, SOCKS5, 강제 upstream 주소 | [upstream guide](upstream/README.md) | [Outbound policies](../docs/UPSTREAM.md) |
| UDP 또는 QUIC passthrough | [udp/config.json](udp/config.json) | [UDP/QUIC](../docs/UDP.md) |
| 독립 Linux IPVS DSR | [dsr/config.json](dsr/config.json) | [DSR](../docs/DSR.md); gateway JSON과 별도의 companion schema입니다. |
| 명시적 애플리케이션·공개·보호 접근 | [access-mode.json](access-mode.json) | [접근 모드](../docs/ko/ACCESS_POLICY.md) |
| 리소스 단위 인가 | [resource-policy.json](resource-policy.json) | [리소스 정책](../docs/ko/RESOURCE_POLICY.md) |
| JWT 인증 | [jwt-auth.json](jwt-auth.json) | [JWT](../docs/ko/JWT_AUTH.md) |
| HTTP 워크로드 상호 TLS | [http-workload-mtls.json](http-workload-mtls.json) | [HTTP 워크로드 신원](../docs/ko/HTTP_WORKLOAD_MTLS.md) |
| TCP 워크로드 상호 TLS | [tcp-mtls.json](tcp-mtls.json) | [TCP 워크로드 신원](../docs/ko/TCP_MTLS.md) |
| 국가별 필터링 | [country-policy.json](country-policy.json) | [GeoIP](../docs/GEOIP.md) |
| 국가 조회와 관찰 | [geoip-observation.json](geoip-observation.json) | [GeoIP](../docs/GEOIP.md) |
| Accept-Language 기반 접근 허용 | [language-policy.json](language-policy.json) | [언어 정책](../docs/LANGUAGE_POLICY.md) |
| 초기 백엔드 상태 기반 수용 | [initial-health.json](initial-health.json) | [상태 기반 수용](../docs/HEALTH_ADMISSION.md) |
| HTTP 메타데이터 기록 | [http-recording.json](http-recording.json) | [HTTP 기록](../docs/HTTP_RECORDING.md) |
| TCP 완료 기록 | [tcp-recording/hangang.json](tcp-recording/hangang.json) | [TCP 기록](../docs/TCP_RECENT_RECORDING.md) |
| TLS SNI 패스스루 | [sni/hangang.json](sni/hangang.json) | [SNI](../docs/SNI.md) |
| 호스트 매칭 예제 | [upstream/matching.json](upstream/matching.json) | [매칭](../docs/MATCHING.md) |
| Lua 본문·스트림 정책 | [transforms/lua/](transforms/lua/) | [변조](../docs/ko/TRANSFORMS.md) |
| 원격 노드 관찰 | [fleet-observations/README.md](fleet-observations/README.md) | [플릿 관찰](../docs/FLEET_OBSERVATIONS.md) |
| 로컬 노드 관찰 데모 | [fleet-observer/run.py](fleet-observer/run.py) | [노드 관찰자](../docs/FLEET_OBSERVER.md) |
| Kubernetes 가져오기 입력 | [kubernetes/ingress-list.json](kubernetes/ingress-list.json) | [Kubernetes](../docs/ko/KUBERNETES.md); 게이트웨이 JSON이 아닌 입력 리소스 목록입니다. |
| 외부 롤아웃 계획 | [enterprise-rollout.json](enterprise-rollout.json) | [rollout_plan.py](../tools/rollout_plan.py); 이미지 다이제스트 자리표시자가 있는 계획 도구 입력이며, 게이트웨이 JSON이나 자동 배포가 아닙니다. |

## 문제 해결

| 증상 | 먼저 확인할 것 |
| --- | --- |
| 설정이 거부됨 | 엄격한 JSON syntax, 정확한 field name, 고유 route ID, `--check` 출력 |
| gateway는 시작하지만 proxy가 실패함 | gateway 자체 network namespace에서 backend 접근 가능 여부와 주소 |
| route가 일치하지 않음 | Host, path, enabled 상태, priority, named listener scope |
| management page에 접근할 수 없음 | 실제 `--admin` 주소와 Docker host port; application port와 management port는 다름 |
| 재시작할 때 첫 setup을 다시 요구함 | 같은 config path와 영속 관리자 state directory를 재사용했는지 |
| 유효한 edit가 활성화되지 않음 | runtime bind/certificate error와 active revision; validation만으로 preparation 성공을 보장하지 않음 |
