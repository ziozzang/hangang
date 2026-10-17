# Kubernetes 경로 보호 (ProtectionPolicy)

[문서 목차](../README.ko.md) · [English](../KUBERNETES_PROTECTION.md)

이 문서는 ADR 0022 P0(Kubernetes 네이티브 Hangang World 패키지, hangang-zerotrust 저장소)의 첫 게이트웨이 구현 단위입니다. Kubernetes로 선언한 경로는 제로 트러스트 보호를 갖추어야 하며, 보호가 없거나 모호하거나 강제할 수 없는 경로는 게시하지 않습니다. 이 기능은 [Kubernetes Ingress 컨트롤러](KUBERNETES.md)를 확장하며, 그 문서의 목록·감시·신선도·호스트 이름 소유·복제본 설명은 그대로 적용됩니다.

보호된 경로는 모든 요청을 Hopae(mTLS를 쓰는 네이티브 gRPC)로 인증한 다음, 요청 메서드에 대한 Pumgye 리소스 결정을 받고 나서야 백엔드로 한 바이트라도 보냅니다. 네트워크 강제가 필요한 정책이면 실제 클라이언트 주소로 Sumunjang 승인을 먼저 수행합니다. 게이트웨이는 각 구성 요소가 이미 허용하는 범위를 넘어 결정을 캐시하지 않습니다.

## 모델

`ProtectionPolicy`(`world.hangang.dev/v1alpha1`, 짧은 이름 `hpp`, 범주 `world`)는 Hangang이 소유하는 네임스페이스 범위 객체이며 다음을 지정합니다.

- `spec.targetRefs`: 같은 네임스페이스 안에서 정책을 붙일 객체입니다(Gateway API *직접 정책 부착*). 이번 릴리스는 `Ingress` 대상(`group: networking.k8s.io`)을 프로그래밍합니다. `HTTPRoute`와 `Gateway` 대상(`group: gateway.networking.k8s.io`)은 지금 매니페스트를 작성할 수 있도록 스키마가 받아들이지만, `Accepted=False`, 이유 `Unsupported`로 보고하며 아무것도 프로그래밍하지 않습니다.
- `targetRefs` 대신 `spec.namespaceDefault: true`: 어떤 정책도 대상으로 삼지 않은 그 네임스페이스의 모든 Ingress에 적용합니다.
- `spec.identity.profileRef.name`: 게이트웨이 운영자가 구성한 Hopae 신원 프로필입니다([보호 활성화](#보호-활성화) 참조). 테넌트는 프로필을 고를 뿐 인증 URL, 키, 인증서를 직접 지정하지 않습니다.
- `spec.authorization.pumgye`: Pumgye `serviceId`, `resource`, 그리고 `{method, action}` 매핑 목록입니다. 목록에 없는 메서드는 거부합니다.
- `spec.network.enforcement`: `Required`(기본값) 또는 `None`입니다. `Required`는 Sumunjang 승인과 Pumgye 네트워크 조건이 실제 클라이언트 주소를 보아야 한다는 뜻이고, `None`은 신원과 인가만 주장합니다.
- `spec.failureMode`: `Closed`만 있습니다.

컨트롤러는 자기 클래스의 각 Ingress에 대해 이름으로 그것을 대상으로 삼은 정책을 고르고, 그런 정책이 없을 때만 네임스페이스 기본 정책을 적용합니다. 적용되는 정책이 정확히 하나일 때 Ingress가 보호됩니다. **적용되는 정책이 여러 개이면 거부합니다**: 생성 순서와 관계없이 Ingress를 보류하고 관련된 모든 정책이 `Accepted=False`, 이유 `Conflicted`를 보고합니다. 이는 가장 오래된 정책이 우선하고 나머지를 `Conflicted`로 표시하는 Gateway API 정책 부착 규약(GEP-713)과 **의도적으로 다른** 동작입니다. 더 새롭고 엄격한 정책이 조용히 무시되어서는 안 되므로 모호함을 나이가 아니라 운영자가 해소하며, 해소될 때까지 아무것도 프로그래밍하지 않습니다. 네임스페이스 기본 정책 두 개도 같은 충돌입니다.

모든 결정은 캐시된 객체와 운영자 설정만의 함수이므로, 서로 다른 이력을 관찰한 복제본도 같은 경로를 게시하고 같은 상태를 기록합니다.

## 보호 활성화

보호는 게이트웨이마다 `--kubernetes-protection-config FILE`로 켭니다. 파일은 운영자가 소유하는 JSON입니다.

| 필드 | 의미 |
| --- | --- |
| `require_protection` | 유효한 정책이 없는 모든 Ingress를 보류합니다. 기본값 `true`. |
| `identity_profiles` | 이름 붙은 Hopae 프로필 1–64개입니다. 각 프로필은 `auth` 블록(경로 `auth` 계약: mTLS를 쓰는 gRPC 네이티브 Hopae, 응답 헤더에 `x-forwarded-user`와 `x-hopae-aal`, 고정 호출자 키)과 선택적 `namespaces` 허용 목록을 가집니다. |
| `pumgye_authority` | 독립 Pumgye 권한 서버(`transport: grpc`와 `tls`). 필수입니다. |
| `pumgye_services` | 선택 항목: Pumgye 서비스 ID에서 그 서비스를 바인딩할 수 있는 네임스페이스로의 맵. 없으면 어느 네임스페이스든 어느 서비스든 지정할 수 있습니다. |
| `client_address` | `{"mode":"none"}`(기본값), `{"mode":"service_local","namespace":…,"name":…}`, `{"mode":"proxy_protocol"}`, `{"mode":"host_network"}` 중 하나입니다. |

모든 프로필은 시작할 때 시험용 경로에 컴파일해 보므로, 쓸 수 없는 프로필은 첫 테넌트에서 실패하는 대신 게이트웨이 시작을 멈춥니다. 환경 변수 참조(`{"env": "NAME"}`)로 키와 토큰을 파일 밖에 둡니다. Sumunjang은 기존 `--guard-*` 플래그로 구성합니다. `enforcement: Required` 정책은 `--guard-url`이 설정되고 `--guard-mode`가 `query`, `--guard-failure-mode`가 `deny`일 때만 프로그래밍됩니다(snapshot 모드는 만료 시 열리므로 실패 시 닫힘이 아닙니다).

제공된 매니페스트로는 다음과 같습니다.

```sh
kubectl apply -k deploy/kubernetes/crds
kubectl create configmap hangang-protection \
  --from-file=settings.json=deploy/kubernetes/protection-settings.example.json
kubectl patch deployment hangang --type strategic \
  --patch-file deploy/kubernetes/protection-patch.yaml
kubectl patch service hangang --type strategic \
  --patch-file deploy/kubernetes/service-local-patch.yaml
```

먼저 예제 설정을 수정하고, 패치가 마운트하는 `hangang-world-mtls`와 `hangang-world-tokens` Secret을 만드십시오. CRD kustomization은 클러스터 범위이며 별도로 두어 CRD 업그레이드가 명시적인 단계로 남게 했습니다. 여기에는 네임스페이스 `edit`/`admin` 사용자가 자기 네임스페이스의 정책을 관리하고 `view` 사용자가 읽을 수 있게 하는 집계 ClusterRole도 포함됩니다. status 하위 리소스는 컨트롤러만 씁니다. 컨트롤러 Role에는 `protectionpolicies`의 `list`/`watch`와 `protectionpolicies/status`의 `patch`가 추가됩니다. CRD가 없으면 정책 목록 조회가 실패하여 컨트롤러가 아무것도 게시하지 않고 복제본은 준비되지 않은 상태로 남습니다. CRD가 없다는 사실이 "정책 없음"으로 해석되는 일은 없습니다.

## 정책 작성

```yaml
apiVersion: world.hangang.dev/v1alpha1
kind: ProtectionPolicy
metadata:
  name: orders
spec:
  targetRefs:
    - group: networking.k8s.io
      kind: Ingress
      name: orders
  identity:
    profileRef:
      name: corp-sso
  authorization:
    pumgye:
      serviceId: orders
      resource: http:orders
      actions:
        - method: GET
          action: read
        - method: POST
          action: write
  network:
    enforcement: Required
```

[examples/kubernetes/protection-policy.yaml](../../examples/kubernetes/protection-policy.yaml)에는 Ingress와 네임스페이스 기본 정책이 추가로 있습니다. 스키마는 모든 문자열과 목록의 크기를 제한하고, `namespaceDefault`가 false일 때에만 정확히 `targetRefs`를 요구하며, 중복 대상과 중복 메서드를 거부하고, `sectionName`은 Gateway API 대상에만 허용합니다. 컨트롤러도 같은 규칙을 다시 검사하고 알 수 없는 필드를 무효로 처리하므로, 완전히 이해하지 못한 정책이 의도보다 약하게 보호하는 일은 없습니다.

Ingress가 생성하는 모든 경로(모든 호스트·경로 규칙과 기본 백엔드)는 `access_mode: protected`, 프로필의 `auth`, 그리고 정책의 매핑을 `pumgye_resource`로 가진 강제 `resource_policy`로 컴파일되며, 문서에는 구성된 `pumgye_authority`가 들어갑니다. 각 경로는 경로 ID와 범위에서 유도한 고유 `resource_id`를 받습니다.

## Hopae 로그인 handoff 경로

Hopae는 브라우저 로그인을 handoff 코드와 함께 `https://<애플리케이션 호스트>/_hopae/login?...`으로 리디렉션해 마치며, 게이트웨이가 검증 중에 이 요청에 응답합니다. 그래서 컨트롤러는 보호된 Ingress의 호스트마다 내부 경로 `/_hopae`(세그먼트 접두사, 대소문자 무시, 테넌트 경로와 똑같이 보호) 하나를 추가하며, 운영자가 직접 경로를 넣지 않습니다. 이 경로는 테넌트의 `/`나 짧은 접두사보다 길어 가려지지 않고, 여러 보호된 Ingress가 같은 호스트를 써도 호스트마다 하나만 만듭니다(namespace/name 순서상 첫 Ingress가 제공). 보호된 Ingress에 `/_hopae` 아래 테넌트 경로(`/_HOPAE/...`, `/%5Fhopae...` 포함)가 있으면 그 Ingress를 `ReservedPath` 이유로 보류합니다. 진단은 Ingress별 호스트(`handoff_hosts`)와 합계(`counts.handoff_routes`, `hangang_kubernetes_handoff_routes`)를 보여 줍니다. 공개 Ingress와 미보호 Ingress에는 handoff 경로가 없습니다.

## 명시적 공개 경로

인증 전에 닿아야 하는 경로가 있습니다. 신원 포털의 로그인과 공급자 콜백, `/.well-known` 문서, 상태 확인입니다. 이를 위해 `require_protection`을 끄면 보호되지 않은 모든 Ingress가 게시됩니다. 대신 그런 Ingress에 `access: Public` 정책을 붙입니다.

```yaml
apiVersion: world.hangang.dev/v1alpha1
kind: ProtectionPolicy
metadata:
  name: auth-portal-public
spec:
  access: Public
  targetRefs:
    - group: networking.k8s.io
      kind: Ingress
      name: auth-portal
  public:
    reason: Hopae sign-in portal (login, provider callbacks, health)
    paths: ["/login/*", "/callback/*", "/healthz"]
```

- `public.reason`(8–256자)은 필수이며 보고됩니다. 공개 정책에는 `identity`, `authorization`, `network`가 없고 명시적 `targetRefs`가 필요합니다(`namespaceDefault` 불가). CRD의 CEL 규칙과 컨트롤러가 이를 강제합니다.
- `public.paths`는 Ingress가 노출할 수 있는 범위를 제한합니다. `/exact`(`Exact` 경로) 또는 `/prefix/*`(그 아래 모든 경로, `Prefix` 경로 `/prefix`도 포함)입니다. 그 밖의 경로나 `defaultBackend`가 있으면 `PublicPathNotAllowed`로 Ingress를 보류합니다. `paths`가 없으면 Ingress 전체가 공개되므로 나열하는 편이 좋습니다.
- 경로는 `access_mode: public`으로 게시됩니다. Ingress는 **`public`**(명시적 공개, 이유 `ExplicitlyPublic`, 정책과 그 이유)으로 보고되고 `hangang_kubernetes_ingresses_public`으로 집계되며, 결코 `unprotected`로 보고되지 않습니다.
- 같은 Ingress를 대상으로 하는 공개 정책과 보호 정책은 다른 두 정책처럼 충돌하며 Ingress는 보류됩니다. 보호 정책과 마찬가지로 대상 지정 정책이 네임스페이스 기본값보다 우선합니다.
- 공개 정책을 지우면 Ingress는 다시 보류되며, `require_protection`이 켜져 있는 동안 미보호로 되돌아가지 않습니다.

## 실패 시 닫힘 규칙

| 상황 | 결과 | 이유 |
| --- | --- | --- |
| 대상 정책도 네임스페이스 기본 정책도 없음, `require_protection: true` | Ingress 보류 | `ProtectionRequired` |
| 정책 없음, `require_protection: false` | `access_mode: public`으로 게시 | — |
| Ingress를 대상으로 하는 정책이 무효(`require_protection: false`여도) | Ingress 보류 | `Invalid` |
| 정책이 둘 이상 적용됨 | Ingress 보류, 모든 정책 `Conflicted` | `Conflicted` |
| 알 수 없는 프로필 | Ingress 보류, `ResolvedRefs=False` | `InvalidIdentityProfile` |
| 프로필이나 Pumgye 서비스가 그 네임스페이스에 허용되지 않음 | Ingress 보류, `ResolvedRefs=False` | `RefNotPermitted` |
| 실패 시 닫히는 Sumunjang 없이 `enforcement: Required` | Ingress 보류 | `GuardUnavailable` |
| 클라이언트 주소 보존 없이 `enforcement: Required` | Ingress 보류, `ClientAddressPreserved=False` | `ClientAddressUnavailable` |
| 이후 호스트 이름 소유, TLS, 경로 검증, 예산으로 철회됨 | 게시되지 않음 | `Pending` |
| `HTTPRoute` 또는 `Gateway` 대상 | 그 대상에는 아무것도 프로그래밍하지 않음 | `Unsupported` |
| `access: Public` 정책과 `public.paths` 밖의 Ingress 경로(또는 `defaultBackend`) | Ingress 보류 | `PublicPathNotAllowed` |
| Hopae 예약 경로 `/_hopae` 아래 경로가 있는 보호된 Ingress | Ingress 보류 | `ReservedPath` |
| API 서버가 `--kubernetes-max-staleness-seconds`(기본값 5분)를 넘도록 스냅샷을 확인하지 못함 | 보호 경로는 `503`, `x-hangang-reason: kubernetes-authority-stale`로 응답하고 공개 경로는 계속 제공 | [제한된 오래됨](KUBERNETES.md#제한된-오래됨) |

보류된 Ingress는 호스트 이름 소유를 유지하고(여전히 호스트를 주장함), `--kubernetes-publish-address` 상태 항목을 받지 않으며, 이미 가지고 있었다면 잃습니다. 보류는 다른 Ingress에 영향을 주지 않습니다.

## 상태, 진단, 지표

컨트롤러는 캐시된 `resourceVersion`을 전제 조건으로 `status`를 씁니다. 최상위 `conditions`에는 `Accepted`, `ResolvedRefs`, `Programmed`와, 네트워크 강제가 있는 정책이면 `ClientAddressPreserved`가 각각 `observedGeneration`과 함께 들어갑니다. `status.ancestors`는 Gateway API 정책 상태 규약을 따릅니다. 대상마다(네임스페이스 기본 정책이면 적용된 Ingress마다, 최대 16개이며 나머지는 `Programmed` 메시지에 개수로 표시) `controllerName: hangang.dev/gateway-controller`와 대상별 조건을 가진 항목 하나가 있습니다. 다른 컨트롤러가 쓴 항목은 보존합니다. `lastTransitionTime`은 조건의 status가 바뀔 때만 바뀌므로 복제본끼리 시각을 두고 다투지 않습니다. 충돌하거나 객체가 사라진 쓰기는 버리고, 그 원인이 된 감시 이벤트가 다시 조정합니다. `networking.k8s.io/v1` Ingress에는 조건 필드가 없으므로 Ingress는 게시 주소를 갖지 않는 것으로만 보류를 나타내며, 이유는 정책 상태와 아래 진단에서 확인합니다.

관리 API의 `GET /v1/kubernetes/protection`(viewer 또는 관리자 역할, 읽기 전용, 비밀 정보 없음)은 이 인스턴스의 최신 보고서를 반환합니다. `require_protection`, 클라이언트 주소와 Sumunjang 상태, 개수, 선택된 Ingress마다 한 행(`protected`, `public`, `unprotected`, `withheld`, 게시된 스냅숏이 제공하는지, 부착된 정책, 이유와 메시지), 정책마다 한 행이 들어 있으며 각각 1,000행으로 제한됩니다. `/metrics`에는 `hangang_kubernetes_ingresses_protected`, `hangang_kubernetes_ingresses_public`, `hangang_kubernetes_ingresses_unprotected`, `hangang_kubernetes_ingresses_withheld`, `hangang_kubernetes_protection_policies_invalid`, `hangang_kubernetes_protection_policies_conflicted`, `hangang_kubernetes_client_address_preserved`가 추가됩니다. 배포 중에는 `withheld > 0`, 이전을 마친 뒤에는 `unprotected > 0`에 경보를 거십시오. 보고서의 `freshness` 객체와 `hangang_kubernetes_snapshot_age_seconds`, `hangang_kubernetes_protected_fail_closed`, `hangang_kubernetes_stale_refusals_total` 지표는 [제한된 오래됨](KUBERNETES.md#제한된-오래됨)을 나타냅니다. `protected_fail_closed == 1`에 경보를 거십시오.

## 클라이언트 주소 보존

네트워크 조건은 게이트웨이가 보는 클라이언트 주소만큼만 믿을 수 있습니다. 일반 ClusterIP Service 뒤에서는 kube-proxy SNAT가 이를 노드 주소로 바꿉니다. 따라서 `enforcement: Required` 정책은 운영자가 게이트웨이가 검사할 수 있는 보존 모드를 선언했을 때만 프로그래밍됩니다.

| 모드 | 검사 |
| --- | --- |
| `none` | 보존되지 않음. `enforcement: Required` 정책은 보류됩니다. |
| `service_local` | 지정한 Service(감시 대상 안)가 `externalTrafficPolicy: Local`인 `LoadBalancer` 또는 `NodePort`인지 변경될 때마다 다시 검사합니다. |
| `proxy_protocol` | 공개 리스너가 PROXY protocol v2를 받습니다(`--proxy-protocol-from`). 그렇지 않으면 게이트웨이가 시작을 거부합니다. |
| `host_network` | `hostNetwork` 에지(현재 베어메탈 토폴로지)에 대해 운영자가 선언합니다. |

`--proxy-protocol-from CIDR`(반복 또는 쉼표 구분, 최대 64개)을 주면 공개 리스너는 그 범위의 피어로부터 TLS나 HTTP보다 먼저 PROXY v2 헤더를 읽습니다. 그 헤더의 출발지 주소가 이후 모든 단계(신뢰하는 전달 헤더, Sumunjang, Pumgye, 로그)의 클라이언트 주소가 됩니다. 신뢰하는 피어가 5초 안에 유효한 v2 헤더를 보내지 않으면 연결을 끊습니다. `LOCAL` 헤더(로드 밸런서 상태 점검)는 피어 주소를 그대로 씁니다. 범위 밖의 피어는 직접 연결로 처리하며 그 바이트를 헤더로 해석하지 않으므로, 클라이언트가 자기 주소를 고를 수 없습니다. 버전 1 텍스트 헤더, UDP와 Unix 주소 계열은 거부합니다. kubelet 프로브 출발지는 신뢰 범위에서 빼거나 관리 리스너를 프로브하십시오.

## 보호된 범위의 해제

게이트웨이는 강제 중인 리소스 범위를 조용히 없애는 설정을 거부합니다(`resource … scope cannot be removed or moved`). Kubernetes 모드에서는 API 객체가 권한이므로, 보호된 Ingress를 삭제하거나 호스트·경로를 바꾸거나 정책을 떼는 것은 명시적인 해제입니다. 컨트롤러는 먼저 해제되는 각 범위를 트래픽을 받지 않는 **비활성** 경로(`enforce: false`)로 남긴 리비전을 게시한 다음 원하는 스냅숏을 게시합니다. 이 단계가 없으면 Ingress 하나를 삭제한 것만으로 이후의 모든 갱신이 멈춥니다.

## 이전

기존 Ingress 배포는 `--kubernetes-protection-config`를 설정할 때까지 동작이 바뀌지 않습니다. 중단 없이 보호를 도입하려면 다음과 같이 진행합니다.

1. CRD와 역할(`deploy/kubernetes/crds`)을 설치하고 컨트롤러 Role에 새 규칙을 부여합니다.
2. `"require_protection": false`로 시작합니다. 보호되지 않은 Ingress는 계속 게시되며 이제 레거시 경로 대신 명시적인 `access_mode: public`이 됩니다. 정책이 있는 Ingress는 즉시 보호됩니다.
3. `/v1/kubernetes/protection`과 `hangang_kubernetes_ingresses_unprotected`에 보호되지 않은 Ingress가 없고 모든 정책이 `Programmed=True`를 보고할 때까지 정책(대상 지정 또는 네임스페이스 기본)을 작성합니다.
4. `require_protection`을 제거하고(기본값 `true`) Deployment를 롤아웃합니다. 이후 정책 없는 새 Ingress는 보류되고 보고됩니다.
5. `enforcement: Required`를 쓰려면 먼저 실패 시 닫히는 query 모드의 Sumunjang과 클라이언트 주소 모드를 켜십시오. 둘 다 갖춰지기 전까지 해당 Ingress는 `GuardUnavailable` 또는 `ClientAddressUnavailable`로 보류됩니다.

되돌리기는 플래그를 제거하는 것입니다. 컨트롤러는 보호되지 않은 Ingress 의미로 돌아가며, 보호된 각 범위는 위에서 설명한 비활성 리비전을 거쳐 해제됩니다.

## 범위와 제한

- 보호된 Ingress는 지원되는 과도기·호환 경로입니다(ADR 0022도 이에 맞게 수정). 장기 목표는 Gateway API 경로입니다. HTTPRoute/Gateway 부착은 같은 스키마와 해석을 사용하며 다음 단계입니다(Gateway API 종류의 조정은 아직 구현되지 않았습니다).
- 동작 매핑은 HTTP 메서드 단위입니다. 경로나 RPC 단위 매핑, `GRPCRoute`, `WorldIdentityProfile` 종류, 서명된 스냅숏 배포, ADR 0022 결정 3의 컨트롤러/권한 서버 분리는 이번 단위에 포함되지 않습니다.
- Pumgye 서비스 정책(예: 자체 네트워크 상한이나 `require_guard`)은 요청 시점에 Pumgye가 평가합니다. 게이트웨이는 `pumgye_services`가 허용하는 네임스페이스 바인딩만 검사합니다.
- 각 복제본은 상태를 독립적으로 씁니다(리더 선출 없음). 입력이 같으면 이어받은 시각을 제외하고 상태도 같습니다.

## 검증

단위 테스트는 설정 검증, 부착과 네임스페이스 기본 정책, 결정적인 충돌 거부, 무효 정책이 절대 열리지 않음, 참조와 네임스페이스 제한, Sumunjang과 클라이언트 주소 전제 조건, Gateway API 상태 형태와 시각 이어받기, 범위 해제 리비전, 제공된 설정 예제, PROXY v2 해석을 다룹니다. 모의 API 서버 테스트는 보호된 Ingress와 보호되지 않은 Ingress로 컨트롤러를 실행합니다. 보호된 것만 (Hopae와 Pumgye 바인딩과 함께) 게시되고 주소를 받으며, 정책 상태가 관찰한 `resourceVersion`으로 기록되고, 정책을 삭제하면 Ingress가 보류되며, CRD가 없으면 아무것도 게시하지 않습니다. 블랙박스 테스트는 바이너리를 통해 PROXY v2를 검증하고, 정적 테스트는 CRD를 ADR 0022 API 규칙과 대조합니다.

```sh
cargo test --lib protection
cargo test --test kubernetes protection
python3 tests/proxy_protocol_smoke.py
python3 -m unittest tests/test_world_crds.py
```
