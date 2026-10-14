# Kubernetes Ingress 사용법과 검증 시나리오

[문서](../README.ko.md) · [컨트롤러 참조](KUBERNETES.md) · [English](../KUBERNETES_SCENARIOS.md)

Hangang v0.3.2는 Ingress 규칙과 기본 백엔드에서 원래 요청의 Host와 포트를 보존합니다. Service DNS는 연결 대상을 정하고 앱에는 공개 Host가 전달됩니다. 이번 유지보수 릴리스는 v0.3.1에 검증한 수정과 문서를 더한 버전이며, main에서 진행 중인 인증 기능 변경은 포함하지 않습니다.

## 진입 구조 선택

컨트롤러가 공개 리스너를 관리할 수 있다면 [deploy/kubernetes](../../deploy/kubernetes)의 Hangang을 직접 진입점으로 사용합니다. Service를 로드 밸런서로 노출하고 인증서를 준비한 뒤 `--kubernetes-tls`를 사용합니다. TLS Secret과 RBAC는 [컨트롤러 참조](KUBERNETES.md)에 설명되어 있습니다.

기존 호스트 Hangang이 80/443을 사용한다면 TLS와 외부 인증을 유지하고 앱별 도메인을 공통 내부 Ingress Service로 전달합니다. 앱 Service는 ClusterIP로 두므로 앱을 추가해도 호스트 포트나 앱별 NodePort가 필요하지 않습니다.

```text
Client HTTPS → edge Hangang (TLS / optional auth)
             → shared internal Hangang Ingress Service
             → echo or echo-b ClusterIP Service → application Pods
```

serverlb 없는 k3d에서는 내부 컨트롤러의 NodePort를 브릿지로 사용할 수 있습니다. 실제 테스트는 두 노드 주소의 30090을 사용했습니다. 외부 프록시에서 노드 주소로 연결할 수 있어야 하며 Docker 노드 IP는 재생성 시 바뀔 수 있습니다. 운영 환경에는 안정적이고 접근을 제한한 진입점을 사용하세요. 물리 서버 하나의 Pod 두 개는 호스트 장애를 견디지 못합니다.

## 컨트롤러와 앱 두 개 배포

[배포 지침](KUBERNETES.md#배포)에 따라 v0.3.2 이미지를 빌드하고 매니페스트의 이미지 자리표시자를 교체하며 관리자 Secret을 준비합니다. 이번 릴리스에는 공개 컨테이너 이미지가 없습니다. 예제 네임스페이스에서 다음을 실행합니다.

```sh
kubectl create namespace demo
kubectl -n demo create secret generic hangang-admin --from-file=token=hangang-admin-token.private
kubectl apply -n demo -k deploy/kubernetes
kubectl apply -f examples/kubernetes/multi-service.yaml
kubectl -n demo rollout status deployment/hangang
kubectl -n demo rollout status deployment/echo
kubectl -n demo rollout status deployment/echo-b
```

토큰 생성은 참조 문서를 따르고 비밀 파일은 커밋하지 마세요. 의도한 클러스터 컨텍스트를 명시적으로 선택하세요. 예제에는 각각 Pod 두 개를 가진 독립 Deployment 두 개와 ClusterIP Service, Ingress가 있습니다. 컨트롤러는 `ingressClassName: hangang`을 선택하고 `demo` 네임스페이스를 감시해야 합니다. IngressClass 객체 자체는 읽지 않습니다. 도메인·DNS·TLS 인증서는 환경에 맞게 설정하세요.

| 요청 | Service | 앱에 전달되는 경로 |
|---|---|---|
| `echo.example.test/check` | echo | `/check` |
| `echo-b.example.test/check` | echo-b | `/check` |
| `echo.example.test/second/check` | echo-b | `/second/check` |
| `echo.example.test/secondish` | echo | `/secondish` |

`Prefix`는 경로 요소 단위로 일치하므로 `/secondish`는 `/second`에 해당하지 않습니다. 같은 호스트에서는 더 긴 일치 경로가 우선입니다. 경로를 그대로 전달하며 `/second`를 제거하지 않습니다. echo 앱은 메서드·쿼리·헤더·본문을 JSON으로 반환하는 공개 진단 앱입니다. 인증 서비스가 아니므로 합성 요청으로 테스트하고 평가 후 제거하세요.

## 기존 외부 게이트웨이 설정

k3d 브릿지 시나리오에서는 컨트롤러 Service를 공통 NodePort로 노출합니다. 클러스터에서 허용하고 다른 서비스가 사용하지 않는 포트를 선택하세요.

```sh
kubectl -n demo patch service hangang --type merge -p '{"spec":{"type":"NodePort","ports":[{"name":"http","port":80,"targetPort":"http","protocol":"TCP","nodePort":30090}]}}'
```

호스트·네트워크 접근 제어로 외부 게이트웨이의 접속만 허용하세요. 앱 Service는 ClusterIP를 유지합니다.

각 도메인에 대해 같은 내부 진입점을 대상으로 TLS 필수 및 Host 보존 HTTP route를 등록합니다. 다음은 기존 설정/API에 넣는 route 객체이며 전체 설정 파일이 아닙니다.

```json
{
  "id": "apps-echo",
  "host": "echo.example.test",
  "path_prefix": "/",
  "access_mode": "public",
  "require_tls": true,
  "preserve_host": true,
  "backends": ["http://NODE_A:30090", "http://NODE_B:30090"],
  "retries": 0
}
```

두 번째 route에는 다른 ID와 `host: echo-b.example.test`를 지정하고 같은 백엔드를 사용합니다. NODE_A/NODE_B는 실제 연결 가능한 노드 주소로 바꾸세요. 공개 echo 예제에는 SSO를 적용하지 않습니다. 보호할 앱은 외부에서 Hopae 인증을 구성하고 내부 직접 접속이 인증을 우회하지 못하게 해야 합니다. 관련 설정은 [인증 문서](../CONSOLE_PLUGINS.md)를 참고하세요. Kubernetes에서 가져온 route가 외부 인증 설정을 자동으로 상속하지는 않습니다.

외부 프록시는 클라이언트가 보낸 forwarded 정보를 덮어써야 합니다. 내부 컨트롤러의 `--trusted-proxy-cidrs`에는 실제 관찰한 좁은 범위의 접속 출처만 지정하세요. 테스트한 k3d에서는 NodePort SNAT 때문에 외부 호스트 IP 대신 CNI/flannel 게이트웨이 주소가 관찰됐습니다. 해당 사설 IP를 그대로 복사하거나 Pod 대역 전체를 신뢰하지 마세요. 이는 HTTPS/클라이언트 메타데이터 복원용 신뢰이며 외부 프록시를 암호학적으로 인증하지 않습니다. 다른 테넌트가 내부 리스너에 접속할 수 있다면 접근 제한이나 별도의 검증된 경계가 필요합니다.

## 검증 방법

```sh
curl --fail https://echo.example.test/check
curl --fail https://echo-b.example.test/check
curl --fail -H 'Content-Type: application/json' -H 'X-Test: ingress' \
  --data '{"message":"hello"}' 'https://echo.example.test/second/check?n=2'
curl --fail https://echo.example.test/secondish
```

`os.hostname`으로 `echo-*`와 `echo-b-*`를 구분합니다. JSON의 `hostname`은 요청 도메인이며 선택된 Pod 이름이 아닙니다. `headers.host`, `path`, `query`, `body`, HTTPS 전달 정보를 검사하세요. JSON 200만으로 올바른 Service 선택을 증명할 수는 없습니다. 실제 도메인을 넣고 [동시 요청 검사](../../tests/ingress_multi.py)를 실행할 수 있습니다.

```sh
python3 tests/ingress_multi.py --host-a echo.example.test --host-b echo-b.example.test
```

## 2026-10-14 실제 검증

Linux amd64 물리 서버 하나의 k3d v5.9.0 / k3s v1.37.1+k3s1에서 외부 Hangang v0.3.1과 내부 v0.3.2-rc.1 컨트롤러 Pod 두 개를 사용했습니다. 각각 Pod 두 개를 가진 echo Service 두 개가 컨트롤러 NodePort 하나를 공유했습니다. 정식 v0.3.2 바이너리는 같은 컨트롤러 코드로 별도 재빌드합니다.

| 검사 | 결과 |
|---|---|
| Host/경로 혼합, 동시 worker 8개 | 100/100 성공, 백엔드 Pod 네 개 확인 |
| Prefix 경계 | `/second/check` → echo-b, `/secondish` → echo |
| 요청 반사 | Host·메서드·경로·쿼리·사용자 헤더·본문·HTTPS/443 보존 |
| GET·JSON POST·텍스트 PUT·64 KiB POST | 프록시 두 단계 통과 |
| 클라이언트의 위조 forwarded 정보 | 외부 프록시가 프로토콜·클라이언트 IP 교체 |
| Ingress 경로 수정·Service 누락·복원 | 변경 반영, 해당 route 철회, 복원 후 회복 |
| 컨트롤러 Pod 재시작 | 수정 이미지에서 감시 요청 72/72 성공 |
| 기존 직접 echo·API·대시보드 진입 | 기존 설정대로 응답 유지 |

RC 네이티브 검증은 라이브러리·프록시·CLI·Host 회귀 검사 687개 통과, 기존 ignored 13개입니다. GNU/musl Linux amd64 gateway smoke는 각각 10개 통과했습니다. Host 회귀 검사는 정확 호스트·와일드카드·기본 백엔드와 Host 포트를 다룹니다. 최종 정식 빌드 결과는 [변경 기록](../../CHANGELOG.md)과 릴리스 설명을 참고하세요.

실제 클러스터 테스트는 WebSocket·SSE·gRPC·물리 노드 장애 전환·장시간 API 장애를 검증하지 않았습니다. RC 검증 당시 GitHub Actions가 비활성화되어 로컬에서 검증했습니다. 정식 버전도 로컬에서 검증하며 워크플로 활성 상태는 별도로 바뀔 수 있습니다. 문서 검사기의 기존 오류 10개는 수정하지 않은 v0.3.1에서도 재현됐습니다. 이 항목들은 통과한 검사가 아닙니다. 이번 유지보수 릴리스는 다른 아키텍처의 자산을 제공하지 않습니다.

## 문제 확인과 제거

404라면 Host·Ingress class·네임스페이스 범위·경로 일치를 확인하세요. 다른 앱이 응답하면 Pod 식별자와 더 구체적인 경로를 확인하세요. HTTPS 뒤에서 forwarded protocol이 http라면 실제 출처 주소와 trusted proxy 설정을 확인하세요. Service가 누락되면 포트를 확인하고 복원하세요. 클러스터를 재생성할 필요는 없습니다. API 캐시가 오래되면 readiness와 컨트롤러 로그를 확인하세요.

평가 후 외부 route를 정확한 ID로 제거하고 `kubectl delete -f examples/kubernetes/multi-service.yaml`을 실행합니다. 이 파일은 전용 `demo` 네임스페이스도 삭제하므로 격리된 데모에서만 사용하고 다른 리소스가 없는지 먼저 확인하세요. 앱 매니페스트 제거는 다른 네임스페이스의 컨트롤러나 외부 route를 제거하지 않습니다. Docker 전체 prune을 사용하지 마세요.

[Kubernetes Ingress 의미](https://kubernetes.io/docs/concepts/services-networking/ingress/) · [Service 네트워킹](https://kubernetes.io/docs/concepts/services-networking/service/)
