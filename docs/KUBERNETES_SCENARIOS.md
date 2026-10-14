# Kubernetes Ingress usage and tested scenarios

[Documentation](README.md) · [Controller reference](KUBERNETES.md) · [한국어](ko/KUBERNETES_SCENARIOS.md)

Hangang v0.3.2 preserves the original request Host for Ingress rules and default backends. Kubernetes Service DNS chooses the upstream; applications still see the public Host, including its port. This maintenance release contains v0.3.1 plus that fix and documentation; ongoing identity work on main is outside the release.

## Choose an entry topology

Use Hangang directly as the cluster entry when the controller can own the public listener. Run the controller from [deploy/kubernetes](../deploy/kubernetes), expose its Service through your load balancer, and provision certificates before enabling `--kubernetes-tls`. Ingress TLS Secrets and the required RBAC are explained in the [controller reference](KUBERNETES.md).

When an existing host gateway already owns ports 80/443, keep TLS and external authentication there. Route each application's hostname from that gateway to one shared internal Ingress Service. Application Services remain ClusterIP; adding an application needs no new host port or application NodePort.

```text
Client HTTPS → edge Hangang (TLS / optional auth)
             → shared internal Hangang Ingress Service
             → echo or echo-b ClusterIP Service → application Pods
```

On k3d without serverlb, a NodePort for the internal controller can provide this bridge. The tested deployment used port 30090 on both node addresses. Those addresses must be reachable from the edge; Docker node IPs can change on recreation. Production exposure should use a stable, restricted endpoint. A controller with two Pods on one physical host does not provide host failure tolerance.

## Deploy the controller and two applications

Use the [controller deployment instructions](KUBERNETES.md#deploy) to build a v0.3.2 image, replace the image placeholder, and create a private administrator Secret. No public container image is published by this release. For the example namespace:

```sh
kubectl create namespace demo
kubectl -n demo create secret generic hangang-admin --from-file=token=hangang-admin-token.private
kubectl apply -n demo -k deploy/kubernetes
kubectl apply -f examples/kubernetes/multi-service.yaml
kubectl -n demo rollout status deployment/hangang
kubectl -n demo rollout status deployment/echo
kubectl -n demo rollout status deployment/echo-b
```

Generate the token as described in the reference, keep it private, and never commit it. Apply these commands using an explicitly chosen cluster context. The example has two independent Deployments with two Pods each, ClusterIP Services, and one Ingress. The controller selects `ingressClassName: hangang`; its namespace scope must include `demo`. It does not read IngressClass objects. Adapt hostnames, DNS and TLS certificates for your environment.

| Incoming request | Service | Application path |
|---|---|---|
| `echo.example.test/check` | echo | `/check` |
| `echo-b.example.test/check` | echo-b | `/check` |
| `echo.example.test/second/check` | echo-b | `/second/check` |
| `echo.example.test/secondish` | echo | `/secondish` |

`Prefix` matches path segments: `/secondish` does not match `/second`. The longest matching path wins within the same host. Paths are forwarded unchanged; this example does not strip `/second`. The echo applications reflect request method, query, headers and body as JSON. They are public diagnostic apps, not authentication services: use synthetic requests and remove them after evaluation.

## Configure an existing edge gateway

For each hostname, register an edge HTTP route to the same internal entry, with TLS required and the original Host preserved. This is a route object for the existing configuration/API, not a complete standalone config:

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

Create another route with a different ID and `host: echo-b.example.test`, using the same backends. Replace NODE_A/NODE_B with reachable node addresses. This public echo example does not enable SSO. For protected applications, configure authentication at the edge using [Hopae](CONSOLE_PLUGINS.md), and ensure direct internal access cannot bypass that policy. Imported Kubernetes routes do not automatically inherit the edge's authentication configuration.

The edge must overwrite client-supplied forwarded metadata. Configure the inner controller's `--trusted-proxy-cidrs` to the narrow source addresses it actually observes. In the tested k3d topology NodePort SNAT exposed CNI/flannel gateway addresses, rather than the edge's host address. Inspect your topology instead of copying those private IPs or trusting an entire Pod subnet. This trust restores forwarded HTTPS/client metadata; it is not cryptographic authentication of the edge. Restrict access or use an independently verified boundary where other tenants can reach the listener.

## Verify the result

```sh
curl --fail https://echo.example.test/check
curl --fail https://echo-b.example.test/check
curl --fail -H 'Content-Type: application/json' -H 'X-Test: ingress' \
  --data '{"message":"hello"}' 'https://echo.example.test/second/check?n=2'
curl --fail https://echo.example.test/secondish
```

Inspect `os.hostname` to distinguish `echo-*` from `echo-b-*`; the JSON `hostname` field describes the requested host, not the selected Pod. Check `headers.host`, `path`, `query`, `body` and forwarded HTTPS information. A JSON 200 response alone cannot prove the correct Service was chosen. Use [`tests/ingress_multi.py`](../tests/ingress_multi.py) for 100 concurrent synthetic requests after substituting real hosts:

```sh
python3 tests/ingress_multi.py --host-a echo.example.test --host-b echo-b.example.test
```

## Qualification on 2026-10-14

A live k3d v5.9.0 / k3s v1.37.1+k3s1 cluster on one Linux amd64 physical server exercised an external Hangang v0.3.1 gateway and two internal v0.3.2-rc.1 controller Pods. Two echo Services, each with two Pods, shared one controller NodePort. The final stable binaries are separately rebuilt as v0.3.2 from the same controller code.

| Check | Observed result |
|---|---|
| Mixed host/path routing, 8 concurrent workers | 100/100 requests; all four backend Pods observed |
| Prefix segment boundary | `/second/check` → echo-b; `/secondish` → echo |
| Request reflection | Host, method, path, query, custom header, exact body and HTTPS/443 preserved |
| GET, JSON POST, plain PUT, 64 KiB POST | Passed through both proxies |
| Forged client forwarded metadata | Outer gateway replaced supplied protocol and client IP |
| Live Ingress path update / missing Service / restore | Routes changed, affected route withdrew, restore recovered |
| Controller Pod restart | 72/72 monitored requests passed with corrected image |
| Existing direct echo, API and dashboard entry | Continued to respond as configured |

Native qualification of the RC passed 687 library/proxy/CLI/Host regression tests, with 13 existing ignored cases. GNU and musl Linux amd64 gateway smoke suites each passed ten checks. The Host regression covers exact, wildcard and default-backend routes including Host ports. See the [release notes](../CHANGELOG.md) and release description for final stable build verification.

The live exercise did not establish WebSocket, SSE, gRPC, physical-node failover or prolonged API-outage behavior. GitHub Actions was disabled; qualification was run locally. The documentation checker has ten known failures also reproduced on the unmodified v0.3.1 baseline. These are recorded limits, not successful checks. Additional architectures have no assets in this maintenance release.

## Troubleshooting and cleanup

For a 404, compare the incoming Host, Ingress class, namespace scope and path match. For a wrong application, inspect Pod identity and more-specific paths. For `http` forwarded protocol behind HTTPS, check observed peer addresses and trusted proxy settings. If the Service backend is missing, inspect its ports and restore it; do not regenerate the cluster. Check readiness and controller logs when API caches are stale.

After the evaluation, remove the edge routes by their exact IDs, then `kubectl delete -f examples/kubernetes/multi-service.yaml`. This manifest also deletes its dedicated `demo` namespace: use it only for an isolated demonstration, and check the namespace for other resources first. Removing application manifests does not remove the separately installed controller in other namespaces or its external gateway routes. Never use whole-Docker pruning as cleanup.

[Kubernetes Ingress semantics](https://kubernetes.io/docs/concepts/services-networking/ingress/) · [Service networking](https://kubernetes.io/docs/concepts/services-networking/service/)
