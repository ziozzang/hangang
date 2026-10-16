# Kubernetes route protection (ProtectionPolicy)

[Documentation](README.md) · [한국어](ko/KUBERNETES_PROTECTION.md)

This is the first gateway slice of ADR 0022 P0 (Kubernetes-native Hangang World package, in the hangang-zerotrust repository): routes declared through Kubernetes carry zero-trust protection, and a route whose protection is missing, ambiguous or cannot be enforced is not published. It extends the [Kubernetes Ingress controller](KUBERNETES.md); everything said there about lists, watches, freshness, hostname ownership and replicas still applies.

A protected route authenticates every request with Hopae (native gRPC with mTLS), then asks Pumgye for a resource decision for the request method, before any byte reaches the backend. With network enforcement required, Sumunjang admission runs first on the real client address. Nothing is cached in the gateway beyond what those components already allow.

## Model

`ProtectionPolicy` (`world.hangang.dev/v1alpha1`, short name `hpp`, category `world`) is a namespaced object owned by Hangang. It names:

- `spec.targetRefs`: the objects it attaches to, in its own namespace (Gateway API *direct policy attachment*). This release programs `Ingress` targets (`group: networking.k8s.io`). `HTTPRoute` and `Gateway` targets (`group: gateway.networking.k8s.io`) are accepted by the schema so manifests can be written now, and are reported `Accepted=False` with reason `Unsupported`; nothing is programmed for them.
- `spec.namespaceDefault: true` instead of `targetRefs`: the policy applies to every Ingress of the namespace that no policy targets.
- `spec.identity.profileRef.name`: a Hopae identity profile configured by the gateway operator (see [Enabling protection](#enabling-protection)). Tenants choose a profile; they never supply authentication URLs, keys or certificates.
- `spec.authorization.pumgye`: the Pumgye `serviceId`, `resource` and a list of `{method, action}` mappings. A method that is not listed is denied.
- `spec.network.enforcement`: `Required` (default) or `None`. `Required` means Sumunjang admission and Pumgye network conditions must see the real client address; `None` claims identity and authorization only.
- `spec.failureMode`: only `Closed` exists.

For each Ingress of the controller's class the controller picks the policies that target it by name; only when there are none does the namespace default apply. Exactly one applicable policy protects the Ingress. **Several applicable policies are refused**: the Ingress is withheld and every policy involved reports `Accepted=False` with reason `Conflicted`, whatever the creation order. Gateway API lets the oldest policy win; here a newer, stricter policy must never be silently ignored, so an ambiguity is resolved by the operator, not by age. Two namespace defaults are the same conflict.

Every decision is a function of the cached objects and the operator settings only, so replicas that observed different histories publish the same routes and write the same status.

## Enabling protection

Protection is enabled per gateway with `--kubernetes-protection-config FILE`. The file is operator-owned JSON:

| Field | Meaning |
| --- | --- |
| `require_protection` | Withhold every Ingress without an effective policy. Default `true`. |
| `identity_profiles` | 1–64 named Hopae profiles. Each holds an `auth` block (the route `auth` contract: native Hopae over gRPC with mTLS, `x-forwarded-user` and `x-hopae-aal` among the response headers, a static caller key) and an optional `namespaces` allow-list. |
| `pumgye_authority` | The independent Pumgye authority (`transport: grpc` with `tls`). Required. |
| `pumgye_services` | Optional map of Pumgye service ID to the namespaces allowed to bind it. Absent: any namespace may name any service. |
| `client_address` | `{"mode":"none"}` (default), `{"mode":"service_local","namespace":…,"name":…}`, `{"mode":"proxy_protocol"}` or `{"mode":"host_network"}`. |

Every profile is compiled against a probe route at startup, so an unusable profile stops the gateway instead of failing the first tenant. Environment references (`{"env": "NAME"}`) keep keys and tokens out of the file. Sumunjang is configured with the existing `--guard-*` flags; a policy with `enforcement: Required` is programmed only while `--guard-url` is set, `--guard-mode` is `query` and `--guard-failure-mode` is `deny` (snapshot mode expires open and is not fail-closed).

With the supplied manifests:

```sh
kubectl apply -k deploy/kubernetes/crds
kubectl create configmap hangang-protection \
  --from-file=settings.json=deploy/kubernetes/protection-settings.example.json
kubectl patch deployment hangang --type strategic \
  --patch-file deploy/kubernetes/protection-patch.yaml
kubectl patch service hangang --type strategic \
  --patch-file deploy/kubernetes/service-local-patch.yaml
```

Edit the example settings first, and create the `hangang-world-mtls` and `hangang-world-tokens` Secrets the patch mounts. The CRD kustomization is cluster-scoped and separate so that CRD upgrades stay an explicit step; it also installs aggregated ClusterRoles that let namespace `edit`/`admin` users manage the policies of their namespace and `view` users read them. The status subresource is written by the controller only. The controller Role gains `list`/`watch` on `protectionpolicies` and `patch` on `protectionpolicies/status`. If the CRD is missing, the policy list fails, the controller publishes nothing, and the replica stays not ready: a missing CRD can never mean "no policies".

## Writing a policy

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

[examples/kubernetes/protection-policy.yaml](../examples/kubernetes/protection-policy.yaml) adds an Ingress and a namespace default. The schema bounds every string and list, requires `targetRefs` exactly when `namespaceDefault` is false, rejects duplicate targets and duplicate methods, and allows `sectionName` only on Gateway API targets. The controller re-checks the same rules and treats unknown fields as invalid, so a policy it does not fully understand never protects less than intended.

Every generated route of the Ingress (all host/path rules and the default backend) is compiled to `access_mode: protected` with the profile's `auth` and an enforced `resource_policy` whose `pumgye_resource` is the policy's mapping, and the document carries the configured `pumgye_authority`. Each route gets its own `resource_id`, derived from its route ID and scope.

## Fail-closed rules

| Situation | Outcome | Reason |
| --- | --- | --- |
| No targeting policy and no namespace default, `require_protection: true` | Ingress withheld | `ProtectionRequired` |
| No policy, `require_protection: false` | Published as `access_mode: public` | — |
| A policy targets the Ingress but is invalid (even with `require_protection: false`) | Ingress withheld | `Invalid` |
| Two or more policies apply | Ingress withheld; all policies `Conflicted` | `Conflicted` |
| Profile unknown | Ingress withheld; `ResolvedRefs=False` | `InvalidIdentityProfile` |
| Profile or Pumgye service not permitted in the namespace | Ingress withheld; `ResolvedRefs=False` | `RefNotPermitted` |
| `enforcement: Required` without fail-closed Sumunjang | Ingress withheld | `GuardUnavailable` |
| `enforcement: Required` without client address preservation | Ingress withheld; `ClientAddressPreserved=False` | `ClientAddressUnavailable` |
| Withdrawn later by hostname ownership, TLS, route validation or budget | Not published | `Pending` |
| `HTTPRoute` or `Gateway` target | Nothing programmed for that target | `Unsupported` |

A withheld Ingress keeps its hostname ownership (it still claims its hosts), never receives the `--kubernetes-publish-address` status entry, and loses it if it carried one. Withholding never touches other Ingresses.

## Status, diagnostics and metrics

The controller writes `status` with the cached `resourceVersion` as a precondition. Top-level `conditions` carry `Accepted`, `ResolvedRefs`, `Programmed` and, for policies with network enforcement, `ClientAddressPreserved`, each with `observedGeneration`. `status.ancestors` follows the Gateway API policy status convention: one entry per target (for a namespace default, per Ingress it applies to; at most 16, the rest counted in the `Programmed` message) with `controllerName: hangang.dev/gateway-controller` and per-target conditions. Entries written by other controllers are preserved. `lastTransitionTime` changes only when a condition's status changes, so replicas do not fight over timestamps. A write that conflicts or finds the object gone is dropped; the watch event behind it reconciles again. `networking.k8s.io/v1` Ingress has no condition field, so an Ingress reports withholding only by not carrying the published address; the policy status and the diagnostics below give the reason.

`GET /v1/kubernetes/protection` on the administration API (administrator role) returns this instance's latest report: `require_protection`, client address and Sumunjang state, counts, and one row per selected Ingress (`protected`, `unprotected` or `withheld`, whether the published snapshot serves it, the attached policy, reason and message) and per policy, bounded to 1,000 rows each. `/metrics` adds `hangang_kubernetes_ingresses_protected`, `hangang_kubernetes_ingresses_unprotected`, `hangang_kubernetes_ingresses_withheld`, `hangang_kubernetes_protection_policies_invalid`, `hangang_kubernetes_protection_policies_conflicted` and `hangang_kubernetes_client_address_preserved`. Alert on `withheld > 0` during rollouts and on `unprotected > 0` once migration is complete.

## Client address preservation

Network conditions are only as good as the client address the gateway sees. Behind a plain ClusterIP Service, kube-proxy SNAT replaces it with a node address. A policy with `enforcement: Required` is therefore programmed only when the operator declares a preserving mode that the gateway can check:

| Mode | Check |
| --- | --- |
| `none` | Never preserved; `enforcement: Required` policies are withheld. |
| `service_local` | The named Service (in the watched set) is `LoadBalancer` or `NodePort` with `externalTrafficPolicy: Local`, re-checked on every change. |
| `proxy_protocol` | The public listener accepts PROXY protocol v2 (`--proxy-protocol-from`); the gateway refuses to start otherwise. |
| `host_network` | Declared by the operator for a `hostNetwork` edge (the current bare-metal topology). |

`--proxy-protocol-from CIDR` (repeatable or comma separated, at most 64) makes the public listener read a PROXY v2 header from peers in those ranges before TLS or HTTP. The header's source address then becomes the client address for every later step (trusted forwarding headers, Sumunjang, Pumgye, logs). A trusted peer that does not send a valid v2 header within 5 seconds is disconnected; a `LOCAL` header (load balancer health check) keeps the peer address. Peers outside the ranges are served as direct connections and their bytes are never parsed as a header, so a client cannot choose its own address. Version 1 text headers, UDP and Unix families are refused. Keep kubelet probe sources out of the trusted ranges, or probe the administration listener.

## Releasing a protected scope

The gateway refuses a configuration that silently drops an enforced resource scope (`resource … scope cannot be removed or moved`). In Kubernetes mode the API objects are the authority, so deleting a protected Ingress, changing its host or path, or detaching its policy is an explicit release: the controller first publishes a revision in which each released scope is kept as a **disabled** route with `enforce: false`, which serves no traffic, and then the desired snapshot. Without this step one deleted Ingress would freeze every later update.

## Migration

Existing Ingress deployments keep their behaviour until `--kubernetes-protection-config` is set. To adopt protection without an outage:

1. Install the CRD and roles (`deploy/kubernetes/crds`) and grant the controller Role the new rules.
2. Start with `"require_protection": false`. Unprotected Ingresses stay published, now explicitly as `access_mode: public` instead of legacy routes; Ingresses with a policy become protected immediately.
3. Write policies (targeted or namespace defaults) until `/v1/kubernetes/protection` and `hangang_kubernetes_ingresses_unprotected` show no unprotected Ingress, and every policy reports `Programmed=True`.
4. Remove `require_protection` (it defaults to `true`) and roll the Deployment. From then on a new Ingress without a policy is withheld and reported.
5. For `enforcement: Required`, enable Sumunjang in fail-closed query mode and a client address mode first; until both hold, those Ingresses are withheld with `GuardUnavailable` or `ClientAddressUnavailable`.

Rolling back is removing the flag: the controller returns to unprotected Ingress semantics, releasing each protected scope through the disabled revision described above.

## Scope and limitations

- ADR 0022 Decision 4 keeps Ingress as an unprotected compatibility path and places `ProtectionPolicy` on Gateway API routes. This slice attaches policies to Ingress first, because Ingress is what the controller reconciles today; HTTPRoute/Gateway attachment uses the same schema and resolution and is the next step (reconciling Gateway API kinds is not implemented yet).
- Action mapping is per HTTP method; path- or RPC-level mappings, `GRPCRoute`, the `WorldIdentityProfile` kind, signed snapshot distribution and the controller/authority split of ADR 0022 Decision 3 are not part of this slice.
- Pumgye service policy (for example its own network ceilings or `require_guard`) is evaluated by Pumgye at request time; the gateway only checks the namespace binding allowed by `pumgye_services`.
- Each replica writes status independently (there is no leader election); identical inputs produce identical status apart from carried timestamps.

## Verification

Unit tests cover settings validation, attachment and namespace defaults, deterministic conflict refusal, invalid policies never failing open, reference and namespace restrictions, Sumunjang and client address prerequisites, Gateway API status shape and timestamp carrying, the scope release revision, the shipped settings example and PROXY v2 parsing. The mock API server test runs the controller with a protected and an unprotected Ingress: only the protected one is published (with Hopae and Pumgye bindings) and receives the address, the policy status is written with the observed `resourceVersion`, deleting the policy withholds the Ingress, and a missing CRD publishes nothing. A black-box test drives PROXY v2 through the binary, and a static test checks the CRD against the ADR 0022 API rules:

```sh
cargo test --lib protection
cargo test --test kubernetes protection
python3 tests/proxy_protocol_smoke.py
python3 -m unittest tests/test_world_crds.py
```
