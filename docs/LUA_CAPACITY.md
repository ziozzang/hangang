# Lua capacity reporting

[Documentation](README.md) · [한국어 요약](ko/LUA_CAPACITY.md)

Route Lua work uses a bounded process pool. When every slot is busy or cooling down after a worker failure, `PolicyPool` rejects immediately; it does not queue an unlimited number of requests or skip the policy. Worker count and deadlines remain the existing process settings. Capacity reporting does not add a request queue.

For a route-policy call rejected with typed `WorkerCapacityUnavailable`, the proxy returns **503** with `policy worker capacity exhausted`. It does not dispatch that request to the origin. A script/worker failure retains `policy evaluation failed`. No `Retry-After` estimate is invented.

| Surface | Field | Meaning |
|---|---|---|
| Status API and SSE | `metrics.policy_capacity_rejections_total` | Process-local count of route Lua calls rejected because all slots are busy/restarting. |
| Prometheus | `hangang_policy_capacity_rejections_total` | Same counter, with no user, route or script labels. |
| Status UI (English/Korean) | Lua capacity rejections | Observed counter; `—` if an older server does not provide it, `0` only when reported zero. |

`policy_errors_total` / `hangang_policy_errors_total` retains its historical aggregate semantics and still includes capacity rejection. **Do not add the subset to the aggregate.** A Lua script's deliberate `hangang.reject(...)` is a policy decision rather than this capacity event. Body-transform admission/`PolicyBusy` is outside the new route-policy counter, even though Lua body transforms share the underlying worker pool. Existing body-transform reporting remains separate.

A counter is not a utilization percentage, available-worker gauge, queue depth or fleet total. Increasing workers changes resource consumption and does not establish unlimited concurrency. Size workers using your workload, memory budget and timeout requirements.

An owned barrier-worker integration test waits until the first request has reached its worker, submits another request, asserts the distinct rejection and unchanged origin count, then releases the worker and proves successful later requests. A separate worker error increments only the aggregate. API/Prometheus tests check the same counter value; browser tests check missing/zero values, SSE updates and Korean labels. These are correctness tests, not commercial-product performance evidence.
