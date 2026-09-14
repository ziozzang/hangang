import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

const read = (relative) => readFileSync(fileURLToPath(new URL(relative, import.meta.url)), 'utf8');
const source = {
  app: read('../app.js'), console: read('../console.js'), operations: read('../operations.js'),
  docker: read('../docker.js'),
};

// Each published operation needs a feature-specific UI surface and a real caller.
// The API reference page alone is deliberately insufficient for any operation
// except GET /openapi.json. Background auth/session flows have visible state.
const coverage = new Map([
  ['GET /openapi.json', ['#view-docs', 'app', "api('/openapi.json'"]],
  ['GET /healthz', ['#check-health', 'app', "api('/healthz'"]],
  ['GET /metrics', ['#load-metrics', 'app', "api('/metrics'"]],
  ['GET /v1/cache', ['#cache-content', 'app', "api('/v1/cache'"]],
  ['GET /v1/certificates', ['#certificate-inventory', 'app', '/v1/certificates?offset=']],
  ['GET /v1/geoip/status', ['#geoip-refresh-status', 'app', "api('/v1/geoip/status'"]],
  ['GET /v1/geoip/lookup', ['#geoip-lookup-form', 'app', '/v1/geoip/lookup?ip=']],
  ['POST /v1/cache/purge', ['#purge-cache', 'app', "api('/v1/cache/purge'"]],
  ['GET /v1/events', ['#stream-state', 'console', "fetch('/v1/events'"]],
  ['GET /v1/traffic', ['#activity-panel', 'console', "fetch('/v1/traffic?limit=128'"]],
  ['GET /v1/connections/tcp/active', ['#tcp-active-rows', 'console', '/v1/connections/tcp/active${query}']],
  ['GET /v1/connections/tcp/recent', ['#tcp-recent-rows', 'console', '/v1/connections/tcp/recent?limit=128']],
  ['GET /v1/operations', ['#view-operations', 'operations', '/v1/operations?offset=']],
  ['GET /v1/retired-members', ['#retired-rows', 'operations', '/v1/retired-members?offset=']],
  ['GET /v1/status', ['#view-status', 'app', "api('/v1/status'"]],
  ['POST /v1/lifecycle/restart', ['#restart-server', 'app', "api('/v1/lifecycle/restart'"]],
  ['GET /v1/update/status', ['#update-state', 'app', "api('/v1/update/status'"]],
  ['POST /v1/update/check', ['#check-update', 'app', "api('/v1/update/check'"]],
  ['GET /v1/config', ['#config-editor', 'app', "api('/v1/config'"]],
  ['PUT /v1/config', ['#apply-config', 'app', "api('/v1/config', { method: 'PUT'"]],
  ['POST /v1/config/validate', ['#validate-config', 'app', "api('/v1/config/validate'"]],
  ['GET /v1/routes/http', ['#http-routes', 'app', '/v1/routes/${type}']],
  ['POST /v1/routes/http', ['[data-new-route="http"]', 'app', "method: editing ? 'PUT' : 'POST'"]],
  ['GET /v1/routes/http/{id}', ['#route-dialog', 'app', 'encodeURIComponent(route.id)']],
  ['PUT /v1/routes/http/{id}', ['#save-route', 'app', 'encodeURIComponent(originalId)']],
  ['DELETE /v1/routes/http/{id}', ['#delete-route', 'app', "method: 'DELETE'"]],
  ['GET /v1/routes/tcp', ['#tcp-routes', 'app', '/v1/routes/${type}']],
  ['POST /v1/routes/tcp', ['[data-new-route="tcp"]', 'app', "method: editing ? 'PUT' : 'POST'"]],
  ['GET /v1/routes/tcp/{id}', ['#route-dialog', 'app', 'encodeURIComponent(route.id)']],
  ['PUT /v1/routes/tcp/{id}', ['#save-route', 'app', 'encodeURIComponent(originalId)']],
  ['DELETE /v1/routes/tcp/{id}', ['#delete-route', 'app', "method: 'DELETE'"]],
  ['GET /v1/docker/connection', ['#view-docker', 'docker', "apiCall('/v1/docker/connection')"]],
  ['PUT /v1/docker/connection', ['#docker-panel', 'docker', "apiCall('/v1/docker/connection', { method: 'PUT'"]],
  ['DELETE /v1/docker/connection', ['#docker-panel', 'docker', "apiCall('/v1/docker/connection', { method: 'DELETE'"]],
  ['POST /v1/docker/connection/test', ['#docker-panel', 'docker', "apiCall('/v1/docker/connection/test', { method: 'POST'"]],
  ['POST /v1/docker/resolve', ['#view-docker', 'docker', "apiCall('/v1/docker/resolve'"]],
  ['POST /v1/util/hash-password', ['#utility-hash-form', 'app', "api('/v1/util/hash-password'"]],
  ['GET /v1/auth/setup', ['#login-dialog', 'app', "api('/v1/auth/setup'"]],
  ['POST /v1/auth/bootstrap', ['#setup-login-fields', 'app', "api('/v1/auth/bootstrap'"]],
  ['POST /v1/auth/login', ['#account-login-fields', 'app', "api('/v1/auth/login'"]],
  ['GET /v1/auth/me', ['#verify-session', 'app', "api('/v1/auth/me'"]],
  ['POST /v1/auth/logout', ['#logout-button', 'app', "fetch('/v1/auth/logout'"]],
  ['GET /v1/users', ['#user-list', 'app', "api('/v1/users'"]],
  ['POST /v1/users', ['#create-user-form', 'app', "api('/v1/users', { method: 'POST'"]],
  ['PUT /v1/users/{id}', ['#user-list', 'app', '/v1/users/${encodeURIComponent(user.id)}']],
  ['DELETE /v1/users/{id}', ['#user-list', 'app', '/v1/users/${encodeURIComponent(user.id)}']],
  ['GET /v1/audit/users', ['#view-audit', 'app', '/v1/audit/users?after=']],
  ['GET /v1/config/operations', ['#view-config-operations', 'app', '/v1/config/operations?after=']],
  ['GET /v1/config/operation-proof', ['#config-proof-state', 'app', "api('/v1/config/operation-proof'"]],
  ['GET /v1/config/commit-receipt', ['#config-receipt-form', 'app', ": '/v1/config/commit-receipt';"]],
  ['GET /v1/config/commit-receipt-v2', ['#config-receipt-mode', 'app', '/v1/config/commit-receipt-v2']],
  ['GET /v1/config/commit-receipts-v2', ['#config-receipt-export-v2', 'app', '/v1/config/commit-receipts-v2?']],
  ['POST /v1/config/operations/prune', ['#config-operations-prune', 'app', "api('/v1/config/operations/prune', { method: 'POST'"]],
  ['POST /v1/audit/users/prune', ['#audit-prune', 'app', "api('/v1/audit/users/prune', { method: 'POST'"]],
]);

test('every OpenAPI operation has a concrete console surface and caller', async ({ page }) => {
  const spec = JSON.parse(read('../../docs/openapi.json'));
  const operations = Object.entries(spec.paths).flatMap(([path, methods]) =>
    Object.keys(methods).filter((method) => /^(get|post|put|patch|delete|head|options)$/.test(method))
      .map((method) => `${method.toUpperCase()} ${path}`));
  expect([...coverage.keys()].sort()).toEqual(operations.sort());

  await page.goto('/ui/');
  for (const [operation, [selector, module, call]] of coverage) {
    if (selector === '#view-docs') expect(operation).toBe('GET /openapi.json');
    await expect(page.locator(selector), `${operation} has no dedicated UI selector ${selector}`).toHaveCount(1);
    expect(source[module], `${operation} has no caller in ${module}.js`).toContain(call);
  }
});

test('embedded public UI asset list includes every locale and operations module', async ({ request }) => {
  const embeddedAssets = read('../../src/ui.rs');
  for (const path of [
    '/ui/', '/ui/index.html', '/ui/lua-editor.js', '/ui/lua-editor.css', '/ui/app.js', '/ui/console.js', '/ui/operations.js', '/ui/docker.js',
    '/ui/i18n.js', '/ui/locales/ko-static.js', '/ui/locales/ko-app.js',
    '/ui/locales/ko-console.js', '/ui/locales/ko-operations.js', '/ui/locales/ko-docker.js', '/ui/style.css',
  ]) {
    const response = await request.get(path);
    expect(response.status(), `${path} is not served by the UI fixture`).toBe(200);
    expect(embeddedAssets).toContain(`"${path}"`);
  }
});

test('new TCP route uses a container-reachable bind and explains host port publishing', async ({ page }) => {
  await page.route('**/*', (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return route.fulfill({ json: {
      revision: 1, http_routes: 0, tcp_routes: 0, uptime_seconds: 1,
      state: { ready: true }, metrics: { requests_total: 0, errors_total: 0 },
    } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/routes/tcp') return route.fulfill({ json: { revision: 1, routes: [] }, headers: { etag: '"1"' } });
    if (path === '/v1/traffic') return route.fulfill({ json: {
      records: [], server_time_unix_ms: Date.now(), next_after: 0,
      latest_id: 0, gap: false, dropped_total: 0, retention_seconds: 60,
    } });
    return route.fulfill({ status: 503, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="tcp"]').click();
  await page.locator('[data-new-route="tcp"]').click();
  await expect(page.locator('#route-field-listen')).toHaveValue('0.0.0.0:9001');
  await expect(page.locator('#route-field-listen-help')).toContainText('Host networking binds directly');
  await expect(page.locator('#route-field-listen-help')).toContainText('bridge networking requires a published port');
  await expect(page.locator('#route-field-listen-help')).toContainText('host firewall');
});
