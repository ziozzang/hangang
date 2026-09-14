import { test, expect } from '@playwright/test';

const uri = 'spiffe://example.test/services/orders';
const tls = {
  cert_file: '/etc/hangang/workload/server.pem', key_file: '/etc/hangang/workload/server-key.pem',
  client_ca_file: '/etc/hangang/workload/client-ca.pem', client_crl_file: null,
  allowed_uri_sans: [uri], handshake_timeout_ms: 5000,
};
const listener = { id: 'orders', listen: '127.0.0.1:9443', tls };
const route = { id: 'orders-api', access_mode: 'public', host: 'api.example.test', path_prefix: '/orders',
  backends: ['http://127.0.0.1:8080'], auth: null, basic_auth: null, jwt_auth: null };

async function fixture(page, locale = 'en') {
  let revision = 7;
  let document = { revision, http: [structuredClone(route)], tcp: [], certificates: [], workload_http: [] };
  const configWrites = []; const routeWrites = [];
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (handled) => {
    const request = handled.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: { revision, http_routes: 1, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/config/validate') return handled.fulfill({ json: { valid: true, revision } });
    if (path === '/v1/config') {
      if (request.method() === 'PUT') {
        const next = request.postDataJSON(); configWrites.push(next); revision++;
        document = { ...next, revision };
        return handled.fulfill({ json: document, headers: { etag: `"${revision}"` } });
      }
      return handled.fulfill({ json: document, headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision, routes: document.http }, headers: { etag: `"${revision}"` } });
    if (path === '/v1/routes/http/orders-api') {
      if (request.method() === 'PUT') {
        const next = request.postDataJSON(); routeWrites.push(next); revision++;
        document.http[0] = next;
        return handled.fulfill({ json: { revision }, headers: { etag: `"${revision}"` } });
      }
      return handled.fulfill({ json: document.http[0], headers: { etag: `"${revision}"` } });
    }
    if (path === '/v1/routes/tcp') return handled.fulfill({ json: { revision, routes: [] }, headers: { etag: `"${revision}"` } });
    return handled.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { configWrites, routeWrites, current: () => document };
}

async function configPanel(page) {
  await page.locator('[data-view="config"]').click();
  await expect(page.locator('#workload-http-panel')).toBeVisible();
  await page.locator('#workload-http-panel summary').click();
}

async function routeEditor(page) {
  await page.locator('[data-view="http"]').click();
  await page.locator('[data-route-id="orders-api"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function reveal(page, name) {
  const section = page.locator(`#route-field-${name}`).locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((node) => node.open))) await section.locator('summary').click();
}

test('listener create, edit, activation and removal are staged through full-config CAS', async ({ page }) => {
  const { configWrites, current } = await fixture(page);
  await configPanel(page);
  await page.locator('#workload-http-add').click();
  const form = page.locator('#workload-http-form');
  for (const [name, value] of Object.entries({ id: listener.id, listen: listener.listen, ...tls })) {
    if (name === 'allowed_uri_sans') await form.locator('[name="allowed_uri_sans"]').fill(value.join('\n'));
    else if (name !== 'client_crl_file') await form.locator(`[name="${name}"]`).fill(String(value));
  }
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await expect(page.locator('#workload-http-list [data-workload-id="orders"]')).toBeVisible();
  expect(configWrites).toHaveLength(0);
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).workload_http[0]).toEqual(listener);
  await page.locator('#apply-config').click();
  expect(configWrites).toHaveLength(1);
  expect(current().workload_http).toEqual([listener]);

  await page.locator('#workload-http-list [data-workload-id="orders"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#workload-http-message')).not.toHaveClass(/is-error/);
  await expect(form.locator('[name="id"]')).toBeFocused();
  await form.locator('[name="handshake_timeout_ms"]').fill('7000');
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await page.locator('#workload-http-list [data-workload-id="orders"]').getByRole('button', { name: 'Deactivate' }).click();
  const staged = JSON.parse(await page.locator('#config-editor').inputValue()).workload_http[0];
  expect(staged.tls.handshake_timeout_ms).toBe(7000);
  expect(staged.enabled).toBe(false);
  await page.locator('#workload-http-list [data-workload-id="orders"]').getByRole('button', { name: 'Remove' }).click();
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).workload_http).toEqual([]);
  expect(configWrites).toHaveLength(1);
});

test('protected route accepts workload principal and exact SPIFFE subject via native controls', async ({ page }) => {
  const { routeWrites } = await fixture(page);
  await routeEditor(page);
  await reveal(page, 'access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await reveal(page, 'workload_auth_enabled');
  await page.locator('#route-field-workload_auth_enabled').check();
  await page.locator('#route-field-workload_listener_ids').fill('orders');
  await page.locator('#route-field-workload_allowed_uri_sans').fill(uri);
  await reveal(page, 'resource_policy_action');
  await page.locator('#route-field-resource_policy_action').selectOption('configured');
  await page.locator('#route-field-resource_policy_id').fill('orders-resource');
  await page.locator('#route-field-resource_policy_source').selectOption('workload');
  await page.locator('.resource-rule-add').click();
  await page.locator('.resource-rule-subjects').fill(uri);
  await page.locator('.resource-rule-methods').fill('GET');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(routeWrites).toHaveLength(1);
  expect(routeWrites[0].workload_auth).toEqual({ listener_ids: ['orders'], allowed_uri_sans: [uri], identity_header: null });
  expect(routeWrites[0].resource_policy.principal).toEqual({ source: 'workload' });
  expect(routeWrites[0].resource_policy.allow[0].subjects).toEqual([uri]);
});

test('advanced workload JSON and principal survive unrelated native edits', async ({ page }) => {
  const { routeWrites } = await fixture(page);
  await routeEditor(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.access_mode = 'protected';
  draft.workload_auth = { listener_ids: ['orders'], allowed_uri_sans: [uri], identity_header: 'x-workload-identity' };
  draft.resource_policy = { resource_id: 'orders-resource', principal: { source: 'workload' }, allow: [{ subjects: [uri], methods: ['GET'] }] };
  await json.fill(JSON.stringify(draft));
  await expect(page.locator('#route-field-workload_auth_enabled')).toBeChecked();
  await expect(page.locator('#route-field-resource_policy_source')).toHaveValue('workload');
  await page.locator('#route-field-priority').fill('4');
  await page.locator('#save-route').click();
  expect(routeWrites).toHaveLength(1);
  expect(routeWrites[0].workload_auth).toEqual(draft.workload_auth);
  expect(routeWrites[0].resource_policy).toEqual(draft.resource_policy);
});

test('workload authorization cannot be saved without a resource policy or canonical URI', async ({ page }) => {
  const { routeWrites } = await fixture(page);
  await routeEditor(page);
  await reveal(page, 'access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await reveal(page, 'workload_auth_enabled');
  await page.locator('#route-field-workload_auth_enabled').check();
  await page.locator('#route-field-workload_listener_ids').fill('orders');
  await page.locator('#route-field-workload_allowed_uri_sans').fill('spiffe://Example.test/services/orders');
  await expect(page.locator('#route-message')).toContainText('canonical SPIFFE URIs');
  await page.locator('#route-field-workload_allowed_uri_sans').fill(uri);
  await expect(page.locator('#route-message')).toContainText('requires resource authorization');
  await page.locator('#save-route').click();
  expect(routeWrites).toHaveLength(0);
});

test('Korean workload listener controls show staged-only publication', async ({ page }) => {
  await fixture(page, 'ko');
  await configPanel(page);
  await expect(page.locator('#workload-http-panel .section-title')).toHaveText('전용 HTTP 워크로드 mTLS 수신기');
  await page.locator('#workload-http-add').click();
  await expect(page.locator('#workload-http-form label[for="workload-http-client_ca_file"]')).toContainText('신뢰할 클라이언트 CA 파일');
  await expect(page.locator('#workload-http-panel .section-note')).toContainText('구성 적용');
});

test('raw configuration JSON refreshes native listener list and logout scrubs it', async ({ page }) => {
  await fixture(page);
  await configPanel(page);
  const editor = page.locator('#config-editor');
  const draft = JSON.parse(await editor.inputValue());
  draft.workload_http = [listener];
  await editor.fill(JSON.stringify(draft));
  await expect(page.locator('#workload-http-list [data-workload-id="orders"]')).toBeVisible();
  await page.locator('#workload-http-list [data-workload-id="orders"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#workload-http-form [name="client_ca_file"]')).toHaveValue(tls.client_ca_file);
  await page.locator('#logout-button').click();
  await expect(page.locator('#workload-http-list')).toBeEmpty();
  await expect(page.locator('#workload-http-form')).toBeHidden();
  await expect(editor).toHaveValue('');
});

test('native listener editor rejects non-path material and noncanonical identities', async ({ page }) => {
  const { configWrites } = await fixture(page);
  await configPanel(page);
  await page.locator('#workload-http-add').click();
  const form = page.locator('#workload-http-form');
  await form.locator('[name="id"]').fill('orders');
  await form.locator('[name="listen"]').fill(listener.listen);
  await form.locator('[name="key_file"]').fill('pasted certificate material is not a file path');
  await form.locator('[name="cert_file"]').fill(tls.cert_file);
  await form.locator('[name="client_ca_file"]').fill(tls.client_ca_file);
  await form.locator('[name="allowed_uri_sans"]').fill(uri);
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await expect(page.locator('#workload-http-message')).toContainText('absolute normalized file path');
  await form.locator('[name="key_file"]').fill(tls.key_file);
  await form.locator('[name="allowed_uri_sans"]').fill('spiffe://Example.test/services/orders');
  await form.getByRole('button', { name: 'Stage listener in document' }).click();
  await expect(page.locator('#workload-http-message')).toContainText('canonical SPIFFE URIs');
  expect(configWrites).toHaveLength(0);
  expect(JSON.parse(await page.locator('#config-editor').inputValue()).workload_http).toEqual([]);
});
