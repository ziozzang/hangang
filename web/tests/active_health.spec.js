import { test, expect } from '@playwright/test';

const active = {
  path: '/ready', host: null, interval_ms: 3000, timeout_ms: 2000,
  healthy_statuses: [200], unhealthy_statuses: [429, 500, 503],
  healthy_successes: 2, unhealthy_http_failures: 2,
  unhealthy_tcp_failures: 2, unhealthy_timeouts: 2,
};
const passive = {
  healthy_statuses: [200, 201], unhealthy_statuses: [429, 500, 503],
  unhealthy_http_failures: 2, unhealthy_tcp_failures: 2, unhealthy_timeouts: 2,
};
const route = {
  id: 'api', host: 'api.example.test', path_prefix: '/', backends: ['http://127.0.0.1:8080'],
  headers: {}, json: {}, deny_cidrs: [], balance: {
    mode: 'round_robin', weights: [], health: null, active_health: active, passive_health: passive,
  },
};

async function fixture(page, configured = route) {
  const writes = [];
  await page.route('**/*', (handled) => {
    const request = handled.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: {
      revision: 3, http_routes: 1, tcp_routes: 0, uptime_seconds: 10,
      metrics: { requests_total: 0, errors_total: 0, active_connections: 1 },
      state: { ready: true },
    } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/routes/http' && ['POST', 'PUT'].includes(request.method())) {
      writes.push(request.postDataJSON());
      return handled.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/http/api' && request.method() === 'PUT') {
      writes.push(request.postDataJSON());
      return handled.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/http/api') return handled.fulfill({ json: configured, headers: { etag: '"3"' } });
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision: 3, routes: [configured] }, headers: { etag: '"3"' } });
    if (path === '/v1/config') return handled.fulfill({ json: { revision: 3, http: [configured], tcp: [] } });
    return handled.fulfill({ status: 404, body: 'missing fixture' });
  });
  return writes;
}

async function openEdit(page) {
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function expand(page, title) {
  const details = page.locator('details.form-section').filter({ has: page.locator('.section-title', { hasText: title }) });
  if (!(await details.evaluate((element) => element.open))) await details.locator('summary').click();
}

test('omitted healthy startup round-trips unchanged, including future policy keys', async ({ page }) => {
  const configured = structuredClone(route);
  configured.balance.active_health.future_marker = 'retain';
  const writes = await fixture(page, configured);
  await openEdit(page);
  await expect(page.locator('#route-field-active_health_initial_state')).toHaveValue('healthy');
  await page.locator('#route-field-priority').fill('1');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].balance.active_health).toEqual(configured.balance.active_health);
  expect(writes[0].balance.active_health).not.toHaveProperty('initial_state');
  expect(writes[0].balance.passive_health).toEqual(passive);
});

test('native controls create checking active probes and passive checks with valid complete policy', async ({ page }) => {
  const writes = await fixture(page);
  await openEdit(page);
  await page.locator('#route-dialog [data-close-dialog]').first().click();
  await page.locator('[data-new-route="http"]').click();
  await page.locator('#route-field-id').fill('new-checking');
  await expand(page, 'Active health checks');
  await page.getByLabel('Enable active health checks').check();
  await expect(page.locator('#route-field-active_health_path')).toBeEnabled();
  await page.locator('#route-field-active_health_path').fill('/ready');
  await page.locator('#route-field-active_health_initial_state').selectOption('checking');
  await page.locator('#route-field-active_health_healthy_successes').fill('2');
  await page.locator('#route-field-active_health_host').fill('probe.example.test');
  await page.locator('#route-field-active_health_interval_ms').fill('4000');
  await page.locator('#route-field-active_health_timeout_ms').fill('1500');
  await page.locator('#route-field-active_health_healthy_statuses').fill('200, 204');
  await page.locator('#route-field-active_health_unhealthy_statuses').fill('429, 503');
  await page.locator('#route-field-active_health_unhealthy_http_failures').fill('3');
  await page.locator('#route-field-active_health_unhealthy_tcp_failures').fill('4');
  await page.locator('#route-field-active_health_unhealthy_timeouts').fill('5');
  await expand(page, 'Passive health checks');
  await page.getByLabel('Enable passive health checks').check();
  await page.locator('#route-field-passive_health_healthy_statuses').fill('200, 204');
  await page.locator('#route-field-passive_health_unhealthy_statuses').fill('429, 503');
  await page.locator('#route-field-passive_health_unhealthy_http_failures').fill('3');
  await page.locator('#route-field-passive_health_unhealthy_tcp_failures').fill('4');
  await page.locator('#route-field-passive_health_unhealthy_timeouts').fill('5');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].balance.active_health).toEqual({ ...active,
    host: 'probe.example.test', interval_ms: 4000, timeout_ms: 1500,
    healthy_statuses: [200, 204], unhealthy_statuses: [429, 503],
    unhealthy_http_failures: 3, unhealthy_tcp_failures: 4, unhealthy_timeouts: 5,
    initial_state: 'checking',
  });
  expect(writes[0].balance.passive_health).toEqual({ ...passive,
    healthy_statuses: [200, 204], unhealthy_statuses: [429, 503],
    unhealthy_http_failures: 3, unhealthy_tcp_failures: 4, unhealthy_timeouts: 5,
  });
});

test('checking with Docker backends is blocked locally and explained in both languages', async ({ page }) => {
  const configured = structuredClone(route);
  configured.backends = ['docker://api/edge/8080'];
  configured.balance.active_health.initial_state = 'healthy';
  const writes = await fixture(page, configured);
  await openEdit(page);
  await expand(page, 'Active health checks');
  await expect(page.locator('#route-dialog')).toContainText('docker:// probe targets are unsupported');
  await page.locator('#route-field-active_health_initial_state').selectOption('checking');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-message')).toContainText('Checking startup does not support docker:// backends');
  expect(writes).toHaveLength(0);
  await page.locator('#locale-select-route').selectOption('ko');
  await page.getByRole('button', { name: '경로 저장' }).click();
  await expect(page.locator('#route-message')).toContainText('docker:// 백엔드를 지원하지 않습니다');
});

test('native validation blocks cooldown conflict, overlapping statuses and timeout longer than interval', async ({ page }) => {
  const configured = structuredClone(route);
  configured.balance.health = { failure_threshold: 2, cooldown_ms: 1000 };
  configured.balance.active_health = null;
  configured.balance.passive_health = null;
  const writes = await fixture(page, configured);
  await openEdit(page);
  await expand(page, 'Active health checks');
  await page.getByLabel('Enable active health checks').check();
  await page.locator('#route-field-active_health_path').fill('/ready');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('conflict');
  await expand(page, 'Load balancing');
  await page.locator('#route-field-health_failure_threshold').fill('');
  await page.locator('#route-field-health_cooldown_ms').fill('');
  await page.locator('#route-field-active_health_unhealthy_statuses').fill('200, 503');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('cannot overlap');
  await page.locator('#route-field-active_health_unhealthy_statuses').fill('503');
  await page.locator('#route-field-active_health_timeout_ms').fill('4000');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes).toHaveLength(0);
  await expect(page.locator('#route-message')).toContainText('cannot exceed interval');
});

test('advanced JSON checking policy and passive removal survive later native edits', async ({ page }) => {
  const writes = await fixture(page);
  await openEdit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.balance.active_health.initial_state = 'checking';
  draft.balance.active_health.future_marker = 'retain';
  draft.balance.passive_health = null;
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.locator('#route-field-active_health_initial_state')).toHaveValue('checking');
  await expect(page.locator('#route-field-passive_health_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('4');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].balance.active_health).toEqual(draft.balance.active_health);
  expect(writes[0].balance.passive_health).toBeNull();
});

test('advanced JSON adds full health policy before unrelated native edit without stale controls', async ({ page }) => {
  const configured = structuredClone(route);
  configured.balance.active_health = null;
  configured.balance.passive_health = null;
  const writes = await fixture(page, configured);
  await openEdit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.balance.active_health = { ...active, initial_state: 'checking', path: '/probe', interval_ms: 5000 };
  draft.balance.passive_health = { ...passive, unhealthy_timeouts: 7 };
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.locator('#route-field-active_health_enabled')).toBeChecked();
  await expect(page.locator('#route-field-passive_health_enabled')).toBeChecked();
  await expect(page.locator('#route-field-active_health_path')).toHaveValue('/probe');
  await expect(page.locator('#route-field-active_health_initial_state')).toHaveValue('checking');
  await expect(page.locator('#route-field-passive_health_unhealthy_timeouts')).toHaveValue('7');
  await page.locator('#route-field-priority').fill('9');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].balance.active_health).toEqual(draft.balance.active_health);
  expect(writes[0].balance.passive_health).toEqual(draft.balance.passive_health);
});

test('advanced JSON removes both health policies before native edit', async ({ page }) => {
  const writes = await fixture(page);
  await openEdit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.balance.active_health = null;
  draft.balance.passive_health = null;
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.locator('#route-field-active_health_enabled')).not.toBeChecked();
  await expect(page.locator('#route-field-passive_health_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('8');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].balance.active_health).toBeNull();
  expect(writes[0].balance.passive_health).toBeNull();
});
