import { test, expect } from '@playwright/test';

const tcp = {
  id: 'socket', listen: '127.0.0.1:9001', backends: ['127.0.0.1:5432'],
  priority: 0, sni: null, deny_cidrs: [],
};
const checking = {
  interval_ms: 4000, timeout_ms: 1500, healthy_successes: 3,
  unhealthy_failures: 4, initial_state: 'checking',
};

async function fixture(page, configured = tcp) {
  const writes = [];
  await page.route('**/*', (handled) => {
    const request = handled.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return handled.continue();
    if (path === '/v1/auth/setup') return handled.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return handled.fulfill({ json: {
      revision: 3, http_routes: 0, tcp_routes: 1, uptime_seconds: 10,
      metrics: { requests_total: 0, errors_total: 0, active_connections: 0 }, state: { ready: true },
    } });
    if (path === '/v1/update/status') return handled.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return handled.fulfill({ json: { records: [] } });
    if (path === '/v1/events') return handled.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/routes/tcp' && request.method() === 'POST') {
      writes.push(request.postDataJSON());
      return handled.fulfill({ status: 201, json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/tcp/socket' && request.method() === 'PUT') {
      writes.push(request.postDataJSON());
      return handled.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/tcp/socket') return handled.fulfill({ json: configured, headers: { etag: '"3"' } });
    if (path === '/v1/routes/tcp') return handled.fulfill({ json: { revision: 3, routes: [configured] }, headers: { etag: '"3"' } });
    if (path === '/v1/routes/http') return handled.fulfill({ json: { revision: 3, routes: [] }, headers: { etag: '"3"' } });
    if (path === '/v1/config') return handled.fulfill({ json: { revision: 3, http: [], tcp: [configured] } });
    return handled.fulfill({ status: 404, body: 'missing fixture' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.getByRole('link', { name: 'TCP routes' }).click();
  return writes;
}

async function edit(page) {
  await page.locator('[data-route-id="socket"]').getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

async function openHealth(page) {
  const details = page.locator('details.form-section').filter({ has: page.locator('.section-title', { hasText: 'TCP connection health checks' }) });
  if (!(await details.evaluate((element) => element.open))) await details.locator('summary').click();
}

test('omitted TCP health remains omitted after an unrelated native edit', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await openHealth(page);
  await expect(page.locator('#route-field-tcp_health_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('2');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0]).not.toHaveProperty('health');
});

test('native controls create a checking TCP connection policy with every field', async ({ page }) => {
  const writes = await fixture(page);
  await page.locator('[data-new-route="tcp"]').click();
  await page.locator('#route-field-id').fill('new-tcp');
  await openHealth(page);
  await page.getByLabel('Enable TCP health checks').check();
  await page.locator('#route-field-tcp_health_initial_state').selectOption('checking');
  await page.locator('#route-field-tcp_health_interval_ms').fill('4000');
  await page.locator('#route-field-tcp_health_timeout_ms').fill('1500');
  await page.locator('#route-field-tcp_health_healthy_successes').fill('3');
  await page.locator('#route-field-tcp_health_unhealthy_failures').fill('4');
  await page.getByRole('button', { name: 'Create route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].health).toEqual(checking);
});

test('healthy default omits initial_state and an existing TCP policy can be disabled', async ({ page }) => {
  const configured = { ...tcp, health: checking };
  const writes = await fixture(page, configured);
  await edit(page);
  await openHealth(page);
  await expect(page.locator('#route-field-tcp_health_initial_state')).toHaveValue('checking');
  await page.locator('#route-field-tcp_health_initial_state').selectOption('healthy');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes[0].health).toEqual({ interval_ms: 4000, timeout_ms: 1500, healthy_successes: 3, unhealthy_failures: 4 });
  await edit(page);
  await openHealth(page);
  await page.getByLabel('Enable TCP health checks').uncheck();
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes[1].health).toBeNull();
});

test('advanced JSON TCP health add and remove survive unrelated native input', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.health = checking;
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.locator('#route-field-tcp_health_enabled')).toBeChecked();
  await expect(page.locator('#route-field-tcp_health_initial_state')).toHaveValue('checking');
  await expect(page.locator('#route-field-tcp_health_timeout_ms')).toHaveValue('1500');
  await page.locator('#route-field-priority').fill('5');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes[0].health).toEqual(checking);

  await edit(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const removed = JSON.parse(await json.inputValue());
  removed.health = null;
  await json.fill(JSON.stringify(removed, null, 2));
  await expect(page.locator('#route-field-tcp_health_enabled')).not.toBeChecked();
  await page.locator('#route-field-priority').fill('6');
  await page.getByRole('button', { name: 'Save route' }).click();
  expect(writes[1].health).toBeNull();
});

test('invalid probe timeout is blocked and Korean switch preserves the dirty policy', async ({ page }) => {
  const writes = await fixture(page);
  await edit(page);
  await openHealth(page);
  await page.getByLabel('Enable TCP health checks').check();
  await page.locator('#route-field-tcp_health_initial_state').selectOption('checking');
  await page.locator('#route-field-tcp_health_interval_ms').fill('1000');
  await page.locator('#route-field-tcp_health_timeout_ms').fill('2000');
  await expect(page.locator('#route-message')).toContainText('TCP probe timeout cannot exceed interval');
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.locator('#route-field-tcp_health_initial_state')).toHaveValue('checking');
  await expect(page.locator('#route-field-tcp_health_interval_ms')).toHaveValue('1000');
  await expect(page.locator('#route-message')).toContainText('TCP 프로브 시간 제한은 간격보다 길 수 없습니다');
  await page.getByRole('button', { name: '경로 저장' }).click();
  expect(writes).toHaveLength(0);
});
