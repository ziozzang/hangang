import { test, expect } from '@playwright/test';

const credential = `alice:${'ab'.repeat(16)}:${'cd'.repeat(32)}`;
const routes = [
  { id: 'legacy', host: 'legacy.example.test', backends: ['http://127.0.0.1:8080'],
    balance: { mode: 'round_robin', weights: [], health: null, active_health: {
      path: '/ready', host: null, interval_ms: 1000, timeout_ms: 500,
      healthy_statuses: [200], unhealthy_statuses: [429, 500, 503],
      healthy_successes: 1, unhealthy_http_failures: 2,
      unhealthy_tcp_failures: 2, unhealthy_timeouts: 2,
    } },
    auth: null, basic_auth: null, lua: 'return true' },
  { id: 'guarded', access_mode: 'protected', host: 'guarded.example.test', backends: ['http://127.0.0.1:8081'],
    auth: { url: 'https://auth.example.test/check' }, basic_auth: null },
  { id: 'open', access_mode: 'public', host: 'open.example.test', backends: ['http://127.0.0.1:8082'], auth: null, basic_auth: null },
  { id: 'app', access_mode: 'application', host: 'app.example.test', backends: ['http://127.0.0.1:8083'], auth: null, basic_auth: null },
];

async function setup(page, locale = 'en') {
  const writes = [];
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: routes.length, tcp_routes: 0, metrics: {}, state: { draining: false }, uptime_seconds: 1, version: 'test', process_id: 1 } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 7, settings: {}, http: routes, tcp: [], certificates: [] }, headers: { etag: '"7"' } });
    if (path === '/v1/routes/http') {
      if (request.method() === 'POST') { writes.push(request.postDataJSON()); return route.fulfill({ status: 201, json: { revision: 8 }, headers: { etag: '"8"' } }); }
      return route.fulfill({ json: { revision: 7, routes }, headers: { etag: '"7"' } });
    }
    if (path.startsWith('/v1/routes/http/')) {
      if (request.method() === 'PUT') { writes.push(request.postDataJSON()); return route.fulfill({ json: { revision: 8 }, headers: { etag: '"8"' } }); }
      const id = decodeURIComponent(path.slice('/v1/routes/http/'.length));
      return route.fulfill({ json: routes.find((item) => item.id === id), headers: { etag: '"7"' } });
    }
    if (path === '/v1/routes/tcp') return route.fulfill({ json: { revision: 7, routes: [] }, headers: { etag: '"7"' } });
    return route.fulfill({ status: 404, body: 'fixture unavailable' });
  });
  await page.goto('/ui/');
  await page.locator('#token-input').fill('fixture-token');
  await page.locator('#login-dialog').getByRole('button', { name: locale === 'ko' ? '연결' : 'Connect' }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('[data-view="http"]').click();
  return writes;
}

async function edit(page, id) {
  await page.locator(`[data-route-id="${id}"]`).getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}
async function reveal(page, selector) {
  const section = page.locator(selector).locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((element) => element.open))) await section.locator('summary').click();
}

test('legacy route stays omitted after native edit and keeps advanced fields', async ({ page }) => {
  const writes = await setup(page);
  await edit(page, 'legacy');
  await expect(page.locator('#route-field-access_mode')).toHaveValue('legacy');
  await page.locator('#route-field-priority').fill('2');
  await expect.poll(async () => JSON.parse(await page.locator('#route-json').inputValue()).priority).toBe(2);
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0]).not.toHaveProperty('access_mode');
  expect(writes[0].balance.active_health).toEqual(routes[0].balance.active_health);
  expect(writes[0].lua).toBe('return true');
});

test('protected requires gateway auth; public and application reject configured auth', async ({ page }) => {
  const writes = await setup(page);
  await page.locator('[data-new-route="http"]').click();
  await page.locator('#route-field-id').fill('new-protected');
  await reveal(page, '#route-field-access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await expect(page.locator('#route-message')).toContainText('Protected access requires Basic, JWT or external authorization');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(0);
  await reveal(page, '#route-field-auth_url');
  await page.locator('#route-field-auth_url').fill('https://auth.example.test/check');
  await expect.poll(async () => JSON.parse(await page.locator('#route-json').inputValue()).access_mode).toBe('protected');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].access_mode).toBe('protected');
  expect(writes[0].auth.url).toBe('https://auth.example.test/check');

  await edit(page, 'guarded');
  await page.locator('#route-field-access_mode').selectOption('legacy');
  await expect(page.locator('#route-message')).toContainText('A protected route cannot return to Legacy');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(1);
  await page.locator('#route-field-access_mode').selectOption('public');
  await expect(page.locator('#route-message')).toContainText('public access cannot configure gateway Basic, JWT or external authorization');
  await page.locator('#save-route').click();
  expect(writes).toHaveLength(1);
  await page.locator('#route-field-access_mode').selectOption('application');
  await expect(page.locator('#route-message')).toContainText('application access cannot configure gateway Basic, JWT or external authorization');
  await page.locator('#route-field-auth_url').fill('');
  await expect.poll(async () => JSON.parse(await page.locator('#route-json').inputValue()).access_mode).toBe('application');
  await page.locator('#save-route').click();
  expect(writes[1].access_mode).toBe('application');
  expect(writes[1].auth).toBeNull();
});

test('protected accepts Basic auth and security overview separates declared modes from inferred controls', async ({ page }) => {
  const writes = await setup(page);
  await page.locator('[data-new-route="http"]').click();
  await page.locator('#route-field-id').fill('basic-protected');
  await reveal(page, '#route-field-basic_auth_credentials');
  await page.locator('#route-field-basic_auth_credentials').fill(credential);
  await reveal(page, '#route-field-access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await page.locator('#save-route').click();
  expect(writes[0].access_mode).toBe('protected');
  expect(writes[0].basic_auth.credentials).toEqual([credential]);
  await expect(page.locator('#route-dialog')).toBeHidden();
  await page.locator('[data-new-route="http"]').click();
  await page.locator('#route-field-id').fill('both-protected');
  await reveal(page, '#route-field-basic_auth_credentials');
  await page.locator('#route-field-basic_auth_credentials').fill(credential);
  await reveal(page, '#route-field-auth_url');
  await page.locator('#route-field-auth_url').fill('https://auth.example.test/check');
  await reveal(page, '#route-field-access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await page.locator('#save-route').click();
  expect(writes[1].access_mode).toBe('protected');
  expect(writes[1].auth.url).toBe('https://auth.example.test/check');
  expect(writes[1].basic_auth.credentials).toEqual([credential]);
  await expect(page.locator('#route-dialog')).toBeHidden();
  await page.locator('[data-view="security"]').click();
  await expect(page.locator('#security-content')).toContainText('1 protected · 1 public · 1 application-owned · 1 legacy');
  await expect(page.locator('#security-content')).toContainText('These are inferred control counts, not proof of identity or device posture');
});

test('Korean access labels and validation preserve route ID and draft during locale switch', async ({ page }) => {
  await setup(page, 'ko');
  await page.locator('[data-new-route="http"]').click();
  await page.locator('#route-field-id').fill('public');
  await expect(page.locator('#route-field-access_mode')).toHaveValue('legacy');
  await expect(page.locator('label[for="route-field-access_mode"]')).toHaveText('접근 방식');
  await reveal(page, '#route-field-access_mode');
  await page.locator('#route-field-access_mode').selectOption('protected');
  await expect(page.locator('#route-message')).toContainText('보호된 접근에는 Basic, JWT 또는 외부 인가가 필요합니다');
  await page.locator('#locale-select-route').selectOption('en');
  await expect(page.locator('label[for="route-field-access_mode"]')).toHaveText('Access mode');
  await expect(page.locator('#route-field-id')).toHaveValue('public');
  await expect(page.locator('#route-field-access_mode')).toHaveValue('protected');
});
