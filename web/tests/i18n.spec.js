import { test, expect } from '@playwright/test';

const TOKEN = 'fixture-locale-admin';
const status = {
  revision: 7, http_routes: 1, tcp_routes: 0, uptime_seconds: 12,
  version: 'test', process_id: 42, state: { ready: true, draining: false },
  metrics: { requests_total: 8, errors_total: 0, active_connections: 1 },
};
const namedRoute = {
  id: 'Status', path_prefix: '/', path_match: 'prefix', host: 'security.example.test',
  headers: {}, json: {}, backends: ['http://127.0.0.1:8080'], deny_cidrs: [],
  require_tls: false, priority: 0,
};

async function koreanBrowser(page) {
  await page.addInitScript(() => {
    Object.defineProperty(navigator, 'language', { configurable: true, get: () => 'ko-KR' });
  });
}

async function fixtures(page, { viewer = false, stream, update = { enabled: false, phase: 'idle' } } = {}) {
  const calls = [];
  await page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, method: request.method(), headers: request.headers() });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(viewer
      ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') return route.fulfill({ json: {
      token: 'fixture-viewer-session', expires_in_seconds: 28800,
      user: { id: 'viewer', username: 'Status', role: 'viewer', enabled: true },
    } });
    if (url.pathname === '/v1/status') return route.fulfill({ json: status });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: update });
    if (url.pathname === '/v1/traffic') return route.fulfill({ json: {
      records: [], server_time_unix_ms: Date.now(), latest_id: 0,
      next_after: 0, gap: false, dropped_total: 0, retention_seconds: 60,
    } });
    if (url.pathname === '/v1/events') {
      if (stream) return stream(route);
      return route.fulfill({ status: 503, body: 'stream unavailable' });
    }
    if (url.pathname === '/v1/routes/http') return route.fulfill({ json: {
      revision: 7, routes: [namedRoute],
    }, headers: { etag: '"7"' } });
    if (url.pathname === '/v1/routes/http/Status') return route.fulfill({ json: namedRoute, headers: { etag: '"7"' } });
    if (url.pathname === '/v1/config') return route.fulfill({ json: {
      revision: 7, http: [namedRoute], tcp: [], certificates: [],
    }, headers: { etag: '"7"' } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  return calls;
}

async function tokenLogin(page) {
  await page.goto('/ui/');
  await page.locator('#token-input').fill(TOKEN);
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
}

test('Korean navigator locale starts without storage; explicit English choice persists on reload', async ({ page }) => {
  await koreanBrowser(page);
  await fixtures(page);
  await page.goto('/ui/');
  await expect(page.locator('html')).toHaveAttribute('lang', 'ko');
  await expect(page.locator('#locale-select')).toHaveValue('ko');
  await expect(page.locator('#locale-select-login')).toHaveValue('ko');
  await expect(page.locator('#login-title')).toContainText(/[가-힣]/);
  expect(await page.evaluate(() => localStorage.getItem('hangang-locale'))).toBeNull();
  await page.locator('#locale-select-login').selectOption('en');
  await expect(page.locator('#login-title')).toHaveText('Connect to this proxy');
  await page.locator('#locale-select-login').selectOption('ko');
  await expect(page.locator('#login-title')).toContainText(/[가-힣]/);
  await page.locator('#token-input').fill(TOKEN);
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await expect(page.locator('[data-view="status"]')).toContainText(/[가-힣]/);
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('#locale-select')).toHaveValue('en');
  await expect(page.locator('[data-view="status"]')).toContainText('Status');
  expect(await page.evaluate(() => localStorage.getItem('hangang-locale'))).toBe('en');
  await page.reload();
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('#locale-select')).toHaveValue('en');
});

test('switching a dirty route dialog translates controls without altering values, draft, or revision', async ({ page }) => {
  await koreanBrowser(page);
  const calls = await fixtures(page);
  await tokenLogin(page);
  await page.locator('[data-view="http"]').click();
  await expect(page.locator('#http-routes .route-card')).toContainText('Status');
  await page.locator('[data-new-route="http"]').click();
  await expect(page.locator('#route-dialog')).toBeVisible();
  await expect(page.locator('label[for="route-field-id"]')).toContainText(/[가-힣]/);
  await expect(page.locator('label[for="route-field-backends"]')).toContainText(/[가-힣]/);
  await page.locator('#route-field-id').fill('Status');
  await page.locator('#route-field-backends').fill('http://127.0.0.1:9000');
  const draft = await page.locator('#route-json').inputValue();
  const revision = await page.locator('#revision-badge').textContent();
  await page.locator('#locale-select-route').selectOption('en');
  await expect(page.locator('html')).toHaveAttribute('lang', 'en');
  await expect(page.locator('#locale-select')).toHaveValue('en');
  await expect(page.locator('label[for="route-field-id"]')).toHaveText('Route ID');
  await expect(page.locator('#route-field-id')).toHaveValue('Status');
  await expect(page.locator('#route-field-backends')).toHaveValue('http://127.0.0.1:9000');
  await expect(page.locator('#route-json')).toHaveValue(draft);
  await expect(page.locator('#revision-badge')).toHaveText(revision);
  await page.locator('#locale-select-route').selectOption('ko');
  await page.locator('#route-dialog .advanced-editor summary').click();
  await page.locator('#route-json').fill('{');
  await page.locator('#save-route').click();
  await expect(page.locator('#route-message')).toContainText(/[가-힣]/);
  await expect(page.locator('#route-json')).toHaveValue('{');
  expect(calls.filter((call) => call.path === '/v1/routes/http' && call.method === 'POST')).toHaveLength(0);
});

test('locale changes keep literal identifiers and do not create another live stream', async ({ page }) => {
  await koreanBrowser(page);
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const calls = await fixtures(page, { stream: async (route) => {
    await gate; await route.fulfill({ status: 503, body: 'fixture stopped' });
  } });
  await tokenLogin(page);
  await expect.poll(() => calls.filter((call) => call.path === '/v1/events').length).toBe(1);
  await page.evaluate(async (base) => {
    const { recordStatus } = await import('/ui/console.js');
    recordStatus({ ...base, uptime_seconds: 13, metrics: { ...base.metrics, requests_total: 13 } });
  }, status);
  const chartBefore = await page.locator('#traffic-line').getAttribute('d');
  expect(chartBefore).not.toBe('');
  await page.locator('#locale-select').selectOption('en');
  await page.locator('#locale-select').selectOption('ko');
  await page.waitForTimeout(350);
  await expect(page.locator('#traffic-line')).toHaveAttribute('d', chartBefore);
  expect(calls.filter((call) => call.path === '/v1/events')).toHaveLength(1);
  await page.locator('[data-view="http"]').click();
  await expect(page.locator('#http-routes .route-card')).toContainText('Status');
  await expect(page.locator('#http-routes .route-card')).toContainText('security.example.test');
  release();
});

test('Korean viewer keeps literal user name and cannot reveal administrator views', async ({ page }) => {
  await koreanBrowser(page);
  const calls = await fixtures(page, { viewer: true });
  await page.goto('/ui/#users');
  await expect(page.locator('#locale-select-login')).toHaveValue('ko');
  await page.locator('#login-username').fill('Status');
  await page.locator('#login-password').fill('viewer-password');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await expect(page.locator('#signed-in-user')).toContainText('Status');
  await expect(page.locator('[data-view="users"]')).toBeHidden();
  await expect(page.locator('[data-view="security"]')).toBeHidden();
  await expect(page.locator('#activity-panel')).toBeHidden();
  await page.locator('#locale-select').selectOption('en');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#signed-in-user')).toContainText('Status');
  await expect(page.locator('[data-view="users"]')).toBeHidden();
  expect(calls.filter((call) => call.path === '/v1/users' || call.path === '/v1/config' || call.path === '/v1/traffic')).toHaveLength(0);
});

test('token visibility, loaded update phase, and real preview count survive locale changes', async ({ page }) => {
  await fixtures(page, { update: { enabled: true, current_version: '1.0', phase: 'idle' } });
  await page.goto('/ui/');
  await page.locator('#toggle-token').click();
  await expect(page.locator('#token-input')).toHaveAttribute('type', 'text');
  await expect(page.locator('#toggle-token')).toHaveAttribute('aria-label', 'Hide token');
  await page.locator('#locale-select-login').selectOption('ko');
  await expect(page.locator('#toggle-token')).toHaveAttribute('aria-label', '토큰 숨기기');
  await expect(page.locator('#toggle-token')).toHaveText('숨기기');
  await page.locator('#token-input').fill(TOKEN);
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await expect(page.locator('#update-state')).toContainText('1.0');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#update-state')).toHaveText('1.0 · idle');

  await page.locator('[data-view="config"]').click();
  const editor = page.locator('#config-editor');
  await expect(editor).toHaveValue(/^\{/);
  const draft = JSON.parse(await editor.inputValue());
  draft.http[0].path_prefix = '/changed';
  const draftText = JSON.stringify(draft, null, 2);
  await editor.fill(draftText);
  await page.locator('#preview-config').click();
  await expect(page.locator('#preview-count')).toHaveText('1 change');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#update-state')).toContainText('1.0');
  await expect(page.locator('#preview-count')).toHaveText('변경 1개');
  await expect(editor).toHaveValue(draftText);
});
