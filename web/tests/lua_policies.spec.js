import { test, expect } from '@playwright/test';

const original = {
  id: 'lua-route', host: 'lua.example.test', path_prefix: '/',
  backends: ['http://127.0.0.1:8080'], headers: {}, json: {}, deny_cidrs: [],
  lua: 'return nil -- policy source',
  request_transform: {
    mode: 'buffered', operations: [], lua: 'return hangang.body() -- request source',
    max_buffer_bytes: 16384, max_output_bytes: 16384, timeout_ms: 5000,
    set_headers: {}, remove_headers: [],
  },
  response_transform: {
    mode: 'buffered', operations: [], lua: 'return hangang.body() -- response source',
    max_buffer_bytes: 16384, max_output_bytes: 16384, timeout_ms: 5000,
    set_headers: {}, remove_headers: [], when_prefix: '  bootstrap=',
  },
  country_policy: { allow: [], deny: ['RU'], on_unknown: 'allow', enforce: false },
  auth: { url: 'http://auth:8080', timeout_ms: 2000, forward_headers: [], response_headers: [] },
  future_policy: { keep: true },
};

async function fixture(page, routeDocument = original) {
  const writes = [];
  await page.route('**/*', (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: 'not found' });
    if (path === '/v1/status') return route.fulfill({ json: {
      revision: 3, http_routes: 1, tcp_routes: 0, uptime_seconds: 10,
      metrics: { requests_total: 0, errors_total: 0, active_connections: 1 },
      state: { ready: true },
    } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/traffic') return route.fulfill({ json: { records: [], retention_seconds: 60 } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: 'stream unavailable' });
    if (path === '/v1/routes/http/lua-route' && request.method() === 'PUT') {
      writes.push(request.postDataJSON());
      return route.fulfill({ json: { revision: 4 }, headers: { etag: '"4"' } });
    }
    if (path === '/v1/routes/http/lua-route') return route.fulfill({ json: routeDocument, headers: { etag: '"3"' } });
    if (path === '/v1/routes/http') return route.fulfill({ json: { revision: 3, routes: [routeDocument] }, headers: { etag: '"3"' } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 3, http: [routeDocument], tcp: [] } });
    return route.fulfill({ status: 404, body: 'missing fixture' });
  });
  return writes;
}

async function connectLua(page) { await page.goto('/ui/'); await page.locator('#token-input').fill('fixture-token'); await page.locator('#login-submit').click(); await expect(page.locator('#login-dialog')).toBeHidden(); await page.getByRole('link', { name: 'Lua policies', exact: true }).click(); }

test('Lua menu finds response scripts and saves CodeMirror edits without unrelated configuration loss', async ({ page }) => {
  const writes = await fixture(page); await connectLua(page);
  await expect(page.locator('#lua-policy-list tbody tr')).toHaveCount(3);
  await expect(page.locator('#lua-policy-list')).not.toContainText('return hangang.body()');
  await page.locator('[data-lua-phase="response_transform_lua"] button').click();
  const editor = page.locator('.cm-content[aria-label="Response transform Lua"]');
  await expect(editor).toBeFocused(); await editor.fill('return hangang.body() -- revised response');
  await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].response_transform).toMatchObject({ lua: 'return hangang.body() -- revised response', when_prefix: '  bootstrap=', max_buffer_bytes: 16384, max_output_bytes: 16384, timeout_ms: 5000 });
  expect(writes[0].country_policy).toEqual(original.country_policy); expect(writes[0].auth).toMatchObject(original.auth); expect(writes[0].future_policy).toEqual({ keep: true });
  await expect(page.locator('#lua-policy-list tbody tr')).toHaveCount(3);
  await page.locator('#locale-select').selectOption('ko'); await expect(page.getByRole('link', { name: 'Lua 정책', exact: true })).toBeVisible();
  await page.locator('#logout-button').click(); await expect(page.locator('#lua-policy-list')).toBeEmpty(); await expect(page.locator('#lua-route-picker')).toBeEmpty();
  await page.locator('#locale-select-login').selectOption('en'); await expect(page.locator('#lua-policy-list')).toBeEmpty();
});

test('empty Lua inventory can configure a response script through the route picker', async ({ page }) => {
  const writes = await fixture(page, { ...original, lua: null, request_transform: null, response_transform: null }); await connectLua(page);
  await expect(page.locator('#lua-policy-list')).toContainText('No configured Lua scripts');
  await page.locator('#lua-phase-picker').selectOption('response_transform_lua'); await page.locator('#configure-lua-policy').click();
  const editor = page.locator('.cm-content[aria-label="Response transform Lua"]'); await expect(editor).toBeFocused(); await expect(editor).toHaveAttribute('contenteditable', 'true');
  await editor.fill('return hangang.body()'); await page.locator('#save-route').click(); await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes[0].response_transform).toMatchObject({ lua: 'return hangang.body()', max_buffer_bytes: 16384, max_output_bytes: 16384 });
});

test('late Lua inventory cannot repopulate after logout or locale change', async ({ page }) => {
  await fixture(page); let release; let arrived;
  const requested = new Promise(resolve => { arrived = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/v1/routes/http', async route => { arrived(); await gate; await route.fulfill({ json: { revision: 3, routes: [original] } }); });
  await connectLua(page); await requested; await page.locator('#logout-button').click(); release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await page.locator('#locale-select-login').selectOption('ko');
  await expect(page.locator('#lua-policy-list')).toBeEmpty(); await expect(page.locator('#lua-route-picker')).toBeEmpty();
  await expect(page.getByRole('link', { name: 'Lua 정책', exact: true })).toBeHidden();
});

test('viewer cannot open Lua menu or trigger route inventory fetches', async ({ page }) => {
  await fixture(page); let inventoryReads = 0;
  await page.route('**/v1/auth/setup', route => route.fulfill({ json: { bootstrap_required: false } }));
  await page.route('**/v1/auth/login', route => route.fulfill({ json: { token: 'viewer-session', user: { id: 'viewer', username: 'viewer', role: 'viewer', enabled: true } } }));
  await page.route('**/v1/routes/http', route => { inventoryReads++; return route.fulfill({ json: { revision: 3, routes: [original] } }); });
  await page.goto('/ui/#lua'); await page.locator('#login-username').fill('viewer'); await page.locator('#login-password').fill('password'); await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden(); await expect(page.getByRole('link', { name: 'Lua policies', exact: true })).toBeHidden();
  await page.evaluate(() => { location.hash = '#lua'; }); await expect(page).toHaveURL(/#status$/); expect(inventoryReads).toBe(0); await expect(page.locator('#lua-policy-list')).toBeEmpty();
});

test('late route editor response cannot restore scripts after logout', async ({ page }) => {
  await fixture(page); await connectLua(page); await expect(page.locator('#lua-policy-list tbody tr')).toHaveCount(3);
  let release; let arrived; const requested = new Promise(resolve => { arrived = resolve; }); const gate = new Promise(resolve => { release = resolve; });
  await page.route('**/v1/routes/http/lua-route', async route => { arrived(); await gate; await route.fulfill({ json: original, headers: { etag: '"3"' } }); });
  await page.locator('[data-lua-phase="response_transform_lua"] button').click(); await requested; await page.locator('#logout-button').click(); release();
  await expect(page.locator('#login-dialog')).toBeVisible(); await expect(page.locator('#route-dialog')).toBeHidden(); await expect(page.locator('#route-form-fields')).toBeEmpty(); await expect(page.locator('#lua-policy-list')).toBeEmpty();
});
