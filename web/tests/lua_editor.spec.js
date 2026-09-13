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
    set_headers: {}, remove_headers: [],
  },
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

async function openEditor(page) {
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-token');
  await page.getByRole('button', { name: 'Connect' }).click();
  await page.getByRole('link', { name: 'HTTP routes' }).click();
  await page.getByRole('button', { name: 'Edit' }).click();
  await expect(page.locator('#route-dialog')).toBeVisible();
}

test('untouched policy and body Lua retain exact source through native route save', async ({ page }) => {
  const cspViolations = [];
  page.on('console', (entry) => { if (/content security policy|refused to apply inline style/i.test(entry.text())) cspViolations.push(entry.text()); });
  const writes = await fixture(page);
  await openEditor(page);
  await expect(page.locator('#route-dialog .hangang-lua-editor')).toHaveCount(3);
  await expect(page.getByRole('textbox', { name: 'Lua policy' })).toContainText('return nil -- policy source');
  await expect(page.getByRole('textbox', { name: 'Request transform Lua' })).toContainText('return hangang.body() -- request source');
  await expect(page.getByRole('textbox', { name: 'Response transform Lua' })).toContainText('return hangang.body() -- response source');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].lua).toBe(original.lua);
  expect(writes[0].request_transform.lua).toBe(original.request_transform.lua);
  expect(writes[0].response_transform.lua).toBe(original.response_transform.lua);
  await expect(page.locator('.hangang-lua-editor')).toHaveCount(0);
  expect(cspViolations).toEqual([]);
});

test('Lua draft survives locale and JSON views, transform disable follows the checkbox, and close/logout scrub the editor', async ({ page }) => {
  await fixture(page, { ...original, request_transform: null, response_transform: null });
  await openEditor(page);
  const policy = page.getByRole('textbox', { name: 'Lua policy' });
  const request = page.locator('.cm-content[aria-label="Request transform Lua"]');
  await expect(request).toHaveAttribute('contenteditable', 'false');
  const source = 'return nil -- </code><img src=x onerror=window.pwned=1>';
  await policy.fill(source);
  await expect(page.locator('#route-field-lua')).toHaveValue(source);
  await expect(page.locator('#route-json')).toHaveValue(new RegExp(source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  await expect(page.locator('#route-dialog img')).toHaveCount(0);
  expect(await page.evaluate(() => window.pwned)).toBeUndefined();
  await page.locator('#locale-select-route').selectOption('ko');
  await expect(page.getByRole('textbox', { name: 'Lua 정책' })).toContainText(source);
  await page.locator('#route-dialog .advanced-editor summary').click();
  await expect(page.locator('#route-json')).toHaveValue(new RegExp(source.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  await page.locator('#route-dialog .advanced-editor summary').click();
  const requestSection = page.locator('#route-field-request_transform_enabled').locator('xpath=ancestor::details[1]');
  if (!(await requestSection.evaluate((element) => element.open))) await requestSection.locator('summary').click();
  await page.locator('[name="request_transform_enabled"]').check();
  await expect(page.getByRole('textbox', { name: '요청 변환 Lua' })).toHaveAttribute('contenteditable', 'true');
  await page.getByRole('textbox', { name: '요청 변환 Lua' }).fill('return hangang.body()');
  await expect(page.locator('#route-field-request_transform_lua')).toHaveValue('return hangang.body()');
  await page.locator('[name="request_transform_enabled"]').uncheck();
  await expect(page.getByRole('textbox', { name: '요청 변환 Lua' })).toHaveAttribute('contenteditable', 'false');
  await page.locator('#route-dialog [data-close-dialog]').first().click();
  await expect(page.locator('.hangang-lua-editor')).toHaveCount(0);
  await page.locator('#logout-button').click();
  await expect(page.locator('#route-form-fields')).toBeEmpty();
  expect(await page.locator('body').textContent()).not.toContain(source);
  expect(await page.evaluate((script) => [...Object.values(localStorage), ...Object.values(sessionStorage)].some((value) => value.includes(script)), source)).toBe(false);
});

test('policy completion saves through the textarea while body suggestions stay phase-specific', async ({ page }) => {
  const writes = await fixture(page, { ...original, lua: null, request_transform: null, response_transform: null });
  await openEditor(page);
  const policySection = page.locator('#route-field-lua').locator('xpath=ancestor::details[1]');
  if (!(await policySection.evaluate((element) => element.open))) await policySection.locator('summary').click();
  const requestSection = page.locator('#route-field-request_transform_enabled').locator('xpath=ancestor::details[1]');
  if (!(await requestSection.evaluate((element) => element.open))) await requestSection.locator('summary').click();
  const policy = page.getByRole('textbox', { name: 'Lua policy' });
  const request = page.locator('.cm-content[aria-label="Request transform Lua"]');
  const requestSource = page.locator('#route-field-request_transform_lua');
  await request.evaluate((element) => element.focus());
  await page.keyboard.type('should-not-write');
  await page.keyboard.press('Control+Space');
  await expect(requestSource).toHaveValue('');
  await expect(page.locator('.cm-tooltip-autocomplete')).toHaveCount(0);

  await policy.fill('hangang.');
  await policy.press('Control+Space');
  const suggestions = page.locator('.cm-tooltip-autocomplete');
  await expect(suggestions).toBeVisible();
  await expect(suggestions).toContainText('select_backend');
  await expect(suggestions).not.toContainText('set_body');
  await suggestions.locator('.cm-completionLabel', { hasText: /^method$/ }).click();
  await expect(page.locator('#route-field-lua')).toHaveValue('hangang.method()');
  await expect(page.locator('#route-json')).toHaveValue(/hangang\.method\(\)/);

  if (!(await requestSection.evaluate((element) => element.open))) await requestSection.locator('summary').click();
  await page.locator('[name="request_transform_enabled"]').check();
  await request.fill('hangang.');
  await request.press('Control+Space');
  await expect(suggestions).toContainText('set_body');
  await expect(suggestions).not.toContainText('select_backend');
  await page.locator('[name="request_transform_enabled"]').uncheck();
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].lua).toBe('hangang.method()');
  expect(writes[0].request_transform).toBeNull();
});

test('advanced JSON Lua edits survive a later native field change and save', async ({ page }) => {
  const writes = await fixture(page);
  await openEditor(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.lua = 'return nil -- JSON policy';
  draft.request_transform.lua = 'return hangang.body() -- JSON request';
  draft.response_transform.lua = 'return hangang.body() -- JSON response';
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.getByRole('textbox', { name: 'Lua policy' })).toContainText(draft.lua);
  await expect(page.getByRole('textbox', { name: 'Request transform Lua' })).toContainText(draft.request_transform.lua);
  await expect(page.getByRole('textbox', { name: 'Response transform Lua' })).toContainText(draft.response_transform.lua);
  await page.locator('#route-field-priority').fill('7');
  await expect(json).toHaveValue(/JSON response/);
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].priority).toBe(7);
  expect(writes[0].lua).toBe(draft.lua);
  expect(writes[0].request_transform.lua).toBe(draft.request_transform.lua);
  expect(writes[0].response_transform.lua).toBe(draft.response_transform.lua);
});

test('advanced JSON can add and remove whole transforms before a native edit without losing unknown fields', async ({ page }) => {
  const writes = await fixture(page, { ...original, request_transform: null });
  await openEditor(page);
  await page.locator('#route-dialog .advanced-editor summary').click();
  const json = page.locator('#route-json');
  const draft = JSON.parse(await json.inputValue());
  draft.request_transform = {
    ...original.request_transform, mode: 'ndjson', operations: [{ op: 'replace', from: 'a', to: 'b' }],
    set_headers: { 'x-draft': 'yes' }, remove_headers: ['x-old'], custom_extension: 'keep-me',
  };
  draft.response_transform = null;
  await json.fill(JSON.stringify(draft, null, 2));
  await expect(page.locator('[name="request_transform_enabled"]')).toBeChecked();
  await expect(page.locator('[name="response_transform_enabled"]')).not.toBeChecked();
  await expect(page.locator('#route-field-request_transform_lua')).toHaveValue(draft.request_transform.lua);
  await expect(page.locator('#route-field-request_transform_mode')).toHaveValue('ndjson');
  await expect(page.locator('#route-field-request_transform_max_buffer_bytes')).toHaveValue('16384');
  await expect(page.locator('#route-field-request_transform_set_headers')).toHaveValue('x-draft: yes');
  await expect(page.locator('.cm-content[aria-label="Request transform Lua"]')).toHaveAttribute('contenteditable', 'true');
  await expect(page.locator('.cm-content[aria-label="Response transform Lua"]')).toHaveAttribute('contenteditable', 'false');
  await page.locator('#route-field-priority').fill('8');
  await page.getByRole('button', { name: 'Save route' }).click();
  await expect(page.locator('#route-dialog')).toBeHidden();
  expect(writes).toHaveLength(1);
  expect(writes[0].priority).toBe(8);
  expect(writes[0].request_transform).toEqual(draft.request_transform);
  expect(writes[0].response_transform).toBeNull();
});

test('Lua editor accepts composed Unicode, supports undo, closes suggestions, and lets Tab leave', async ({ page }) => {
  await fixture(page, { ...original, lua: null, request_transform: null, response_transform: null });
  await openEditor(page);
  const section = page.locator('#route-field-lua').locator('xpath=ancestor::details[1]');
  if (!(await section.evaluate((element) => element.open))) await section.locator('summary').click();
  const editor = page.getByRole('textbox', { name: 'Lua policy' });
  await editor.click();
  await editor.evaluate((element) => element.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true, data: 'ㅎ' })));
  await page.keyboard.insertText('한글');
  await editor.evaluate((element) => element.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true, data: '한글' })));
  await expect(page.locator('#route-field-lua')).toHaveValue('한글');
  await editor.press('Control+z');
  await expect(page.locator('#route-field-lua')).toHaveValue('');
  await editor.fill('hangang.');
  await editor.press('Control+Space');
  await expect(page.locator('.cm-tooltip-autocomplete')).toBeVisible();
  await editor.press('Escape');
  await expect(page.locator('.cm-tooltip-autocomplete')).toHaveCount(0);
  await editor.press('Tab');
  expect(await page.evaluate(() => document.activeElement?.classList.contains('cm-content'))).toBe(false);
  await expect(page.locator('#route-field-lua')).toHaveValue('hangang.');
});
