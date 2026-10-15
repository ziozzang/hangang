import { test, expect } from '@playwright/test';

async function setup(page, { scope = '"3"', delayed = false, source = 'native', sourceState = 'native', healthy = true } = {}) {
  const calls = [];
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let document = { revision: 7, policy: { version: 1, information_classes: ['internal'], services: {
    orders: { permissions: ['read'], roles: { reader: { permissions: ['read'], information_classes: ['internal'] } },
      users: { 'fixture-user': ['reader'] }, networks: [{ cidr: '192.0.2.0/24', roles: ['reader'] }], require_guard: true },
  }, resources: { "db:orders": { service: "orders", information_class: "internal", actions: { select: "read" }, minimum_aal: 2 } } } };
  await page.route('**/*', async route => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    calls.push({ path, method: request.method(), headers: request.headers(), body: request.postDataJSON?.() });
    if (path === '/v1/auth/setup') return route.fulfill({ status: 404, body: '' });
    if (path === '/v1/auth/logout') return route.fulfill({ status: 204, body: '' });
    if (path === '/v1/status') return route.fulfill({ json: { revision: 3, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {} } });
    if (path === '/v1/config') return route.fulfill({ json: { revision: 3, http: [], tcp: [], pumgye_authority: {
      decision_address: '127.0.0.1:9085', management_address: '127.0.0.1:9084',
      decision_token_env: 'PUMGYE_DECISION_TOKEN', admin_token_env: 'PUMGYE_ADMIN_TOKEN',
    } } });
    if (path === '/v1/pumgye/policy') {
      if (request.method() === 'GET' && delayed) await gate;
      if (request.method() === 'PUT') document = { ...request.postDataJSON(), revision: document.revision + 1 };
      const headers = { etag: `"${document.revision}"` }; if (scope) headers['x-hangang-config-revision'] = scope;
      return route.fulfill({ json: document, headers });
    }
    if (path === '/v1/pumgye/status') return route.fulfill({ json: { healthy, source_state: sourceState, source_lease_remaining_ms: source === 'kubernetes' ? 0 : null, policy_source: source, policy_revision: document.revision, decision_queries: 42 } });
    if (path === '/v1/pumgye/audit') return route.fulfill({ json: [{ revision: document.revision, actor: 'mtls:fixture-node', sha256: 'a'.repeat(64) }] });
    return route.fulfill({ status: 404, body: '' });
  });
  await page.goto('/ui/');
  await page.getByLabel('Administrator token').fill('fixture-admin-token');
  await page.getByRole('button', { name: 'Connect', exact: true }).click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  await page.locator('.sidebar a[data-view="pumgye"]').click();
  return { calls, release };
}

test('independent policy publication targets owning authority and binds both revisions', async ({ page }) => {
  const { calls } = await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await expect(page.locator('#pumgye-authority-panel')).toBeVisible();
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('Observe mode or unavailable evidence refuses access.');
  await expect(page.locator('#pumgye-authority-status')).toContainText('"policy_revision": 7');
  await page.locator('#pumgye-subject').fill('new-guest');
  await page.locator('#pumgye-assignment-form button').click();
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(3);
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText('Authorization policy published.');
  const write = calls.find(call => call.path === '/v1/pumgye/policy' && call.method === 'PUT');
  expect(write.headers['if-match']).toBe('"7"');
  expect(write.headers['x-hangang-config-revision']).toBe('"3"');
  expect(write.body.policy.services.orders.users['new-guest']).toEqual(['guest']);
  expect(write.body.policy.resources['db:orders'].minimum_aal).toBe(2);
  await expect(page.locator('#pumgye-resources tr')).toHaveCount(1);
  await expect(page.locator('#pumgye-resources')).toContainText('select → read');
  expect(write.body.revision).toBe(7);
  expect(write.body.http).toBeUndefined();
  expect(calls.some(call => call.path === '/v1/config' && call.method === 'PUT')).toBe(false);
  await page.locator('#logout-button').click();
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-audit')).toHaveText('');
  await expect(page.locator('#pumgye-resources tr')).toHaveCount(0);
  await expect(page.locator('#pumgye-guard-requirement')).toHaveText('');
});

test('missing owning authority scope prevents publication', async ({ page }) => {
  const { calls } = await setup(page, { scope: null });
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText('Reload before publishing.');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});

test('late authority result cannot restore policy or audit after logout', async ({ page }) => {
  const { release } = await setup(page, { delayed: true });
  await page.locator('#logout-button').click();
  release();
  await page.waitForTimeout(150);
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(0);
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-audit')).toHaveText('');
});


test('Kubernetes source policy remains inspectable but cannot be edited or published', async ({ page }) => {
  const { calls } = await setup(page, { source: 'kubernetes' });
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await expect(page.locator('#pumgye-message')).toContainText('Kubernetes owns this policy.');
  await expect(page.locator('#pumgye-document')).toHaveAttribute('readonly', '');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await expect(page.locator('#pumgye-subject')).toBeDisabled();
  await expect(page.locator('#pumgye-new-service')).toBeDisabled();
  for (const button of await page.locator('#pumgye-matrix button').all()) await expect(button).toBeDisabled();
  await page.locator('#pumgye-publish').dispatchEvent('click');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});


test('expired Kubernetes authority is explicit and its persisted matrix stays read-only', async ({ page }) => {
  const { calls } = await setup(page, { source: 'kubernetes', sourceState: 'expired', healthy: false });
  await expect(page.locator('#pumgye-source-summary')).toContainText('Kubernetes source expired');
  await expect(page.locator('#pumgye-source-summary')).toContainText('Authority unavailable');
  await expect(page.locator('#pumgye-source-summary')).toContainText('Applied policy revision 7');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await page.route('**/v1/pumgye/status', route => route.fulfill({ status: 503, json: { error: 'unavailable' } }));
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-source-summary')).toHaveText('Authority unavailable');
  await expect(page.locator('#pumgye-authority-status')).toHaveText('');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});

test('unreported policy ownership never enables database edits', async ({ page }) => {
  const { calls } = await setup(page, { source: undefined, sourceState: 'starting', healthy: false });
  // An unknown explicit source is also not a native authority.
  await page.route('**/v1/pumgye/status', route => route.fulfill({ json: { healthy: false, policy_revision: 7 } }));
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-source-summary')).toContainText('Source state unreported');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await page.locator('#pumgye-publish').dispatchEvent('click');
  expect(calls.some(call => call.method === 'PUT')).toBe(false);
});


test('service guard requirement follows policy drafts and language changes', async ({ page }) => {
  await setup(page);
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('Observe mode');
  await page.locator('#locale-select').selectOption('ko');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('관찰 모드');
  const policy = JSON.parse(await page.locator('#pumgye-document').inputValue());
  policy.services.orders.require_guard = false;
  await page.locator('#pumgye-document').fill(JSON.stringify(policy));
  await page.locator('#pumgye-document').dispatchEvent('change');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('필수가 아닙니다');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#pumgye-guard-requirement')).toContainText('explicit network denial refuses access.');
});

test('catalog draft changes publish to the owner and source-managed catalogs stay read-only', async ({ page }) => {
  const { calls } = await setup(page);
  await expect(page.locator('#pumgye-resources')).toContainText('db:orders');
  const policy = JSON.parse(await page.locator('#pumgye-document').inputValue());
  policy.resources['db:orders'].minimum_aal = 3;
  policy.resources['db:orders'].actions = { inspect: 'read' };
  await page.locator('#pumgye-document').fill(JSON.stringify(policy));
  await page.locator('#pumgye-document').dispatchEvent('change');
  await expect(page.locator('#pumgye-resources')).toContainText('inspect → read');
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText('Authorization policy published.');
  const write = calls.find(call => call.path === '/v1/pumgye/policy' && call.method === 'PUT');
  expect(write.body.policy.resources['db:orders']).toEqual(policy.resources['db:orders']);
  await page.route('**/v1/pumgye/status', route => route.fulfill({ json: { healthy: true, policy_source: 'kubernetes', source_state: 'fresh', policy_revision: 8 } }));
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-document')).toHaveAttribute('readonly', '');
  await expect(page.locator('#pumgye-resources')).toContainText('inspect → read');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
});

test('navigation retains invalid raw draft and refresh requires explicit discard', async ({ page }) => {
  const { calls } = await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#pumgye-document').fill('{ incomplete draft');
  await page.locator('.sidebar a[data-view="status"]').click();
  await page.locator('.sidebar a[data-view="pumgye"]').click();
  await expect(page.locator('#pumgye-document')).toHaveValue('{ incomplete draft');
  const before = calls.filter(c => c.path === '/v1/pumgye/policy').length;
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-document')).toHaveValue('{ incomplete draft');
  expect(calls.filter(c => c.path === '/v1/pumgye/policy')).toHaveLength(before);
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-document')).toHaveValue(/"version": 1/);
});

for (const locale of ['en', 'ko']) {
test(`delayed publish retains newer edits and advances their exact request base (${locale})`, async ({ page }) => {
  await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#locale-select').selectOption(locale);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const writes = [];
  await page.route('**/v1/pumgye/policy', async route => {
    if (route.request().method() !== 'PUT') return route.fallback();
    const request = route.request();
    writes.push({ body: request.postDataJSON(), headers: request.headers() });
    if (writes.length === 1) await gate;
    await route.fulfill({ json: { ...request.postDataJSON(), revision: 7 + writes.length }, headers: { etag: `"${7 + writes.length}"`, 'x-hangang-config-revision': '"4"' } });
  });
  await page.locator('#pumgye-publish').click();
  await expect.poll(() => writes.length).toBe(1);
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await expect(page.locator('#pumgye-refresh')).toBeDisabled();
  await page.locator('#pumgye-subject').fill('later-guest');
  await page.locator('#pumgye-assignment-form button').click();
  release();
  await expect(page.locator('#pumgye-message')).toContainText(locale === 'ko' ? '이후 수정한 초안은 아직 저장되지 않았습니다.' : 'Newer draft edits are still unsaved.');
  await expect(page.locator('#pumgye-matrix')).toContainText('later-guest');
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText(locale === 'ko' ? '권한 정책을 게시했습니다.' : 'Authorization policy published.');
  expect(writes).toHaveLength(2);
  expect(writes[1].headers['if-match']).toBe('"8"');
  expect(writes[1].headers['x-hangang-config-revision']).toBe('"4"');
  expect(writes[1].body.revision).toBe(8);
  expect(writes[1].body.policy.services.orders.users['later-guest']).toEqual(['guest']);
});

}

for (const locale of ['en', 'ko']) {
test(`uncertain publish keeps draft and requires explicit reconciliation (${locale})`, async ({ page }) => {
  await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  await page.locator('#locale-select').selectOption(locale);
  await page.locator('#pumgye-subject').fill('uncertain-guest');
  await page.locator('#pumgye-assignment-form button').click();
  let writes = 0;
  await page.route('**/v1/pumgye/policy', route => {
    if (route.request().method() !== 'PUT') return route.fallback();
    writes++;
    return route.abort('failed');
  });
  await page.locator('#pumgye-publish').click();
  await expect(page.locator('#pumgye-message')).toContainText(locale === 'ko' ? '게시 결과를 확인할 수 없습니다.' : 'Outcome unknown; refresh to reconcile');
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  await expect(page.locator('#pumgye-matrix')).toContainText('uncertain-guest');
  await page.locator('#pumgye-publish').dispatchEvent('click');
  expect(writes).toBe(1);
  page.once('dialog', dialog => dialog.dismiss());
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-publish')).toBeDisabled();
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#pumgye-refresh').click();
  await expect(page.locator('#pumgye-publish')).toBeEnabled();
});

}

test('late publish result cannot restore draft or mutation state after logout', async ({ page }) => {
  await setup(page);
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(2);
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  let started = false;
  await page.route('**/v1/pumgye/policy', async route => {
    if (route.request().method() !== 'PUT') return route.fallback();
    const data = route.request().postDataJSON(); started = true;
    await gate;
    await route.fulfill({ json: { ...data, revision: 8 }, headers: { etag: '"8"', 'x-hangang-config-revision': '"3"' } });
  });
  await page.locator('#pumgye-subject').fill('private-draft-user');
  await page.locator('#pumgye-assignment-form button').click();
  await page.locator('#pumgye-publish').click();
  await expect.poll(() => started).toBe(true);
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#pumgye-document')).toHaveValue('');
  await expect(page.locator('#pumgye-service option')).toHaveCount(0);
  await expect(page.locator('#pumgye-message')).toHaveText('');
  await expect(page.locator('#pumgye-matrix tr')).toHaveCount(0);
  await expect(page.locator('#pumgye-subject')).toHaveValue('');
});

// Reserved fixture data only. CSS viewport/DPR emulate browser zoom reflow.
// Mobile 200% is a separately labelled host-min320 stress case, not 195px support.
for (const width of [390, 1280]) for (const zoom of [1, 2]) for (const locale of ['en', 'ko']) for (const theme of ['light', 'dark']) {
  test(`policy layout ${width}px ${zoom * 100}% ${width / zoom < 320 ? "host-min320" : "reflow"} ${locale} ${theme}`, async ({ browser }, testInfo) => {
    const context = await browser.newContext({ baseURL: testInfo.project.use.baseURL,
      viewport: { width: Math.max(320, Math.floor(width / zoom)), height: 900 }, deviceScaleFactor: zoom });
    const page = await context.newPage();
    try {
      await setup(page);
      await page.locator('#locale-select').selectOption(locale);
      await page.evaluate(value => document.documentElement.dataset.theme = value, theme);
      await expect(page.locator('#pumgye-source-summary')).toBeVisible();
      await expect(page.locator('#pumgye-document')).toBeVisible();
      await expect(page.locator('#pumgye-authority-status')).not.toBeVisible();
      await page.locator('#pumgye-authority-status').locator('..').locator('summary').click();
      const bounds = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, width: document.documentElement.scrollWidth,
        controls: [...document.querySelectorAll('#view-pumgye .pumgye-table-wrap, #view-pumgye input, #view-pumgye select, #view-pumgye textarea, #view-pumgye button')].filter(el => el.getClientRects().length && (el.classList.contains('pumgye-table-wrap') || !el.closest('.pumgye-table-wrap'))).map(el => { const r = el.getBoundingClientRect(); return { id: el.id, left: r.left, right: r.right }; }),
        tables: [...document.querySelectorAll('#view-pumgye .pumgye-table-wrap')].map(el => ({ width: el.clientWidth, scroll: el.scrollWidth })) }));
      expect(bounds.width).toBeLessThanOrEqual(bounds.viewport);
      for (const control of bounds.controls) { expect(control.left, control.id).toBeGreaterThanOrEqual(0); expect(control.right, control.id).toBeLessThanOrEqual(bounds.viewport + 1); }
      if (width / zoom < 600) for (const table of bounds.tables) expect(table.scroll).toBeGreaterThan(table.width);
      if (width / zoom < 600) {
        const table = page.getByRole('region', { name: locale === 'ko' ? '권한 할당 표' : 'Authorization matrix', exact: true });
        await table.focus();
        await page.keyboard.press('ArrowRight');
        await expect.poll(() => table.evaluate(el => el.scrollLeft)).toBeGreaterThan(0);
        await table.evaluate(el => el.scrollLeft = 0);
      }
      await page.locator('#pumgye-subject').fill('fixture-layout-user-' + 'x'.repeat(100));
      await page.locator('#pumgye-assignment-form button').click();
      await expect(page.locator('#pumgye-matrix')).toContainText('fixture-layout-user');
      await page.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
      await page.screenshot({ path: `/tmp/hangang-pumgye-layout-after/${width}-${zoom}-${locale}-${theme}.png`, fullPage: true });
    } finally { await context.close(); }
  });
}
