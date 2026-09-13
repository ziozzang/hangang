import { test, expect } from '@playwright/test';

const authority = 'a'.repeat(32);
const operation = 'b'.repeat(32);
const receipt = { scope: 'configuration_authority', supported: true,
  receipt: { epoch: 'c'.repeat(32), revision: 17,
    stamp: { authority_id: authority, operation_id: operation, candidate_sha256: 'd'.repeat(64) } },
  stored_records: 2, capacity: 100000, writes_available: true, server_time_unix_ms: 1789000002000 };
const emptyHistory = { scope: 'instance', coverage: ['acceptance', 'local_outcome'],
  authority_id: 'e'.repeat(32), started_at_unix_ms: 1788999999000,
  records: [], next_after: 0, oldest_id: null, latest_id: 0, history_revision: 0,
  pruned_through: 0, truncated: false, stored_records: 0, capacity: 10000,
  writes_available: true, server_time_unix_ms: 1789000001000, has_more: false };

async function fixture(page, { mode = 'present', hold = false, locale = 'en', accounts = false } = {}) {
  const calls = [];
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, query: url.searchParams, authorization: request.headers().authorization });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(accounts ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') {
      const username = request.postDataJSON().username;
      return route.fulfill({ json: { token: `${username}-session`, user: { id: 2, username, role: username === 'viewer' ? 'viewer' : 'admin', enabled: true } } });
    }
    if (url.pathname === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (url.pathname === '/v1/config/operations') return route.fulfill({ json: emptyHistory });
    if (url.pathname === '/v1/config/operation-proof') return route.fulfill({ json: { scope: 'configuration_authority', supported: false, proof: null, server_time_unix_ms: 1789000002000 } });
    if (url.pathname === '/v1/config/commit-receipt') {
      if (hold) await gate;
      if (mode === 'error') return route.fulfill({ status: 503, json: { title: 'Unavailable' } });
      if (mode === 'forbidden') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      if (mode === 'missing') return route.fulfill({ json: { ...receipt, receipt: null, writes_available: false, stored_records: 100000 } });
      if (mode === 'unsupported') return route.fulfill({ json: { ...receipt, supported: false, receipt: null, stored_records: null, capacity: null, writes_available: null } });
      if (mode === 'invalid') return route.fulfill({ json: { ...receipt, receipt: { ...receipt.receipt, stamp: { ...receipt.receipt.stamp, operation_id: 'f'.repeat(32) } } } });
      return route.fulfill({ json: receipt });
    }
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  if (accounts) {
    await page.locator('#login-username').fill('viewer');
    await page.locator('#login-password').fill('viewer password');
  } else await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { calls, release };
}

async function search(page) {
  await page.locator('#config-receipt-authority').fill(authority);
  await page.locator('#config-receipt-operation').fill(operation);
  await page.locator('#config-receipt-search').click();
}

test('historical receipt requires explicit exact lookup and shows only SQL commit evidence', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(0);
  await search(page);
  await expect(page.locator('#config-receipt-fields')).toContainText('17');
  await expect(page.locator('#config-receipt-fields')).toContainText('d'.repeat(64));
  await expect(page.locator('#config-receipt-state')).toContainText('does not prove current configuration, local activation, or fleet acknowledgement');
  await expect(page.locator('#config-receipt-state')).toContainText('2/100,000');
  const queries = calls.filter((call) => call.path === '/v1/config/commit-receipt');
  expect(queries).toHaveLength(1);
  expect([...queries[0].query.entries()]).toEqual([['authority_id', authority], ['operation_id', operation]]);
  expect(queries[0].authorization).toBe('Bearer fixture-admin-token');
});

test('invalid IDs never issue privileged lookup; changed query clears prior evidence', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await page.locator('#config-receipt-authority').fill('A'.repeat(32));
  await page.locator('#config-receipt-operation').fill(operation);
  await page.locator('#config-receipt-form').evaluate((form) => form.requestSubmit());
  await expect(page.locator('#config-receipt-state')).toContainText('lowercase hexadecimal');
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(0);
  await search(page);
  await expect(page.locator('#config-receipt-fields')).toContainText('17');
  await page.locator('#config-receipt-operation').fill('f'.repeat(32));
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
  await expect(page.locator('#config-receipt-state')).toBeEmpty();
});

for (const [mode, expected] of [
  ['missing', 'commit outcome is unknown'],
  ['unsupported', 'does not support historical SQL receipts'],
  ['error', 'receipt unavailable'],
  ['invalid', 'receipt unavailable'],
]) test(`${mode} receipt stays distinct from a recorded SQL commit`, async ({ page }) => {
  await fixture(page, { mode });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect(page.locator('#config-receipt-state')).toContainText(expected);
  if (mode === 'missing') await expect(page.locator('#config-receipt-state')).toContainText('Receipt quota admission: blocked');
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
});

test('editing a query while its response is held prevents stale receipt display', async ({ page }) => {
  const { calls, release } = await fixture(page, { hold: true });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/commit-receipt')).toBe(true);
  await page.locator('#config-receipt-operation').fill('f'.repeat(32));
  release();
  await expect(page.locator('#config-receipt-state')).toBeEmpty();
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
});

test('logout and navigation scrub a held response and both query IDs', async ({ page }) => {
  const { calls, release } = await fixture(page, { hold: true });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/commit-receipt')).toBe(true);
  await page.locator('[data-view="status"]').click();
  release();
  await expect(page.locator('#config-receipt-authority')).toHaveValue('');
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect(page.locator('#config-receipt-fields')).toContainText('17');
  await page.locator('#logout-button').click();
  await expect(page.locator('#config-receipt-operation')).toHaveValue('');
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
});

test('viewer cannot search and 403 clears session', async ({ page }) => {
  const { calls } = await fixture(page, { accounts: true });
  await expect(page.locator('[data-view="config-operations"]')).toBeHidden();
  await page.evaluate(() => { location.hash = '#config-operations'; });
  await expect(page).toHaveURL(/#status$/);
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(0);
  const admin = await fixture(page, { mode: 'forbidden' });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#config-receipt-fields')).toBeEmpty();
  expect(admin.calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(1);
});

test('Korean receipt copy rerenders without altering IDs or repeating lookup', async ({ page }) => {
  const { calls } = await fixture(page, { locale: 'ko' });
  await page.locator('[data-view="config-operations"]').click();
  await search(page);
  await expect(page.locator('#config-receipt-state')).toContainText('과거 SQL 커밋');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-receipt-state')).toContainText('Historical SQL commit recorded');
  await expect(page.locator('#config-receipt-authority')).toHaveValue(authority);
  expect(calls.filter((call) => call.path === '/v1/config/commit-receipt')).toHaveLength(1);
});
