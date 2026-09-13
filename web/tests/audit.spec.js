import { test, expect } from '@playwright/test';
import { readFile } from 'node:fs/promises';

const events = Array.from({ length: 101 }, (_, index) => ({
  id: index + 1, time_unix_ms: 1789000000000 + index * 1000,
  action: index ? 'create' : 'baseline', actor_kind: index ? 'account' : 'system',
  ...(index ? { actor_user_id: 1, target_user_id: index + 1, after: { role: 'viewer', enabled: true } } : {}),
  password_changed: false,
}));

async function fixture(page, { locale = 'en', accounts = false, unavailable = false, delayed = false, pruneConflict = false } = {}) {
  const calls = [];
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  let blockedOnce = false;
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, search: url.search, method: request.method(), body: request.postDataJSON?.(), authorization: request.headers().authorization });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(accounts ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') {
      const username = request.postDataJSON().username;
      return route.fulfill({ json: { token: `${username}-session`, user: { id: username === 'viewer' ? 2 : 1, username, role: username === 'viewer' ? 'viewer' : 'admin', enabled: true } } });
    }
    if (url.pathname === '/v1/auth/logout') return route.fulfill({ status: 204 });
    if (url.pathname === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (url.pathname === '/v1/audit/users') {
      if (delayed && !blockedOnce) { blockedOnce = true; await blocked; }
      if (unavailable) return route.fulfill({ status: 503, json: { title: 'Audit Unavailable', detail: 'audit storage unavailable' } });
      if (request.headers().authorization === 'Bearer viewer-session') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      const after = Number(url.searchParams.get('after'));
      const rows = events.filter((event) => event.id > after).slice(0, 100);
      return route.fulfill({ json: { scope: 'instance', coverage: ['bootstrap', 'create', 'update', 'delete', 'prune'],
        started_at_unix_ms: 1788999999000, records: rows, next_after: rows.at(-1)?.id ?? after,
        oldest_id: 1, latest_id: 101, pruned_through: 0, truncated: false,
        stored_records: 100000, capacity: 100000, writes_available: false,
        server_time_unix_ms: 1789000111000, has_more: after === 0 } });
    }
    if (url.pathname === '/v1/audit/users/prune') return route.fulfill(pruneConflict
      ? { status: 409, json: { title: 'Revision Conflict', detail: 'audit changed' } }
      : { json: { pruned_records: 100, record: { id: 102, action: 'prune' } } });
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  if (accounts) {
    await page.locator('#login-username').fill('admin');
    await page.locator('#login-password').fill('admin password');
    await page.locator('#login-submit').click();
  } else {
    await page.locator('#token-input').fill('fixture-admin-token');
    await page.locator('#login-submit').click();
  }
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { calls, release };
}

test('admin audit shows scope, capacity and bounded ordered pages; export includes only current page', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-rows tr')).toHaveCount(100);
  await expect(page.locator('#audit-meta')).toContainText('This instance only');
  await expect(page.locator('#audit-meta')).toContainText('100,000/100,000');
  await expect(page.locator('#audit-message')).toContainText('Account changes are blocked');
  await expect(page.locator('#audit-prune')).toBeEnabled();
  await page.locator('#audit-next').click();
  await expect(page.locator('#audit-rows tr')).toHaveCount(1);
  await expect(page.locator('#audit-rows')).toContainText('101');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#audit-export').click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toContain('page-100');
  const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
  expect(exported.scope).toBe('instance');
  expect(exported.records.map((record) => record.id)).toEqual([101]);
  await page.locator('#audit-previous').click();
  await expect(page.locator('#audit-rows tr')).toHaveCount(100);
  expect(calls.filter((call) => call.path === '/v1/audit/users').map((call) => call.search)).toEqual([
    '?after=0&limit=100', '?after=100&limit=100', '?after=0&limit=100',
  ]);
});

test('prune needs explicit confirmation and exact page/CAS values; conflict never retries', async ({ page }) => {
  const { calls } = await fixture(page, { pruneConflict: true });
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-rows tr')).toHaveCount(100);
  await page.locator('#audit-prune').click();
  await expect(page.locator('#confirm-dialog')).toBeVisible();
  await expect(page.locator('#confirm-message')).toContainText('Archive all records through #100 first');
  await page.locator('#confirm-dialog [value="cancel"]').click();
  expect(calls.filter((call) => call.path.endsWith('/prune'))).toHaveLength(0);
  await page.locator('#audit-prune').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#audit-message')).toContainText('No automatic retry');
  const prunes = calls.filter((call) => call.path.endsWith('/prune'));
  expect(prunes).toHaveLength(1);
  expect(prunes[0].body).toEqual({ through_id: 100, expected_latest_id: 101 });
  expect(prunes[0].authorization).toBe('Bearer fixture-admin-token');
});

test('unavailable audit never appears as empty history, and viewer cannot open it', async ({ page }) => {
  await fixture(page, { unavailable: true });
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-meta')).toContainText('Audit unavailable');
  await expect(page.locator('#audit-export')).toBeDisabled();
  await expect(page.locator('#audit-prune')).toBeDisabled();
});

test('delayed admin audit response cannot repopulate after logout and viewer login', async ({ page }) => {
  const { calls, release } = await fixture(page, { accounts: true, delayed: true });
  await page.locator('[data-view="audit"]').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/audit/users')).toBe(true);
  await page.locator('#logout-button').click();
  await page.locator('#login-username').fill('viewer');
  await page.locator('#login-password').fill('viewer password');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  release();
  await expect(page.locator('[data-view="audit"]')).toBeHidden();
  await expect(page.locator('#audit-rows')).toBeEmpty();
  await expect(page.locator('#audit-export')).toBeDisabled();
  expect(calls.filter((call) => call.path === '/v1/audit/users')).toHaveLength(1);
});

test('Korean audit copy and row labels follow locale without losing page data', async ({ page }) => {
  await fixture(page, { locale: 'ko' });
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-title')).toHaveText('계정 감사 기록');
  await expect(page.locator('#audit-rows tr')).toHaveCount(100);
  await expect(page.locator('#audit-rows tr').first()).toContainText('감사 기준점');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#audit-rows tr').first()).toContainText('Audit baseline');
  await expect(page.locator('#audit-rows tr')).toHaveCount(100);
});
