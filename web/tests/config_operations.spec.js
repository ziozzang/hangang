import { test, expect } from '@playwright/test';

const operation = (id, state = 'candidate_activated') => ({
  id, operation_id: id.toString(16).padStart(32, '0'), authority_id: 'b'.repeat(32),
  actor_kind: id % 2 ? 'account' : 'system', actor_user_id: id % 2 ? 7 : null,
  accepted_at_unix_ms: 1789000000000 + id * 1000,
  finished_at_unix_ms: ['accepted', 'indeterminate'].includes(state) ? null : 1789000001000 + id * 1000,
  expected_revision: id - 1, candidate_sha256: 'a'.repeat(64),
  store_kind: 'local_file', authority_epoch: null, state,
});

async function fixture(page, { locale = 'en', accounts = false, unavailable = false, delayed = false, invalid = false, longHistory = false } = {}) {
  const calls = [];
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const url = new URL(request.url());
    if (url.pathname.startsWith('/ui/')) return route.continue();
    calls.push({ path: url.pathname, search: url.search, authorization: request.headers().authorization });
    if (url.pathname === '/v1/auth/setup') return route.fulfill(accounts ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (url.pathname === '/v1/auth/login') {
      const username = request.postDataJSON().username;
      return route.fulfill({ json: { token: `${username}-session`, user: { id: username === 'viewer' ? 2 : 1, username, role: username === 'viewer' ? 'viewer' : 'admin', enabled: true } } });
    }
    if (url.pathname === '/v1/auth/logout') return route.fulfill({ status: 204 });
    if (url.pathname === '/v1/status') return route.fulfill({ json: { revision: 7, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (url.pathname === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (url.pathname === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (url.pathname === '/v1/config/operations') {
      if (delayed) await blocked;
      if (unavailable) return route.fulfill({ status: 503, json: { title: 'Unavailable', detail: 'history unavailable' } });
      if (request.headers().authorization === 'Bearer viewer-session') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      const after = Number(url.searchParams.get('after'));
      const rows = longHistory ? Array.from({ length: 100 }, (_, index) => operation(after + index + 1))
        : after ? [operation(101, 'indeterminate')] : Array.from({ length: 100 }, (_, index) =>
          operation(index + 1, index === 0 ? 'accepted' : index === 1 ? 'failed' : 'candidate_activated'));
      const data = { scope: 'instance', authority_id: 'b'.repeat(32), records: rows,
        next_after: rows.at(-1).id, has_more: longHistory ? after < 9900 : after === 0,
        capacity: 10000, stored_records: longHistory ? 10000 : 101, writes_available: !longHistory, server_time_unix_ms: 1789001000000 };
      if (invalid) delete data.writes_available;
      return route.fulfill({ json: data });
    }
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  if (accounts) {
    await page.locator('#login-username').fill('admin');
    await page.locator('#login-password').fill('admin password');
  } else await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { calls, release };
}

test('configuration history separates accepted, local activation and unknown outcomes; pages and exports only current page', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('outcome not yet recorded');
  await expect(page.locator('#config-operations-rows tr').nth(2)).toContainText('on this instance');
  await expect(page.locator('#config-operations-message')).toContainText('Do not infer fleet activation');
  await page.locator('#config-operations-next').click();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(1);
  await expect(page.locator('#config-operations-rows')).toContainText('outcome unknown');
  const downloadPromise = page.waitForEvent('download');
  await page.locator('#config-operations-export').click();
  const download = await downloadPromise;
  const contents = await (await import('node:fs/promises')).readFile(await download.path(), 'utf8');
  const exported = JSON.parse(contents);
  expect(exported.export_scope).toBe('current_page_only');
  expect(exported.records.map((record) => record.id)).toEqual([101]);
  await page.locator('#config-operations-previous').click();
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  expect(calls.filter((call) => call.path === '/v1/config/operations').map((call) => call.search)).toEqual([
    '?after=0&limit=100', '?after=100&limit=100', '?after=0&limit=100',
  ]);
});

test('unavailable or invalid history is never rendered as an empty successful result', async ({ page }) => {
  await fixture(page, { unavailable: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-meta')).toContainText('unavailable');
  await expect(page.locator('#config-operations-export')).toBeDisabled();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
});

test('missing operation capacity metadata fails closed', async ({ page }) => {
  await fixture(page, { invalid: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-meta')).toContainText('unavailable');
  await expect(page.locator('#config-operations-message')).toContainText('response is invalid');
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
});

test('viewer cannot open history and delayed admin result cannot repopulate after logout', async ({ page }) => {
  const { calls, release } = await fixture(page, { accounts: true, delayed: true });
  await page.locator('[data-view="config-operations"]').click();
  await expect.poll(() => calls.some((call) => call.path === '/v1/config/operations')).toBe(true);
  await page.locator('#logout-button').click();
  await page.locator('#login-username').fill('viewer');
  await page.locator('#login-password').fill('viewer password');
  await page.locator('#login-submit').click();
  release();
  await expect(page.locator('[data-view="config-operations"]')).toBeHidden();
  await expect(page.locator('#config-operations-rows')).toBeEmpty();
  await expect(page.locator('#config-operations-export')).toBeDisabled();
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(1);
});

test('Korean configuration history re-renders labels without refetching or losing rows', async ({ page }) => {
  const { calls } = await fixture(page, { locale: 'ko' });
  await page.locator('[data-view="config-operations"]').click();
  await expect(page.locator('#config-operations-title')).toHaveText('구성 작업 이력');
  await expect(page.locator('#config-operations-rows tr')).toHaveCount(100);
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('최종 결과 미기록');
  await page.locator('#locale-select').selectOption('en');
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('outcome not yet recorded');
  expect(calls.filter((call) => call.path === '/v1/config/operations')).toHaveLength(1);
});

test('all 10,000 retained operations remain reachable beyond the recent backcursor stack', async ({ page }) => {
  await fixture(page, { longHistory: true });
  await page.locator('[data-view="config-operations"]').click();
  for (let pageNumber = 2; pageNumber <= 66; pageNumber += 1) {
    await page.locator('#config-operations-next').click();
    await expect(page.locator('#config-operations-page-state')).toContainText(`Page ${pageNumber} ·`);
  }
  await expect(page.locator('#config-operations-rows tr').first()).toContainText('6501');
  await expect(page.locator('#config-operations-next')).toBeEnabled();
  await page.locator('#config-operations-previous').click();
  await expect(page.locator('#config-operations-page-state')).toContainText('Page 65 ·');
});
