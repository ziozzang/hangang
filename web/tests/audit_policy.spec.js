import { test, expect } from '@playwright/test';

const initial = { scope: 'instance', revision: 0, policy: { default_action: 'record', rules: [] }, filtered_total: 0, last_changed_at_unix_ms: 0 };
const auditPage = { scope: 'instance', coverage: ['bootstrap', 'create', 'update', 'delete', 'prune', 'config_operations_prune', 'policy_change'],
  started_at_unix_ms: 1789000000000, server_time_unix_ms: 1789000001000, records: [
    { id: 1, time_unix_ms: 1789000000000, action: 'baseline', actor_kind: 'system', password_changed: false, affected_count: 1, policy_revision: 0 },
  ], next_after: 1, oldest_id: 1, latest_id: 1, pruned_through: 0, truncated: false,
  stored_records: 1, capacity: 100000, writes_available: true, has_more: false,
  policy_revision: 0, filtered_total: 0, coverage_filtered: false };

async function fixture(page, { locale = 'en', role = 'admin', putStatus = 200, delayed = false } = {}) {
  const calls = [];
  let observation = structuredClone(initial);
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  if (locale === 'ko') await page.addInitScript(() => localStorage.setItem('hangang-locale', 'ko'));
  await page.route('**/*', async (route) => {
    const request = route.request(); const path = new URL(request.url()).pathname;
    if (path.startsWith('/ui/')) return route.continue();
    calls.push({ path, method: request.method(), body: request.postDataJSON?.() });
    if (path === '/v1/auth/setup') return route.fulfill(role === 'viewer' ? { json: { bootstrap_required: false } } : { status: 404, body: 'not found' });
    if (path === '/v1/auth/login') return route.fulfill({ json: { token: 'viewer-session', user: { id: 2, username: 'viewer', role: 'viewer', enabled: true } } });
    if (path === '/v1/auth/logout') return route.fulfill({ status: 204 });
    if (path === '/v1/auth/me') return route.fulfill({ json: { user: { id: 1, username: 'fixture', role, enabled: true } } });
    if (path === '/v1/status') return route.fulfill({ json: { revision: 1, http_routes: 0, tcp_routes: 0, uptime_seconds: 1, metrics: {}, state: { ready: true } } });
    if (path === '/v1/update/status') return route.fulfill({ json: { enabled: false, phase: 'idle' } });
    if (path === '/v1/events') return route.fulfill({ status: 503, body: 'no stream' });
    if (path === '/v1/audit/users') {
      const records = observation.revision ? [...auditPage.records, { id: 2, time_unix_ms: 1789000002000,
        action: 'policy_change', actor_kind: 'account', actor_user_id: 1, password_changed: false,
        affected_count: 1, policy_revision: observation.revision, policy_snapshot: observation.policy }] : auditPage.records;
      return route.fulfill({ json: { ...auditPage, records, next_after: records.at(-1).id,
        latest_id: records.at(-1).id, stored_records: records.length, policy_revision: observation.revision,
        filtered_total: observation.filtered_total, coverage_filtered: observation.filtered_total > 0 } });
    }
    if (path === '/v1/audit/policy') {
      if (role === 'viewer') return route.fulfill({ status: 403, json: { title: 'Forbidden' } });
      if (request.method() === 'GET') { if (delayed) await pending; return route.fulfill({ json: observation }); }
      if (putStatus !== 200) return route.fulfill({ status: putStatus, json: { title: putStatus === 409 ? 'Conflict' : 'Unavailable', detail: 'test condition' } });
      const body = request.postDataJSON(); observation = { ...observation, revision: observation.revision + 1, policy: body.policy,
        last_changed_at_unix_ms: 1789000002000, filtered_total: 2 };
      return route.fulfill({ json: observation });
    }
    return route.fulfill({ status: 404, body: 'fixture missing' });
  });
  await page.goto('/ui/');
  if (role === 'viewer') {
    await page.locator('#login-username').fill('viewer');
    await page.locator('#login-password').fill('viewer password');
  } else await page.locator('#token-input').fill('fixture-admin-token');
  await page.locator('#login-submit').click();
  await expect(page.locator('#login-dialog')).toBeHidden();
  return { calls, release };
}

test('native ordered policy saves exact CAS body and shows partial coverage', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-policy-meta')).toContainText('revision #0');
  await page.locator('#audit-policy-default').selectOption('drop');
  await page.locator('#audit-policy-add').click();
  const rule = page.locator('#audit-policy-rules .panel');
  await expect(rule).toHaveCount(1);
  await rule.locator('input[type="text"]').fill('omit-viewer-create');
  await rule.locator('fieldset').first().locator('label').first().locator('input').check();
  await rule.locator('fieldset').nth(1).locator('label').nth(1).locator('input').check();
  await rule.locator('textarea').last().fill('42, 43');
  await page.locator('#audit-policy-save').click();
  await expect(page.locator('#confirm-dialog')).toContainText('Missing account records will not prove no change');
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#audit-policy-meta')).toContainText('Filtered account events: 2');
  await expect(page.locator('#audit-message')).toContainText('partial');
  await expect(page.locator('#audit-rows')).toContainText('Recording policy revision #1');
  const put = calls.find((call) => call.path === '/v1/audit/policy' && call.method === 'PUT');
  expect(put.body).toEqual({ expected_revision: 0, policy: { default_action: 'drop', rules: [
    { id: 'omit-viewer-create', action: 'record', match: { actions: ['create'], actor_kinds: ['account'], actor_user_ids: [], target_user_ids: [42, 43] } },
  ] } });
});

test('rule ordering, explicit catch-all and empty conditions stay local until valid save', async ({ page }) => {
  const { calls } = await fixture(page);
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-policy-add')).toBeEnabled();
  await page.locator('#audit-policy-add').click();
  await page.locator('#audit-policy-add').click();
  const cards = page.locator('#audit-policy-rules .panel');
  await cards.first().locator('input[type="text"]').fill('first');
  await cards.nth(1).locator('input[type="text"]').fill('second');
  await cards.nth(1).getByRole('button', { name: 'Move up' }).click();
  await expect(cards.first().locator('input[type="text"]')).toHaveValue('second');
  await cards.first().getByText('Match all account changes').locator('input').check();
  await page.locator('#audit-policy-save').click();
  await expect(page.locator('#audit-policy-message')).toContainText('Select a condition');
  expect(calls.filter((call) => call.path === '/v1/audit/policy' && call.method === 'PUT')).toHaveLength(0);
  await cards.nth(1).getByText('Match all account changes').locator('input').check();
  await page.locator('#audit-policy-save').click();
  await page.locator('#confirm-accept').click();
  await expect(page.locator('#audit-policy-meta')).toContainText('revision #1');
  const put = calls.find((call) => call.path === '/v1/audit/policy' && call.method === 'PUT');
  expect(put.body.policy.rules.map(({ id, match }) => [id, match])).toEqual([['second', {}], ['first', {}]]);
});

for (const putStatus of [409, 503]) {
  test(`${putStatus} policy outcome retains draft without replay`, async ({ page }) => {
    const { calls } = await fixture(page, { putStatus });
    await page.locator('[data-view="audit"]').click();
    await expect(page.locator('#audit-policy-add')).toBeEnabled();
    await page.locator('#audit-policy-default').selectOption('drop');
    await page.locator('#audit-policy-save').click(); await page.locator('#confirm-accept').click();
    await expect(page.locator('#audit-policy-message')).toContainText('no automatic save retry');
    await expect(page.locator('#audit-policy-default')).toHaveValue('drop');
    expect(calls.filter((call) => call.path === '/v1/audit/policy' && call.method === 'PUT')).toHaveLength(1);
  });
}

test('Korean policy labels survive locale rerender; late GET is scrubbed after logout', async ({ page }) => {
  const { release } = await fixture(page, { locale: 'ko', delayed: true });
  await page.locator('[data-view="audit"]').click();
  await expect(page.locator('#audit-policy-panel')).toContainText('계정 감사 기록 정책');
  await page.locator('#logout-button').click();
  release();
  await expect(page.locator('#login-dialog')).toBeVisible();
  await expect(page.locator('#audit-policy-rules .panel')).toHaveCount(0);
  await expect(page.locator('#audit-policy-meta')).toBeEmpty();
});

test('viewer has no account audit policy controls or fetch', async ({ page }) => {
  const { calls } = await fixture(page, { role: 'viewer' });
  await expect(page.locator('[data-view="audit"]')).toBeHidden();
  expect(calls.some((call) => call.path === '/v1/audit/policy')).toBe(false);
});
